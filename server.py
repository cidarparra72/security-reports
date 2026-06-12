#!/usr/bin/env python3
"""
FastAPI server exposing APISecurityScanner.
"""

import asyncio
import contextlib
import json
import mimetypes
import os
import sqlite3
import sys
import tempfile
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from security import APISecurityScanner, EthicalHackingReportGenerator
from security.checks_catalog import checks_catalog, normalize_selected_checks
from security.endpoint_probe import (
    build_consolidated_report,
    parse_endpoints_from_json,
    parse_paths_multiline,
    prepare_endpoints,
    run_probes,
)
from security.infer_api_url import (
    _SKIP_INFER_FILE_NAMES_LOWER,
    infer_api_candidates,
    infer_api_endpoints,
)
from security.infer_auth_repo import infer_auth_hints_from_repo
from security.external_tool_findings import merge_external_scan_tool_reports
from security.scan_scope import discover_openapi_specs
from security.vuln_filters import filter_vulnerabilities_for_report, recalculate_summary
from security.endpoint_report import build_endpoint_report

DB_PATH = os.path.join(os.path.dirname(__file__), "scanner.db")
REPORTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "reports"))

# ── Configuración via variables de entorno ────────────────────────────────────
_ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "ALLOWED_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,"
        "http://localhost:5174,http://127.0.0.1:5174,"
        "http://localhost:3000,http://127.0.0.1:3000,"
        "http://localhost:3001,http://127.0.0.1:3001,"
        "http://localhost:3002,http://127.0.0.1:3002,"
        "http://localhost:3003,http://127.0.0.1:3003,"
        "http://localhost:3004,http://127.0.0.1:3004,"
        "http://localhost:3005,http://127.0.0.1:3005,"
        "http://localhost:3006,http://127.0.0.1:3006",
    ).split(",")
    if o.strip()
]
_SCANNER_API_KEY = os.environ.get("SCANNER_API_KEY", "").strip()
_REPORTS_MAX_AGE_DAYS = int(os.environ.get("REPORTS_MAX_AGE_DAYS", "7"))
# SSE / UI: escaneos con ZAP pueden superar 5 min; mantener alineado con useScan.js (polling).
_SCAN_EVENTS_MAX_WAIT_SEC = float(os.environ.get("SCAN_EVENTS_MAX_WAIT_SEC", "1800"))


def _is_local_request(request: Request) -> bool:
    host = (request.client.host if request.client else None) or ""
    return host in ("127.0.0.1", "::1", "localhost")


def _verify_api_key(request: Request) -> None:
    """Dependency: requires X-API-Key header when SCANNER_API_KEY env var is set.
    Local requests (127.0.0.1 / ::1) are always allowed regardless."""
    if not _SCANNER_API_KEY:
        return  # No key configured → dev mode, open
    if _is_local_request(request):
        return  # Local requests always pass
    if request.headers.get("X-API-Key", "") != _SCANNER_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing X-API-Key header")


def _cleanup_old_reports() -> None:
    """Delete files in reports/ older than _REPORTS_MAX_AGE_DAYS."""
    cutoff = datetime.now() - timedelta(days=_REPORTS_MAX_AGE_DAYS)
    try:
        for f in Path(REPORTS_DIR).iterdir():
            if f.is_file():
                try:
                    if datetime.fromtimestamp(f.stat().st_mtime) < cutoff:
                        f.unlink(missing_ok=True)
                except OSError:
                    pass
    except OSError:
        pass


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Startup: init DB, create reports dir, clean old files."""
    init_db()
    os.makedirs(REPORTS_DIR, exist_ok=True)
    _cleanup_old_reports()
    yield


app = FastAPI(title="API Security Scanner", version="1.0.0", lifespan=_lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT,
                created_at TEXT,
                result_json TEXT,
                status TEXT
            )
            """
        )
        cur = conn.execute("PRAGMA table_info(scans)")
        col_names = {r[1] for r in cur.fetchall()}
        if "status" not in col_names:
            conn.execute("ALTER TABLE scans ADD COLUMN status TEXT")
            conn.execute(
                "UPDATE scans SET status = 'completed' WHERE result_json IS NOT NULL AND (status IS NULL OR status = '')"
            )
        conn.commit()
    finally:
        conn.close()


def save_scan(path: str, result: dict) -> int:
    created_at = datetime.now(timezone.utc).isoformat()
    result_json = json.dumps(result, ensure_ascii=False)
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.execute(
            "INSERT INTO scans (path, created_at, result_json, status) VALUES (?, ?, ?, ?)",
            (path, created_at, result_json, "completed"),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def insert_pending_scan(path: str) -> int:
    created_at = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.execute(
            "INSERT INTO scans (path, created_at, result_json, status) VALUES (?, ?, NULL, ?)",
            (path, created_at, "pending"),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def update_scan_completed(scan_id: int, result: dict) -> None:
    result_json = json.dumps(result, ensure_ascii=False)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "UPDATE scans SET result_json = ?, status = ? WHERE id = ?",
            (result_json, "completed", scan_id),
        )
        conn.commit()
    finally:
        conn.close()


def update_scan_failed(scan_id: int, error_message: str) -> None:
    result_json = json.dumps({"error": error_message}, ensure_ascii=False)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "UPDATE scans SET result_json = ?, status = ? WHERE id = ?",
            (result_json, "failed", scan_id),
        )
        conn.commit()
    finally:
        conn.close()


def get_scan(scan_id: int) -> dict:
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.execute(
            "SELECT id, path, created_at, result_json, status FROM scans WHERE id = ?",
            (scan_id,),
        )
        row = cur.fetchone()
    finally:
        conn.close()
    if row is None:
        raise KeyError(scan_id)
    result = json.loads(row[3]) if row[3] is not None else None
    return {
        "id": row[0],
        "path": row[1],
        "created_at": row[2],
        "result": result,
        "status": row[4],
    }


def list_scans(limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    """Listado ligero de corridas (sin devolver el JSON completo del resultado)."""
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    conn = sqlite3.connect(DB_PATH)
    try:
        try:
            cur = conn.execute(
                """
                SELECT id, path, created_at, status,
                       json_extract(result_json, '$.total_vulnerabilities') AS tv,
                       json_extract(result_json, '$.dynamic_api_url') AS api,
                       json_extract(result_json, '$.zap_baseline.html_report') AS zh,
                       json_extract(result_json, '$.zap_baseline.enabled') AS ze
                FROM scans
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            )
            use_extract = True
        except sqlite3.OperationalError:
            cur = conn.execute(
                """
                SELECT id, path, created_at, status, result_json
                FROM scans
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            )
            use_extract = False
        rows = cur.fetchall()
    finally:
        conn.close()

    out: list[dict[str, Any]] = []
    for row in rows:
        if use_extract:
            scan_id, path, created_at, status, tv, api, zh, ze = row
            item: dict[str, Any] = {
                "id": scan_id,
                "path": path,
                "created_at": created_at,
                "status": status or "",
                "total_vulnerabilities": int(tv) if tv is not None else None,
                "dynamic_api_url": api,
                "zap_baseline_html": zh,
                "zap_baseline_enabled": bool(ze) if ze is not None else False,
            }
        else:
            scan_id, path, created_at, status, result_json = row
            item = {
                "id": scan_id,
                "path": path,
                "created_at": created_at,
                "status": status or "",
                "total_vulnerabilities": None,
                "dynamic_api_url": None,
                "zap_baseline_html": None,
                "zap_baseline_enabled": False,
            }
            if str(status or "").lower() == "completed" and result_json:
                try:
                    r = json.loads(result_json)
                except json.JSONDecodeError:
                    r = {}
                t = r.get("total_vulnerabilities")
                item["total_vulnerabilities"] = int(t) if t is not None else None
                item["dynamic_api_url"] = r.get("dynamic_api_url")
                zb = r.get("zap_baseline") or {}
                if isinstance(zb, dict):
                    item["zap_baseline_html"] = zb.get("html_report")
                    item["zap_baseline_enabled"] = bool(zb.get("enabled"))

        rid = int(item["id"])
        item["report_html_cached"] = os.path.isfile(
            os.path.join(REPORTS_DIR, f"report_{rid}.html")
        )
        item["report_pdf_cached"] = os.path.isfile(
            os.path.join(REPORTS_DIR, f"report_{rid}.pdf")
        )
        out.append(item)
    return out


# Startup is handled by the lifespan context manager above.


class ScanRequest(BaseModel):
    path: str = Field(
        default="",
        description="Path to the project directory to scan (vacío si solo hay JSON embebido en el cuerpo).",
    )
    api_url: Optional[str] = Field(
        None,
        description="Base URL del API (https://...) para pruebas dinámicas: TLS, cabeceras, CORS, /swagger.json",
    )
    zap_report: Optional[Any] = Field(
        None,
        description="JSON de OWASP ZAP (alertas exportadas o JSON API) para fusionar en el informe.",
    )
    burp_report: Optional[Any] = Field(
        None,
        description="JSON exportado desde Burp (issues) para fusionar en el informe.",
    )
    run_zap_baseline: bool = Field(
        False,
        description="Si true, ejecuta OWASP ZAP baseline en Docker y fusiona hallazgos.",
    )
    manual_findings: Optional[list[dict]] = Field(
        None,
        description="Hallazgos manuales asistidos (IDOR/enumeracion/rate-limit/JWT) con evidencia estructurada.",
    )
    selected_checks: Optional[list[str]] = Field(
        None,
        description="Lista de checks a ejecutar desde el catalogo.",
    )
    selected_endpoints: Optional[list[str]] = Field(
        None,
        description="Endpoints seleccionados para documentar el alcance del analisis.",
    )
    selected_endpoint_details: Optional[list[dict]] = Field(
        None,
        description="Detalle de endpoints seleccionados: metodo, path, url y origen.",
    )
    languages: Optional[list[str]] = Field(
        None,
        description="Lenguajes del proyecto seleccionados por usuario para contexto.",
    )
    auto_reuse_external_json: bool = Field(
        True,
        description="Si true, reutiliza automaticamente ZAP/Burp JSON del ultimo scan del mismo proyecto cuando no se adjunten nuevos archivos.",
    )
    auth_token: str = Field(
        "",
        description="Bearer token del usuario principal para pruebas dinámicas autenticadas (JWT inspector, checks authórización).",
    )
    second_token: str = Field(
        "",
        description="Token de un segundo usuario (User B) para prueba BOLA/IDOR automática.",
    )
    auth_headers: Optional[dict] = Field(
        None,
        description="Cabeceras HTTP extra para pruebas dinámicas (p.ej. {'X-Api-Key': 'xxx', 'Authorization': 'Bearer ...'}).",
    )
    run_advanced_checks: bool = Field(
        True,
        description="Si true, ejecuta HTTP methods, SSRF, mass assignment, GraphQL introspection, legacy versions y error verbosity.",
    )
    run_project_tests: bool = Field(
        False,
        description="Si true, intenta ejecutar tests del repo (npm test o pytest) y guarda resumen en project_tests.",
    )
    dynamic_http_max_per_endpoint: int = Field(
        0,
        ge=0,
        le=100,
        description="Máx. peticiones HTTP dinámicas por URL de endpoint; 0 = sin tope.",
    )
    code_only: bool = Field(
        False,
        description="Si true, solo SAST/repo: sin inferir URL ni pruebas HTTP dinámicas en el escáner base.",
    )


class ReportRequest(BaseModel):
    scan_id: int


class InferApiRequest(BaseModel):
    path: str = Field(..., min_length=1, description="Path to the project directory")
    limit: int = Field(30, ge=1, le=80, description="Maximum candidate API base URLs to return")
    languages: Optional[List[str]] = Field(
        None,
        description="Optional language ids (javascript, typescript, …); same extension set as /scan",
    )


class InferEndpointsRequest(BaseModel):
    path: str = Field(..., min_length=1, description="Path to the project directory")
    api_url: str = Field(..., min_length=1, description="Selected API base URL")
    limit: int = Field(500, ge=1, le=2000, description="Maximum endpoints to return")
    languages: Optional[List[str]] = Field(
        None,
        description="Optional language ids; must match infer-api for consistent endpoint discovery",
    )


class InferAuthHintsRequest(BaseModel):
    path: str = Field(..., min_length=1, description="Path to the project directory")
    languages: Optional[List[str]] = Field(
        None,
        description="Optional language ids; same extension set as /infer-endpoints",
    )
    limit: int = Field(15, ge=1, le=40, description="Max JWT-like hints to return")


class ApiProbePrepareRequest(BaseModel):
    mode: Literal["json", "base_url"]
    json_text: Optional[str] = None
    base_url: Optional[str] = None
    paths_text: Optional[str] = None


class ApiProbeRunRequest(BaseModel):
    endpoints: List[Dict[str, Any]]
    timeout_sec: float = Field(15.0, ge=1.0, le=120.0)
    max_response_bytes: int = Field(500_000, ge=1024, le=10_000_000)
    indices: Optional[List[int]] = None


class ApiProbeZapRequest(BaseModel):
    """OWASP ZAP baseline (Docker) por cada índice seleccionado; un escaneo secuencial por URL."""

    endpoints: List[Dict[str, Any]]
    indices: List[int] = Field(..., min_length=1, max_length=20)
    spider_minutes: int = Field(2, ge=1, le=15)
    ignore_info: bool = True


class ScanApiAuditorRequest(BaseModel):
    """Colección Postman v2.x + URL base (auditor scanApi)."""

    base_url: str = Field(..., min_length=1, description="URL base real del API")
    collection: Dict[str, Any] = Field(
        ...,
        description="JSON de colección Postman exportado",
    )


class ScanApiPdfRequest(BaseModel):
    static_findings: List[Dict[str, Any]] = Field(default_factory=list)
    live_findings: List[Dict[str, Any]] = Field(default_factory=list)


def _compute_retest_diff(scan_id: int, project_path: str, current_result: dict) -> dict:
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(
            """
            SELECT result_json
            FROM scans
            WHERE id < ? AND path = ? AND status = 'completed' AND result_json IS NOT NULL
            ORDER BY id DESC
            LIMIT 1
            """,
            (scan_id, project_path),
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return {
            "has_previous": False,
            "delta_total": 0,
            "new_titles": [],
            "resolved_titles": [],
        }
    try:
        prev = json.loads(row[0] or "{}")
    except json.JSONDecodeError:
        prev = {}
    curr_v = current_result.get("vulnerabilities", [])
    prev_v = prev.get("vulnerabilities", [])
    curr_titles = {str(v.get("title", "")).strip() for v in curr_v if isinstance(v, dict)}
    prev_titles = {str(v.get("title", "")).strip() for v in prev_v if isinstance(v, dict)}
    curr_titles.discard("")
    prev_titles.discard("")
    return {
        "has_previous": True,
        "delta_total": int(current_result.get("total_vulnerabilities", 0)) - int(prev.get("total_vulnerabilities", 0)),
        "new_titles": sorted(list(curr_titles - prev_titles)),
        "resolved_titles": sorted(list(prev_titles - curr_titles)),
    }


def _endpoint_key_from_detail(endpoint: dict) -> str:
    method = str(endpoint.get("method") or "GET").upper()
    url = str(endpoint.get("url") or "").strip()
    return f"{method} {url}".strip()


def _external_checks_summary_rows(
    external_runs: Optional[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not external_runs:
        return []
    rows: list[dict[str, Any]] = []
    for check_id, data in external_runs.items():
        if not isinstance(data, dict):
            continue
        rows.append(
            {
                "id": str(check_id),
                "status": str(data.get("status", "?")),
                "reason": str(data.get("reason", "")),
                "exit_code": data.get("exit_code"),
            }
        )
    return sorted(rows, key=lambda x: x["id"])


def _build_executive_summary_block(
    result: dict[str, Any],
    api_url_requested: Optional[str],
    selected: Set[str],
    external_rows: list[dict[str, Any]],
    endpoint_details: Optional[list[dict]] = None,
    code_only: bool = False,
) -> dict[str, Any]:
    summary = result.get("summary") or {}
    total = int(result.get("total_vulnerabilities") or 0)
    sev_order = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def _sev_key(v: dict) -> int:
        s = str(v.get("severity", "LOW")).upper()
        return sev_order.index(s) if s in sev_order else 99

    vulns = [v for v in (result.get("vulnerabilities") or []) if isinstance(v, dict)]
    ranked = sorted(vulns, key=_sev_key)
    top = [
        str(v.get("title", "")).strip()
        for v in ranked[:5]
        if str(v.get("title", "")).strip()
    ]
    dyn = str(result.get("dynamic_api_url") or "").strip()
    inferred = bool(result.get("dynamic_api_inferred"))
    openapi_n = len(result.get("openapi_specs") or [])
    skipped = [r for r in external_rows if r.get("status") == "skipped"]
    headline_parts = [f"{total} hallazgos"]
    if summary.get("CRITICAL"):
        headline_parts.append(f"{int(summary['CRITICAL'])} críticos")
    actions: list[str] = []
    secrets_n = int((result.get("secrets_audit") or {}).get("findings_count") or 0)
    if secrets_n:
        actions.insert(
            0,
            f"URGENTE: {secrets_n} secreto(s) o token(s) quemado(s) en código — rotar credenciales y ver sección del informe.",
        )
    if summary.get("CRITICAL"):
        actions.append(
            "Priorizar remediación de hallazgos CRITICAL (secretos, inyección, auth rota)."
        )
    if summary.get("HIGH"):
        actions.append(
            "Planificar corrección de hallazgos HIGH (transporte, headers, exposición)."
        )
    if not code_only and not dyn and "dynamic_http_tls" in selected:
        actions.append(
            "Indicar URL base del API o usar inferencia desde código para habilitar pruebas dinámicas HTTP/TLS."
        )
    if code_only and skipped:
        actions.append(
            "Instala Semgrep, Trivy o Grype en el servidor del escáner para ampliar cobertura SAST/dependencias."
        )
    ep_details = (
        endpoint_details
        if endpoint_details is not None
        else (result.get("selected_endpoint_details") or [])
    )
    if isinstance(ep_details, list) and len(ep_details) > 24:
        actions.append(
            "Muchos endpoints en alcance: priorizar remediación y validar que la URL base corresponda al entorno."
        )
    if openapi_n and "schemathesis" in selected:
        actions.append(
            f"OpenAPI/Swagger local detectado ({openapi_n} ruta(s)): con Schemathesis instalado se puede fuzzear el contrato."
        )
    if skipped:
        actions.append(
            f"{len(skipped)} check(s) externo(s) omitido(s) (binario ausente o requisito no cumplido); ver tabla en el informe."
        )
    return {
        "total_findings": total,
        "summary_counts": {k: int(summary.get(k) or 0) for k in sev_order},
        "headline": " — ".join(headline_parts),
        "priority_titles": top,
        "dynamic_api_url": dyn or None,
        "dynamic_api_inferred": inferred,
        "api_url_requested": (api_url_requested or "").strip() or None,
        "openapi_specs_found": openapi_n,
        "recommended_actions": actions,
    }


_DYNAMIC_CHECK_IDS = frozenset(
    {"dynamic_http_tls", "api_runtime_core", "docs_exposure_probe"}
)


def _skip_dynamic_scan(
    api_url: Optional[str],
    selected: Set[str],
    code_only: bool,
) -> bool:
    if code_only:
        return True
    if (api_url or "").strip():
        return False
    return not bool(selected & _DYNAMIC_CHECK_IDS)


def _effective_auth_headers(
    auth_headers: Optional[dict], auth_token: str
) -> Optional[dict]:
    """Combina cabeceras extra con Authorization derivada del token A si hace falta."""
    merged = dict(auth_headers or {})
    token = (auth_token or "").strip()
    if token and not any(k.lower() == "authorization" for k in merged):
        bearer = token if token.lower().startswith("bearer ") else f"Bearer {token}"
        merged["Authorization"] = bearer
    return merged or None


def _merge_endpoint_details_lists(*lists: list) -> list[dict]:
    """Une listas de detalles de endpoint sin duplicar por método+URL."""
    by_key: dict[str, dict] = {}
    for lst in lists:
        for d in lst or []:
            if not isinstance(d, dict):
                continue
            if not str(d.get("url", "")).strip():
                continue
            k = _endpoint_key_from_detail(d)
            if k not in by_key:
                by_key[k] = d
    return list(by_key.values())


def _api_origin_from_endpoint_list(endpoints: list[dict]) -> Optional[str]:
    """Obtiene https://host de la primera URL absoluta en la lista de endpoints."""
    for e in endpoints:
        if not isinstance(e, dict):
            continue
        u = str(e.get("url") or "").strip()
        if u.startswith("http://") or u.startswith("https://"):
            p = urlparse(u)
            if p.scheme in ("http", "https") and p.netloc:
                return f"{p.scheme}://{p.netloc}"
    return None


def _validate_http_api_url(url: Optional[str], field_name: str = "api_url") -> Optional[str]:
    u = (url or "").strip()
    if not u:
        return None
    pu = urlparse(u)
    if pu.scheme not in ("http", "https") or not pu.netloc:
        raise HTTPException(
            status_code=400,
            detail={
                "message": f"{field_name} must be a valid URL with scheme http or https",
                field_name: url,
            },
        )
    return u


@contextlib.contextmanager
def _scanner_print_silenced():
    """Scanner uses print() with UTF-8 symbols; avoid Windows console encoding errors during API calls."""
    with open(os.devnull, "w", encoding="utf-8") as devnull:
        old = sys.stdout
        sys.stdout = devnull
        try:
            yield
        finally:
            sys.stdout = old


def _run_scan_in_background(
    scan_id: int,
    project_path: str,
    api_url: Optional[str] = None,
    zap_report: Any = None,
    burp_report: Any = None,
    run_zap_baseline_enabled: bool = False,
    manual_findings: Optional[list[dict]] = None,
    selected_checks: Optional[list[str]] = None,
    selected_endpoints: Optional[list[str]] = None,
    selected_endpoint_details: Optional[list[dict]] = None,
    languages: Optional[list[str]] = None,
    uploaded_zap_json_file: Optional[str] = None,
    uploaded_burp_json_file: Optional[str] = None,
    auto_reuse_external_json: bool = True,
    auth_token: str = "",
    second_token: str = "",
    auth_headers: Optional[dict] = None,
    run_advanced_checks: bool = True,
    collection_inventory_full: Optional[list[dict]] = None,
    run_project_tests: bool = False,
    dynamic_http_max_per_endpoint: int = 0,
    code_only: bool = False,
) -> None:
    try:
        from security.http_probe_budget import HttpRequestBudget

        http_budget = (
            HttpRequestBudget(dynamic_http_max_per_endpoint)
            if int(dynamic_http_max_per_endpoint) > 0
            else None
        )
        from security.external_import import (
            merge_external_findings,
            parse_burp_report,
            parse_zap_report,
        )
        from security.manual_checks import parse_manual_findings, summarize_manual_findings
        from security.zap_baseline_runner import run_zap_baseline
        from security.external_checks import run_selected_external_checks

        selected = normalize_selected_checks(selected_checks)
        skip_dynamic = _skip_dynamic_scan(api_url, selected, code_only)
        enabled_patterns = set()
        if "static_patterns" in selected:
            from security.checks_catalog import PATTERN_CHECKS

            enabled_patterns = set(PATTERN_CHECKS)

        scanner = APISecurityScanner(
            project_path,
            target_api_url=api_url,
            enabled_pattern_ids=enabled_patterns,
            languages=languages,
            skip_dynamic_checks=skip_dynamic,
        )
        with _scanner_print_silenced():
            result = scanner.scan()
        result["code_only"] = bool(code_only)
        scope = result.get("scan_scope")
        if isinstance(scope, dict) and languages:
            scope["languages"] = list(languages)
        run_zap = run_zap_baseline_enabled or ("zap_baseline" in selected)
        if run_zap:
            os.makedirs(REPORTS_DIR, exist_ok=True)
            scan_prefix = f"scan-{scan_id}-zap-baseline"
            run_zap_baseline(
                project_path=Path(project_path),
                target_url=api_url,
                spider_minutes=5,
                ignore_info=True,
                html_report=f"{scan_prefix}.html",
                json_report=f"{scan_prefix}.json",
                work_dir=Path(REPORTS_DIR),
            )
            zap_json_path = Path(REPORTS_DIR) / f"{scan_prefix}.json"
            if zap_json_path.exists():
                try:
                    with zap_json_path.open("r", encoding="utf-8") as f:
                        zap_report = json.load(f)
                except (OSError, json.JSONDecodeError):
                    pass

        def _load_reusable_external_json(kind: str) -> Any:
            conn = sqlite3.connect(DB_PATH)
            try:
                row = conn.execute(
                    """
                    SELECT result_json
                    FROM scans
                    WHERE id < ? AND path = ? AND status = 'completed' AND result_json IS NOT NULL
                    ORDER BY id DESC
                    LIMIT 10
                    """,
                    (scan_id, project_path),
                ).fetchall()
            finally:
                conn.close()
            for (payload,) in row:
                try:
                    obj = json.loads(payload or "{}")
                except json.JSONDecodeError:
                    continue
                arts = obj.get("artifacts", []) or []
                for art in arts:
                    if not isinstance(art, dict):
                        continue
                    if str(art.get("kind", "")) != kind:
                        continue
                    name = str(art.get("name", "")).strip()
                    if not name:
                        continue
                    p = Path(REPORTS_DIR) / name
                    if not p.exists():
                        continue
                    try:
                        with p.open("r", encoding="utf-8") as fh:
                            return json.load(fh)
                    except (OSError, json.JSONDecodeError):
                        continue
            return None

        if auto_reuse_external_json:
            if zap_report is None:
                zap_report = _load_reusable_external_json("uploaded_zap_json")
            if burp_report is None:
                burp_report = _load_reusable_external_json("uploaded_burp_json")

        zap_list = parse_zap_report(zap_report) if zap_report is not None else []
        burp_list = parse_burp_report(burp_report) if burp_report is not None else []
        manual_list = parse_manual_findings(manual_findings or [])
        extras = zap_list + burp_list + manual_list
        if extras:
            merge_external_findings(result, extras)
            result["external_import"] = {
                "zap": len(zap_list),
                "burp": len(burp_list),
                "manual": len(manual_list),
            }
        if manual_findings:
            result["manual_assisted"] = summarize_manual_findings(manual_findings)
        if run_zap:
            result["zap_baseline"] = {
                "enabled": True,
                "html_report": f"scan-{scan_id}-zap-baseline.html",
                "json_report": f"scan-{scan_id}-zap-baseline.json",
            }
        os.makedirs(REPORTS_DIR, exist_ok=True)
        external_runs = run_selected_external_checks(
            project_path=project_path,
            selected_checks=selected,
            target_api_url=api_url or result.get("dynamic_api_url"),
            scan_id=scan_id,
            languages=languages,
            artifacts_dir=REPORTS_DIR,
        )
        if external_runs:
            result["external_checks"] = external_runs

        if "js_code_analysis" in selected:
            from dataclasses import asdict

            from security.js_code_analysis import run_js_code_analysis

            js_findings, js_meta = run_js_code_analysis(
                project_path,
                languages,
                APISecurityScanner.CVSS_BY_SEVERITY,
            )
            result["js_code_analysis_meta"] = js_meta
            result["function_http_audit"] = js_meta.get("function_http_audit") or []
            ext_js = list(result.get("external_checks_summary") or [])
            ext_js.append(
                {
                    "id": "js_code_analysis",
                    "status": "completed" if js_meta.get("enabled", True) else "skipped",
                    "reason": (
                        f"{js_meta.get('functions_analyzed', 0)} funciones en "
                        f"{js_meta.get('files_scanned', 0)} archivos JS/TS; "
                        f"{js_meta.get('api_functions_reviewed', 0)} con llamadas API revisadas; "
                        f"{js_meta.get('findings_count', 0)} hallazgos"
                        + (
                            f"; {js_meta.get('hygiene_findings_count', 0)} calidad/linter"
                            if js_meta.get("hygiene_findings_count")
                            else ""
                        )
                    )[:500],
                }
            )
            result["external_checks_summary"] = ext_js
            if js_findings:
                result["vulnerabilities"].extend([asdict(v) for v in js_findings])
                summary = result.get("summary", {}) or {}
                for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    summary[sev] = 0
                for v in result.get("vulnerabilities", []):
                    s = str(v.get("severity", "")).upper()
                    if s in summary:
                        summary[s] += 1
                result["summary"] = summary
                result["total_vulnerabilities"] = len(result.get("vulnerabilities", []))
        elif code_only:
            result["js_code_analysis_meta"] = {
                "enabled": False,
                "reason": "Check js_code_analysis no seleccionado",
            }

        result["openapi_specs"] = discover_openapi_specs(Path(project_path))
        ext_summary = _external_checks_summary_rows(
            external_runs if isinstance(external_runs, dict) else None
        )
        merged_ext: dict[str, dict[str, Any]] = {}
        for row in result.get("external_checks_summary") or []:
            if isinstance(row, dict) and row.get("id"):
                merged_ext[str(row["id"])] = row
        for row in ext_summary:
            merged_ext[str(row["id"])] = row
        result["external_checks_summary"] = sorted(
            merged_ext.values(), key=lambda x: str(x.get("id", ""))
        )

        merged_tool_counts = merge_external_scan_tool_reports(
            result,
            project_path,
            external_runs if isinstance(external_runs, dict) else None,
            artifacts_dir=REPORTS_DIR,
        )
        if merged_tool_counts:
            result["external_tool_findings_merged"] = merged_tool_counts

        if run_project_tests:
            from security.repo_tests import run_project_tests as run_repo_tests_fn

            result["project_tests"] = run_repo_tests_fn(project_path)
            pt = result["project_tests"]
            if isinstance(pt, dict):
                parts: list[str] = []
                if pt.get("runner"):
                    parts.append(str(pt["runner"]))
                ju = pt.get("junit") if isinstance(pt.get("junit"), dict) else None
                if ju:
                    parts.append(
                        f"tests={ju.get('tests', 0)} failures={ju.get('failures', 0)} errors={ju.get('errors', 0)}"
                    )
                elif pt.get("parsed_passed") is not None:
                    parts.append(f"passed≈{pt['parsed_passed']}")
                reason = "; ".join(parts) if parts else (str(pt.get("reason") or "").strip() or "—")
                if pt.get("exit_code") is not None and not ju:
                    reason = f"{reason} (exit {pt['exit_code']})".strip()
                ext_summary2 = list(result.get("external_checks_summary") or [])
                ext_summary2.append(
                    {
                        "id": "project_tests",
                        "status": str(pt.get("status", "skipped")),
                        "reason": reason[:500],
                    }
                )
                result["external_checks_summary"] = ext_summary2

        endpoint_scope = [
            str(x).strip() for x in (selected_endpoints or []) if str(x).strip()
        ]
        endpoint_details = [
            x for x in (selected_endpoint_details or []) if isinstance(x, dict)
        ]
        result["selected_endpoints"] = endpoint_scope
        result["selected_endpoint_details"] = endpoint_details
        if "api_runtime_core" in selected and (api_url or result.get("dynamic_api_url")):
            from security.dynamic_checks import run_api_runtime_core_checks

            runtime_findings = run_api_runtime_core_checks(
                str(api_url or result.get("dynamic_api_url") or ""),
                endpoint_details,
                APISecurityScanner.CVSS_BY_SEVERITY,
                http_budget=http_budget,
            )
            if runtime_findings:
                result["vulnerabilities"].extend([v.__dict__ for v in runtime_findings])
                summary = result.get("summary", {}) or {}
                for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    summary[sev] = 0
                for v in result.get("vulnerabilities", []):
                    s = str(v.get("severity", "")).upper()
                    if s in summary:
                        summary[s] += 1
                result["summary"] = summary
                result["total_vulnerabilities"] = len(result.get("vulnerabilities", []))
        session_headers = _effective_auth_headers(auth_headers, auth_token)

        if auth_token and run_advanced_checks:
            from security.jwt_inspector import inspect_jwt, test_alg_none_on_server
            jwt_findings = inspect_jwt(auth_token)
            if jwt_findings:
                result["vulnerabilities"].extend([v.__dict__ for v in jwt_findings])
            if api_url or result.get("dynamic_api_url"):
                alg_findings = test_alg_none_on_server(
                    str(api_url or result.get("dynamic_api_url") or ""),
                    auth_token,
                    session_headers,
                )
                if alg_findings:
                    result["vulnerabilities"].extend([v.__dict__ for v in alg_findings])

        if auth_token and second_token and run_advanced_checks:
            from security.bola_check import run_bola_checks
            bola_findings = run_bola_checks(
                endpoint_details, auth_token, second_token, http_budget=http_budget
            )
            if bola_findings:
                result["vulnerabilities"].extend([v.__dict__ for v in bola_findings])

        if run_advanced_checks and (api_url or result.get("dynamic_api_url")):
            from security.advanced_dynamic_checks import run_advanced_dynamic_checks
            advanced_findings = run_advanced_dynamic_checks(
                base_url=str(api_url or result.get("dynamic_api_url") or ""),
                endpoints=endpoint_details,
                auth_headers=session_headers,
                cvss_map=APISecurityScanner.CVSS_BY_SEVERITY,
                trivy_json_path=str(project_path) + "/trivy-results.json",
                grype_json_path=str(project_path) + "/grype-results.json",
                http_budget=http_budget,
            )
            if advanced_findings:
                result["vulnerabilities"].extend([v.__dict__ for v in advanced_findings])

        # Recalculate summary if advanced checks ran
        if run_advanced_checks:
            summary = result.get("summary", {}) or {}
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                summary[sev] = 0
            for v in result.get("vulnerabilities", []):
                s = str(v.get("severity", "")).upper()
                if s in summary:
                    summary[s] += 1
            result["summary"] = summary
            result["total_vulnerabilities"] = len(result.get("vulnerabilities", []))

        if code_only or "static_patterns" in selected:
            from dataclasses import asdict as _asdict_sec

            from security.secrets_audit import run_secrets_audit

            secret_vulns, secrets_meta = run_secrets_audit(
                project_path,
                languages,
                APISecurityScanner.CVSS_BY_SEVERITY,
            )
            result["secrets_audit"] = secrets_meta
            if secret_vulns:
                result["vulnerabilities"].extend(
                    [_asdict_sec(v) for v in secret_vulns]
                )

        inv = (
            [x for x in (collection_inventory_full or []) if isinstance(x, dict)]
            if collection_inventory_full
            else []
        )
        from security.js_code_analysis import enrich_vulnerabilities_with_function_names

        vulns_raw = [x for x in result.get("vulnerabilities", []) if isinstance(x, dict)]
        enrich_vulnerabilities_with_function_names(
            vulns_raw, Path(project_path), languages
        )
        vulns_final = filter_vulnerabilities_for_report(vulns_raw)
        result["vulnerabilities"] = vulns_final
        summary_f, total_f = recalculate_summary(vulns_final)
        result["summary"] = summary_f
        result["total_vulnerabilities"] = total_f
        if isinstance(result.get("executive_summary"), dict):
            result["executive_summary"]["total_findings"] = total_f
            result["executive_summary"]["summary_counts"] = summary_f
        # Sonda + hallazgos por URL (presupuesto nuevo para el informe, no reutiliza el del scan).
        report_http_budget = (
            HttpRequestBudget(dynamic_http_max_per_endpoint)
            if int(dynamic_http_max_per_endpoint) > 0
            else None
        )
        result["api_endpoint_report"] = build_endpoint_report(
            api_url or result.get("dynamic_api_url") or "",
            endpoint_scope,
            endpoint_details,
            vulns_final,
            http_budget=report_http_budget,
        )
        result["endpoint_report_meta"] = {
            "inventory_total": len(inv) if inv else len(endpoint_details),
            "dynamic_scope_total": len(endpoint_details),
            "report_lists_full_collection": bool(inv) and len(inv) > len(endpoint_details),
        }

        result["executive_summary"] = _build_executive_summary_block(
            result,
            api_url,
            selected,
            result.get("external_checks_summary") or [],
            endpoint_details,
            code_only=bool(code_only),
        )
        pt = result.get("project_tests")
        if isinstance(pt, dict) and pt.get("status") in ("failed", "timeout"):
            es = result.get("executive_summary")
            if isinstance(es, dict):
                actions = list(es.get("recommended_actions") or [])
                if pt.get("status") == "timeout":
                    actions.append(
                        "Tests del repositorio excedieron el tiempo máximo; revisa salida y REPO_TESTS_TIMEOUT_SEC."
                    )
                else:
                    actions.append(
                        "Tests del repositorio reportaron fallos; revisa el bloque «Tests del repositorio» en resultados."
                    )
                es["recommended_actions"] = actions

        artifacts = []
        result_json_name = f"scan-{scan_id}-result.json"
        result_json_path = Path(REPORTS_DIR) / result_json_name
        try:
            with result_json_path.open("w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            artifacts.append({"name": result_json_name, "kind": "scan_result_json"})
        except OSError:
            pass

        if run_zap and result.get("zap_baseline", {}).get("json_report"):
            artifacts.append(
                {
                    "name": str(result["zap_baseline"]["json_report"]),
                    "kind": "zap_baseline_json",
                }
            )
            html_name = result["zap_baseline"].get("html_report")
            if html_name:
                artifacts.append(
                    {
                        "name": str(html_name),
                        "kind": "zap_baseline_html",
                    }
                )
        if uploaded_zap_json_file:
            artifacts.append({"name": uploaded_zap_json_file, "kind": "uploaded_zap_json"})
        if uploaded_burp_json_file:
            artifacts.append({"name": uploaded_burp_json_file, "kind": "uploaded_burp_json"})
        if isinstance(result.get("external_checks"), dict):
            for check_id, check_data in result["external_checks"].items():
                if isinstance(check_data, dict) and check_data.get("report_file"):
                    artifacts.append(
                        {
                            "name": str(check_data["report_file"]),
                            "kind": f"{check_id}_json",
                        }
                    )
        if result.get("dynamic_api_url"):
            base = str(result["dynamic_api_url"]).rstrip("/")
            artifacts.append({"name": f"{base}/swagger.json", "kind": "swagger_url", "location": "url"})

        result["artifacts"] = artifacts

        from security.analysis_run_summary import build_analysis_run_summary

        result["analysis_run_summary"] = build_analysis_run_summary(
            result, selected, bool(code_only)
        )

        result["retest_diff"] = _compute_retest_diff(scan_id, project_path, result)
        result["technical_annex"] = {
            "commands": [
                "python -m src.security.api_scanner --path <project>",
                "python -m src.security.zap_baseline_runner --path <project> --target-url <api_url>",
            ],
            "languages": languages or [],
            "selected_checks": sorted(list(selected)),
            "selected_endpoints": endpoint_scope,
            "selected_endpoint_details": endpoint_details,
            "openapi_specs_discovered": result.get("openapi_specs") or [],
            "api_runtime_probe_options": {
                "dynamic_http_max_per_endpoint": dynamic_http_max_per_endpoint,
            },
            "references": [
                "https://owasp.org/API-Security/",
                "https://owasp.org/www-project-web-security-testing-guide/",
                "https://cwe.mitre.org/",
            ],
        }
        update_scan_completed(scan_id, result)
    except OSError as e:
        update_scan_failed(scan_id, f"Failed to read project path: {e}")
    except Exception as e:
        update_scan_failed(scan_id, str(e))


@app.post("/scan")
def scan(req: ScanRequest, background_tasks: BackgroundTasks, _key: None = Depends(_verify_api_key)) -> dict:
    """
    Queue a security scan: create a pending DB row, return scan_id, run scanner in background.
    """
    has_embedded = req.zap_report is not None or req.burp_report is not None

    resolved: Optional[Path] = None
    path_stripped = (req.path or "").strip()
    if path_stripped:
        try:
            cand = Path(path_stripped).expanduser().resolve()
            if cand.exists() and cand.is_dir():
                resolved = cand
        except (OSError, ValueError):
            resolved = None

    if resolved is None and has_embedded:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        resolved = Path(tempfile.mkdtemp(prefix="scan-json-", dir=REPORTS_DIR))

    if resolved is None:
        raise HTTPException(
            status_code=404,
            detail={
                "message": "Path does not exist",
                "path": req.path or "(vacío)",
                "hint": "Indica una carpeta válida o envía zap_report/burp_report en el JSON.",
            },
        )

    api_url = _validate_http_api_url((req.api_url or "").strip() or None, "api_url")

    project_path = str(resolved)
    scan_id = insert_pending_scan(project_path)
    background_tasks.add_task(
        _run_scan_in_background,
        scan_id,
        project_path,
        api_url,
        req.zap_report,
        req.burp_report,
        req.run_zap_baseline,
        req.manual_findings,
        req.selected_checks,
        req.selected_endpoints,
        req.selected_endpoint_details,
        req.languages,
        None,
        None,
        req.auto_reuse_external_json,
        req.auth_token,
        req.second_token,
        req.auth_headers,
        req.run_advanced_checks,
        None,
        req.run_project_tests,
        req.dynamic_http_max_per_endpoint,
        req.code_only,
    )
    return {"scan_id": scan_id, "status": "pending"}


@app.post("/infer-api")
def infer_api(req: InferApiRequest) -> dict:
    try:
        resolved = Path(req.path).expanduser().resolve()
    except (OSError, ValueError) as e:
        raise HTTPException(
            status_code=400,
            detail={"message": "Invalid path", "error": str(e)},
        ) from e
    if not resolved.exists():
        raise HTTPException(
            status_code=404,
            detail={"message": "Path does not exist", "path": req.path},
        )
    if not resolved.is_dir():
        raise HTTPException(
            status_code=400,
            detail={"message": "Path is not a directory", "path": req.path},
        )
    candidates = infer_api_candidates(
        resolved, limit=req.limit, languages=req.languages
    )
    return {"candidates": candidates}


@app.post("/infer-endpoints")
def infer_endpoints(req: InferEndpointsRequest) -> dict:
    try:
        resolved = Path(req.path).expanduser().resolve()
    except (OSError, ValueError) as e:
        raise HTTPException(
            status_code=400,
            detail={"message": "Invalid path", "error": str(e)},
        ) from e
    if not resolved.exists():
        raise HTTPException(
            status_code=404,
            detail={"message": "Path does not exist", "path": req.path},
        )
    if not resolved.is_dir():
        raise HTTPException(
            status_code=400,
            detail={"message": "Path is not a directory", "path": req.path},
        )
    pu = urlparse(req.api_url)
    if pu.scheme not in ("http", "https") or not pu.netloc:
        raise HTTPException(
            status_code=400,
            detail={"message": "api_url must be a valid URL with scheme http or https"},
        )
    from security.infer_api_url import filter_endpoints_by_api_base, infer_api_endpoints

    endpoints = infer_api_endpoints(
        resolved, req.api_url, limit=req.limit, languages=req.languages
    )
    endpoints = filter_endpoints_by_api_base(req.api_url, endpoints)
    return {"api_url": req.api_url, "endpoints": endpoints}


@app.post("/infer-auth-hints")
def infer_auth_hints(req: InferAuthHintsRequest) -> dict:
    """JWT / Bearer literales en .env y código (heurística para rellenar sesión en la UI)."""
    try:
        resolved = Path(req.path).expanduser().resolve()
    except (OSError, ValueError) as e:
        raise HTTPException(
            status_code=400,
            detail={"message": "Invalid path", "error": str(e)},
        ) from e
    if not resolved.exists():
        raise HTTPException(
            status_code=404,
            detail={"message": "Path does not exist", "path": req.path},
        )
    if not resolved.is_dir():
        raise HTTPException(
            status_code=400,
            detail={"message": "Path is not a directory", "path": req.path},
        )
    hints = infer_auth_hints_from_repo(
        resolved, languages=req.languages, limit=req.limit
    )
    return {"hints": hints}


@app.post("/api-probe/prepare")
def api_probe_prepare(req: ApiProbePrepareRequest) -> dict:
    """Normaliza lista de endpoints desde JSON o desde base_url + rutas multilínea."""
    if req.mode == "json":
        if not (req.json_text or "").strip():
            raise HTTPException(
                status_code=400,
                detail={"message": "En modo json se requiere json_text"},
            )
        raw, parse_errors = parse_endpoints_from_json(req.json_text)
    else:
        if not (req.base_url or "").strip():
            raise HTTPException(
                status_code=400,
                detail={"message": "En modo base_url se requiere base_url"},
            )
        raw, parse_errors = parse_paths_multiline(req.paths_text or "")

    normalized, norm_errors = prepare_endpoints(raw, req.base_url)
    return {
        "endpoints": normalized,
        "parse_errors": parse_errors,
        "normalize_errors": norm_errors,
        "ok": bool(normalized),
    }


@app.post("/api-probe/run")
def api_probe_run(req: ApiProbeRunRequest) -> dict:
    """Ejecuta peticiones HTTP sobre endpoints ya normalizados (subset vía indices)."""
    if not req.endpoints:
        raise HTTPException(
            status_code=400,
            detail={"message": "endpoints no puede estar vacío"},
        )
    for i, ep in enumerate(req.endpoints):
        url = ep.get("url")
        if not url or not isinstance(url, str):
            raise HTTPException(
                status_code=400,
                detail={"message": f"endpoints[{i}] requiere url http(s)"},
            )
        if not str(url).lower().startswith(("http://", "https://")):
            raise HTTPException(
                status_code=400,
                detail={"message": f"endpoints[{i}]: url debe ser http o https"},
            )

    rows = run_probes(
        req.endpoints,
        timeout_sec=req.timeout_sec,
        max_response_bytes=req.max_response_bytes,
        indices=req.indices,
    )
    return build_consolidated_report(rows)


@app.post("/api-probe/zap-baseline")
def api_probe_zap_baseline(req: ApiProbeZapRequest) -> dict:
    """
    Ejecuta zap-baseline.py en Docker una vez por cada endpoint seleccionado.
    Los informes quedan en /reports/probe-zap-<job>/zap-<índice>.{json,html}.
    """
    from security.zap_baseline_runner import run_zap_baseline_on_indices

    if not req.endpoints:
        raise HTTPException(
            status_code=400,
            detail={"message": "endpoints no puede estar vacío"},
        )
    job = str(uuid.uuid4())[:12]
    folder_name = f"probe-zap-{job}"
    work_dir = Path(REPORTS_DIR) / folder_name
    rows, global_err = run_zap_baseline_on_indices(
        work_dir,
        req.endpoints,
        req.indices,
        spider_minutes=req.spider_minutes,
        ignore_info=req.ignore_info,
    )
    if global_err:
        raise HTTPException(
            status_code=400,
            detail={"message": global_err},
        )

    enriched = []
    for r in rows:
        jr = r.get("json_file")
        hr = r.get("html_file")
        enriched.append(
            {
                **r,
                "json_url": f"/reports/{folder_name}/{jr}" if jr else None,
                "html_url": f"/reports/{folder_name}/{hr}" if hr else None,
            }
        )

    return {
        "job_id": job,
        "folder": folder_name,
        "spider_minutes": req.spider_minutes,
        "results": enriched,
        "hint": "ZAP usa cada URL como punto de entrada del spider; no reproduce el método HTTP del probe.",
    }


@app.post("/scan-api/static")
def scan_api_auditor_static(req: ScanApiAuditorRequest) -> dict:
    """
    Análisis estático de diseño sobre colección Postman (reglas BOLA, HTTP, auth, etc.).
    """
    from security.scan_api_auditor import analyze_static, count_by_severity

    if not isinstance(req.collection.get("item"), list):
        raise HTTPException(
            status_code=400,
            detail={
                "message": "La colección debe ser Postman v2.x con clave «item».",
                "hint": "Exporta desde Postman → Collection v2.1 (JSON).",
            },
        )
    base = (req.base_url or "").strip()
    if not base.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail={"message": "base_url debe empezar por http:// o https://"},
        )
    findings = analyze_static(req.collection, base)
    return {
        "findings": findings,
        "metrics": count_by_severity(findings),
    }


@app.post("/scan-api/live")
def scan_api_auditor_live(req: ScanApiAuditorRequest) -> dict:
    """
    Health check live: GET a URLs de la colección y revisión de cabeceras/cookies.
    """
    from security.scan_api_auditor import (
        analyze_dynamic_live,
        collect_postman_raw_urls,
        count_by_severity,
    )

    if not isinstance(req.collection.get("item"), list):
        raise HTTPException(
            status_code=400,
            detail={"message": "La colección debe ser Postman v2.x con clave «item»."},
        )
    base = (req.base_url or "").strip()
    if not base.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail={"message": "base_url debe empezar por http:// o https://"},
        )
    from security.scan_api_auditor import clean_url

    urls = collect_postman_raw_urls(req.collection)
    findings = analyze_dynamic_live(urls, base)
    http_urls = {clean_url(u, base) for u in urls}
    http_urls = {u for u in http_urls if u.startswith("http")}
    return {
        "findings": findings,
        "metrics": count_by_severity(findings),
        "urls_probed": len(http_urls),
    }


@app.post("/scan-api/report-pdf")
def scan_api_auditor_pdf(req: ScanApiPdfRequest) -> Response:
    """Genera PDF con hallazgos estáticos y dinámicos (requiere fpdf2)."""
    from security.scan_api_auditor import build_pdf_bytes

    try:
        data = build_pdf_bytes(
            list(req.static_findings or []),
            list(req.live_findings or []),
        )
    except RuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail={"message": str(exc)},
        ) from exc
    return Response(
        content=data,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="Auditoria_API.pdf"',
        },
    )


async def _read_upload_json_file(f: Optional[UploadFile]) -> Any:
    if f is None or not f.filename:
        return None
    raw = await f.read()
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise HTTPException(
            status_code=400,
            detail={"message": "Invalid JSON in upload", "file": f.filename, "error": str(e)},
        ) from e


@app.post("/parse-api-collection")
async def parse_api_collection_endpoint(
    collection_file: UploadFile = File(...),
    api_url: Optional[str] = Form(None),
) -> dict:
    """
    Extrae endpoints desde Postman v2.x, OpenAPI 3 o Swagger 2 (sin ejecutar scan).
    """
    from security.collection_import import parse_api_collection

    data = await _read_upload_json_file(collection_file)
    if not isinstance(data, dict):
        raise HTTPException(
            status_code=400,
            detail={"message": "El archivo debe ser un JSON de objeto (colección o spec)."},
        )
    api_url_s = (api_url or "").strip() or None
    endpoints, suggested = parse_api_collection(data, api_url_s)
    if not endpoints:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "No se pudieron extraer endpoints del JSON.",
                "hint": "Formatos soportados: Postman Collection v2.1 (.json, .postman_collection), OpenAPI 3.x, Swagger 2.0. "
                "Si el spec usa servers relativos o variables {{baseUrl}}, indica también api_url.",
            },
        )
    keys = [_endpoint_key_from_detail(e) for e in endpoints]
    return {
        "endpoints": endpoints,
        "endpoint_keys": keys,
        "suggested_api_url": suggested or api_url_s or "",
        "count": len(endpoints),
    }


@app.post("/scan/upload")
async def scan_upload(
    background_tasks: BackgroundTasks,
    path: str = Form(""),
    api_url: Optional[str] = Form(None),
    zap_file: Optional[UploadFile] = File(None),
    burp_file: Optional[UploadFile] = File(None),
    api_collection_file: Optional[UploadFile] = File(None),
    run_zap_baseline: bool = Form(False),
    selected_checks: Optional[str] = Form(None),
    selected_endpoints: Optional[str] = Form(None),
    selected_endpoint_details: Optional[str] = Form(None),
    languages: Optional[str] = Form(None),
    auto_reuse_external_json: bool = Form(True),
    auth_token: str = Form(""),
    second_token: str = Form(""),
    auth_headers: Optional[str] = Form(None),
    run_advanced_checks: bool = Form(True),
    run_project_tests: bool = Form(False),
    dynamic_http_max_per_endpoint: int = Form(0),
    code_only: bool = Form(False),
) -> dict:
    """
    Igual que POST /scan pero acepta JSON de ZAP/Burp como archivos (útil para reportes grandes).
    Si la ruta del proyecto no existe pero adjuntas JSON (ZAP/Burp/colección), se usa un directorio
    temporal y la URL del API se puede inferir desde la colección o los endpoints.
    """
    zap_report = await _read_upload_json_file(zap_file)
    burp_report = await _read_upload_json_file(burp_file)
    api_collection_json = await _read_upload_json_file(api_collection_file)
    has_upload_payload = (
        zap_report is not None
        or burp_report is not None
        or api_collection_json is not None
    )

    api_url_s = _validate_http_api_url((api_url or "").strip() or None, "api_url")
    selected_checks_list: Optional[list[str]] = None
    selected_endpoints_list: Optional[list[str]] = None
    selected_endpoint_details_list: Optional[list[dict]] = None
    languages_list: Optional[list[str]] = None
    if selected_checks:
        try:
            parsed = json.loads(selected_checks)
            if isinstance(parsed, list):
                selected_checks_list = [str(x) for x in parsed]
        except json.JSONDecodeError:
            pass
    if selected_endpoints:
        try:
            parsed = json.loads(selected_endpoints)
            if isinstance(parsed, list):
                selected_endpoints_list = [str(x) for x in parsed]
        except json.JSONDecodeError:
            pass
    if selected_endpoint_details:
        try:
            parsed = json.loads(selected_endpoint_details)
            if isinstance(parsed, list):
                selected_endpoint_details_list = [x for x in parsed if isinstance(x, dict)]
        except json.JSONDecodeError:
            pass
    if languages:
        try:
            parsed = json.loads(languages)
            if isinstance(parsed, list):
                languages_list = [str(x) for x in parsed]
        except json.JSONDecodeError:
            pass

    rl_max_http = max(0, min(int(dynamic_http_max_per_endpoint), 100))

    collection_inventory_full_arg: Optional[list[dict]] = None

    if api_collection_json is not None:
        from security.collection_import import parse_api_collection

        coll_eps, coll_suggest = parse_api_collection(api_collection_json, api_url_s)
        if not coll_eps:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "No se pudieron extraer endpoints del JSON de colección.",
                    "hint": "Usa Postman v2.1, OpenAPI 3 o Swagger 2. Si el spec es relativo, envía api_url.",
                },
            )
        if coll_suggest and not api_url_s:
            api_url_s = coll_suggest
        collection_inventory_full_arg = list(coll_eps)
        user_sel = [x for x in (selected_endpoint_details_list or []) if isinstance(x, dict)]
        if user_sel:
            selected_endpoint_details_list = user_sel
            selected_endpoints_list = [_endpoint_key_from_detail(d) for d in user_sel]
        else:
            selected_endpoint_details_list = list(coll_eps)
            selected_endpoints_list = [_endpoint_key_from_detail(d) for d in coll_eps]

    if not api_url_s and selected_endpoint_details_list:
        api_url_s = _api_origin_from_endpoint_list(selected_endpoint_details_list)

    if api_url_s:
        api_url_s = _validate_http_api_url(api_url_s, "api_url")

    auth_headers_dict: Optional[dict] = None
    if auth_headers:
        try:
            parsed = json.loads(auth_headers)
            if isinstance(parsed, dict):
                auth_headers_dict = parsed
        except json.JSONDecodeError:
            pass

    resolved: Optional[Path] = None
    path_stripped = (path or "").strip()
    if path_stripped:
        try:
            cand = Path(path_stripped).expanduser().resolve()
            if cand.exists() and cand.is_dir():
                resolved = cand
        except (OSError, ValueError):
            resolved = None

    if resolved is None:
        if has_upload_payload:
            os.makedirs(REPORTS_DIR, exist_ok=True)
            resolved = Path(
                tempfile.mkdtemp(prefix="scan-upload-", dir=REPORTS_DIR)
            )
        else:
            raise HTTPException(
                status_code=404,
                detail={
                    "message": "Path does not exist",
                    "path": path or "(vacío)",
                    "hint": "Indica una carpeta de proyecto válida en el servidor, o sube un JSON "
                    "(ZAP, Burp o colección OpenAPI/Postman) para analizar sin código local.",
                },
            )

    project_path = str(resolved)
    scan_id = insert_pending_scan(project_path)
    uploaded_zap_name = None
    uploaded_burp_name = None
    if zap_report is not None:
        uploaded_zap_name = f"scan-{scan_id}-zap-upload.json"
        try:
            with open(os.path.join(REPORTS_DIR, uploaded_zap_name), "w", encoding="utf-8") as f:
                json.dump(zap_report, f, ensure_ascii=False, indent=2)
        except OSError:
            uploaded_zap_name = None
    if burp_report is not None:
        uploaded_burp_name = f"scan-{scan_id}-burp-upload.json"
        try:
            with open(os.path.join(REPORTS_DIR, uploaded_burp_name), "w", encoding="utf-8") as f:
                json.dump(burp_report, f, ensure_ascii=False, indent=2)
        except OSError:
            uploaded_burp_name = None
    background_tasks.add_task(
        _run_scan_in_background,
        scan_id,
        project_path,
        api_url_s,
        zap_report,
        burp_report,
        run_zap_baseline,
        None,
        selected_checks_list,
        selected_endpoints_list,
        selected_endpoint_details_list,
        languages_list,
        uploaded_zap_name,
        uploaded_burp_name,
        auto_reuse_external_json,
        auth_token,
        second_token,
        auth_headers_dict,
        run_advanced_checks,
        collection_inventory_full_arg,
        run_project_tests,
        rl_max_http,
        code_only,
    )
    return {"scan_id": scan_id, "status": "pending"}


@app.get("/checks/catalog")
def checks_catalog_endpoint() -> dict:
    return checks_catalog()


@app.get("/manual-checks/templates")
def manual_checks_templates() -> dict:
    from security.manual_checks import manual_checklist_templates

    return manual_checklist_templates()


@app.get("/scan/{scan_id}/events")
async def scan_events(scan_id: int):
    """Server-Sent Events stream: emits status events until scan completes or times out."""
    async def _stream():
        max_wait, elapsed, interval = _SCAN_EVENTS_MAX_WAIT_SEC, 0.0, 0.4
        while elapsed < max_wait:
            try:
                row = get_scan(scan_id)
            except KeyError:
                yield 'event: error\ndata: {"error": "scan not found"}\n\n'
                return
            status = row.get("status", "pending")
            result = row.get("result") or {}
            summary = result.get("summary", {}) if status == "completed" else {}
            payload = json.dumps({"status": status, "summary": summary}, ensure_ascii=False)
            yield f"event: status\ndata: {payload}\n\n"
            if status in ("completed", "failed"):
                return
            await asyncio.sleep(interval)
            elapsed += interval
        yield "event: timeout\ndata: {}\n\n"

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/scans")
def scans_list(limit: int = 100, offset: int = 0) -> dict:
    items = list_scans(limit=limit, offset=offset)
    return {"scans": items, "limit": limit, "offset": offset}


@app.get("/scan/{scan_id}")
def get_scan_by_id(scan_id: int) -> dict:
    try:
        return get_scan(scan_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Scan not found") from None


@app.get("/scan/{scan_id}/artifacts")
def get_scan_artifacts(scan_id: int) -> dict:
    try:
        row = get_scan(scan_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Scan not found") from None
    result = row.get("result") or {}
    artifacts = []
    result_artifacts = result.get("artifacts", []) or []
    # Backward compatibility: older scans may not include "artifacts".
    if not result_artifacts:
        legacy = [{"name": f"scan-{scan_id}-result.json", "kind": "scan_result_json"}]
        zap_info = result.get("zap_baseline") or {}
        if isinstance(zap_info, dict) and zap_info.get("json_report"):
            legacy.append(
                {
                    "name": str(zap_info["json_report"]),
                    "kind": "zap_baseline_json",
                    "location": "project_path",
                }
            )
        if isinstance(zap_info, dict) and zap_info.get("html_report"):
            legacy.append(
                {
                    "name": str(zap_info["html_report"]),
                    "kind": "zap_baseline_html",
                    "location": "project_path",
                }
            )
        ext = result.get("external_checks") or {}
        if isinstance(ext, dict):
            for check_id, check_data in ext.items():
                if isinstance(check_data, dict) and check_data.get("report_file"):
                    legacy.append(
                        {
                            "name": str(check_data["report_file"]),
                            "kind": f"{check_id}_json",
                            "location": "project_path",
                        }
                    )
        if result.get("dynamic_api_url"):
            base = str(result["dynamic_api_url"]).rstrip("/")
            legacy.append({"name": f"{base}/swagger.json", "kind": "swagger_url", "location": "url"})
        result_artifacts = legacy

    for item in result_artifacts:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        kind = str(item.get("kind", "artifact")).strip()
        location = str(item.get("location", "reports")).strip()
        if not name:
            continue
        if location == "url":
            artifacts.append({"name": name, "kind": kind, "url": name})
        elif location == "project_path":
            artifacts.append({"name": name, "kind": kind, "url": f"/scan/{scan_id}/project-artifact/{name}"})
        else:
            artifacts.append({"name": name, "kind": kind, "url": f"/scan/{scan_id}/artifact/{name}"})
    return {"artifacts": artifacts}


@app.get("/scan/{scan_id}/artifact/{filename}")
def download_scan_artifact(scan_id: int, filename: str):
    safe = os.path.basename(filename)
    if safe != filename:
        raise HTTPException(status_code=400, detail="Invalid artifact name")
    path = os.path.join(REPORTS_DIR, safe)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Artifact not found")
    guessed, _ = mimetypes.guess_type(safe)
    media = guessed or "application/octet-stream"
    return FileResponse(path, media_type=media, filename=safe)


@app.get("/scan/{scan_id}/project-artifact/{filename:path}")
def download_project_artifact(scan_id: int, filename: str):
    try:
        row = get_scan(scan_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Scan not found") from None
    project_path = str(row.get("path") or "")
    safe_name = os.path.basename(filename)
    reports_target = os.path.join(REPORTS_DIR, safe_name)
    if os.path.exists(reports_target):
        target = reports_target
    else:
        target = os.path.abspath(os.path.join(project_path, safe_name))
        if not target.startswith(os.path.abspath(project_path)):
            raise HTTPException(status_code=400, detail="Invalid path")
        if not os.path.exists(target):
            raise HTTPException(status_code=404, detail="Artifact not found")
    guessed, _ = mimetypes.guess_type(safe_name)
    media = guessed or "application/octet-stream"
    return FileResponse(target, media_type=media, filename=safe_name)


@app.post("/report")
def create_report(req: ReportRequest) -> dict:
    try:
        row = get_scan(req.scan_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Scan not found") from None

    st = str(row.get("status") or "").strip().lower()
    if st != "completed" or row.get("result") is None:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "El scan no está completado o no tiene resultado",
                "status": row.get("status"),
                "scan_id": req.scan_id,
            },
        )

    os.makedirs(REPORTS_DIR, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tf:
        json.dump(row["result"], tf, ensure_ascii=False)
        tmp_path = tf.name

    row_path = str(row.get("path") or "").strip()
    try:
        project_name = Path(row_path).name if row_path else f"scan_{req.scan_id}"
        if not project_name or project_name in (".", ".."):
            project_name = f"scan_{req.scan_id}"
    except (OSError, ValueError):
        project_name = f"scan_{req.scan_id}"

    out_path = os.path.join(REPORTS_DIR, f"report_{req.scan_id}.html")
    out_pdf_path = os.path.join(REPORTS_DIR, f"report_{req.scan_id}.pdf")
    pdf_error: Optional[str] = None

    try:
        target_url = (row["result"] or {}).get("dynamic_api_url", "")
        generator = EthicalHackingReportGenerator(project_name, target_url)
        generator.load_from_scan(tmp_path)
        generator.generate_html(out_path)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "message": "No se pudo generar el informe HTML",
                "error": str(e),
            },
        ) from e
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    try:
        generator.generate_pdf(out_pdf_path)
    except Exception as e:
        pdf_error = str(e)

    payload: Dict[str, Any] = {
        "report_url": f"/reports/report_{req.scan_id}.html",
    }
    if pdf_error:
        payload["report_pdf_url"] = None
        payload["pdf_error"] = pdf_error
    else:
        payload["report_pdf_url"] = f"/reports/report_{req.scan_id}.pdf"
    return payload


os.makedirs(REPORTS_DIR, exist_ok=True)
app.mount("/reports", StaticFiles(directory=REPORTS_DIR), name="reports")


def main() -> None:
    import uvicorn

    # En Windows, reload=True usa multiprocessing y a veces deja el servidor a medias al guardar archivos.
    # Activa recarga explícita: set UVICORN_RELOAD=1
    _reload = os.environ.get("UVICORN_RELOAD", "").strip().lower() in ("1", "true", "yes")
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=_reload)


if __name__ == "__main__":
    main()
