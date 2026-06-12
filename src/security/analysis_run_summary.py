#!/usr/bin/env python3
"""Tabla unificada: qué se analizó y si terminó OK, falló u omitido."""

from __future__ import annotations

from typing import Any, Dict, List, Set

from .checks_catalog import CHECKS, PATTERN_CHECKS

_CHECK_LABELS: Dict[str, str] = {c["id"]: c["name"] for c in CHECKS}
_CHECK_LABELS.update(
    {
        "static_patterns": "Patrones SAST estáticos",
        "secrets_audit": "Secretos y tokens quemados",
        "project_tests": "Tests del repositorio",
    }
)

_OUTCOME_LABELS = {
    "ok": "OK",
    "failed": "Falló",
    "skipped": "Omitido",
    "warning": "Revisar",
}


def _outcome_from_status(status: str, *, findings: int = 0, test_failures: int = 0) -> str:
    st = (status or "").lower()
    if st in ("failed", "timeout", "error"):
        return "failed"
    if st == "skipped":
        return "skipped"
    if test_failures > 0:
        return "failed"
    if findings > 0:
        return "warning"
    if st in ("completed", "ok", "done"):
        return "ok"
    return "warning"


def _row(
    check_id: str,
    status: str,
    detail: str,
    *,
    findings: int = 0,
    test_failures: int = 0,
) -> Dict[str, Any]:
    outcome = _outcome_from_status(status, findings=findings, test_failures=test_failures)
    return {
        "id": check_id,
        "label": _CHECK_LABELS.get(check_id, check_id.replace("_", " ").title()),
        "status": status,
        "outcome": outcome,
        "outcome_label": _OUTCOME_LABELS.get(outcome, outcome),
        "detail": (detail or "—")[:500],
    }


def build_analysis_run_summary(
    result: Dict[str, Any],
    selected: Set[str],
    code_only: bool,
) -> List[Dict[str, Any]]:
    """Construye filas para informe: análisis ejecutado + resultado OK/fallo."""
    rows: List[Dict[str, Any]] = []
    vulns = [v for v in (result.get("vulnerabilities") or []) if isinstance(v, dict)]
    scope = result.get("scan_scope") if isinstance(result.get("scan_scope"), dict) else {}

    pattern_ids = set(PATTERN_CHECKS)
    static_n = sum(
        1
        for v in vulns
        if str(v.get("pattern_id") or "") in pattern_ids
        or (
            str(v.get("category") or "") not in (
                "JavaScript / Consumo API",
                "JavaScript / Sink peligroso",
                "Secretos / Tokens en código",
            )
            and "<dynamic" not in str(v.get("file") or "")
        )
    )

    if "static_patterns" in selected or scope.get("files_scanned"):
        rows.append(
            _row(
                "static_patterns",
                "completed",
                f"{scope.get('files_scanned', 0)} archivos — {static_n} hallazgo(s) patrón estático",
                findings=static_n,
            )
        )

    js = result.get("js_code_analysis_meta") if isinstance(result.get("js_code_analysis_meta"), dict) else {}
    if "js_code_analysis" in selected:
        if js.get("enabled") is False:
            rows.append(
                _row(
                    "js_code_analysis",
                    "skipped",
                    str(js.get("reason") or "No ejecutado"),
                )
            )
        else:
            fc = int(js.get("findings_count") or 0)
            hygiene_n = int(js.get("hygiene_findings_count") or 0)
            detail = (
                f"{js.get('functions_analyzed', 0)} funciones en {js.get('files_scanned', 0)} archivos; "
                f"{js.get('api_functions_reviewed', 0)} con consumo API; "
                f"{fc} hallazgo(s) JS"
            )
            if hygiene_n:
                detail += f"; {hygiene_n} estilo linter (console.log, debugger, …)"
            rows.append(
                _row(
                    "js_code_analysis",
                    "completed",
                    detail,
                    findings=fc,
                )
            )

    sa = result.get("secrets_audit") if isinstance(result.get("secrets_audit"), dict) else {}
    if code_only or "static_patterns" in selected:
        sn = int(sa.get("findings_count") or 0)
        rows.append(
            _row(
                "secrets_audit",
                "completed" if sa.get("enabled", True) else "skipped",
                str(sa.get("status_message") or f"{sa.get('files_scanned', 0)} archivos revisados"),
                findings=sn,
            )
        )

    seen_ext: set[str] = set()
    for ext in result.get("external_checks_summary") or []:
        if not isinstance(ext, dict):
            continue
        cid = str(ext.get("id") or "")
        if not cid or cid in seen_ext or cid in {
            "js_code_analysis",
            "secrets_audit",
            "static_patterns",
            "project_tests",
        }:
            continue
        seen_ext.add(cid)
        st = str(ext.get("status") or "?")
        rows.append(_row(cid, st, str(ext.get("reason") or "")))

    if isinstance(result.get("external_checks"), dict):
        for cid, data in result["external_checks"].items():
            if cid in seen_ext or not isinstance(data, dict):
                continue
            seen_ext.add(str(cid))
            st = str(data.get("status") or "?")
            rows.append(_row(str(cid), st, str(data.get("reason") or "")))

    pt = result.get("project_tests") if isinstance(result.get("project_tests"), dict) else {}
    if pt:
        ju = pt.get("junit") if isinstance(pt.get("junit"), dict) else {}
        failures = int(ju.get("failures") or 0) + int(ju.get("errors") or 0) if ju else 0
        rows.append(
            _row(
                "project_tests",
                str(pt.get("status") or "skipped"),
                str(pt.get("reason") or pt.get("runner") or "—"),
                test_failures=failures,
            )
        )

    if not code_only:
        dyn = result.get("dynamic_api_url")
        if dyn and ("dynamic_http_tls" in selected or "api_runtime_core" in selected):
            dyn_n = sum(1 for v in vulns if str(v.get("file") or "").startswith("<dynamic"))
            rows.append(
                _row(
                    "dynamic_http_tls",
                    "completed" if dyn else "skipped",
                    f"API {dyn}" if dyn else "Sin URL de API",
                    findings=dyn_n,
                )
            )

    order = {r["id"]: i for i, r in enumerate(rows)}
    rows.sort(key=lambda r: (r.get("outcome") != "failed", r.get("outcome") != "warning", r["id"]))
    return rows
