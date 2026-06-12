#!/usr/bin/env python3
"""
Auditoría de secretos y tokens quemados en código (SAST focalizado).
Genera hallazgos para el informe y metadatos para la sección dedicada.
"""

from __future__ import annotations

import re
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .api_scanner import Vulnerability
from .infer_api_url import _SKIP_DIRS
from .js_code_analysis import _cached_js_function_blocks, function_name_at_line
from .js_function_blocks import innermost_block_at
from .scan_scope import extensions_for_languages, is_scan_artifact_filename
from .vuln_filters import is_false_positive_credential_finding

_SKIP_DIRS_LOWER = frozenset(d.lower() for d in _SKIP_DIRS)
_MAX_FILE_BYTES = 2_000_000

_SECRET_FILE_EXTS = frozenset(
    {
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".vue",
        ".json",
        ".env",
        ".yaml",
        ".yml",
        ".properties",
        ".xml",
        ".py",
        ".java",
        ".go",
        ".php",
    }
)

_JWT_RE = re.compile(
    r"\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b"
)
_BEARER_RE = re.compile(
    r"\bBearer\s+([A-Za-z0-9_\-\.]{24,})\b",
    re.I,
)
_TOKEN_ASSIGN_RE = re.compile(
    r"(?:access[_-]?token|refresh[_-]?token|auth[_-]?token|api[_-]?key|"
    r"secret[_-]?key|client[_-]?secret|private[_-]?key)\s*[=:]\s*"
    r'["\']([^"\']{8,})["\']',
    re.I,
)
_PASSWORD_ASSIGN_RE = re.compile(
    r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']',
    re.I,
)
_AWS_KEY_RE = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
_STRIPE_KEY_RE = re.compile(r"\b(sk_live_[A-Za-z0-9]{16,}|sk_test_[A-Za-z0-9]{16,})\b")
_GOOGLE_KEY_RE = re.compile(r"\b(AIza[0-9A-Za-z_-]{20,})\b")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
_COMMENT_LINE_RE = re.compile(r"^\s*(//|#|\*|<!--)")

_RULES: tuple[tuple[str, str, str, str, re.Pattern[str]], ...] = (
    (
        "jwt_literal",
        "JWT hardcodeado en código",
        "CRITICAL",
        "CWE-798",
        _JWT_RE,
    ),
    (
        "bearer_token",
        "Token Bearer quemado en código",
        "CRITICAL",
        "CWE-798",
        _BEARER_RE,
    ),
    (
        "token_assignment",
        "Token o clave API asignada en literal",
        "CRITICAL",
        "CWE-798",
        _TOKEN_ASSIGN_RE,
    ),
    (
        "password_literal",
        "Contraseña en literal",
        "CRITICAL",
        "CWE-798",
        _PASSWORD_ASSIGN_RE,
    ),
    (
        "aws_access_key",
        "AWS Access Key ID en código",
        "CRITICAL",
        "CWE-798",
        _AWS_KEY_RE,
    ),
    (
        "stripe_secret",
        "Stripe secret key en código",
        "CRITICAL",
        "CWE-798",
        _STRIPE_KEY_RE,
    ),
    (
        "google_api_key",
        "Google API key en código",
        "CRITICAL",
        "CWE-798",
        _GOOGLE_KEY_RE,
    ),
    (
        "private_key_pem",
        "Clave privada PEM en repositorio",
        "CRITICAL",
        "CWE-321",
        _PRIVATE_KEY_RE,
    ),
)

_TYPE_LABELS = {
    "jwt_literal": "JWT en código",
    "bearer_token": "Bearer token",
    "token_assignment": "Token / API key",
    "password_literal": "Contraseña",
    "aws_access_key": "AWS key",
    "stripe_secret": "Stripe key",
    "google_api_key": "Google API key",
    "private_key_pem": "Clave privada PEM",
}


def mask_secret(value: str, visible: int = 4) -> str:
    v = (value or "").strip()
    if len(v) <= visible * 2:
        return "***"
    return f"{v[:visible]}…{v[-visible:]}"


def mask_line_snippet(line: str, secret: str) -> str:
    if not secret or secret not in line:
        return line.strip()[:400]
    masked = mask_secret(secret)
    return line.replace(secret, masked).strip()[:400]


def _iter_secret_files(root: Path, languages: Optional[List[str]]) -> List[Path]:
    lang_exts = extensions_for_languages(languages) if languages else _SECRET_FILE_EXTS
    allowed = (lang_exts | _SECRET_FILE_EXTS) if languages else _SECRET_FILE_EXTS
    out: List[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part.lower() in _SKIP_DIRS_LOWER for part in p.parts):
            continue
        if is_scan_artifact_filename(p.name):
            continue
        suf = p.suffix.lower()
        name_l = p.name.lower()
        if suf not in allowed and name_l not in (".env", ".env.local", ".env.production"):
            if not name_l.startswith(".env"):
                continue
        try:
            if p.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        out.append(p)
    return out


def _vuln_from_row(
    row: Dict[str, Any],
    cvss_map: Dict[str, float],
) -> Vulnerability:
    sev = str(row.get("severity") or "CRITICAL").upper()
    return Vulnerability(
        severity=sev,
        category="Secretos / Tokens en código",
        title=str(row.get("title") or "Secreto en código"),
        description=str(row.get("description") or ""),
        file=str(row.get("file") or ""),
        line=int(row.get("line") or 0),
        code_snippet=str(row.get("snippet_masked") or "")[:400],
        recommendation=str(
            row.get(
                "recommendation",
                "Elimina el secreto del repositorio, rota la credencial y usa variables de entorno o vault.",
            )
        ),
        cwe_id=str(row.get("cwe_id") or "CWE-798"),
        cvss=float(cvss_map.get(sev, 9.0)),
        confidence="high",
        pattern_id=str(row.get("type") or "HARDCODED_SECRET"),
        function_name=str(row.get("function_name") or ""),
        false_positive_note=str(row.get("false_positive_note") or ""),
    )


def run_secrets_audit(
    project_path: str,
    languages: Optional[List[str]] = None,
    cvss_map: Optional[Dict[str, float]] = None,
) -> Tuple[List[Vulnerability], Dict[str, Any]]:
    """Escanea el repo en busca de tokens/secretos quemados."""
    cvss = cvss_map or {"CRITICAL": 9.0, "HIGH": 8.0, "MEDIUM": 6.0, "LOW": 3.0}
    root = Path(project_path).expanduser().resolve()
    meta: Dict[str, Any] = {
        "enabled": True,
        "files_scanned": 0,
        "findings_count": 0,
        "by_type": {},
        "findings": [],
        "status_message": "",
    }
    if not root.is_dir():
        meta["enabled"] = False
        meta["status_message"] = "Ruta de proyecto inválida"
        return [], meta

    findings_rows: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    file_count = 0

    for fp in _iter_secret_files(root, languages):
        file_count += 1
        rel = str(fp.relative_to(root)).replace("\\", "/")
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        js_blocks = None
        if fp.suffix.lower() in {
            ".js",
            ".jsx",
            ".ts",
            ".tsx",
            ".mjs",
            ".cjs",
            ".vue",
        }:
            js_blocks = list(_cached_js_function_blocks(text))

        for line_no, line in enumerate(text.splitlines(), 1):
            if _COMMENT_LINE_RE.match(line):
                continue
            if js_blocks is not None:
                inner = innermost_block_at(js_blocks, line_no)
                func = inner.name if inner else function_name_at_line(text, line_no)
            else:
                func = ""

            for rule_type, title, sev, cwe, pattern in _RULES:
                m = pattern.search(line)
                if not m:
                    continue
                secret_val = ""
                if m.lastindex and m.lastindex >= 1:
                    secret_val = (m.group(1) or "").strip()
                if rule_type == "private_key_pem":
                    secret_val = "PRIVATE_KEY"

                row = {
                    "type": rule_type,
                    "type_label": _TYPE_LABELS.get(rule_type, rule_type),
                    "title": title,
                    "severity": sev,
                    "cwe_id": cwe,
                    "file": rel,
                    "line": line_no,
                    "function_name": func,
                    "masked_value": mask_secret(secret_val) if secret_val else "***",
                    "snippet_masked": mask_line_snippet(line, secret_val),
                    "description": (
                        f"Posible secreto ({_TYPE_LABELS.get(rule_type, rule_type)}) en "
                        f"`{func}` — {rel}:{line_no}."
                    ),
                    "recommendation": (
                        "Quita el valor del código fuente, revoca/rota el token o clave expuesta, "
                        "y carga credenciales desde entorno seguro (CI secrets, vault, Key Vault)."
                    ),
                }
                vuln_probe = {
                    "pattern_id": "HARDCODED_SECRET",
                    "title": title,
                    "code_snippet": row["snippet_masked"],
                    "description": row["description"],
                    "file": rel,
                    "line": line_no,
                    "severity": sev,
                }
                if is_false_positive_credential_finding(vuln_probe):
                    continue

                dedupe = f"{rule_type}|{rel}|{line_no}|{row['masked_value']}"
                if dedupe in seen:
                    continue
                seen.add(dedupe)
                findings_rows.append(row)

    findings_rows.sort(
        key=lambda r: (
            0 if r.get("severity") == "CRITICAL" else 1,
            str(r.get("file") or ""),
            int(r.get("line") or 0),
        )
    )

    by_type: Dict[str, int] = {}
    for row in findings_rows:
        t = str(row.get("type") or "other")
        by_type[t] = by_type.get(t, 0) + 1

    meta["files_scanned"] = file_count
    meta["findings_count"] = len(findings_rows)
    meta["by_type"] = by_type
    meta["findings"] = findings_rows[:80]

    if findings_rows:
        meta["status_message"] = (
            f"Se detectaron {len(findings_rows)} posible(s) secreto(s) o token(s) quemado(s) "
            f"en {file_count} archivos revisados. Rotar credenciales expuestas."
        )
    else:
        meta["status_message"] = (
            f"Revisados {file_count} archivos: no se detectaron JWT, Bearer tokens, "
            f"API keys ni contraseñas hardcodeadas (patrones conocidos)."
        )

    vulns = [_vuln_from_row(r, cvss) for r in findings_rows]
    return vulns, meta
