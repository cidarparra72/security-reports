#!/usr/bin/env python3
"""
Análisis de seguridad orientado a JavaScript/TypeScript:
- Extracción de bloques de función (cuerpo completo)
- Llamadas HTTP/API sin indicios de autenticación en toda la función
- Sinks peligrosos (eval, innerHTML, dangerouslySetInnerHTML, etc.)
- Almacenamiento sensible en localStorage/sessionStorage
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .api_scanner import Vulnerability
from .infer_api_url import _SKIP_DIRS
from .js_function_blocks import (
    JsFunctionBlock,
    extract_js_functions,
    innermost_block_at,
    module_level_segments,
)
from .scan_scope import extensions_for_languages, is_scan_artifact_filename

_SKIP_DIRS_LOWER = frozenset(d.lower() for d in _SKIP_DIRS)
_MAX_FILE_BYTES = 2_000_000

_JS_LANG_KEYS = frozenset({"javascript", "typescript"})

_PAREN = r"[^)]{0,512}"
_MAX_REGEX_LINE_LEN = 4_000

_FUNC_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s*\*?\s+(\w+)", re.I),
    re.compile(
        rf"^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\({_PAREN}\)\s*=>)",
        re.I,
    ),
    re.compile(r"^\s*(\w+)\s*:\s*(?:async\s+)?function\b", re.I),
    re.compile(rf"^\s*(\w+)\s*:\s*(?:async\s+)?\({_PAREN}\)\s*=>", re.I),
    re.compile(rf"^\s*(?:async\s+)?(\w+)\s*\({_PAREN}\)\s*\{{", re.I),
)

_RESERVED_METHOD_NAMES = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "else",
        "do",
        "try",
        "finally",
        "with",
        "return",
        "throw",
        "new",
        "class",
        "constructor",
        "get",
        "set",
        "static",
        "import",
        "export",
        "default",
    }
)

_HTTP_CALL_RE = re.compile(
    r"\b("
    r"fetch|"
    r"axios\.(?:get|post|put|delete|patch|head|options|request)|"
    r"my\.requestLogs|my\.request|wx\.request|uni\.request|tt\.request|"
    r"http\.(?:get|post|put|delete|request)|"
    r"https?\.(?:get|post|request)|"
    r"request\.(?:get|post|put|delete|patch)|"
    r"api(?:Client)?\.(?:get|post|put|delete|patch|request|fetch)|"
    r"merchantRequestWithLog|merchantRequest|storeRequestLog|"
    r"\$\.ajax|jQuery\.ajax"
    r")\s*\(",
    re.I,
)

_WRAPPER_IMPL_NAMES = frozenset(
    {
        "merchantrequestwithlog",
        "merchantrequest",
        "clarologs",
        "storerequestlog",
    }
)

_REQUEST_WRAPPER_RE = re.compile(
    r"my\.request\s*\(\s*(options|requestProps|opts|req|config)\s*\)",
    re.I,
)

_OPTIONS_FORWARD_RE = re.compile(
    r"\.\.\.\s*options|\.\.\.\s*requestProps|options\s*,|requestProps\s*,",
    re.I,
)

_AUTH_CONTEXT_RE = re.compile(
    r"Authorization|Bearer\s|['\"]token['\"]\s*:|['\"]auth(?:orization)?['\"]\s*:|"
    r"headers\s*:\s*\{|getToken\s*\(|setAuth|accessToken|idToken|apiKey\s*:|"
    r"x-api-key|X-Api-Key|credentials\s*:\s*['\"]include['\"]|"
    r"getAuthHeaders\s*\(|Signature\s*:|Client-Id|Merchant-id|authCode",
    re.I,
)

_HEADERS_PARAM_AUTH_RE = re.compile(
    rf"\(\s*{_PAREN}\bheaders\b{_PAREN}\)",
    re.I,
)

_RESILIENCE_VALIDATION_RE = re.compile(
    rf"\bif\s*\({_PAREN}(?:null|undefined|!\s*\w+|error|status|code|resultStatus|\.data\b|success|fail|instanceof\s+Error)",
    re.I,
)

_DANGEROUS_RULES: tuple[tuple[str, str, str, str, str, str], ...] = (
    (
        "JS_EVAL",
        "HIGH",
        "Uso de eval() o Function constructor",
        r"\b(eval\s*\(|new\s+Function\s*\()",
        "CWE-95",
        "Evita eval/Function con datos dinámicos; usa alternativas seguras o parsing acotado.",
    ),
    (
        "JS_INNER_HTML",
        "HIGH",
        "Asignación innerHTML / outerHTML (XSS)",
        r"\.(innerHTML|outerHTML)\s*=",
        "CWE-79",
        "No asignes HTML no confiable; usa textContent o sanitización (DOMPurify).",
    ),
    (
        "JS_DOCUMENT_WRITE",
        "MEDIUM",
        "document.write / writeln",
        r"\bdocument\.write(?:ln)?\s*\(",
        "CWE-79",
        "Evita document.write; usa DOM API o plantillas sanitizadas.",
    ),
    (
        "JS_REACT_DANGEROUS_HTML",
        "HIGH",
        "React dangerouslySetInnerHTML",
        r"dangerouslySetInnerHTML\s*=",
        "CWE-79",
        "Sanitiza HTML antes de dangerouslySetInnerHTML (DOMPurify u equivalente).",
    ),
    (
        "JS_JWT_DECODE_NO_VERIFY",
        "HIGH",
        "jwt.decode / jwt_decode sin verificación explícita",
        r"jwt[_\.]?decode\s*\(|jsonwebtoken\.decode\s*\(",
        "CWE-347",
        "Usa verify con clave/issuer; decode sin verify permite tokens falsificados.",
    ),
    (
        "JS_POSTMESSAGE_WILDCARD",
        "MEDIUM",
        "postMessage con origen '*' o sin validar event.origin",
        r"postMessage\s*\([^)]*['\"]\*['\"]|addEventListener\s*\(\s*['\"]message['\"]",
        "CWE-345",
        "Valida event.origin en message y usa targetOrigin explícito en postMessage.",
    ),
    (
        "JS_SENSITIVE_STORAGE",
        "MEDIUM",
        "Token o credencial en localStorage/sessionStorage",
        r"(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*['\"]"
        r"(?:token|auth|password|passwd|secret|api[_-]?key|session|credential)",
        "CWE-922",
        "Evita almacenar tokens en storage del cliente; usa memoria, httpOnly cookies o almacén seguro.",
    ),
)

# Reglas estilo linter (console.log, debugger, etc.) — categoría distinta a sinks de seguridad.
_HYGIENE_RULES: tuple[tuple[str, str, str, str, str, str, bool], ...] = (
    (
        "JS_CONSOLE_LOG",
        "LOW",
        "console.log / debug / info en código",
        r"\bconsole\.(log|debug|info|dir|table|trace)\s*\(",
        "CWE-532",
        "Quita logs de depuración antes de producción o usa un logger con niveles (sin datos sensibles).",
        True,
    ),
    (
        "JS_DEBUGGER",
        "MEDIUM",
        "Sentencia debugger",
        r"\bdebugger\b",
        "CWE-489",
        "Elimina debugger antes de desplegar; bloquea la ejecución en DevTools.",
        False,
    ),
    (
        "JS_ALERT",
        "LOW",
        "alert() en código",
        r"\balert\s*\(",
        "CWE-489",
        "Evita alert() en producción; usa UI del miniprograma o notificaciones nativas.",
        False,
    ),
)


def _is_test_path(rel: str) -> bool:
    r = rel.replace("\\", "/").lower()
    return (
        r.startswith("test/")
        or r.startswith("tests/")
        or "/test/" in r
        or r.endswith(".test.js")
        or r.endswith(".test.ts")
        or r.endswith(".spec.js")
        or r.endswith(".spec.ts")
    )


def _js_extensions(languages: Optional[List[str]]) -> frozenset[str]:
    exts = extensions_for_languages(languages)
    js_exts = set()
    for key in _JS_LANG_KEYS:
        from .scan_scope import LANGUAGE_EXTENSIONS

        js_exts |= LANGUAGE_EXTENSIONS.get(key, frozenset())
    code_exts = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue"}
    if languages:
        scoped = exts & (js_exts | code_exts)
        scoped = {e for e in scoped if e not in {".axml", ".acss", ".sss"}}
        return frozenset(scoped) if scoped else frozenset(code_exts)
    return frozenset(code_exts)


def _iter_js_files(root: Path, languages: Optional[List[str]]) -> Iterable[Path]:
    exts = _js_extensions(languages)
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part.lower() in _SKIP_DIRS_LOWER for part in p.parts):
            continue
        if p.suffix.lower() not in exts:
            continue
        if is_scan_artifact_filename(p.name):
            continue
        try:
            if p.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield p


@lru_cache(maxsize=128)
def _cached_js_function_blocks(text: str) -> tuple[JsFunctionBlock, ...]:
    return tuple(extract_js_functions(text))


def function_name_at_line(text: str, target_line: int) -> str:
    """Nombre de función/método más cercano antes de target_line (heurística)."""
    blocks = list(_cached_js_function_blocks(text))
    inner = innermost_block_at(blocks, target_line)
    if inner:
        return inner.name
    if target_line < 1:
        return "<module>"
    lines = text.splitlines()
    current = "<module>"
    limit = min(target_line - 1, len(lines))
    for i in range(limit):
        line = lines[i]
        if len(line) > _MAX_REGEX_LINE_LEN:
            continue
        for pat in _FUNC_PATTERNS:
            try:
                m = pat.match(line)
            except RuntimeError:
                break
            if not m:
                continue
            name = next((g for g in m.groups() if g), None)
            if name and name.lower() not in _RESERVED_METHOD_NAMES:
                current = name
                break
    return current


def _v(
    cvss_map: Dict[str, float],
    *,
    severity: str,
    category: str,
    title: str,
    description: str,
    file: str,
    line: int,
    snippet: str,
    recommendation: str,
    cwe: str,
    confidence: str = "medium",
    function_name: str = "",
    pattern_id: str = "",
    false_positive_note: str = "",
) -> Vulnerability:
    return Vulnerability(
        severity=severity,
        category=category,
        title=title,
        description=description,
        file=file,
        line=line,
        code_snippet=snippet[:400],
        recommendation=recommendation,
        cwe_id=cwe,
        cvss=float(cvss_map.get(severity, 6.0)),
        confidence=confidence,
        false_positive_note=false_positive_note,
        pattern_id=pattern_id,
        function_name=function_name,
    )


def _is_comment_line(stripped: str) -> bool:
    return (
        stripped.startswith("//")
        or stripped.startswith("*")
        or stripped.startswith("<!--")
    )


def _is_request_wrapper_body(body: str) -> bool:
    if not _REQUEST_WRAPPER_RE.search(body):
        return False
    if _OPTIONS_FORWARD_RE.search(body):
        return True
    return bool(re.search(r"my\.request\s*\(\s*\{", body, re.I) and _OPTIONS_FORWARD_RE.search(body))


def _is_wrapper_implementation(scope_name: str, body: str, file: str = "") -> bool:
    if scope_name.lower() in _WRAPPER_IMPL_NAMES:
        return True
    path = file.replace("\\", "/").lower()
    if path.endswith("merchantrequestlog.js") and scope_name.lower() in {"success", "fail"}:
        return True
    return _is_request_wrapper_body(body)


def _api_calls_in_text(text: str) -> List[str]:
    return sorted({m.group(1) for m in _HTTP_CALL_RE.finditer(text)})


def _auth_via_headers_parameter(scope_lines: List[str], body_text: str) -> bool:
    """Auth delegada: la función recibe `headers` y los pasa al request."""
    head = "\n".join(scope_lines[:4])
    if not _HEADERS_PARAM_AUTH_RE.search(head):
        return False
    return bool(re.search(r"\bheaders\s*[,\}]", body_text))


def _priority_function_key(name: str, file: str) -> tuple:
    path = file.replace("\\", "/").lower()
    score = 0
    if name.startswith("_"):
        score += 8
    if "node_modules" in path:
        score += 20
    for pref in ("pages/", "main/", "utils/", "services/", "api/", "components/"):
        if pref in path:
            score -= 6
            break
    return (score, path, name.lower())


def _api_resilience(body_text: str) -> Dict[str, Any]:
    """try/catch, .catch() y validaciones de respuesta en el cuerpo de la función."""
    has_try = bool(re.search(r"\btry\s*\{", body_text))
    has_catch = bool(re.search(r"\bcatch\s*\(", body_text))
    has_promise_catch = bool(re.search(r"\.catch\s*\(", body_text))
    has_validation = bool(_RESILIENCE_VALIDATION_RE.search(body_text))
    has_throw = bool(re.search(r"\bthrow\s+(?:new\s+)?Error", body_text))
    error_handling = (has_try and has_catch) or has_promise_catch

    issues: List[str] = []
    if not error_handling:
        issues.append("sin try/catch ni .catch()")
    if not has_validation and not has_throw:
        issues.append("sin validación evidente de respuesta/errores")

    if not issues:
        resilience = "ok"
    elif error_handling and has_validation:
        resilience = "ok"
    elif error_handling or has_throw:
        resilience = "partial"
    else:
        resilience = "review"

    return {
        "has_try_catch": has_try and has_catch,
        "has_promise_catch": has_promise_catch,
        "has_validation": has_validation or has_throw,
        "resilience": resilience,
        "resilience_notes": "; ".join(issues),
    }


def _append_function_audit(
    audit: List[Dict[str, Any]],
    *,
    function: str,
    file: str,
    line: int,
    api_calls: List[str],
    auth_in_function: bool,
    status: str,
    notes: str = "",
    body_text: str = "",
) -> None:
    if not api_calls and status != "wrapper_impl":
        return
    resilience = _api_resilience(body_text) if body_text else {}
    row: Dict[str, Any] = {
        "function": function,
        "file": file,
        "line": line,
        "api_calls": api_calls,
        "auth_in_function": auth_in_function,
        "status": status,
        "notes": notes,
    }
    if resilience:
        row.update(resilience)
    audit.append(row)


def _analyze_scope(
    rel: str,
    scope_name: str,
    scope_lines: List[str],
    line_offset: int,
    body_text: str,
    cvss_map: Dict[str, float],
    seen: Set[str],
    findings: List[Vulnerability],
    audit: List[Dict[str, Any]],
) -> None:
    """Analiza un bloque (función o módulo) línea a línea con contexto = cuerpo completo."""
    api_calls = _api_calls_in_text(body_text)
    body_has_auth = bool(_AUTH_CONTEXT_RE.search(body_text)) or _auth_via_headers_parameter(
        scope_lines, body_text
    )
    is_wrapper_impl = _is_wrapper_implementation(scope_name, body_text, rel)

    resilience = _api_resilience(body_text)

    if is_wrapper_impl:
        _append_function_audit(
            audit,
            function=scope_name,
            file=rel,
            line=line_offset,
            api_calls=api_calls,
            auth_in_function=body_has_auth,
            status="wrapper_impl",
            notes="Implementación de wrapper HTTP (reenvío)",
            body_text=body_text,
        )
        return

    if api_calls:
        notes_parts: List[str] = []
        if not body_has_auth:
            notes_parts.append("Sin indicios de auth en el cuerpo de la función")
        if resilience.get("resilience_notes"):
            notes_parts.append(str(resilience["resilience_notes"]))
        combined_status = "ok"
        if not body_has_auth or resilience.get("resilience") == "review":
            combined_status = "review"
        elif resilience.get("resilience") == "partial":
            combined_status = "partial"
        _append_function_audit(
            audit,
            function=scope_name,
            file=rel,
            line=line_offset,
            api_calls=api_calls,
            auth_in_function=body_has_auth,
            status=combined_status,
            notes="; ".join(notes_parts),
            body_text=body_text,
        )

        if resilience.get("resilience") == "review" and not body_has_auth:
            pass  # auth finding handled below
        elif resilience.get("resilience") == "review":
            for i, line in enumerate(scope_lines):
                line_no = line_offset + i
                if not _HTTP_CALL_RE.search(line):
                    continue
                key = f"resilience|{rel}|{line_no}|{scope_name}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    _v(
                        cvss_map,
                        severity="MEDIUM",
                        category="JavaScript / Consumo API",
                        title="Consumo de servicio sin manejo de errores robusto",
                        description=(
                            f"La función `{scope_name}` ({rel}:{line_no}) llama APIs sin try/catch "
                            "ni validación clara de la respuesta."
                        ),
                        file=rel,
                        line=line_no,
                        snippet=line.strip()[:400],
                        recommendation=(
                            "Envuelve la llamada en try/catch o .catch(); valida status, resultStatus "
                            "o estructura de data antes de usar el resultado."
                        ),
                        cwe="CWE-755",
                        confidence="low",
                        function_name=scope_name,
                        pattern_id="JS_API_WEAK_ERROR_HANDLING",
                        false_positive_note="Heurística: puede haber manejo en capa superior.",
                    )
                )
                break

    for i, line in enumerate(scope_lines):
        line_no = line_offset + i
        stripped = line.strip()
        if not stripped or _is_comment_line(stripped):
            continue

        m_http = _HTTP_CALL_RE.search(line)
        if m_http and not _REQUEST_WRAPPER_RE.search(line):
            if _OPTIONS_FORWARD_RE.search(line):
                continue
            if not body_has_auth:
                callee = m_http.group(1)
                key = f"http|{rel}|{line_no}|{scope_name}|{callee}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        _v(
                            cvss_map,
                            severity="HIGH",
                            category="JavaScript / Consumo API",
                            title=f"Llamada HTTP/API sin autenticación en función ({callee})",
                            description=(
                                f"En `{scope_name}` ({rel}:{line_no}) se detectó `{callee}(…)` y "
                                "no hay indicios de Authorization, token ni cabeceras de auth en "
                                "todo el cuerpo de la función."
                            ),
                            file=rel,
                            line=line_no,
                            snippet=line.strip()[:400],
                            recommendation=(
                                "Añade autenticación (Bearer, API key en headers, sesión) según el contrato del API. "
                                "Si es endpoint público, documenta la excepción y valida rate-limit."
                            ),
                            cwe="CWE-306",
                            confidence="low",
                            function_name=scope_name,
                            pattern_id="JS_HTTP_NO_AUTH",
                            false_positive_note=(
                                "Heurística por función: la auth puede estar en un interceptor global "
                                "(axios/fetch) definido fuera de esta función."
                            ),
                        )
                    )

        for rule_id, sev, title, regex, cwe, rec in _DANGEROUS_RULES:
            if not re.search(regex, line, re.I):
                continue
            key = f"{rule_id}|{rel}|{line_no}|{scope_name}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                _v(
                    cvss_map,
                    severity=sev,
                    category="JavaScript / Sink peligroso",
                    title=title,
                    description=(
                        f"Patrón `{rule_id}` en función `{scope_name}` ({rel}:{line_no}). "
                        "Revisión sobre el cuerpo completo de la función."
                    ),
                    file=rel,
                    line=line_no,
                    snippet=line.strip()[:400],
                    recommendation=rec,
                    cwe=cwe,
                    confidence="medium",
                    function_name=scope_name,
                    pattern_id=rule_id,
                )
            )

        for rule_id, sev, title, regex, cwe, rec, skip_tests in _HYGIENE_RULES:
            if skip_tests and _is_test_path(rel):
                continue
            try:
                if not re.search(regex, line, re.I):
                    continue
            except RuntimeError:
                continue
            key = f"{rule_id}|{rel}|{line_no}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                _v(
                    cvss_map,
                    severity=sev,
                    category="JavaScript / Calidad (linter)",
                    title=title,
                    description=(
                        f"Regla `{rule_id}` en `{scope_name}` ({rel}:{line_no}). "
                        "Equivalente a avisos típicos de ESLint (no-console, no-debugger)."
                    ),
                    file=rel,
                    line=line_no,
                    snippet=line.strip()[:400],
                    recommendation=rec,
                    cwe=cwe,
                    confidence="high",
                    function_name=scope_name,
                    pattern_id=rule_id,
                )
            )


def _analyze_file(
    rel: str,
    text: str,
    cvss_map: Dict[str, float],
    seen: Set[str],
    stats: Dict[str, Any],
    audit: List[Dict[str, Any]],
) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    lines = text.splitlines()
    blocks = extract_js_functions(text)
    stats["functions_analyzed"] = int(stats.get("functions_analyzed", 0)) + len(blocks)

    fn_records: List[tuple[str, str]] = stats.setdefault("_fn_records", [])  # type: ignore[assignment]
    if isinstance(fn_records, list):
        for b in blocks:
            fn_records.append((b.name, rel))

    for block in blocks:
        file_slice = lines[block.start_line - 1 : block.end_line]
        _analyze_scope(
            rel,
            block.name,
            file_slice,
            block.start_line,
            block.body_text,
            cvss_map,
            seen,
            findings,
            audit,
        )

    for start_ln, _end_ln, seg_text in module_level_segments(text, blocks):
        seg_lines = seg_text.splitlines()
        _analyze_scope(
            rel,
            "<module>",
            seg_lines,
            start_ln,
            seg_text,
            cvss_map,
            seen,
            findings,
            audit,
        )

    return findings


def enrich_vulnerabilities_with_function_names(
    vulns: List[dict],
    project_path: Path,
    languages: Optional[List[str]],
) -> None:
    """Añade function_name a hallazgos en archivos JS/TS si falta."""
    cache: Dict[str, str] = {}
    exts = _js_extensions(languages)
    for v in vulns:
        if not isinstance(v, dict):
            continue
        if str(v.get("function_name") or "").strip():
            continue
        rel = str(v.get("file") or "").replace("\\", "/")
        if not rel or rel.startswith("<"):
            continue
        try:
            line = int(v.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        if line < 1:
            continue
        fp = project_path / rel
        if fp.suffix.lower() not in exts:
            continue
        cache_key = rel
        if cache_key not in cache:
            try:
                cache[cache_key] = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                cache[cache_key] = ""
        text = cache[cache_key]
        if text:
            v["function_name"] = function_name_at_line(text, line)


def run_js_code_analysis(
    project_path: str,
    languages: Optional[List[str]],
    cvss_map: Optional[Dict[str, float]] = None,
) -> Tuple[List[Vulnerability], Dict[str, Any]]:
    """
    Ejecuta reglas JS/TS por función sobre el árbol del proyecto.

    Returns:
        (hallazgos, meta) — meta incluye files_scanned, functions_analyzed, etc.
    """
    cvss = cvss_map or {"CRITICAL": 9.0, "HIGH": 8.0, "MEDIUM": 6.0, "LOW": 3.0}
    root = Path(project_path).expanduser().resolve()
    meta: Dict[str, Any] = {
        "enabled": True,
        "files_scanned": 0,
        "functions_analyzed": 0,
        "findings_count": 0,
        "api_functions_reviewed": 0,
        "api_functions_ok": 0,
        "api_functions_review": 0,
        "checks": [
            "function_body_http_auth",
            "function_body_dangerous_sinks",
            "function_body_sensitive_storage",
            "module_scope",
            "miniprogram_wrappers",
        ],
        "function_names_sample": [],
        "function_http_audit": [],
    }
    audit: List[Dict[str, Any]] = []

    if not root.is_dir():
        meta["enabled"] = False
        meta["reason"] = "Ruta no es directorio"
        return [], meta

    langs = {str(x).lower() for x in (languages or [])}
    if langs and not (langs & _JS_LANG_KEYS):
        meta["enabled"] = False
        meta["reason"] = "Lenguajes seleccionados sin JavaScript/TypeScript"
        return [], meta

    findings: List[Vulnerability] = []
    seen: Set[str] = set()
    file_count = 0

    for fp in _iter_js_files(root, languages):
        file_count += 1
        rel = str(fp.relative_to(root)).replace("\\", "/")
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(_analyze_file(rel, text, cvss, seen, meta, audit))

    fn_records = meta.pop("_fn_records", [])
    if isinstance(fn_records, list):
        sample_pairs = sorted(
            {(n, f) for n, f in fn_records if n and n != "<module>"},
            key=lambda x: _priority_function_key(x[0], x[1]),
        )[:25]
        meta["function_names_sample"] = [n for n, _f in sample_pairs]
    else:
        meta["function_names_sample"] = []

    audit_sorted = sorted(
        audit,
        key=lambda row: (
            0 if row.get("status") == "review" else 1 if row.get("status") == "ok" else 2,
            _priority_function_key(str(row.get("function", "")), str(row.get("file", ""))),
        ),
    )
    meta["function_http_audit"] = audit_sorted[:60]
    meta["api_functions_reviewed"] = len(audit_sorted)
    meta["api_functions_ok"] = sum(1 for a in audit_sorted if a.get("status") == "ok")
    meta["api_functions_review"] = sum(
        1 for a in audit_sorted if a.get("status") in ("review", "partial")
    )
    meta["api_resilience_ok"] = sum(
        1 for a in audit_sorted if a.get("resilience") == "ok"
    )
    meta["api_resilience_review"] = sum(
        1 for a in audit_sorted if a.get("resilience") in ("review", "partial")
    )

    meta["files_scanned"] = file_count
    meta["functions_analyzed"] = int(meta.get("functions_analyzed", 0))
    meta["findings_count"] = len(findings)
    meta["hygiene_findings_count"] = sum(
        1 for v in findings if getattr(v, "category", "") == "JavaScript / Calidad (linter)"
    )
    return findings, meta


def semgrep_config_args(languages: Optional[List[str]]) -> List[str]:
    """Configs Semgrep recomendadas para stack JS/TS."""
    langs = {str(x).lower() for x in (languages or [])}
    js_focus = not langs or bool(langs & _JS_LANG_KEYS) or "json" in langs
    if not js_focus:
        return ["auto"]
    packs = [
        "p/javascript",
        "p/typescript",
        "p/owasp-top-ten",
        "p/security-audit",
        "p/xss",
        "p/jwt",
        "p/eslint",
        "p/nodejs",
    ]
    args: List[str] = []
    for pack in packs:
        args.extend(["--config", pack])
    return args
