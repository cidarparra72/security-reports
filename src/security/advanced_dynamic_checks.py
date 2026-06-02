#!/usr/bin/env python3
"""
Advanced dynamic checks for API vulnerability analysis.
Covers:
  - HTTP Methods (forbidden methods, TRACE/XST)
  - SSRF payloads
  - Mass Assignment (extra fields in POST/PUT)
  - GraphQL introspection
  - Legacy API versions / inventory
  - Error verbosity / stack trace exposure
  - CVE parsing from Trivy/Grype JSON output
Only uses stdlib + requests (if available, fallback to urllib).
"""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from .api_scanner import Vulnerability
from .http_probe_budget import HttpRequestBudget

_TIMEOUT = 7.0
_USER_AGENT = "APISecurityScanner/1.0"
_CVSS_MAP: Dict[str, float] = {"CRITICAL": 9.0, "HIGH": 8.0, "MEDIUM": 6.0, "LOW": 3.0}


# ─── helpers ──────────────────────────────────────────────────────────────────

def _v(severity: str, category: str, title: str, description: str,
       snippet: str, recommendation: str, cwe: str,
       confidence: str = "medium", file_tag: str = "<dynamic:advanced>") -> Vulnerability:
    return Vulnerability(
        severity=severity, category=category, title=title,
        description=description, file=file_tag, line=0,
        code_snippet=snippet, recommendation=recommendation,
        cwe_id=cwe, cvss=_CVSS_MAP.get(severity, 6.0), confidence=confidence,
    )


def _do(
    method: str,
    url: str,
    extra_headers: Optional[dict] = None,
    data: Optional[bytes] = None,
    budget: Optional[HttpRequestBudget] = None,
    budget_key: Optional[str] = None,
) -> tuple[Optional[int], dict, str]:
    """Returns (status_code, response_headers, body[:2000])."""
    key = budget_key or url
    if budget is not None and not budget.allow(key):
        return None, {"_budget_exhausted": "1"}, ""
    headers = {"User-Agent": _USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    ctx = ssl.create_default_context()
    try:
        req = urllib.request.Request(url, headers=headers, method=method.upper(), data=data)
        with urllib.request.urlopen(req, timeout=_TIMEOUT, context=ctx) as resp:
            body = resp.read(2000).decode("utf-8", errors="replace")
            if budget is not None:
                budget.record(key)
            return int(resp.getcode()), dict(resp.headers.items()), body
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(2000)
        except Exception:
            pass
        if budget is not None:
            budget.record(key)
        return int(e.code), dict(e.headers.items() if e.headers else []), body.decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, ValueError):
        return None, {}, ""


# ─── 1. HTTP Methods check ────────────────────────────────────────────────────

_DANGEROUS_METHODS = {"TRACE", "TRACK", "DEBUG"}
_UNEXPECTED_WRITABLE = {"PUT", "DELETE", "PATCH"}
_ALL_PROBE_METHODS = ["OPTIONS", "TRACE", "TRACK", "PUT", "DELETE", "PATCH", "HEAD"]


def check_http_methods(
    endpoint_url: str,
    auth_headers: Optional[dict] = None,
    cvss_map: Optional[dict] = None,
    budget: Optional[HttpRequestBudget] = None,
) -> List[Vulnerability]:
    """Probe endpoint with dangerous/unexpected HTTP methods."""
    cvss = cvss_map or _CVSS_MAP
    findings: List[Vulnerability] = []
    h = auth_headers or {}

    # First GET baseline — skip if endpoint completely unreachable
    bk = endpoint_url
    code_get, _, _ = _do("GET", endpoint_url, h, budget=budget, budget_key=bk)
    if code_get is None:
        return findings

    # OPTIONS — read allowed methods
    code_opt, opt_headers, _ = _do("OPTIONS", endpoint_url, h, budget=budget, budget_key=bk)
    allowed_str = str(opt_headers.get("Allow", opt_headers.get("allow", ""))).upper()

    for method in _ALL_PROBE_METHODS:
        if method == "OPTIONS":
            continue
        code, _, body = _do(method, endpoint_url, h, budget=budget, budget_key=bk)
        if code is None:
            continue

        if method in _DANGEROUS_METHODS and code not in (405, 404, 403, 501):
            severity = "HIGH" if method == "TRACE" else "MEDIUM"
            findings.append(_v(
                severity, "Security Misconfiguration",
                f"Método HTTP peligroso habilitado: {method}",
                f"El endpoint respondió {code} a {method}. "
                f"TRACE/TRACK puede revelar cabeceras de autenticación (XST).",
                f"{method} {endpoint_url} → {code}",
                f"Deshabilita {method} en la configuración del servidor web/API gateway.",
                "CWE-16", confidence="high",
            ))
        elif method in _UNEXPECTED_WRITABLE and code not in (405, 404, 403, 501):
            # Only flag if GET returned 2xx (resource exists) and write method is also 2xx
            if code_get is not None and 200 <= code_get < 300 and code < 400:
                findings.append(_v(
                    "HIGH", "Authorization",
                    f"Método {method} no esperado aceptado en endpoint de solo lectura",
                    f"GET {endpoint_url} → {code_get}, {method} → {code}. "
                    "Posible BFLA (Broken Function Level Authorization).",
                    f"{method} {endpoint_url} → {code}",
                    f"Restringe {method} con validación de rol y método permitido por recurso.",
                    "CWE-285", confidence="medium",
                ))

    return findings


# ─── 2. SSRF payloads ─────────────────────────────────────────────────────────

_SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",   # AWS IMDSv1
    "http://169.254.169.254/computeMetadata/v1/",  # GCP metadata
    "http://100.100.100.200/latest/meta-data/",    # Alibaba Cloud metadata
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "file:///etc/passwd",
]
_SSRF_PARAMS = ["url", "uri", "link", "src", "source", "redirect", "image", "file", "path", "target"]
_SSRF_CANARY_STRINGS = ["ami-id", "instance-id", "computeMetadata", "root:x:0:0", "meta-data"]


def check_ssrf(base_url: str, auth_headers: Optional[dict] = None,
               cvss_map: Optional[dict] = None) -> List[Vulnerability]:
    """Probe common SSRF vectors in URL parameters."""
    cvss = cvss_map or _CVSS_MAP
    findings: List[Vulnerability] = []
    h = auth_headers or {}

    for param in _SSRF_PARAMS:
        for payload in _SSRF_PAYLOADS:
            encoded = urllib.parse.quote(payload, safe="")
            probe_url = f"{base_url.rstrip('/')}/?{param}={encoded}"
            code, _, body = _do("GET", probe_url, h)
            if code is None:
                continue
            if any(canary in body for canary in _SSRF_CANARY_STRINGS):
                findings.append(_v(
                    "CRITICAL", "SSRF",
                    f"SSRF confirmado: parámetro '{param}'",
                    f"El servidor accedió a {payload} y devolvió contenido sensible.",
                    f"GET {probe_url}\nRespuesta (inicio): {body[:300]}",
                    "Valida y sanitiza URLs de entrada. Usa allowlist de hosts. "
                    "Bloquea acceso a IPs de metadata cloud y rangos privados (RFC1918).",
                    "CWE-918", confidence="high",
                ))
                return findings  # One confirmed is enough
            elif code == 200 and payload.startswith("http://127"):
                findings.append(_v(
                    "HIGH", "SSRF",
                    f"Posible SSRF: parámetro '{param}' respondió 200 a localhost",
                    f"GET {probe_url} → {code}. El servidor puede estar reenviando requests internos.",
                    f"GET {probe_url} → {code}",
                    "Implementa validación de URLs de entrada con allowlist de hosts permitidos.",
                    "CWE-918", confidence="low",
                ))

    return findings[:5]  # Cap findings


# ─── 3. Mass Assignment check ─────────────────────────────────────────────────

_MASS_ASSIGNMENT_FIELDS = [
    {"role": "admin"}, {"is_admin": True}, {"admin": True},
    {"status": "active"}, {"verified": True}, {"balance": 999999},
    {"permissions": ["admin", "superuser"]}, {"user_type": "admin"},
    {"is_staff": True}, {"is_superuser": True},
]


def check_mass_assignment(endpoint_url: str, auth_headers: Optional[dict] = None,
                          cvss_map: Optional[dict] = None) -> List[Vulnerability]:
    """POST/PATCH extra privilege fields and check if server accepts them."""
    cvss = cvss_map or _CVSS_MAP
    findings: List[Vulnerability] = []
    h = {**(auth_headers or {}), "Content-Type": "application/json"}

    for extra in _MASS_ASSIGNMENT_FIELDS:
        payload_bytes = json.dumps(extra).encode()
        code, resp_headers, body = _do("POST", endpoint_url, h, data=payload_bytes)
        if code is None:
            continue
        # If server accepts the payload without rejecting the extra field
        body_lower = body.lower()
        key = list(extra.keys())[0]
        val = str(list(extra.values())[0]).lower()
        if code < 400 and (key in body_lower or val in body_lower):
            findings.append(_v(
                "HIGH", "Input Validation",
                f"Posible Mass Assignment: campo '{key}' aceptado",
                f"El servidor respondió {code} a POST con campo extra '{key}': {extra[key]} "
                "y el campo aparece reflejado en la respuesta.",
                f"POST {endpoint_url}\n  payload={json.dumps(extra)}\n  status={code}\n  body={body[:200]}",
                "Implementa una whitelist explícita de campos permitidos en cada endpoint. "
                "Usa DTOs/schema validation para rechazar campos no definidos.",
                "CWE-915", confidence="medium",
            ))
            return findings  # One confirmed is enough

    return findings


# ─── 4. GraphQL Introspection ─────────────────────────────────────────────────

_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/gql", "/query", "/v1/graphql"]
_INTROSPECTION_QUERY = json.dumps({
    "query": "{ __schema { types { name } } }"
}).encode()


def check_graphql_introspection(base_url: str, auth_headers: Optional[dict] = None,
                                cvss_map: Optional[dict] = None) -> List[Vulnerability]:
    """Check if GraphQL introspection is enabled on common paths."""
    cvss = cvss_map or _CVSS_MAP
    findings: List[Vulnerability] = []
    h = {**(auth_headers or {}), "Content-Type": "application/json"}
    root = base_url.rstrip("/")

    for gql_path in _GRAPHQL_PATHS:
        url = f"{root}{gql_path}"
        code, _, body = _do("POST", url, h, data=_INTROSPECTION_QUERY)
        if code is not None and code < 400 and "__schema" in body:
            findings.append(_v(
                "MEDIUM", "Information Disclosure",
                "GraphQL introspection habilitada en producción",
                f"El endpoint {url} devolvió el schema completo ante una query de introspección. "
                "Esto expone toda la estructura de la API a atacantes.",
                f"POST {url} → {code}\nbody (inicio): {body[:300]}",
                "Deshabilita GraphQL introspection en producción. "
                "Usa persisted queries o allowlists de operaciones.",
                "CWE-200", confidence="high",
            ))
            break  # Found one, no need to continue

    return findings


# ─── 5. Legacy API versions / Inventory ───────────────────────────────────────

_LEGACY_PATHS = [
    "/v0", "/v0/", "/api/v0", "/api/v0/",
    "/v1-old", "/api-old", "/api-old/",
    "/beta", "/beta/", "/alpha", "/alpha/",
    "/internal", "/internal/api", "/internal/v1",
    "/admin/api", "/private/api",
    "/.well-known/security.txt",
    "/robots.txt",
]


def check_legacy_versions(base_url: str, current_version: str = "",
                          auth_headers: Optional[dict] = None,
                          cvss_map: Optional[dict] = None) -> List[Vulnerability]:
    """Probe common legacy API version paths for active responses."""
    cvss = cvss_map or _CVSS_MAP
    findings: List[Vulnerability] = []
    h = auth_headers or {}
    root = base_url.rstrip("/")

    # Detect current version from URL (e.g. /v2 → also probe /v1, /v0)
    import re
    ver_match = re.search(r"/v(\d+)", root)
    current_ver = int(ver_match.group(1)) if ver_match else 0
    extra_legacy = [f"/v{i}" for i in range(max(0, current_ver - 1), -1, -1) if i < current_ver]

    all_paths = list(dict.fromkeys(_LEGACY_PATHS + extra_legacy))

    for path in all_paths:
        url = f"{root}{path}"
        code, _, body = _do("GET", url, h)
        if code is not None and code < 400:
            severity = "HIGH" if "internal" in path or "admin" in path or "private" in path else "MEDIUM"
            findings.append(_v(
                severity, "API Inventory Management",
                f"API legacy/interna activa: {path}",
                f"El path '{path}' está activo y responde {code}. "
                "Versiones antiguas pueden carecer de parches de seguridad recientes.",
                f"GET {url} → {code}",
                "Desactiva o restringe versiones legacy. Implementa un inventario de API actualizado. "
                "Usa API gateways para gestionar deprecación de versiones.",
                "CWE-1059", confidence="medium",
            ))

    return findings[:8]  # Cap to avoid noise


# ─── 6. Error verbosity / Stack trace exposure ────────────────────────────────

_ERROR_PAYLOADS = [
    (b'{"id": null}', "application/json"),
    (b'{"id": "aaa<>\\u0000"}', "application/json"),
    (b"INVALID_JSON{{{", "application/json"),
    (b"<invalid>xml<</invalid>", "application/xml"),
    (b"' OR 1=1 --", "text/plain"),
]
_STACK_TRACE_INDICATORS = [
    "traceback", "stack trace", "at line", "sqlexception", "nullpointerexception",
    "syntaxerror", "django.core", "flask.app", "express.js", "internal server error",
    "pg::", "mysql_query", "ora-", "microsoft ole db", "odbc", "exception in thread",
    "java.lang.", "python", "ruby on rails", "stack_trace",
]


def check_error_verbosity(endpoint_url: str, auth_headers: Optional[dict] = None,
                          cvss_map: Optional[dict] = None) -> List[Vulnerability]:
    """Send malformed payloads and check for stack traces or verbose errors in responses."""
    cvss = cvss_map or _CVSS_MAP
    findings: List[Vulnerability] = []
    h = auth_headers or {}

    for payload_bytes, content_type in _ERROR_PAYLOADS:
        req_headers = {**h, "Content-Type": content_type}
        code, _, body = _do("POST", endpoint_url, req_headers, data=payload_bytes)
        if code is None:
            continue
        body_lower = body.lower()
        matched = [ind for ind in _STACK_TRACE_INDICATORS if ind in body_lower]
        if matched:
            findings.append(_v(
                "MEDIUM", "Information Disclosure",
                "Stack trace / error verboso expuesto",
                f"El servidor devolvió información técnica interna al recibir un payload malformado. "
                f"Indicadores detectados: {', '.join(matched[:4])}.",
                f"POST {endpoint_url}\n  payload={payload_bytes[:60]!r}\n  status={code}\n  body={body[:300]}",
                "Implementa manejadores de error globales que devuelvan mensajes genéricos en producción. "
                "Nunca expongas stack traces, nombres de framework o consultas SQL en respuestas.",
                "CWE-209", confidence="high",
            ))
            return findings  # One confirmed is enough

    # Also check for 500 on random path
    random_path = endpoint_url.rstrip("/") + "/nonexistent-security-probe-12345"
    code_500, _, body_500 = _do("GET", random_path, h)
    if code_500 is not None and code_500 >= 500:
        body_lower = body_500.lower()
        matched = [ind for ind in _STACK_TRACE_INDICATORS if ind in body_lower]
        if matched:
            findings.append(_v(
                "MEDIUM", "Information Disclosure",
                "Stack trace en respuesta 5xx",
                f"Path inválido devolvió {code_500} con indicadores de error verboso: {', '.join(matched[:4])}.",
                f"GET {random_path} → {code_500}\nbody: {body_500[:300]}",
                "Configura manejo de errores global para responder con mensajes genéricos.",
                "CWE-209", confidence="high",
            ))

    return findings


# ─── 7. Parse CVEs from Trivy/Grype JSON ─────────────────────────────────────

def parse_trivy_findings(trivy_json_path: str, cvss_map: Optional[dict] = None) -> List[Vulnerability]:
    """Convert Trivy JSON output to native Vulnerability objects."""
    cvss = cvss_map or _CVSS_MAP
    findings: List[Vulnerability] = []
    try:
        with open(trivy_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return findings

    results = data.get("Results", []) or []
    for result in results:
        target = str(result.get("Target", "unknown"))
        vulns = result.get("Vulnerabilities") or []
        for vuln in vulns:
            vid = str(vuln.get("VulnerabilityID", ""))
            sev = str(vuln.get("Severity", "UNKNOWN")).upper()
            if sev not in cvss:
                sev = "MEDIUM"
            pkg = str(vuln.get("PkgName", ""))
            installed = str(vuln.get("InstalledVersion", ""))
            fixed = str(vuln.get("FixedVersion", "sin fix disponible"))
            title = str(vuln.get("Title", vid))
            desc = str(vuln.get("Description", ""))[:300]
            cvss_score = float(vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", cvss.get(sev, 6.0)) or cvss.get(sev, 6.0))
            cwe_ids = vuln.get("CweIDs") or []
            cwe = cwe_ids[0] if cwe_ids else "CWE-1035"
            refs = vuln.get("References") or []

            findings.append(Vulnerability(
                severity=sev,
                category="Supply Chain / Dependency",
                title=f"CVE {vid}: {pkg}@{installed}",
                description=f"{title}. {desc}",
                file=f"<trivy:{target}>",
                line=0,
                code_snippet=f"Package: {pkg}\nInstalled: {installed}\nFixed in: {fixed}\nCVE: {vid}",
                recommendation=f"Actualiza {pkg} a {fixed}. Refs: {', '.join(refs[:2])}",
                cwe_id=cwe,
                cvss=cvss_score,
                confidence="high",
            ))

    return sorted(findings, key=lambda v: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(v.severity, 9))


def parse_grype_findings(grype_json_path: str, cvss_map: Optional[dict] = None) -> List[Vulnerability]:
    """Convert Grype JSON output to native Vulnerability objects."""
    cvss = cvss_map or _CVSS_MAP
    findings: List[Vulnerability] = []
    try:
        with open(grype_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return findings

    matches = data.get("matches", []) or []
    for match in matches:
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        vid = str(vuln.get("id", ""))
        sev = str(vuln.get("severity", "UNKNOWN")).upper()
        if sev not in cvss:
            sev = "MEDIUM"
        pkg = str(artifact.get("name", ""))
        installed = str(artifact.get("version", ""))
        fix_info = match.get("vulnerability", {}).get("fix", {})
        fixed = ", ".join(fix_info.get("versions", [])) or "sin fix disponible"
        desc = str(vuln.get("description", ""))[:300]
        cvss_score = float(cvss.get(sev, 6.0))
        for score_entry in (vuln.get("cvss") or []):
            try:
                cvss_score = float(score_entry.get("metrics", {}).get("baseScore", cvss_score))
                break
            except (TypeError, ValueError):
                pass
        cwe = "CWE-1035"
        urls = vuln.get("urls") or []

        findings.append(Vulnerability(
            severity=sev,
            category="Supply Chain / Dependency",
            title=f"CVE {vid}: {pkg}@{installed}",
            description=desc or f"Vulnerabilidad {vid} en {pkg}@{installed}.",
            file=f"<grype:{pkg}>",
            line=0,
            code_snippet=f"Package: {pkg}\nInstalled: {installed}\nFixed in: {fixed}\nCVE: {vid}",
            recommendation=f"Actualiza {pkg} a {fixed}. Refs: {', '.join(urls[:2])}",
            cwe_id=cwe,
            cvss=cvss_score,
            confidence="high",
        ))

    return sorted(findings, key=lambda v: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(v.severity, 9))


# ─── 8. Orchestrator ─────────────────────────────────────────────────────────

def run_advanced_dynamic_checks(
    base_url: str,
    endpoints: List[Dict[str, Any]],
    auth_headers: Optional[dict] = None,
    cvss_map: Optional[dict] = None,
    trivy_json_path: Optional[str] = None,
    grype_json_path: Optional[str] = None,
    http_budget: Optional[HttpRequestBudget] = None,
) -> List[Vulnerability]:
    """Run all advanced checks and return combined findings."""
    cvss = cvss_map or _CVSS_MAP
    findings: List[Vulnerability] = []
    h = auth_headers or {}
    root = base_url.rstrip("/")

    # GraphQL introspection (on base URL)
    findings.extend(check_graphql_introspection(root, h, cvss))

    # Legacy versions (on base URL)
    findings.extend(check_legacy_versions(root, auth_headers=h, cvss_map=cvss))

    # SSRF (on base URL, limited)
    findings.extend(check_ssrf(root, h, cvss))

    # Per-endpoint checks (cap at 5 endpoints to avoid long scans)
    endpoint_urls: List[str] = []
    for ep in (endpoints or []):
        if isinstance(ep, dict):
            url = str(ep.get("url", "")).strip()
            if url and url.startswith(("http://", "https://")):
                endpoint_urls.append(url)

    if not endpoint_urls:
        endpoint_urls = [root + "/"]

    for ep_url in endpoint_urls[:5]:
        findings.extend(check_http_methods(ep_url, h, cvss, budget=http_budget))
        findings.extend(check_error_verbosity(ep_url, h, cvss))
        findings.extend(check_mass_assignment(ep_url, h, cvss))

    # CVE parsing from external tool outputs
    if trivy_json_path and Path(trivy_json_path).exists():
        findings.extend(parse_trivy_findings(trivy_json_path, cvss))
    if grype_json_path and Path(grype_json_path).exists():
        findings.extend(parse_grype_findings(grype_json_path, cvss))

    return findings
