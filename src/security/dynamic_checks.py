#!/usr/bin/env python3
"""
Pruebas dinámicas contra la URL base del API (TLS, cabeceras HTTP, CORS, swagger).
Complementa el análisis estático de código (similar enfoque a retest manual vía Burp/proxy,
sin sustituir pruebas de lógica de negocio: IDOR, enumeración, JWT requieren contexto manual).

Solo stdlib: socket, ssl, urllib.
"""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from .api_scanner import Vulnerability
from .http_probe_budget import HttpRequestBudget

_USER_AGENT = "APISecurityScanner/1.0"
_TIMEOUT = 8.0
_CORS_PROBE_ORIGIN = "https://cors-probe-scanner.invalid"


def _v(
    cvss_map: Dict[str, float],
    severity: str,
    category: str,
    title: str,
    description: str,
    snippet: str,
    recommendation: str,
    cwe: str,
    confidence: str = "medium",
) -> Vulnerability:
    return Vulnerability(
        severity=severity,
        category=category,
        title=title,
        description=description,
        file="<dynamic:api>",
        line=0,
        code_snippet=snippet,
        recommendation=recommendation,
        cwe_id=cwe,
        cvss=cvss_map.get(severity, 6.0),
        confidence=confidence,
    )


def _http_get(
    url: str,
    extra_headers: Optional[dict] = None,
    budget: Optional[HttpRequestBudget] = None,
) -> tuple[Optional[int], dict]:
    """Devuelve (código, headers_dict) o (None, {{}}) si falla o se agotó el presupuesto."""
    if budget is not None and not budget.allow(url):
        return None, {"_budget_exhausted": "1"}
    if budget is not None:
        budget.record(url)
    h = {"User-Agent": _USER_AGENT}
    if extra_headers:
        h.update(extra_headers)
    try:
        req = urllib.request.Request(url, headers=h, method="GET")
        with urllib.request.urlopen(
            req, timeout=_TIMEOUT, context=ssl.create_default_context()
        ) as resp:
            code = resp.getcode()
            raw = dict(resp.headers.items()) if resp.headers else {}
            return int(code), {k: v for k, v in raw.items()}
    except urllib.error.HTTPError as e:
        raw = dict(e.headers.items()) if e.headers else {}
        try:
            return int(e.code), {k: v for k, v in raw.items()}
        except (TypeError, ValueError):
            return None, {"_error": str(e)}
    except (urllib.error.URLError, OSError, ValueError, TypeError) as e:
        return None, {"_error": str(e)}


def _http_request(
    method: str,
    url: str,
    extra_headers: Optional[dict] = None,
    budget: Optional[HttpRequestBudget] = None,
) -> tuple[Optional[int], dict]:
    if budget is not None and not budget.allow(url):
        return None, {"_budget_exhausted": "1"}
    if budget is not None:
        budget.record(url)
    h = {"User-Agent": _USER_AGENT}
    if extra_headers:
        h.update(extra_headers)
    try:
        req = urllib.request.Request(url, headers=h, method=method.upper())
        with urllib.request.urlopen(
            req, timeout=_TIMEOUT, context=ssl.create_default_context()
        ) as resp:
            code = resp.getcode()
            raw = dict(resp.headers.items()) if resp.headers else {}
            return int(code), {k: v for k, v in raw.items()}
    except urllib.error.HTTPError as e:
        raw = dict(e.headers.items()) if e.headers else {}
        try:
            return int(e.code), {k: v for k, v in raw.items()}
        except (TypeError, ValueError):
            return None, {"_error": str(e)}
    except (urllib.error.URLError, OSError, ValueError, TypeError) as e:
        return None, {"_error": str(e)}


def _http_get_accessible(url: str, budget: Optional[HttpRequestBudget] = None) -> bool:
    code, _ = _http_get(url, budget=budget)
    return code is not None and 200 <= code < 300


def run_dynamic_api_checks(
    base_url: str, cvss_map: Dict[str, float]
) -> List[Vulnerability]:
    base_url = (base_url or "").strip()
    if not base_url:
        return []

    out: List[Vulnerability] = []
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return [
            _v(
                cvss_map,
                "MEDIUM",
                "Configuration",
                "URL del API no válida",
                "La URL base proporcionada no es un http(s) válido con host.",
                base_url,
                "Indica una URL completa, p. ej. https://api.ejemplo.com",
                "CWE-20",
            )
        ]

    scheme = parsed.scheme
    host = parsed.hostname
    if not host:
        return out

    port = parsed.port or (443 if scheme == "https" else 80)
    path_prefix = parsed.path.rstrip("/") or ""

    if scheme == "http":
        out.append(
            _v(
                cvss_map,
                "HIGH",
                "Transport Security",
                "Base del API en HTTP (sin TLS)",
                "El cliente de escaneo recibió una URL con esquema http. El tráfico hacia el API no va cifrado en transporte.",
                f"URL: {base_url}",
                "Usa https:// para el API en producción y redirige HTTP a HTTPS.",
                "CWE-319",
                confidence="high",
            )
        )
        return out

    # --- TLS: versión negociada
    if scheme == "https":
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=_TIMEOUT) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                    ver = ssock.version() or "?"
                    cipher = ssock.cipher()
                    cname = cipher[0] if cipher else "?"
                    snippet = f"TLS: {ver}\nCipher: {cname}"
                    if ver in ("TLSv1", "TLSv1.1"):
                        out.append(
                            _v(
                                cvss_map,
                                "HIGH",
                                "Transport Security",
                                "Protocolos TLS obsoletos (TLS 1.0/1.1)",
                                f"El servidor negoció {ver}, considerado inseguro.",
                                snippet,
                                "Habilita solo TLS 1.2+ (preferible TLS 1.3) y desactiva 1.0/1.1.",
                                "CWE-327",
                                confidence="high",
                            )
                        )
                    if cipher and isinstance(cipher[0], str):
                        if any(
                            x in cipher[0].upper()
                            for x in ("NULL", "EXPORT", "RC4", "DES", "MD5")
                        ):
                            out.append(
                                _v(
                                    cvss_map,
                                    "MEDIUM",
                                    "Transport Security",
                                    "Suite criptográfica débil en TLS",
                                    f"La suite negociada puede ser débil: {cipher[0]}",
                                    snippet,
                                    "Deshabilita suites obsoletas; usa solo ciphers modernos.",
                                    "CWE-326",
                                )
                            )
        except (OSError, ssl.SSLError) as e:
            out.append(
                _v(
                    cvss_map,
                    "LOW",
                    "Transport Security",
                    "No se pudo inspeccionar el handshake TLS",
                    str(e),
                    f"host={host!r} port={port}",
                    "Verifica certificado, firewall y que el servicio acepte TLS en ese puerto.",
                    "CWE-295",
                )
            )

    # URL base normalizada para peticiones HTTP (respeta path si p.ej. /api)
    root = f"{scheme}://{parsed.netloc}{path_prefix}"
    if not root.endswith("/"):
        root = root + "/"
    get_url = root

    code, headers = _http_get(get_url)
    if code is None:
        err = headers.get("_error", "unknown")
        out.append(
            _v(
                cvss_map,
                "MEDIUM",
                "Availability",
                "No se pudo conectar al API (GET base)",
                f"Error: {err}",
                get_url,
                "Comprueba que la URL sea pública, el certificado sea válido y no haya bloqueo de IP.",
                "CWE-20",
            )
        )
        return out

    hdr = {k.title(): v for k, v in headers.items()}

    server = hdr.get("Server")
    if server:
        out.append(
            _v(
                cvss_map,
                "LOW",
                "Information Disclosure",
                "Divulgación de software (cabecera Server)",
                f"El servidor anuncia: {server!r}",
                f"Server: {server}",
                "Oculta o reduce la cabecera Server y X-Powered-By en producción.",
                "CWE-200",
            )
        )
    for leak in ("X-Powered-By", "X-Aspnet-Version"):
        v = hdr.get(leak) or headers.get(leak) or headers.get(leak.title())
        if v:
            out.append(
                _v(
                    cvss_map,
                    "LOW",
                    "Information Disclosure",
                    f"Divulgación de stack ({leak})",
                    f"Valor: {v!r}",
                    f"{leak}: {v}",
                    "Elimina o restringe esta cabecera en el edge origen.",
                    "CWE-200",
                )
            )

    if scheme == "https" and not hdr.get("Strict-Transport-Security"):
        out.append(
            _v(
                cvss_map,
                "MEDIUM",
                "Transport Security",
                "Falta cabecera Strict-Transport-Security (HSTS)",
                "No se detectó HSTS en la respuesta; los clientes no reciben la política de forzar HTTPS.",
                "\n".join(f"{k}: {v}" for k, v in list(hdr.items())[:12]),
                "Añade HSTS con un max-age adecuado (y preload si aplica) en el balanceador o API gateway.",
                "CWE-319",
            )
        )

    # CORS: petición con Origin de prueba
    _, h2 = _http_get(get_url, {"Origin": _CORS_PROBE_ORIGIN})
    if h2 and "_error" not in h2:
        h2m = {k.title(): v for k, v in h2.items()}
        aco = h2m.get("Access-Control-Allow-Origin", "")
        if aco == "*":
            out.append(
                _v(
                    cvss_map,
                    "MEDIUM",
                    "Configuration",
                    "CORS: Access-Control-Allow-Origin: *",
                    "Cualquier origen en el navegador podría consumir el recurso con credenciales según política de cookies; revisar impacto con APIs sensibles.",
                    f"Access-Control-Allow-Origin: {aco}",
                    "Restringe ACAO a orígenes explícitos; evita * en entornos con datos sensibles.",
                    "CWE-942",
                )
            )
        elif aco == _CORS_PROBE_ORIGIN:
            out.append(
                _v(
                    cvss_map,
                    "HIGH",
                    "Configuration",
                    "CORS: reflejo del origen (pseudoorigen)",
                    f"El servidor refleja el orígen de la petición: {aco!r}",
                    f"Access-Control-Allow-Origin: {aco}",
                    "No reflejes Origin arbitrario; usa lista blanca de dominios confiables.",
                    "CWE-942",
                    confidence="high",
                )
            )

    # Documentación pública (mismo criterio que sondas en código)
    for suffix in ("/swagger.json", "/api-docs", "/api-docs/"):
        doc_url = urljoin(root, suffix.lstrip("/"))
        if _http_get_accessible(doc_url):
            out.append(
                _v(
                    cvss_map,
                    "HIGH",
                    "Information Disclosure",
                    "Exposed API Documentation (sonda dinámica)",
                    f"Respuesta exitosa en {doc_url}",
                    f"GET {doc_url} → 2xx",
                    "Restringe o desactiva documentación pública en producción.",
                    "CWE-200",
                    confidence="high",
                )
            )
            break

    return out


def run_api_runtime_core_checks(
    base_url: str,
    endpoints: List[Dict[str, Any]],
    cvss_map: Dict[str, float],
    *,
    http_budget: Optional[HttpRequestBudget] = None,
) -> List[Vulnerability]:
    """Heuristic runtime checks for endpoint/API behavior.

    http_budget: tope de peticiones por URL; al agotarse se omite el resto para ese endpoint.
    """
    out: List[Vulnerability] = []
    base_url = (base_url or "").strip().rstrip("/")
    if not base_url:
        return out

    endpoint_urls: List[str] = []
    for e in endpoints or []:
        if not isinstance(e, dict):
            continue
        url = str(e.get("url") or "").strip()
        if url and url.startswith(("http://", "https://")):
            endpoint_urls.append(url)

    if not endpoint_urls:
        endpoint_urls.append(base_url + "/")

    # 1) Security headers baseline on base API
    code, headers = _http_get(base_url + "/", budget=http_budget)
    if code is not None:
        hdr = {k.title(): v for k, v in headers.items()}
        if not hdr.get("X-Content-Type-Options"):
            out.append(
                _v(
                    cvss_map,
                    "LOW",
                    "Configuration",
                    "Falta X-Content-Type-Options",
                    "La respuesta no incluye X-Content-Type-Options: nosniff.",
                    base_url + "/",
                    "Agrega X-Content-Type-Options: nosniff en API gateway/backend.",
                    "CWE-16",
                )
            )
        if not hdr.get("Referrer-Policy"):
            out.append(
                _v(
                    cvss_map,
                    "LOW",
                    "Configuration",
                    "Falta Referrer-Policy",
                    "No se encontró cabecera Referrer-Policy en la respuesta del API.",
                    base_url + "/",
                    "Configura Referrer-Policy estricta (p. ej., no-referrer).",
                    "CWE-16",
                )
            )

    # 2) OPTIONS/Allow probe for dangerous methods (todos los endpoints en alcance)
    for u in endpoint_urls:
        if http_budget is not None and not http_budget.allow(u):
            continue
        status, h = _http_request("OPTIONS", u, budget=http_budget)
        if status is None:
            continue
        allow = str(h.get("Allow") or h.get("allow") or "")
        if allow and any(m in allow.upper() for m in ("DELETE", "PUT", "PATCH")):
            out.append(
                _v(
                    cvss_map,
                    "MEDIUM",
                    "Authorization",
                    "Métodos sensibles expuestos en Allow (heurístico)",
                    f"OPTIONS {u} devolvió Allow={allow!r}.",
                    f"OPTIONS {u}",
                    "Verifica autorización estricta por método y rol; evita exponer métodos no requeridos.",
                    "CWE-285",
                    confidence="low",
                )
            )

    # 3) Error handling leakage probe (malformed path)
    malformed = base_url + "/this-path-should-not-exist-security-probe"
    if http_budget is None or http_budget.allow(malformed):
        status, h = _http_get(malformed, budget=http_budget)
    else:
        status, h = None, {}
    if status is not None and status >= 500:
        server = str(h.get("Server") or h.get("server") or "")
        out.append(
            _v(
                cvss_map,
                "MEDIUM",
                "Information Disclosure",
                "Manejo de errores potencialmente inseguro",
                "Un path inválido devolvió error 5xx; podría exponer trazas o detalles internos.",
                f"GET {malformed} -> {status} | Server={server}",
                "Usa manejadores de error consistentes y sanitiza mensajes internos.",
                "CWE-209",
            )
        )

    # 4) Manual-required coverage items included in report.
    manual_gap_titles = [
        (
            "Validación manual requerida: BOLA/IDOR por objeto",
            "Authorization",
            "CWE-639",
            "Ejecuta pruebas con dos identidades y cruza IDs para detectar acceso indebido a recursos de terceros.",
        ),
        (
            "Validación manual requerida: BFLA por rol",
            "Authorization",
            "CWE-285",
            "Prueba endpoints de privilegio alto con cuentas de menor rol y verifica denegación consistente.",
        ),
        (
            "Validación manual requerida: Mass Assignment",
            "Input Validation",
            "CWE-915",
            "Intenta campos no permitidos en payloads (role, status, flags internos) y valida whitelists server-side.",
        ),
        (
            "Validación manual requerida: JWT claims/TTL/revocación",
            "Session Management",
            "CWE-613",
            "Verifica exp/iat/nbf/aud/iss/jti, rotación de claves y revocación de tokens.",
        ),
    ]
    for title, category, cwe, rec in manual_gap_titles:
        out.append(
            _v(
                cvss_map,
                "LOW",
                category,
                title,
                "Este control requiere pruebas autenticadas diferenciales y contexto de negocio.",
                base_url,
                rec,
                cwe,
                confidence="high",
            )
        )

    return out
