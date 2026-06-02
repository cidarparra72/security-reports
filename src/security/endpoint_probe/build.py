"""Normalize raw endpoint dicts into concrete method + URL (+ params, body, headers)."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlunparse

# Placeholders típicos de Postman / OpenAPI generators (reemplazo por la base sin barra final)
_KNOWN_TEMPLATE_PATTERNS = (
    re.compile(r"\{\{baseUrl\}\}", re.I),
    re.compile(r"\{\{base_url\}\}", re.I),
    re.compile(r"\{\{BASE_URL\}\}", re.I),
    re.compile(r"\{\{host\}\}", re.I),
)


def _ensure_scheme(base_url: str) -> str:
    u = (base_url or "").strip()
    if not u:
        return ""
    if not u.startswith(("http://", "https://")):
        u = "https://" + u.lstrip("/")
    return u.rstrip("/")


def merge_base_path(base_url: str, path: str) -> str:
    """Join base and path without urljoin host-reset surprises."""
    p = (path or "").strip()
    if not p:
        return base_url
    low = p.lower()
    if low.startswith("http://") or low.startswith("https://"):
        return p
    b = base_url.rstrip("/")
    seg = p.lstrip("/")
    return f"{b}/{seg}"


def _collapse_slashes_in_url_path(url: str) -> str:
    """Mantiene scheme://host y reduce // duplicados en el path (p. ej. host//seg → host/seg)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return url
    path = parsed.path or ""
    if "//" not in path and path != "":
        return url
    segments = [s for s in path.split("/") if s]
    new_path = "/" + "/".join(segments) if segments else "/"
    return urlunparse(
        (parsed.scheme, parsed.netloc, new_path, "", parsed.query, parsed.fragment)
    )


def _expand_template_url(url: str, base: Optional[str]) -> str:
    """
    Resuelve URLs de colección con {{base_url}}, {{baseUrl}}, o prefijo {{cualquierVariable}}.
    Requiere base (URL absoluta o host al que se añade https://).
    """
    u = (url or "").strip()
    b_raw = (base or "").strip().rstrip("/")
    if not u or not b_raw:
        return u
    b = _ensure_scheme(b_raw)

    if u.startswith("{{"):
        end = u.find("}}")
        if end != -1:
            tail = u[end + 2 :].lstrip("/")
            if not tail:
                return _collapse_slashes_in_url_path(b)
            merged = merge_base_path(b, tail)
            return _collapse_slashes_in_url_path(merged)

    out = u
    b_no_slash = b.rstrip("/")
    for rx in _KNOWN_TEMPLATE_PATTERNS:
        out = rx.sub(b_no_slash, out)
    if out != u:
        out = _collapse_slashes_in_url_path(out)
    return out


def normalize_probe_endpoint(
    raw: Dict[str, Any],
    default_base: Optional[str],
) -> Dict[str, Any]:
    method = str(raw.get("method") or "GET").strip().upper() or "GET"
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        method = "GET"

    url = str(
        raw.get("url")
        or raw.get("href")
        or raw.get("URI")
        or raw.get("uri")
        or ""
    ).strip()
    path = str(
        raw.get("path")
        or raw.get("route")
        or raw.get("endpoint")
        or raw.get("relativePath")
        or ""
    ).strip()

    params = raw.get("params") if isinstance(raw.get("params"), dict) else {}
    headers = raw.get("headers") if isinstance(raw.get("headers"), dict) else {}
    body = raw.get("body")

    if url:
        final = url
        if default_base and ("{{" in final or final.startswith("{{")):
            final = _expand_template_url(final, default_base)
    elif default_base and path:
        p_work = (path or "").strip()
        if "{{" in p_work:
            p_work = _expand_template_url(p_work, default_base)
        if p_work.lower().startswith(("http://", "https://")):
            final = _collapse_slashes_in_url_path(p_work)
        else:
            final = merge_base_path(_ensure_scheme(default_base), p_work)
    elif path and path.lower().startswith(("http://", "https://")):
        final = path
    else:
        raise ValueError("Cada ítem necesita 'url' absoluta o 'path' con base_url")

    if "{{" in final:
        raise ValueError(
            f"URL con variables sin resolver: {final}. "
            "Indica la URL base del API en el formulario (campo base / URL base) y vuelve a «Cargar / normalizar»."
        )

    parsed = urlparse(final)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(
            f"URL no válida: {final}. "
            "Si usas Postman, rellena la URL base (https://tu-api.com) antes de normalizar."
        )

    return {
        "method": method,
        "url": final,
        "params": params,
        "headers": {str(k): str(v) for k, v in headers.items()},
        "body": body,
    }


def prepare_endpoints(
    raw_items: List[Dict[str, Any]],
    base_url: Optional[str],
) -> tuple[List[Dict[str, Any]], List[str]]:
    base = _ensure_scheme(base_url) if base_url else None
    out: List[Dict[str, Any]] = []
    errors: List[str] = []
    for i, raw in enumerate(raw_items):
        try:
            out.append(normalize_probe_endpoint(raw, base))
        except ValueError as e:
            errors.append(f"Ítem {i}: {e}")
    return out, errors
