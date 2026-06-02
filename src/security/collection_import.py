#!/usr/bin/env python3
"""
Importa endpoints desde JSON de colección de APIs:
- Postman Collection v2.x
- OpenAPI 3.x
- Swagger 2.0
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .infer_api_url import filter_endpoints_by_api_base

_HTTP_METHODS = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}
)


def _detail(
    method: str,
    path: str,
    full_url: str,
    source: str,
) -> Dict[str, Any]:
    p = path.strip() or "/"
    if not p.startswith("/"):
        p = "/" + p
    return {
        "method": method.upper(),
        "path": p,
        "url": full_url.strip(),
        "files": [],
        "count": 1,
        "source": source,
        "strong_binding": True,
    }


def _normalize_path(path: str) -> str:
    p = (path or "").strip()
    if not p.startswith("/"):
        p = "/" + p
    return p


def _join_url(base: str, path: str) -> str:
    b = (base or "").rstrip("/")
    p = (path or "").strip()
    if not p.startswith("/"):
        p = "/" + p
    if not b:
        return p
    return b + p


def _is_postman(data: Dict[str, Any]) -> bool:
    info = data.get("info")
    if isinstance(info, dict):
        sch = str(info.get("schema") or "").lower()
        if "getpostman.com" in sch:
            return True
    return data.get("item") is not None and "openapi" not in data and not str(
        data.get("swagger") or ""
    ).startswith("2")


def _openapi_resolve_base(spec: Dict[str, Any], hint: Optional[str]) -> str:
    hint_b = (hint or "").strip().rstrip("/")
    servers = spec.get("servers") or []
    if not servers or not isinstance(servers[0], dict):
        return hint_b
    su = str(servers[0].get("url") or "").strip().rstrip("/")
    if not su:
        return hint_b
    if su.startswith("http://") or su.startswith("https://"):
        return su
    if hint_b:
        return _join_url(hint_b, su)
    return su


def _swagger_base(spec: Dict[str, Any], hint: Optional[str]) -> str:
    if hint:
        return hint.rstrip("/")
    schemes = spec.get("schemes") or ["https"]
    host = str(spec.get("host") or "").strip()
    base_path = str(spec.get("basePath") or "/").strip() or "/"
    if not host:
        return ""
    scheme = str(schemes[0]).lower() if schemes else "https"
    if not base_path.startswith("/"):
        base_path = "/" + base_path
    return f"{scheme}://{host}{base_path}".rstrip("/")


def _paths_from_openapi(
    spec: Dict[str, Any], base: str, source: str
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return out
    for path_key, ops in paths.items():
        if not isinstance(path_key, str) or not isinstance(ops, dict):
            continue
        path_norm = _normalize_path(str(path_key))
        for method, _ in ops.items():
            m = str(method).upper()
            if m not in _HTTP_METHODS:
                continue
            full = _join_url(base, path_norm) if base else path_norm
            out.append(_detail(m, path_norm, full, source))
    return out


def _postman_host_path(url_obj: Any) -> Tuple[str, str]:
    """Devuelve (host_con_protocolo_o_vacío, path_con_slash)."""
    if isinstance(url_obj, str):
        u = url_obj.strip()
        if u.startswith("http://") or u.startswith("https://"):
            p = urlparse(u)
            path = p.path or "/"
            return f"{p.scheme}://{p.netloc}", _normalize_path(path)
        return "", _normalize_path(u)
    if not isinstance(url_obj, dict):
        return "", "/"
    raw = str(url_obj.get("raw") or "").strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        p = urlparse(raw.split("?")[0])
        path = p.path or "/"
        return f"{p.scheme}://{p.netloc}", _normalize_path(path)
    protocol = str(url_obj.get("protocol") or "https").strip() or "https"
    host_parts = url_obj.get("host")
    path_parts = url_obj.get("path")
    host_s = ""
    if isinstance(host_parts, list):
        host_s = ".".join(str(x) for x in host_parts if x)
    elif isinstance(host_parts, str):
        host_s = host_parts
    path_s = "/"
    if isinstance(path_parts, list):
        path_s = "/" + "/".join(str(x).strip("/") for x in path_parts if str(x).strip())
    elif isinstance(path_parts, str):
        path_s = _normalize_path(path_parts)
    if host_s:
        return f"{protocol}://{host_s}", _normalize_path(path_s)
    return "", _normalize_path(path_s)


def _expand_postman_raw(raw: str, base_hint: Optional[str]) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    if "{{" in raw and "}}" in raw and base_hint:
        if raw.startswith("{{"):
            end = raw.find("}}")
            if end != -1:
                rest = raw[end + 2 :].lstrip("/")
                return _join_url(base_hint, rest)
        raw = raw.replace("{{baseUrl}}", base_hint.rstrip("/"))
        raw = raw.replace("{{base_url}}", base_hint.rstrip("/"))
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw.split("?")[0]
    if base_hint:
        return _join_url(base_hint, raw)
    return raw


def _postman_request_url(
    req: Dict[str, Any], base_hint: Optional[str]
) -> Tuple[str, str]:
    url_obj = req.get("url")
    if isinstance(url_obj, dict) and str(url_obj.get("raw") or "").strip():
        full = _expand_postman_raw(str(url_obj.get("raw")), base_hint)
        if full.startswith("http"):
            p = urlparse(full)
            return full, _normalize_path(p.path or "/")
    host_prefix, path = _postman_host_path(url_obj)
    if host_prefix:
        return f"{host_prefix}{path}", path
    if base_hint:
        full = _join_url(base_hint, path)
        return full, path
    return path, path


def _walk_postman_items(
    items: Any,
    base_hint: Optional[str],
    out: List[Dict[str, Any]],
) -> None:
    if not isinstance(items, list):
        return
    for it in items:
        if not isinstance(it, dict):
            continue
        nested = it.get("item")
        if nested is not None:
            _walk_postman_items(nested, base_hint, out)
            continue
        req = it.get("request")
        if not isinstance(req, dict):
            continue
        method = str(req.get("method") or "GET").upper()
        if method not in _HTTP_METHODS:
            continue
        full_url, path = _postman_request_url(req, base_hint)
        if not full_url.startswith("http") and base_hint:
            full_url = _join_url(base_hint, path)
        det = _detail(method, path, full_url, "collection:postman")
        name = str(it.get("name") or "").strip()
        if name:
            det["name"] = name
        out.append(det)


def _postman_base_from_variables(data: Dict[str, Any]) -> Optional[str]:
    for key in ("variable", "auth"):
        block = data.get(key)
        if not isinstance(block, list):
            continue
        for v in block:
            if not isinstance(v, dict):
                continue
            k = str(v.get("key") or "").lower()
            if k in ("baseurl", "base_url", "host", "root"):
                val = str(v.get("value") or "").strip()
                if val.startswith("http://") or val.startswith("https://"):
                    return val.rstrip("/")
    return None


def _endpoint_method_path(ep: Dict[str, Any]) -> Tuple[str, str]:
    """Clave (método, path) para fusionar la misma ruta con URL relativa y absoluta."""
    m = str(ep.get("method") or "GET").upper()
    path = _normalize_path(str(ep.get("path") or "/"))
    url = str(ep.get("url") or "").strip().split("?")[0].rstrip("/")
    if url.startswith(("http://", "https://")):
        pr = urlparse(url)
        if pr.path:
            path = _normalize_path(pr.path)
    return m, path


def _prefer_richer_endpoint(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Conserva la variante con URL absoluta o más información."""
    a_url = str(a.get("url") or "")
    b_url = str(b.get("url") or "")
    if not a_url.startswith(("http://", "https://")) and b_url.startswith(
        ("http://", "https://")
    ):
        merged = dict(b)
        if not merged.get("name") and a.get("name"):
            merged["name"] = a["name"]
        return merged
    if a_url.startswith(("http://", "https://")) and not b_url.startswith(
        ("http://", "https://")
    ):
        merged = dict(a)
        if not merged.get("name") and b.get("name"):
            merged["name"] = b["name"]
        return merged
    return a if len(a_url) >= len(b_url) else b


def dedupe_collection_endpoints(
    eps: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Unifica p. ej. GET /api/x y GET https://host/api/x; conserva la URL absoluta."""
    buckets: Dict[Tuple[str, str], Dict[str, Any]] = {}
    order: List[Tuple[str, str]] = []
    for ep in eps or []:
        if not isinstance(ep, dict):
            continue
        key = _endpoint_method_path(ep)
        if key in buckets:
            buckets[key] = _prefer_richer_endpoint(buckets[key], ep)
            continue
        buckets[key] = ep
        order.append(key)
    return [buckets[k] for k in order]


def _filter_collection_endpoints(
    eps: List[Dict[str, Any]],
    sugg: Optional[str],
    hint: Optional[str],
) -> List[Dict[str, Any]]:
    filter_base = (hint or sugg or "").strip()
    if filter_base and eps:
        return filter_endpoints_by_api_base(filter_base, eps)
    return eps


def parse_api_collection(
    data: Any, api_url_hint: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Parsea un dict JSON de colección/spec.
    Devuelve (lista de endpoint details compatibles con infer_api_endpoints, api_base sugerida o None).
    """
    if not isinstance(data, dict):
        return [], None

    hint = (api_url_hint or "").strip() or None

    # OpenAPI 3
    if str(data.get("openapi") or "").startswith("3"):
        base = _openapi_resolve_base(data, hint)
        eps = _paths_from_openapi(data, base, "collection:openapi3")
        if eps and not any(
            str(e.get("url") or "").startswith("http") for e in eps
        ):
            return [], None
        sugg = base if base.startswith("http") else hint
        filtered = _filter_collection_endpoints(eps, sugg, hint)
        return dedupe_collection_endpoints(filtered), sugg

    # Swagger 2
    if str(data.get("swagger") or "").startswith("2"):
        base = _swagger_base(data, hint)
        eps = _paths_from_openapi(data, base, "collection:swagger2")
        if eps and not any(
            str(e.get("url") or "").startswith("http") for e in eps
        ):
            return [], None
        sugg = base if base.startswith("http") else hint
        filtered = _filter_collection_endpoints(eps, sugg, hint)
        return dedupe_collection_endpoints(filtered), sugg

    # Postman Collection v2.x
    if _is_postman(data):
        base = hint or _postman_base_from_variables(data)
        out: List[Dict[str, Any]] = []
        _walk_postman_items(data.get("item"), base, out)
        if out and not any(str(e.get("url") or "").startswith("http") for e in out):
            return [], None
        sugg = base if (base or "").startswith("http") else hint
        filtered = _filter_collection_endpoints(out, sugg, hint)
        return dedupe_collection_endpoints(filtered), sugg

    return [], None
