"""Parse endpoint definitions from JSON text or multiline path specs."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

_LINE_RE = re.compile(
    r"^(?:(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+)?(?P<path>\S+)(?:\s+.*)?$",
    re.IGNORECASE,
)

_HTTP_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
)


def _expand_openapi_paths(paths_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    """OpenAPI 3 / Swagger 2: paths is an object path -> { get: {...}, post: ... }."""
    out: List[Dict[str, Any]] = []
    if not isinstance(paths_obj, dict):
        return out
    for path_key, path_item in paths_obj.items():
        if not isinstance(path_item, dict):
            continue
        p = str(path_key or "").strip()
        if not p:
            continue
        if not p.startswith("/"):
            p = "/" + p
        for m, _op in path_item.items():
            if str(m).lower() not in _HTTP_METHODS:
                continue
            out.append({"method": str(m).upper(), "path": p})
    return out


def _flatten_postman_items(nodes: Any) -> List[Dict[str, Any]]:
    """Postman Collection v2.1: extrae request.method + URL (raw o string)."""
    out: List[Dict[str, Any]] = []

    def walk(items: Any) -> None:
        if not isinstance(items, list):
            return
        for node in items:
            if not isinstance(node, dict):
                continue
            if "item" in node:
                walk(node.get("item"))
            req = node.get("request")
            if not isinstance(req, dict):
                continue
            method = str(req.get("method") or "GET").strip().upper() or "GET"
            url_obj = req.get("url")
            if isinstance(url_obj, str):
                url = url_obj.strip()
            elif isinstance(url_obj, dict):
                url = str(url_obj.get("raw") or "").strip()
            else:
                url = ""
            if url:
                out.append({"method": method, "url": url})

    walk(nodes)
    return out


def parse_endpoints_from_json(json_text: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Accepts:
    - JSON array: [{"method":"GET","path":"/x",...}, ...]
    - Object with "endpoints": [ ... ]
    - OpenAPI/Swagger: object with "paths": { "/route": { "get": ... } }
    - Postman v2.1: object with "info" + "item" (árbol de carpetas)
    """
    errors: List[str] = []
    text = (json_text or "").strip()
    if text.startswith("\ufeff"):
        text = text[1:].lstrip()
    if not text:
        return [], ["JSON vacío"]

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        return [], [f"JSON inválido: {e}"]

    if isinstance(data, dict):
        if isinstance(data.get("endpoints"), list):
            data = data["endpoints"]
        elif isinstance(data.get("paths"), list):
            data = data["paths"]
        elif "info" in data and isinstance(data.get("item"), list):
            pm = _flatten_postman_items(data.get("item"))
            if pm:
                data = pm
            else:
                return [], [
                    "Colección Postman sin requests con URL reconocible "
                    "(revisa que cada request tenga url.raw o url como texto)"
                ]
        elif isinstance(data.get("paths"), dict):
            expanded = _expand_openapi_paths(data["paths"])
            if expanded:
                data = expanded
            else:
                return [], [
                    'El objeto "paths" no parece OpenAPI/Swagger (no se encontraron métodos HTTP)'
                ]
        elif isinstance(data.get("items"), list):
            data = data["items"]
        else:
            return [], [
                'Formato no reconocido: usa un array, '
                '{"endpoints":[...]}, OpenAPI con "paths", o Postman con "item"'
            ]

    if not isinstance(data, list):
        return [], ["Tras interpretar el JSON, se esperaba una lista de endpoints"]

    out: List[Dict[str, Any]] = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            errors.append(f"Ítem {i}: no es un objeto")
            continue
        out.append(dict(item))

    return out, errors


def parse_paths_multiline(paths_text: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    One endpoint per line:
      GET /api/health
      POST /v1/login
      /metrics   (defaults to GET)
    """
    errors: List[str] = []
    lines = (paths_text or "").splitlines()
    out: List[Dict[str, Any]] = []
    for num, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _LINE_RE.match(line)
        if not m:
            errors.append(f"Línea {num}: formato no reconocido ({line[:40]}…)")
            continue
        method = (m.group("method") or "GET").upper()
        path = m.group("path").strip()
        out.append({"method": method, "path": path})
    if not out and not errors:
        errors.append("No hay rutas en el texto (usa una línea por ruta)")
    return out, errors
