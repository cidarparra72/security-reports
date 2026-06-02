"""Execute HTTP probes with timeouts and light response analysis."""

from __future__ import annotations

import json as json_lib
import re
import time
from typing import Any, Dict, List, Optional

import requests

_ERROR_LEAK_RE = re.compile(
    r"(stack trace|exception in thread|sql syntax|syntax error|traceback \(most recent|"
    r"internal server error|fatal error|nullpointerexception)",
    re.IGNORECASE,
)


def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _light_vuln_hints(status_code: int, body_text: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    hints: List[Dict[str, Any]] = []
    if status_code >= 500:
        hints.append(
            {
                "severity": "MEDIUM",
                "title": "Respuesta 5xx",
                "detail": "El servidor respondió con error; revisar estabilidad y filtrado de errores.",
            }
        )
    if body_text and _ERROR_LEAK_RE.search(body_text):
        hints.append(
            {
                "severity": "LOW",
                "title": "Posible filtrado de error en cuerpo",
                "detail": "El cuerpo contiene patrones típicos de mensajes de error o stack.",
            }
        )
    ctype = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
    if "application/json" in ctype and body_text:
        try:
            json_lib.loads(body_text)
        except json_lib.JSONDecodeError:
            hints.append(
                {
                    "severity": "LOW",
                    "title": "JSON inválido pese a Content-Type",
                    "detail": "Se anunció JSON pero el cuerpo no parsea.",
                }
            )
    return hints


def probe_one(
    endpoint: Dict[str, Any],
    *,
    timeout_sec: float,
    max_response_bytes: int,
) -> Dict[str, Any]:
    """Run a single request; endpoint must be normalized (method, url, params, headers, body)."""
    method = str(endpoint.get("method") or "GET").upper()
    url = str(endpoint["url"])
    params = endpoint.get("params") or {}
    headers = dict(endpoint.get("headers") or {})
    body = endpoint.get("body")

    result: Dict[str, Any] = {
        "request": {
            "method": method,
            "url": url,
            "params": params,
            "headers": headers,
            "body": body,
        },
        "status_code": None,
        "elapsed_ms": None,
        "error": None,
        "response_headers": {},
        "body_preview": "",
        "body_truncated": False,
        "validations": [],
        "hints": [],
    }

    json_body = None
    data = None
    if body is not None and method in ("POST", "PUT", "PATCH"):
        if isinstance(body, (dict, list)):
            json_body = body
            headers.setdefault("Content-Type", "application/json")
        else:
            data = body

    t0 = time.perf_counter()
    try:
        resp = requests.request(
            method,
            url,
            params=params or None,
            headers=headers or None,
            json=json_body,
            data=data,
            timeout=timeout_sec,
            allow_redirects=True,
            stream=True,
        )
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        result["elapsed_ms"] = elapsed_ms
        result["status_code"] = resp.status_code
        rh = {k: v for k, v in resp.headers.items()}
        result["response_headers"] = rh

        chunks: List[bytes] = []
        total = 0
        for chunk in resp.iter_content(chunk_size=65536):
            if not chunk:
                continue
            total += len(chunk)
            if total <= max_response_bytes:
                chunks.append(chunk)
            else:
                result["body_truncated"] = True
                break
        raw = b"".join(chunks)
        try:
            text = raw.decode(resp.encoding or "utf-8", errors="replace")
        except Exception:
            text = raw.decode("utf-8", errors="replace")
        preview_cap = min(8000, max_response_bytes)
        if len(text) > preview_cap:
            result["body_preview"] = _truncate(text, preview_cap)
            result["body_truncated"] = True
        else:
            result["body_preview"] = text

        vals: List[Dict[str, Any]] = []
        sc = resp.status_code
        if 200 <= sc < 300:
            vals.append({"name": "status", "ok": True, "detail": f"{sc} (2xx)"})
        elif 300 <= sc < 400:
            vals.append({"name": "status", "ok": True, "detail": f"{sc} (redirect)"})
        else:
            vals.append({"name": "status", "ok": False, "detail": str(sc)})

        ctype = (rh.get("Content-Type") or "").lower()
        if "json" in ctype and result["body_preview"]:
            try:
                json_lib.loads(result["body_preview"])
                vals.append({"name": "json_body", "ok": True, "detail": "JSON válido"})
            except json_lib.JSONDecodeError as e:
                vals.append({"name": "json_body", "ok": False, "detail": str(e)[:120]})
        result["validations"] = vals
        result["hints"] = _light_vuln_hints(sc, result["body_preview"], rh)

    except requests.exceptions.Timeout:
        result["error"] = f"Timeout tras {timeout_sec}s"
        result["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)[:500]
        result["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 2)

    return result


def run_probes(
    endpoints: List[Dict[str, Any]],
    *,
    timeout_sec: float = 15.0,
    max_response_bytes: int = 500_000,
    indices: Optional[List[int]] = None,
) -> List[Dict[str, Any]]:
    """Run probes for all or selected indices; each item includes index + endpoint + result."""
    to_run = list(range(len(endpoints))) if indices is None else [i for i in indices if 0 <= i < len(endpoints)]
    out: List[Dict[str, Any]] = []
    for i in to_run:
        out.append(
            {
                "index": i,
                "endpoint": endpoints[i],
                "result": probe_one(
                    endpoints[i],
                    timeout_sec=timeout_sec,
                    max_response_bytes=max_response_bytes,
                ),
            }
        )
    return out


__all__ = ["probe_one", "run_probes"]
