#!/usr/bin/env python3
"""
Informe por endpoint: sonda HTTP, asociación de hallazgos y metadatos de análisis.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .dynamic_checks import _http_get, _http_request
from .http_probe_budget import HttpRequestBudget
from .infer_api_url import _SKIP_INFER_FILE_NAMES_LOWER

_DYNAMIC_VULN_FILES = frozenset(
    {
        "<dynamic:api>",
        "<dynamic:advanced>",
        "<dynamic:bola>",
        "<dynamic:jwt>",
    }
)


def _norm(s: str) -> str:
    return str(s or "").strip().lower()


def _norm_url(url: str) -> str:
    return _norm(url).rstrip("/")


def _endpoint_key_from_detail(detail: dict) -> str:
    method = str(detail.get("method") or "GET").upper()
    url = str(detail.get("url") or "").strip()
    return f"{method} {url}".strip()


def probe_endpoint_url(
    url: str,
    budget: Optional[HttpRequestBudget] = None,
) -> Dict[str, Any]:
    """GET + OPTIONS rápidos para demostrar que el endpoint fue analizado."""
    u = (url or "").strip()
    if not u.startswith(("http://", "https://")):
        return {
            "analyzed": False,
            "probe_status": "sin_url",
            "message": "URL no absoluta; no se pudo sondar.",
            "get_status": None,
            "options_status": None,
        }
    if budget is not None and not budget.allow(u):
        return {
            "analyzed": True,
            "probe_status": "budget_exhausted",
            "message": "Presupuesto HTTP agotado para esta URL (sube el tope o usa 0 = sin límite).",
            "get_status": None,
            "options_status": None,
        }
    code_get, h_get = _http_get(u, budget=budget)
    if h_get.get("_budget_exhausted"):
        return {
            "analyzed": True,
            "probe_status": "budget_exhausted",
            "message": "Presupuesto HTTP agotado durante GET.",
            "get_status": None,
            "options_status": None,
        }
    code_opt, h_opt = _http_request("OPTIONS", u, budget=budget)
    allow = str(h_opt.get("Allow") or h_opt.get("allow") or "").strip()
    parts: List[str] = []
    if code_get is not None:
        parts.append(f"GET → {code_get}")
    else:
        parts.append("GET → sin respuesta")
    if code_opt is not None:
        parts.append(f"OPTIONS → {code_opt}")
        if allow:
            parts.append(f"Allow: {allow[:80]}")
    elif h_opt.get("_budget_exhausted"):
        parts.append("OPTIONS → omitido (presupuesto)")
    else:
        parts.append("OPTIONS → sin respuesta")
    return {
        "analyzed": True,
        "probe_status": "ok" if code_get is not None else "unreachable",
        "message": "; ".join(parts),
        "get_status": code_get,
        "options_status": code_opt,
        "allow": allow or None,
    }


def _finding_matches_endpoint(
    v: Dict[str, Any],
    *,
    path_norm: str,
    url_norm: str,
    api_url_norm: str,
    endpoint_source_files: set[str],
) -> bool:
    endpoint_field = _norm_url(str(v.get("endpoint") or ""))
    snippet = _norm(v.get("code_snippet"))
    desc = _norm(v.get("description"))
    blob = f"{snippet} {desc} {endpoint_field}"
    vuln_file = _norm(v.get("file")).replace("\\", "/")

    if url_norm and (endpoint_field == url_norm or url_norm in blob):
        return True
    if path_norm and len(path_norm) > 1 and (endpoint_field == path_norm or path_norm in blob):
        return True
    vuln_base = (vuln_file.split("/")[-1] if vuln_file else "").lower()
    if (
        vuln_base not in _SKIP_INFER_FILE_NAMES_LOWER
        and endpoint_source_files
        and vuln_file in endpoint_source_files
    ):
        return True
    if vuln_file in _DYNAMIC_VULN_FILES or vuln_file.startswith("<dynamic:"):
        if not api_url_norm:
            return True
        if api_url_norm in blob or api_url_norm in _norm_url(snippet):
            return True
        if url_norm.startswith(api_url_norm + "/") or url_norm == api_url_norm:
            return True
        try:
            if urlparse(url_norm).netloc and urlparse(api_url_norm).netloc:
                if urlparse(url_norm).netloc == urlparse(api_url_norm).netloc:
                    return True
        except ValueError:
            pass
    if vuln_file == "<external:tool>":
        return False
    return False


def build_endpoint_report(
    api_url: str,
    selected_endpoints: list[str],
    endpoint_details: list[dict],
    vulnerabilities: list[dict],
    http_budget: Optional[HttpRequestBudget] = None,
) -> list[dict]:
    details_by_key = {
        _endpoint_key_from_detail(e): e for e in endpoint_details if isinstance(e, dict)
    }
    ordered_keys = selected_endpoints or list(details_by_key.keys())
    api_url_norm = _norm_url(api_url)
    report: list[dict] = []

    for key in ordered_keys:
        detail = details_by_key.get(key, {})
        method = str(detail.get("method") or key.split(" ", 1)[0] or "GET").upper()
        url = str(detail.get("url") or (key.split(" ", 1)[1] if " " in key else key)).strip()
        path = str(detail.get("path") or url).strip()
        endpoint_source_files = {
            _norm(x.get("file")).replace("\\", "/")
            for x in (detail.get("files") or [])
            if isinstance(x, dict) and x.get("file")
        }
        path_norm = _norm(path)
        if path_norm and not path_norm.startswith("/"):
            path_norm = "/" + path_norm
        path_norm = path_norm.rstrip("/") or path_norm
        url_norm = _norm_url(url)

        probe = probe_endpoint_url(url, budget=http_budget)
        endpoint_findings: list[dict] = []
        seen_finding_keys: set[str] = set()

        for v in vulnerabilities:
            if not isinstance(v, dict):
                continue
            if not _finding_matches_endpoint(
                v,
                path_norm=path_norm,
                url_norm=url_norm,
                api_url_norm=api_url_norm,
                endpoint_source_files=endpoint_source_files,
            ):
                continue
            fk = (
                f"{v.get('title')}|{v.get('file')}|{v.get('line')}|"
                f"{str(v.get('code_snippet', ''))[:120]}"
            )
            if fk in seen_finding_keys:
                continue
            seen_finding_keys.add(fk)
            endpoint_findings.append(v)

        report.append(
            {
                "method": method,
                "path": path,
                "url": url,
                "api_url": api_url,
                "source": detail.get("source", ""),
                "files": detail.get("files", []),
                "findings": endpoint_findings,
                "finding_count": len(endpoint_findings),
                "probe": probe,
                "analysis_status": "completed" if probe.get("analyzed") else "pending",
            }
        )
    return report
