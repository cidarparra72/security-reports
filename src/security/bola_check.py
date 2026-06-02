#!/usr/bin/env python3
"""
BOLA (Broken Object Level Authorization) automático.
Requiere 2 tokens: token_a (recurso propio) y token_b (otro usuario).
Para cada endpoint, intenta acceder al recurso de User A con las credenciales de User B.
Si el servidor devuelve 2xx → BOLA confirmado.
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from .api_scanner import Vulnerability
from .http_probe_budget import HttpRequestBudget

_USER_AGENT = "APISecurityScanner/1.0"
_TIMEOUT = 8.0


def _v(severity: str, title: str, description: str, snippet: str, recommendation: str, cwe: str) -> Vulnerability:
    return Vulnerability(
        severity=severity, category="Authorization",
        title=title, description=description,
        file="<dynamic:bola>", line=0,
        code_snippet=snippet, recommendation=recommendation,
        cwe_id=cwe, cvss={"CRITICAL": 9.0, "HIGH": 8.0, "MEDIUM": 6.0, "LOW": 3.0}.get(severity, 6.0),
        confidence="high",
    )


def _request(
    method: str,
    url: str,
    headers: dict,
    budget: Optional[HttpRequestBudget] = None,
) -> Optional[int]:
    if budget is not None and not budget.allow(url):
        return None
    h = {"User-Agent": _USER_AGENT, **headers}
    try:
        req = urllib.request.Request(url, headers=h, method=method.upper())
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=_TIMEOUT, context=ctx) as resp:
            code = int(resp.getcode())
            if budget is not None:
                budget.record(url)
            return code
    except urllib.error.HTTPError as e:
        if budget is not None:
            budget.record(url)
        return int(e.code)
    except (urllib.error.URLError, OSError):
        return None


def _bearer(token: str) -> dict:
    t = (token or "").strip()
    if not t:
        return {}
    return {"Authorization": f"Bearer {t}" if not t.lower().startswith("bearer ") else t}


def check_bola(
    endpoint_url: str,
    token_a: str,
    token_b: str,
    method: str = "GET",
    http_budget: Optional[HttpRequestBudget] = None,
) -> List[Vulnerability]:
    """
    Access endpoint_url as User A first (must be 2xx), then as User B.
    If User B also gets 2xx → BOLA/IDOR confirmed.
    """
    findings = []
    headers_a = _bearer(token_a)
    headers_b = _bearer(token_b)

    if not headers_a or not headers_b:
        return findings

    code_a = _request(method, endpoint_url, headers_a, budget=http_budget)
    if code_a is None or not (200 <= code_a < 300):
        return findings  # Resource not accessible by owner, skip

    code_b = _request(method, endpoint_url, headers_b, budget=http_budget)
    if code_b is not None and 200 <= code_b < 300:
        findings.append(_v(
            "CRITICAL",
            f"BOLA/IDOR confirmado: {method} {endpoint_url}",
            f"User B accedió al recurso de User A. "
            f"User A status={code_a}, User B status={code_b}.",
            f"{method} {endpoint_url}\n  User A → {code_a}\n  User B → {code_b}",
            "Implementa validación de propiedad server-side en cada acceso a objeto. "
            "Verifica que el ID del recurso pertenece al usuario autenticado antes de responder.",
            "CWE-639",
        ))
    return findings


def run_bola_checks(
    endpoints: List[Dict[str, Any]],
    token_a: str,
    token_b: str,
    http_budget: Optional[HttpRequestBudget] = None,
) -> List[Vulnerability]:
    """Run BOLA checks on a list of endpoint dicts from infer_api_endpoints."""
    if not token_a or not token_b:
        return []

    findings: List[Vulnerability] = []
    seen_urls: set[str] = set()

    for ep in endpoints or []:
        if not isinstance(ep, dict):
            continue
        url = str(ep.get("url", "")).strip()
        method = str(ep.get("method", "GET")).upper()
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)

        # Only test GET and non-destructive methods
        if method in ("DELETE", "OPTIONS", "HEAD", "TRACE"):
            continue

        ep_findings = check_bola(url, token_a, token_b, method, http_budget=http_budget)
        findings.extend(ep_findings)

    return findings
