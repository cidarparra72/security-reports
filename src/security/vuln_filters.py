#!/usr/bin/env python3
"""Filtros compartidos para hallazgos en informe y asociación por endpoint."""

from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from .infer_api_url import _infer_candidate_url_is_non_public

_URL_IN_TEXT_RE = re.compile(r"https?://[^\s\"'`<\])]+", re.IGNORECASE)


def first_http_url_in_text(text: str) -> str:
    for m in _URL_IN_TEXT_RE.finditer(str(text or "")):
        u = m.group(0).rstrip(".,);'\"")
        if u:
            return u
    return ""


def url_is_non_public(url: str) -> bool:
    return _infer_candidate_url_is_non_public(url)


_EXAMPLE_EMAIL_RE = re.compile(
    r"@(?:ejemplo|example|test|sample|localhost)\b|correo@ejemplo|user@example|foo@bar|@ejemplo\.com",
    re.IGNORECASE,
)
_SCAN_ARTIFACT_FILE_RE = re.compile(
    r"(?:^|/)scan-\d+-(?:trivy|grype|semgrep|nuclei)",
    re.IGNORECASE,
)


def is_false_positive_credential_finding(v: Dict[str, Any]) -> bool:
    """Emails de ejemplo en UI, refs pkg: de Trivy, JSON de artefactos del escáner."""
    pid = str(v.get("pattern_id") or "").upper()
    title = str(v.get("title") or "").lower()
    if pid not in ("HARDCODED_CREDENTIALS", "HARDCODED_SECRET", "HARDCODED_API_KEY_MARKERS"):
        if "credential" not in title and "hardcoded" not in title:
            return False
    snippet = str(v.get("code_snippet") or "")
    blob = f"{snippet} {v.get('description', '')}"
    if _EXAMPLE_EMAIL_RE.search(blob):
        return True
    if "pkg:npm/" in snippet or "pkg:pypi/" in snippet or snippet.strip().startswith('"pkg:'):
        return True
    vuln_file = str(v.get("file") or "").replace("\\", "/")
    if _SCAN_ARTIFACT_FILE_RE.search(vuln_file):
        return True
    if vuln_file.lower().endswith(("-trivy.json", "-grype.json", "-semgrep.json")):
        return True
    return False


def is_lan_insecure_http_finding(v: Dict[str, Any]) -> bool:
    """HTTP en IP privada/LAN o WSDL de mock en tests — no reportar."""
    pid = str(v.get("pattern_id") or "").upper()
    title = str(v.get("title") or "").lower()
    if pid != "INSECURE_HTTP" and "insecure http" not in title:
        return False
    blob = f"{v.get('code_snippet', '')} {v.get('description', '')}"
    u = first_http_url_in_text(blob)
    if u and url_is_non_public(u):
        return True
    vuln_file = str(v.get("file") or "").replace("\\", "/").lower()
    snippet_l = str(v.get("code_snippet") or "").lower()
    if "?wsdl" in snippet_l and (
        "/test/" in vuln_file or vuln_file.startswith("test/")
    ):
        return True
    return False


def _dedupe_key(v: Dict[str, Any]) -> str:
    return "|".join(
        [
            str(v.get("title") or ""),
            str(v.get("file") or ""),
            str(v.get("line") or ""),
            str(v.get("code_snippet") or "")[:200],
            str(v.get("pattern_id") or ""),
        ]
    )


def filter_vulnerabilities_for_report(vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for v in vulns or []:
        if not isinstance(v, dict):
            continue
        if is_lan_insecure_http_finding(v):
            continue
        if is_false_positive_credential_finding(v):
            continue
        key = _dedupe_key(v)
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out


def recalculate_summary(vulns: List[Dict[str, Any]]) -> tuple[Dict[str, int], int]:
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulns:
        s = str(v.get("severity", "")).upper()
        if s in summary:
            summary[s] += 1
    return summary, len(vulns)
