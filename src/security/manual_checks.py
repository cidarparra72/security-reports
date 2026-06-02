#!/usr/bin/env python3
"""
Manual-assisted checks for ethical hacking retest.
Produces structured findings that can be merged with scanner output.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, List

from .api_scanner import Vulnerability

_SEVERITY_CVSS = {
    "CRITICAL": 9.0,
    "HIGH": 8.0,
    "MEDIUM": 6.0,
    "LOW": 3.0,
}

_CHECK_TEMPLATES: Dict[str, Dict[str, str]] = {
    "bola": {
        "title": "Broken Object Level Authorization (BOLA) by Role",
        "category": "Authorization",
        "cwe": "CWE-285",
        "recommendation": "Validate role/object ownership server-side for every object access/update.",
    },
    "idor": {
        "title": "Insecure Direct Object Reference (IDOR)",
        "category": "Authorization",
        "cwe": "CWE-639",
        "recommendation": "Validate ownership and authorization on every resource access server-side.",
    },
    "enumeration": {
        "title": "User Enumeration",
        "category": "Authentication",
        "cwe": "CWE-203",
        "recommendation": "Return uniform responses and add anti-automation controls for identity checks.",
    },
    "rate_limit": {
        "title": "Rate Limiting / Abuse of Functionality",
        "category": "Business Logic",
        "cwe": "CWE-799",
        "recommendation": "Implement per-user/IP rate-limits, throttling, and temporary lockouts.",
    },
    "jwt": {
        "title": "Sensitive Information in JWT",
        "category": "Session Management",
        "cwe": "CWE-1270",
        "recommendation": "Keep JWT claims minimal, avoid PII, validate claims strictly, and rotate keys.",
    },
    "cors": {
        "title": "CORS Policy Misconfiguration",
        "category": "Configuration",
        "cwe": "CWE-942",
        "recommendation": "Allow only explicit trusted origins, avoid wildcard with sensitive APIs.",
    },
    "jwt_ttl": {
        "title": "JWT Claims / TTL Weakness",
        "category": "Session Management",
        "cwe": "CWE-613",
        "recommendation": "Use short-lived access tokens and strict validation for exp/iat/nbf/aud/iss/jti.",
    },
}


def manual_checklist_templates() -> Dict[str, Any]:
    return {
        "checks": [
            {
                "id": cid,
                "title": tpl["title"],
                "category": tpl["category"],
                "cwe_id": tpl["cwe"],
                "required_fields": [
                    "status",
                    "endpoint",
                    "impact",
                    "cvss_vector",
                    "poc",
                    "severity",
                ],
            }
            for cid, tpl in _CHECK_TEMPLATES.items()
        ]
    }


def parse_manual_findings(entries: List[Dict[str, Any]]) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    for item in entries or []:
        check_id = str(item.get("check_id", "")).strip().lower()
        tpl = _CHECK_TEMPLATES.get(check_id)
        if not tpl:
            continue
        severity = str(item.get("severity", "MEDIUM")).upper().strip()
        if severity not in _SEVERITY_CVSS:
            severity = "MEDIUM"
        endpoint = str(item.get("endpoint", "")).strip()
        impact = str(item.get("impact", "")).strip()
        cvss_vector = str(item.get("cvss_vector", "")).strip()
        poc = str(item.get("poc", "")).strip()
        status = str(item.get("status", "Persistente")).strip() or "Persistente"

        description_parts = []
        if impact:
            description_parts.append(f"Impacto: {impact}")
        if cvss_vector:
            description_parts.append(f"Vector CVSS: {cvss_vector}")
        if status:
            description_parts.append(f"Estado retest: {status}")
        description = " | ".join(description_parts) or tpl["title"]

        findings.append(
            Vulnerability(
                severity=severity,
                category=f"Manual ({tpl['category']})",
                title=tpl["title"],
                description=description,
                file="<manual-check>",
                line=0,
                code_snippet=poc or endpoint,
                recommendation=str(item.get("recommendation") or tpl["recommendation"]),
                cwe_id=str(item.get("cwe_id") or tpl["cwe"]),
                cvss=_SEVERITY_CVSS[severity],
                confidence="high",
            )
        )
    return findings


def summarize_manual_findings(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for item in entries or []:
        out.append(
            {
                "check_id": item.get("check_id"),
                "status": item.get("status", "Persistente"),
                "endpoint": item.get("endpoint", ""),
                "impact": item.get("impact", ""),
                "cvss_vector": item.get("cvss_vector", ""),
                "poc": item.get("poc", ""),
                "severity": item.get("severity", "MEDIUM"),
                "references": item.get("references", []),
            }
        )
    return out

