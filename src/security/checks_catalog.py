#!/usr/bin/env python3
"""
Catalog of available API security checks and language applicability.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set


PATTERN_CHECKS = [
    "INSECURE_HTTP",
    "HARDCODED_SECRET",
    "HARDCODED_CREDENTIALS",
    "MISSING_AUTH",
    "SQL_INJECTION",
    "XSS_VULNERABILITY",
    "MISSING_INPUT_VALIDATION",
    "WEAK_CRYPTO",
    "DEBUG_MODE",
    "SENSITIVE_DATA_LOGGING",
    "HARDCODED_API_KEY_MARKERS",
    "SQL_STRING_CONCAT",
    "XSS_INNER_OUTER_HTML",
    "INSECURE_CLIENT_STORAGE",
]

CHECKS: List[Dict[str, Any]] = [
    {
        "id": "static_patterns",
        "name": "Static Pattern Checks",
        "type": "internal",
        "supports_languages": ["javascript", "typescript", "json", "python"],
        "pattern_ids": PATTERN_CHECKS,
    },
    {
        "id": "dynamic_http_tls",
        "name": "Dynamic HTTP/TLS/CORS Checks",
        "type": "internal",
        "supports_languages": ["any"],
    },
    {
        "id": "api_runtime_core",
        "name": "API Runtime Core Checks (Auth/Error/Methods)",
        "type": "internal",
        "supports_languages": ["any"],
    },
    {
        "id": "docs_exposure_probe",
        "name": "API Docs Exposure Probe",
        "type": "internal",
        "supports_languages": ["any"],
    },
    {
        "id": "zap_baseline",
        "name": "OWASP ZAP Baseline (Docker)",
        "type": "external",
        "supports_languages": ["any"],
    },
    {
        "id": "schemathesis",
        "name": "Schemathesis (OpenAPI Fuzzing)",
        "type": "external",
        "supports_languages": ["any"],
    },
    {
        "id": "nuclei",
        "name": "Nuclei API Templates",
        "type": "external",
        "supports_languages": ["any"],
    },
    {
        "id": "semgrep",
        "name": "Semgrep (SAST Security Rules)",
        "type": "external",
        "supports_languages": ["javascript", "typescript", "python", "java", "go", "php"],
    },
    {
        "id": "trivy",
        "name": "Trivy (Dependencies / Image / IaC)",
        "type": "external",
        "supports_languages": ["any"],
    },
    {
        "id": "grype",
        "name": "Grype (Dependency Vulnerability Scan)",
        "type": "external",
        "supports_languages": ["any"],
    },
    {
        "id": "jwt_toolkit",
        "name": "JWT Toolkit / jose utils (manual-assisted)",
        "type": "manual-assisted",
        "supports_languages": ["any"],
    },
    {
        "id": "burp_manual",
        "name": "Burp Suite Manual Testing",
        "type": "manual-assisted",
        "supports_languages": ["any"],
    },
    {
        "id": "manual_bola",
        "name": "Manual Assisted - BOLA by Role",
        "type": "manual-assisted",
        "supports_languages": ["any"],
    },
    {
        "id": "manual_cors",
        "name": "Manual Assisted - Strict CORS",
        "type": "manual-assisted",
        "supports_languages": ["any"],
    },
    {
        "id": "manual_jwt_ttl",
        "name": "Manual Assisted - JWT Claims / TTL",
        "type": "manual-assisted",
        "supports_languages": ["any"],
    },
    {
        "id": "manual_idor",
        "name": "Manual Assisted - IDOR",
        "type": "manual-assisted",
        "supports_languages": ["any"],
    },
    {
        "id": "manual_enumeration",
        "name": "Manual Assisted - Enumeration",
        "type": "manual-assisted",
        "supports_languages": ["any"],
    },
    {
        "id": "manual_rate_limit",
        "name": "Manual Assisted - Rate Limit",
        "type": "manual-assisted",
        "supports_languages": ["any"],
    },
    {
        "id": "manual_jwt",
        "name": "Manual Assisted - JWT",
        "type": "manual-assisted",
        "supports_languages": ["any"],
    },
]


def checks_catalog() -> Dict[str, Any]:
    return {"checks": CHECKS}


def normalize_selected_checks(selected: List[str] | None) -> Set[str]:
    ids = {str(x).strip() for x in (selected or []) if str(x).strip()}
    if not ids:
        return {
            "static_patterns",
            "dynamic_http_tls",
            "api_runtime_core",
            "docs_exposure_probe",
        }
    known = {c["id"] for c in CHECKS}
    return {x for x in ids if x in known}

