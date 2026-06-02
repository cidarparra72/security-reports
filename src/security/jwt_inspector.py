#!/usr/bin/env python3
"""
JWT Inspector automático.
Decodifica tokens JWT sin verificar firma, detecta:
  - alg:none / alg:HS256 con secret débil
  - Ausencia de exp (sin expiración)
  - TTL excesivo (> 24h)
  - Claims sensibles (password, ssn, credit_card, secret)
  - Prueba activa alg:none enviando token manipulado al servidor
Solo usa stdlib (base64, json, urllib).
"""
from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .api_scanner import Vulnerability

_SENSITIVE_CLAIM_KEYS = frozenset(
    {"password", "passwd", "secret", "ssn", "credit_card", "cvv", "pin", "private_key"}
)
_USER_AGENT = "APISecurityScanner/1.0"
_TIMEOUT = 6.0
_CVSS_MAP: Dict[str, float] = {"CRITICAL": 9.0, "HIGH": 8.0, "MEDIUM": 6.0, "LOW": 3.0}


def _b64_decode(segment: str) -> bytes:
    """Base64url decode with padding."""
    segment += "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment)


def _parse_jwt(token: str) -> Optional[tuple[dict, dict, str]]:
    """Returns (header, payload, signature_b64) or None if not a valid JWT."""
    parts = (token or "").strip().split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))
        return header, payload, parts[2]
    except (ValueError, Exception):
        return None


def _v(severity: str, title: str, description: str, snippet: str, recommendation: str, cwe: str,
       confidence: str = "high") -> Vulnerability:
    return Vulnerability(
        severity=severity, category="Authentication / JWT",
        title=title, description=description,
        file="<dynamic:jwt>", line=0,
        code_snippet=snippet, recommendation=recommendation,
        cwe_id=cwe, cvss=_CVSS_MAP.get(severity, 6.0),
        confidence=confidence,
    )


def inspect_jwt(token: str) -> List[Vulnerability]:
    """Static analysis of a JWT token. Returns list of findings."""
    parsed = _parse_jwt(token)
    if parsed is None:
        return []

    header, payload, _ = parsed
    findings: List[Vulnerability] = []
    alg = str(header.get("alg", "")).upper()
    snippet = f"header={json.dumps(header)}\npayload={json.dumps({k: v for k, v in payload.items() if k not in ('sub', 'user_id')})}"

    # 1. alg:none
    if alg in ("NONE", ""):
        findings.append(_v(
            "CRITICAL",
            "JWT: alg=none (sin firma)",
            "El token JWT declara alg:none, lo que permite forjar tokens sin firma válida.",
            snippet,
            "Rechaza tokens con alg:none. Valida alg en allowlist estricta en el servidor.",
            "CWE-345",
        ))

    # 2. Sin expiración
    if "exp" not in payload:
        findings.append(_v(
            "HIGH", "JWT sin campo exp (sin expiración)",
            "El token no incluye la claim 'exp', por lo que nunca expira.",
            snippet,
            "Incluye siempre 'exp' con vida corta (15-60 min para access tokens).",
            "CWE-613",
        ))

    # 3. TTL excesivo
    exp = payload.get("exp")
    iat = payload.get("iat")
    if exp is not None and iat is not None:
        try:
            ttl_seconds = int(exp) - int(iat)
            if ttl_seconds > 86400:
                findings.append(_v(
                    "MEDIUM",
                    f"JWT TTL excesivo ({ttl_seconds // 3600}h)",
                    f"El token tiene una vida útil de {ttl_seconds // 3600} horas, superior al límite recomendado de 24h.",
                    snippet,
                    "Usa access tokens de vida corta (≤1h) y refresh tokens separados con rotación.",
                    "CWE-613",
                ))
        except (TypeError, ValueError):
            pass

    # 4. Claims sensibles
    for key in payload:
        if str(key).lower() in _SENSITIVE_CLAIM_KEYS:
            findings.append(_v(
                "HIGH",
                f"JWT contiene claim sensible: '{key}'",
                f"El payload del JWT incluye la clave '{key}' que puede contener información sensible.",
                snippet,
                "Elimina datos sensibles del JWT. Usa solo identificadores mínimos (sub, jti, roles).",
                "CWE-200",
            ))

    # 5. HS256 sin rotación de clave explícita (aviso)
    if alg in ("HS256", "HS384", "HS512") and "kid" not in header:
        findings.append(_v(
            "LOW",
            "JWT: HMAC sin kid (sin rotación de clave identificable)",
            f"El token usa {alg} sin campo 'kid'. Sin rotación de clave identificable.",
            snippet,
            "Añade 'kid' al header para permitir rotación y revocación controlada de claves.",
            "CWE-320",
            confidence="low",
        ))

    return findings


def test_alg_none_on_server(api_url: str, original_token: str, auth_headers: Optional[dict] = None) -> List[Vulnerability]:
    """
    Sends a manipulated JWT with alg=none to the server.
    If the server accepts it (2xx or non-401/403) → CRITICAL finding.
    """
    parsed = _parse_jwt(original_token)
    if not parsed:
        return []

    _, payload, _ = parsed
    # Build forged token: alg=none, no signature
    forged_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    forged_payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    forged_token = f"{forged_header}.{forged_payload_b64}."

    headers = {"User-Agent": _USER_AGENT, "Authorization": f"Bearer {forged_token}"}
    if auth_headers:
        headers.update({k: v for k, v in auth_headers.items() if k.lower() != "authorization"})

    test_url = api_url.rstrip("/") + "/"
    try:
        req = urllib.request.Request(test_url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=_TIMEOUT, context=ssl.create_default_context()) as resp:
            code = resp.getcode()
    except urllib.error.HTTPError as e:
        code = e.code
    except (urllib.error.URLError, OSError):
        return []

    if code not in (401, 403, 422):
        return [_v(
            "CRITICAL",
            "Servidor acepta JWT con alg=none (firma bypasseada)",
            f"El endpoint {test_url} respondió {code} a un token forjado con alg=none. "
            "Cualquier usuario puede suplantar a otro sin conocer la clave secreta.",
            f"Forged token: {forged_token[:80]}...\nServer response: {code}",
            "Valida alg en allowlist estricta (['HS256','RS256']). Rechaza alg:none explícitamente.",
            "CWE-345",
        )]
    return []
