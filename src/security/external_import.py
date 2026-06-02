#!/usr/bin/env python3
"""
Importa hallazgos de OWASP ZAP (JSON) y Burp (JSON) y los unifica al mismo formato
que el escáner interno, para un informe tipo retest (estático + dinámico + DAST).
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, List, Optional

from .api_scanner import Vulnerability

_SEV_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFORMATIONAL": "LOW",
    "INFO": "LOW",
    "INFORMATION": "LOW",
    # burp
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    # zap display
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "Informational": "LOW",
}


def _map_sev(level: str) -> str:
    s = (level or "").strip()
    return _SEV_MAP.get(s) or _SEV_MAP.get(s.title()) or "MEDIUM"


def _cvss_for_severity(sev: str) -> float:
    return {
        "CRITICAL": 9.0,
        "HIGH": 8.0,
        "MEDIUM": 6.0,
        "LOW": 3.0,
    }.get(sev, 6.0)


def _vuln_from_external(
    title: str,
    description: str,
    ref_url: str,
    solution: str,
    severity: str,
    cwe: str,
    source: str,
) -> Vulnerability:
    sev = _map_sev(severity)
    return Vulnerability(
        severity=sev,
        category=f"External ({source})",
        title=title[:500] or f"Finding ({source})",
        description=description[:8000] or title,
        file=f"<external:{source}>",
        line=0,
        code_snippet=ref_url[:2000] if ref_url else "",
        recommendation=(solution or "")[:4000] or "Revisa en la guía de la herramienta o en OWASP.",
        cwe_id=cwe,
        cvss=_cvss_for_sev(sev),
        confidence="high",
    )


# --- ZAP: JSON (API / reporte) — recorre "alerts" anidadas (formato reporte / API)
def _extract_zap_alerts(data: Any) -> List[dict]:
    out: List[dict] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, list):
            for it in obj:
                walk(it)
        elif isinstance(obj, dict):
            al = obj.get("alerts")
            if isinstance(al, list):
                for a in al:
                    if isinstance(a, dict) and a.get("risk") and (
                        a.get("name") or a.get("alert")
                    ):
                        out.append(a)
            for k, v in obj.items():
                if k == "alerts":
                    continue
                walk(v)

    walk(data)
    if not out and isinstance(data, list) and data and isinstance(data[0], dict):
        if data[0].get("risk") and (data[0].get("name") or data[0].get("alert")):
            return [x for x in data if isinstance(x, dict) and x.get("risk")]
    seen = set()
    uniq: List[dict] = []
    for a in out:
        key = (a.get("name"), a.get("url") or a.get("uri"), a.get("risk"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(a)
    return uniq


def parse_zap_report(data: Any) -> List[Vulnerability]:
    if not data:
        return []
    alerts = _extract_zap_alerts(data)
    r: List[Vulnerability] = []
    for a in alerts:
        name = str(a.get("name") or a.get("alert") or "ZAP finding")
        desc = str(a.get("description") or a.get("desc", ""))
        url = str(a.get("url") or a.get("uri", ""))
        sol = str(a.get("solution") or "")
        risk = str(a.get("risk", "medium"))
        cweid = a.get("cweid")
        cwe = f"CWE-{cweid}" if cweid and str(cweid).isdigit() else "CWE-0"
        r.append(
            _vuln_from_external(
                f"[ZAP] {name}",
                desc,
                url,
                sol,
                risk,
                cwe,
                "ZAP",
            )
        )
    return r


# --- Burp: JSON (exportación) — { "issues": [...] } o lista
def _extract_burp_issues(data: Any) -> List[dict]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        if "issues" in data and isinstance(data["issues"], list):
            return [x for x in data["issues"] if isinstance(x, dict)]
    return []


def parse_burp_report(data: Any) -> List[Vulnerability]:
    if not data:
        return []
    items = _extract_burp_issues(data)
    r: List[Vulnerability] = []
    for a in items:
        name = str(a.get("name", a.get("type", "Burp finding")))
        sev = str(
            a.get("severity", a.get("level", a.get("confidence", "medium")))
        )
        path = a.get("path", "")
        base = a.get("host", "") or ""
        if isinstance(path, str) and base and not str(path).startswith("http"):
            ref = f"https://{base}{path}"
        else:
            ref = str(path or a.get("url", ""))
        background = str(
            a.get("issueBackground", a.get("background", a.get("description", "")))
        )[:4000]
        rem = str(a.get("remediationBackground", a.get("remediation", "")))[:4000]
        cwe = a.get("cwe")
        cwe_s = f"CWE-{cwe}" if cwe and str(cwe).isdigit() else ("CWE-0")
        r.append(
            _vuln_from_external(
                f"[Burp] {name}",
                background or name,
                ref,
                rem,
                sev,
                cwe_s,
                "Burp",
            )
        )
    return r


def merge_external_findings(
    report: Dict[str, Any], extras: List[Vulnerability]
) -> None:
    """Añade hallazgos externos al dict del informe y recalcula resumen y totales."""
    if not extras:
        return
    for v in extras:
        report["vulnerabilities"].append(asdict(v))
    summ = report.setdefault("summary", {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})
    for v in extras:
        if v.severity in summ:
            summ[v.severity] = summ.get(v.severity, 0) + 1
    report["total_vulnerabilities"] = len(report["vulnerabilities"])
    # reordenar por gravedad
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    report["vulnerabilities"].sort(
        key=lambda x: order.get((x or {}).get("severity", "MEDIUM"), 99)
    )
