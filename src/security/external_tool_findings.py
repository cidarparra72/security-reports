#!/usr/bin/env python3
"""
Parse Semgrep / Trivy / Grype / Nuclei report files produced by external_checks.py
and merge them into the main scan result (same shape as ZAP/Burp via merge_external_findings).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .api_scanner import Vulnerability
from .external_import import merge_external_findings


def _map_severity(raw: str, default: str = "MEDIUM") -> str:
    s = (raw or "").strip().upper()
    m = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "UNKNOWN": "MEDIUM",
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
    }
    return m.get(s, default)


def _cvss_for(sev: str) -> float:
    return {
        "CRITICAL": 9.0,
        "HIGH": 8.0,
        "MEDIUM": 6.0,
        "LOW": 3.0,
    }.get(sev, 6.0)


def _rel_path(project: Path, abs_or_rel: str) -> str:
    p = (abs_or_rel or "").strip()
    if not p:
        return ""
    try:
        path = Path(p)
        if path.is_absolute():
            return str(path.resolve().relative_to(project.resolve()))
    except ValueError:
        pass
    return p.replace("\\", "/")


def _normalize_cwe(raw: Any) -> str:
    if raw is None:
        return "CWE-0"
    if isinstance(raw, list) and raw:
        raw = raw[0]
    s = str(raw).strip()
    if not s:
        return "CWE-0"
    if s.upper().startswith("CWE-"):
        return s.upper()
    if s.isdigit():
        return f"CWE-{s}"
    return "CWE-0"


def _v(
    *,
    title: str,
    description: str,
    file: str,
    line: int,
    snippet: str,
    recommendation: str,
    severity: str,
    category: str,
    cwe_id: str = "CWE-0",
    confidence: str = "medium",
) -> Vulnerability:
    sev = _map_severity(severity)
    cwe_norm = _normalize_cwe(cwe_id)
    return Vulnerability(
        severity=sev,
        category=category,
        title=title[:500] or "External finding",
        description=(description or title)[:8000],
        file=file or "<external:tool>",
        line=int(line) if line else 0,
        code_snippet=(snippet or "")[:4000],
        recommendation=(recommendation or "")[:4000],
        cwe_id=cwe_norm,
        cvss=_cvss_for(sev),
        confidence=confidence,
    )


def parse_semgrep_json(data: Any, project: Path) -> List[Vulnerability]:
    if not isinstance(data, dict):
        return []
    results = data.get("results")
    if not isinstance(results, list):
        return []
    out: List[Vulnerability] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        check_id = str(r.get("check_id", "semgrep")).strip()
        raw_path = str(r.get("path", ""))
        rel = _rel_path(project, raw_path) or raw_path
        line = 0
        try:
            line = int((r.get("start") or {}).get("line", 0))
        except (TypeError, ValueError):
            line = 0
        extra = r.get("extra") or {}
        msg = str(extra.get("message") or check_id)
        sev_raw = str(extra.get("severity", "WARNING"))
        sev = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(sev_raw.upper(), "MEDIUM")
        meta = extra.get("metadata") or {}
        cwe_s = _normalize_cwe(meta.get("cwe") or meta.get("cwe2021"))
        lines = str(extra.get("lines", "") or "")[:2000]
        short_name = check_id.split(".")[-1] if "." in check_id else check_id
        out.append(
            _v(
                title=f"[Semgrep] {short_name or check_id}",
                description=msg,
                file=rel,
                line=line,
                snippet=lines or msg[:500],
                recommendation="Corregir según la regla Semgrep indicada; revisar documentación del lenguaje y OWASP.",
                severity=sev,
                category="SAST (Semgrep)",
                cwe_id=cwe_s,
                confidence="medium",
            )
        )
    return out


def parse_trivy_fs_json(data: Any, project: Path) -> List[Vulnerability]:
    if not isinstance(data, dict):
        return []
    out: List[Vulnerability] = []
    for res in data.get("Results") or []:
        if not isinstance(res, dict):
            continue
        target = str(res.get("Target", ""))
        rel_target = _rel_path(project, target) or target
        for vuln in res.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            vid = str(vuln.get("VulnerabilityID", "CVE"))
            pkg = str(vuln.get("PkgName", ""))
            ver = str(vuln.get("InstalledVersion", ""))
            fixed = str(vuln.get("FixedVersion", ""))
            sev = str(vuln.get("Severity", "MEDIUM"))
            title = str(vuln.get("Title", vid))
            desc = str(vuln.get("Description", ""))[:4000]
            primary = str(vuln.get("PrimaryURL", ""))
            out.append(
                _v(
                    title=f"[Trivy] {vid} — {pkg}",
                    description=f"{title}\n\n{desc}".strip(),
                    file=rel_target,
                    line=0,
                    snippet=primary or f"{pkg}@{ver}",
                    recommendation=f"Actualizar dependencia. Versión corregida sugerida: {fixed or 'consultar advisory'}.".strip(),
                    severity=sev,
                    category="SCA (Trivy)",
                cwe_id="0",
                confidence="high",
                )
            )
        for mc in res.get("Misconfigurations") or []:
            if not isinstance(mc, dict):
                continue
            title = str(mc.get("Title", "Misconfiguration"))
            sev = str(mc.get("Severity", "MEDIUM"))
            msg = str(mc.get("Message", mc.get("Description", "")))[:4000]
            cause = mc.get("CauseMetadata") or {}
            try:
                ln = int(cause.get("StartLine") or cause.get("Line") or 0)
            except (TypeError, ValueError):
                ln = 0
            out.append(
                _v(
                    title=f"[Trivy] {title}",
                    description=msg,
                    file=rel_target,
                    line=ln,
                    snippet=str(cause.get("Resource", ""))[:2000],
                    recommendation=str(mc.get("Resolution", "Aplicar hardening según documentación del recurso.")),
                    severity=sev,
                    category="IaC / Config (Trivy)",
                    cwe_id="0",
                    confidence="medium",
                )
            )
    return out


def parse_grype_json(data: Any, project: Path) -> List[Vulnerability]:
    if not isinstance(data, dict):
        return []
    out: List[Vulnerability] = []
    for m in data.get("matches") or []:
        if not isinstance(m, dict):
            continue
        vobj = m.get("vulnerability") or {}
        vid = str(vobj.get("id", "CVE"))
        sev = str(vobj.get("severity", "MEDIUM"))
        desc = str(vobj.get("description", ""))[:4000]
        art = m.get("artifact") or {}
        pkg = str(art.get("name", ""))
        ver = str(art.get("version", ""))
        locs = art.get("locations") or []
        path = ""
        if isinstance(locs, list) and locs and isinstance(locs[0], dict):
            path = str(locs[0].get("path", ""))
        rel = _rel_path(project, path) or path or "<grype>"
        out.append(
            _v(
                title=f"[Grype] {vid} — {pkg}",
                description=desc or f"Vulnerabilidad en {pkg} {ver}".strip(),
                file=rel,
                line=0,
                snippet=f"{pkg}@{ver}",
                recommendation="Actualizar paquete o imagen base según el advisory del CVE.",
                severity=sev,
                category="SCA (Grype)",
                cwe_id="0",
                confidence="high",
            )
        )
    return out


def _nuclei_row_to_vuln(row: dict) -> Optional[Vulnerability]:
    if not isinstance(row, dict):
        return None
    info = row.get("info") or {}
    name = str(info.get("name", row.get("template-id", "Nuclei")))
    sev = str(info.get("severity", "medium"))
    matched = str(row.get("matched-at", row.get("host", "")))
    desc = str(info.get("description", name))[:4000]
    tid = str(row.get("template-id", ""))
    return _v(
        title=f"[Nuclei] {name}",
        description=desc,
        file="<dynamic:api>",
        line=0,
        snippet=matched[:2000],
        recommendation=f"Validar hallazgo DAST (plantilla {tid}). Corregir configuración o superficie expuesta.",
        severity=sev,
        category="DAST (Nuclei)",
        cwe_id="0",
        confidence="medium",
    )


def parse_nuclei_ndjson(text: str) -> List[Vulnerability]:
    text = (text or "").strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            arr = json.loads(text)
            if isinstance(arr, list):
                out: List[Vulnerability] = []
                for row in arr:
                    if isinstance(row, dict):
                        v = _nuclei_row_to_vuln(row)
                        if v:
                            out.append(v)
                return out
        except json.JSONDecodeError:
            pass
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        v = _nuclei_row_to_vuln(row) if isinstance(row, dict) else None
        if v:
            out.append(v)
    return out


def _load_json_file(path: Path) -> Optional[Any]:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return None


def merge_external_scan_tool_reports(
    result: Dict[str, Any],
    project_path: str,
    external_runs: Optional[Dict[str, Any]],
) -> Dict[str, int]:
    """
    Lee JSON generados por run_selected_external_checks y los fusiona en result['vulnerabilities'].
    Devuelve conteos por herramienta (hallazgos añadidos).
    """
    counts: Dict[str, int] = {}
    if not external_runs or not isinstance(external_runs, dict):
        return counts
    project = Path(project_path).resolve()
    batch: List[Vulnerability] = []

    def _add(tool: str, vulns: List[Vulnerability]) -> None:
        if vulns:
            counts[tool] = len(vulns)
            batch.extend(vulns)

    # --- Semgrep ---
    sg = external_runs.get("semgrep")
    if isinstance(sg, dict) and sg.get("status") == "completed" and sg.get("report_file"):
        data = _load_json_file(project / str(sg["report_file"]))
        if data is not None:
            _add("semgrep", parse_semgrep_json(data, project))

    # --- Trivy ---
    tv = external_runs.get("trivy")
    if isinstance(tv, dict) and tv.get("status") == "completed" and tv.get("report_file"):
        data = _load_json_file(project / str(tv["report_file"]))
        if data is not None:
            _add("trivy", parse_trivy_fs_json(data, project))

    # --- Grype ---
    gr = external_runs.get("grype")
    if isinstance(gr, dict) and gr.get("status") == "completed" and gr.get("report_file"):
        data = _load_json_file(project / str(gr["report_file"]))
        if data is not None:
            _add("grype", parse_grype_json(data, project))

    # --- Nuclei (archivo NDJSON línea a línea) ---
    nu = external_runs.get("nuclei")
    if isinstance(nu, dict) and nu.get("status") == "completed" and nu.get("report_file"):
        p = project / str(nu["report_file"])
        if p.is_file():
            try:
                raw = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                raw = ""
            nv = parse_nuclei_ndjson(raw)
            _add("nuclei", nv)

    if batch:
        merge_external_findings(result, batch)
    return counts
