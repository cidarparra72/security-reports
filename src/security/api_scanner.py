#!/usr/bin/env python3
"""
Escáner estático de patrones inseguros en código (mini programs / APIs) y
pruebas dinámicas básicas HTTP/TLS cuando hay URL base.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from .infer_api_url import (
    _SKIP_DIRS,
    _SKIP_INFER_FILE_NAMES_LOWER,
    infer_primary_api_url,
)
from .scan_scope import extensions_for_languages, is_finding_suppressed, load_suppressions


@dataclass
class Vulnerability:
    severity: str
    category: str
    title: str
    description: str
    file: str
    line: int
    code_snippet: str
    recommendation: str
    cwe_id: str
    cvss: float
    confidence: str
    false_positive_note: str = ""
    pattern_id: str = field(default="", repr=False)


@dataclass(frozen=True)
class _PatternRule:
    pattern_id: str
    title: str
    category: str
    severity: str
    confidence: str
    cwe_id: str
    recommendation: str
    regex: re.Pattern[str]
    false_positive_note: str = ""


def _build_rules() -> List[_PatternRule]:
    return [
        _PatternRule(
            pattern_id="INSECURE_HTTP",
            title="Insecure HTTP Endpoint",
            category="Transport Security",
            severity="MEDIUM",
            confidence="high",
            cwe_id="CWE-319",
            recommendation="Usa https:// para APIs en producción y fuerza redirección HTTP→HTTPS.",
            regex=re.compile(
                r"http://(?!localhost\b|127\.0\.0\.1\b)([^\s\"'`\)>\]]+)",
                re.IGNORECASE,
            ),
        ),
        _PatternRule(
            pattern_id="HARDCODED_SECRET",
            title="Hardcoded API Secret",
            category="Sensitive Data",
            severity="CRITICAL",
            confidence="high",
            cwe_id="CWE-798",
            recommendation="Externaliza secretos (vault, variables de entorno, secret manager).",
            regex=re.compile(
                r'(?:"(?:api_secret|api_key)"\s*:\s*"([^"]{6,})"|(?:\bAPI_KEY\b|\bapi_key\b|apiSecret)\s*=\s*["\']([^"\']{6,})["\'])',
                re.IGNORECASE,
            ),
        ),
        _PatternRule(
            pattern_id="HARDCODED_CREDENTIALS",
            title="Hardcoded Credentials",
            category="Sensitive Data",
            severity="CRITICAL",
            confidence="high",
            cwe_id="CWE-798",
            recommendation="No almacenes contraseñas en código; usa gestores de secretos.",
            regex=re.compile(
                r'(?:"password"\s*:\s*"([^"]+)"|["\']([^"\']{1,48}):([^"\']{3,})@[^"\']+["\'])',
                re.IGNORECASE,
            ),
        ),
        _PatternRule(
            pattern_id="DEBUG_MODE",
            title="Debug Mode Enabled",
            category="Configuration",
            severity="MEDIUM",
            confidence="high",
            cwe_id="CWE-489",
            recommendation="Desactiva modo debug en builds de producción.",
            regex=re.compile(r"\bdebug\s*:\s*true\b", re.IGNORECASE),
        ),
        _PatternRule(
            pattern_id="SENSITIVE_DATA_LOGGING",
            title="Sensitive Data in Logs",
            category="Sensitive Data",
            severity="MEDIUM",
            confidence="high",
            cwe_id="CWE-532",
            recommendation="No registres contraseñas ni tokens; usa enmascaramiento o niveles de log seguros.",
            regex=re.compile(
                r"console\.(log|debug|info)\s*\([^)]*(password|token|secret)[^)]*\)",
                re.IGNORECASE,
            ),
        ),
        _PatternRule(
            pattern_id="SQL_STRING_CONCAT",
            title="SQL Built via String Concatenation",
            category="Injection",
            severity="HIGH",
            confidence="high",
            cwe_id="CWE-89",
            recommendation="Usa consultas parametrizadas o ORM; evita concatenar SQL con entrada.",
            regex=re.compile(r"SELECT[\w\W]*?\+\s*\w+", re.IGNORECASE),
        ),
        _PatternRule(
            pattern_id="XSS_INNER_OUTER_HTML",
            title="Potential XSS via innerHTML / outerHTML",
            category="Injection",
            severity="HIGH",
            confidence="high",
            cwe_id="CWE-79",
            recommendation="Evita innerHTML con datos no confiables; usa textContent o sanitización.",
            regex=re.compile(
                r"\.(innerHTML|outerHTML)\s*=\s*[^;\n]+", re.IGNORECASE
            ),
        ),
        _PatternRule(
            pattern_id="SQL_INJECTION",
            title="Potential SQL Injection (string building)",
            category="Injection",
            severity="HIGH",
            confidence="medium",
            cwe_id="CWE-89",
            recommendation="Parametriza consultas y valida entrada.",
            regex=re.compile(
                r"(SELECT|INSERT|UPDATE|DELETE)\s+[^;\"']+\+.*['\"%]", re.IGNORECASE
            ),
        ),
        _PatternRule(
            pattern_id="INSECURE_CLIENT_STORAGE",
            title="Potentially Insecure Client-Side Storage",
            category="Data Storage",
            severity="HIGH",
            confidence="low",
            cwe_id="CWE-922",
            recommendation="No guardes tokens ni secretos en localStorage/sessionStorage.",
            regex=re.compile(
                r"localStorage\.setItem\s*\(|sessionStorage\.setItem\s*\(", re.IGNORECASE
            ),
            false_positive_note=(
                "Revisar manualmente: localStorage es inseguro para secretos, "
                "pero puede ser aceptable para preferencias no sensibles."
            ),
        ),
        _PatternRule(
            pattern_id="HARDCODED_API_KEY_MARKERS",
            title="Hardcoded API Key Material",
            category="Sensitive Data",
            severity="CRITICAL",
            confidence="medium",
            cwe_id="CWE-798",
            recommendation="Elimina claves reales del repositorio y rota credenciales expuestas.",
            regex=re.compile(
                r"\b(sk_live_|sk_test_|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,})\b"
            ),
        ),
        _PatternRule(
            pattern_id="MISSING_AUTH",
            title="Client Request Without Obvious Auth Context",
            category="Authentication",
            severity="LOW",
            confidence="low",
            cwe_id="CWE-306",
            recommendation="Verifica que cada llamada a API incluya autenticación adecuada.",
            regex=re.compile(
                r"my\.request\s*\(\s*\{\s*url\s*:", re.IGNORECASE
            ),
            false_positive_note=(
                "Heurística débil: my.request puede incluir auth en otras propiedades no visibles en la línea."
            ),
        ),
    ]


_RULES: List[_PatternRule] = _build_rules()
_RULE_BY_ID: Dict[str, _PatternRule] = {r.pattern_id: r for r in _RULES}


class APISecurityScanner:
    """Escaneo de directorio de proyecto: patrones + (opcional) checks HTTP/TLS."""

    CVSS_BY_SEVERITY: Dict[str, float] = {
        "CRITICAL": 9.0,
        "HIGH": 8.0,
        "MEDIUM": 6.0,
        "LOW": 3.0,
    }

    def __init__(
        self,
        project_path: str,
        target_api_url: Optional[str] = None,
        enabled_pattern_ids: Optional[Set[str]] = None,
        languages: Optional[List[str]] = None,
    ) -> None:
        self.project_path = str(Path(project_path).expanduser())
        self.target_api_url = (target_api_url or "").strip() or None
        self.enabled_pattern_ids: Optional[Set[str]] = enabled_pattern_ids
        self.languages = languages

    def scan(self) -> Dict[str, Any]:
        root = Path(self.project_path).expanduser().resolve()
        vulns: List[Vulnerability] = []
        files_scanned = 0
        ext_used: Set[str] = set()

        suppress = load_suppressions(root) if root.is_dir() else []

        enabled = self.enabled_pattern_ids
        if enabled is not None and len(enabled) == 0:
            rules: Iterable[_PatternRule] = []
        elif enabled is None:
            rules = _RULES
        else:
            rules = [_RULE_BY_ID[i] for i in sorted(enabled) if i in _RULE_BY_ID]

        if root.is_dir():
            for fp in _iter_scan_files(root, self.languages):
                files_scanned += 1
                ext_used.add(fp.suffix.lower() or "(no ext)")
                rel = str(fp.relative_to(root)).replace("\\", "/")
                try:
                    text = fp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for line_no, line in enumerate(text.splitlines(), 1):
                    for rule in rules:
                        for m in rule.regex.finditer(line):
                            snippet = (m.group(0) or "")[:400]
                            if rule.pattern_id == "INSECURE_HTTP":
                                from .vuln_filters import is_lan_insecure_http_finding

                                if is_lan_insecure_http_finding(
                                    {
                                        "pattern_id": "INSECURE_HTTP",
                                        "title": rule.title,
                                        "code_snippet": snippet,
                                        "file": rel,
                                    }
                                ):
                                    continue
                            desc = f"Coincidencia de patrón {rule.pattern_id} en {rel}:{line_no}."
                            v = Vulnerability(
                                severity=rule.severity,
                                category=rule.category,
                                title=rule.title,
                                description=desc,
                                file=rel,
                                line=line_no,
                                code_snippet=snippet,
                                recommendation=rule.recommendation,
                                cwe_id=rule.cwe_id,
                                cvss=float(self.CVSS_BY_SEVERITY.get(rule.severity, 6.0)),
                                confidence=rule.confidence,
                                false_positive_note=rule.false_positive_note,
                                pattern_id=rule.pattern_id,
                            )
                            if is_finding_suppressed(rule.pattern_id, rel, suppress):
                                continue
                            if any(
                                str(x.file) == rel
                                and int(x.line) == line_no
                                and x.title == rule.title
                                for x in vulns
                            ):
                                continue
                            vulns.append(v)

        dynamic_url = self.target_api_url
        inferred = False
        if not dynamic_url and root.is_dir():
            dynamic_url = infer_primary_api_url(root)
            inferred = bool(dynamic_url)

        if dynamic_url:
            from .dynamic_checks import run_dynamic_api_checks

            try:
                dyn = run_dynamic_api_checks(dynamic_url, self.CVSS_BY_SEVERITY)
                vulns.extend(dyn)
            except Exception as exc:  # noqa: BLE001
                vulns.append(
                    Vulnerability(
                        severity="LOW",
                        category="Dynamic",
                        title="Dynamic checks error",
                        description=f"Fallo al ejecutar pruebas dinámicas: {exc}",
                        file="<dynamic:api>",
                        line=0,
                        code_snippet=dynamic_url,
                        recommendation="Revisa conectividad, TLS y URL base.",
                        cwe_id="CWE-754",
                        cvss=3.0,
                        confidence="low",
                        false_positive_note="",
                        pattern_id="",
                    )
                )

        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in vulns:
            s = str(v.severity).upper()
            if s in summary:
                summary[s] += 1

        scan_date = datetime.now(timezone.utc).isoformat()

        vuln_dicts: List[Dict[str, Any]] = []
        for v in vulns:
            d = asdict(v)
            d.pop("pattern_id", None)
            vuln_dicts.append(d)

        return {
            "project_path": str(root),
            "scan_date": scan_date,
            "vulnerabilities": vuln_dicts,
            "summary": summary,
            "total_vulnerabilities": len(vulns),
            "dynamic_api_url": dynamic_url,
            "dynamic_api_inferred": inferred,
            "openapi_specs": [],
            "scan_scope": {
                "files_scanned": files_scanned,
                "extensions": sorted(ext_used),
            },
        }


def _iter_scan_files(project_path: Path, languages: Optional[List[str]]) -> List[Path]:
    exts = extensions_for_languages(languages)
    skip = set(_SKIP_DIRS)
    out: List[Path] = []
    for p in project_path.rglob("*"):
        if not p.is_file():
            continue
        if any(part in skip for part in p.parts):
            continue
        if p.name.lower() in _SKIP_INFER_FILE_NAMES_LOWER:
            continue
        suf = p.suffix.lower()
        if suf not in exts and not p.name.endswith((".axml", ".acss")):
            continue
        try:
            if p.stat().st_size > 2_000_000:
                continue
        except OSError:
            continue
        out.append(p)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="API / mini-program static pattern scanner")
    parser.add_argument("--path", default=".", help="Project directory")
    parser.add_argument("--output", "-o", default="", help="Write JSON results to this path")
    parser.add_argument("--url", default="", help="Optional API base URL for dynamic checks")
    args = parser.parse_args()

    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        print(f"ERROR: not a directory: {root}", file=sys.stderr)
        return 2

    scanner = APISecurityScanner(str(root), target_api_url=args.url or None)
    result = scanner.scan()
    if args.output:
        outp = Path(args.output)
        outp.parent.mkdir(parents=True, exist_ok=True)
        outp.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Wrote {outp}")
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
