#!/usr/bin/env python3
"""
Auditor de colección Postman (estático + live + PDF).
Portado desde scanApi (Streamlit) para security-reports.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

import requests

try:
    from fpdf import FPDF
except ImportError:  # pragma: no cover
    FPDF = None  # type: ignore

REMEDIATION_DB: Dict[str, Dict[str, str]] = {
    "BOLA": {
        "title": "Broken Object Level Authorization (BOLA)",
        "sol": "Implementar UUIDs y validar propiedad del recurso en backend.",
        "cwe": "CWE-285",
    },
    "INSECURE_HTTP": {
        "title": "Protocolo Inseguro (HTTP)",
        "sol": "Forzar HTTPS y configurar HSTS.",
        "cwe": "CWE-295",
    },
    "UNPROTECTED_METHOD": {
        "title": "Metodo Critico sin Autorizacion",
        "sol": "Aplicar middleware de Auth a POST, PUT y DELETE.",
        "cwe": "CWE-306",
    },
    "HSTS": {
        "title": "Falta de HSTS",
        "sol": "Agregar header: Strict-Transport-Security: max-age=31536000.",
        "cwe": "CWE-523",
    },
    "COOKIE_INSECURE": {
        "title": "Cookies de Sesion Inseguras",
        "sol": "Configurar flags 'Secure' y 'HttpOnly' en el servidor.",
        "cwe": "CWE-1004",
    },
    "FINGERPRINTING": {
        "title": "Revelacion de Tecnologias (Fingerprinting)",
        "sol": "Ocultar headers 'Server' y 'X-Powered-By'.",
        "cwe": "CWE-200",
    },
    "CORS_WILDCARD": {
        "title": "Politica de CORS Permisiva (*)",
        "sol": "Reemplazar '*' por dominios especificos autorizados.",
        "cwe": "CWE-942",
    },
    "REFERRER": {
        "title": "Falta de Referrer-Policy",
        "sol": "Implementar header: Referrer-Policy: strict-origin-when-cross-origin",
        "cwe": "CWE-116",
    },
    "X_CONTENT_TYPE": {
        "title": "Falta de X-Content-Type-Options",
        "sol": "Implementar header: X-Content-Type-Options: nosniff",
        "cwe": "CWE-693",
    },
    "NO_VERSIONING": {
        "title": "Falta de Versionamiento",
        "sol": "Incluir version en la ruta (ej. /v1/).",
        "cwe": "CWE-114",
    },
    "INFO_LEAK_QUERY": {
        "title": "Parametros de Control Expuestos",
        "sol": "Validar parametros de ordenamiento y limite en backend.",
        "cwe": "CWE-209",
    },
}

FindingRow = Dict[str, str]


def clean_url(raw_url: str, base_url_input: str) -> str:
    raw_url = str(raw_url).strip()
    base_url_input = base_url_input.strip().rstrip("/")
    match = re.match(r"^(\{\{.*?\}\})", raw_url)
    if match:
        return raw_url.replace(match.group(1), base_url_input, 1)
    if raw_url.startswith("/"):
        return base_url_input + raw_url
    return raw_url


def _row(severity: str, endpoint: str, finding: str, solution: str) -> FindingRow:
    return {
        "severity": severity,
        "endpoint": endpoint,
        "finding": finding,
        "solution": solution,
    }


def collect_postman_raw_urls(collection: Dict[str, Any]) -> List[str]:
    urls: List[str] = []

    def walk(items: Any) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            nested = item.get("item")
            if nested is not None:
                walk(nested)
            req = item.get("request")
            if not isinstance(req, dict):
                continue
            u_data = req.get("url", "")
            raw = (
                u_data.get("raw", "")
                if isinstance(u_data, dict)
                else str(u_data)
            )
            if raw:
                urls.append(str(raw))

    walk(collection.get("item"))
    return list(dict.fromkeys(urls))


def analyze_static(collection: Dict[str, Any], base_url_input: str) -> List[FindingRow]:
    findings: List[FindingRow] = []

    def walk(items: Any) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            nested = item.get("item")
            if nested is not None:
                walk(nested)
            req = item.get("request")
            if not isinstance(req, dict):
                continue
            name = item.get("name", "Endpoint")
            method = str(req.get("method", "GET")).upper()
            u_data = req.get("url", "")
            raw_url = (
                u_data.get("raw", "")
                if isinstance(u_data, dict)
                else str(u_data)
            )
            url = clean_url(raw_url, base_url_input)
            headers = req.get("header", [])
            label = f"{method}-{name}"

            if re.search(r"/\d+(?=/|$)", url):
                findings.append(
                    _row(
                        "CRITICAL",
                        label,
                        REMEDIATION_DB["BOLA"]["title"],
                        REMEDIATION_DB["BOLA"]["sol"],
                    )
                )
            if url.startswith("http://"):
                findings.append(
                    _row(
                        "HIGH",
                        label,
                        REMEDIATION_DB["INSECURE_HTTP"]["title"],
                        REMEDIATION_DB["INSECURE_HTTP"]["sol"],
                    )
                )
            if method in ("POST", "PUT", "DELETE") and not any(
                str(h.get("key", "")).lower() == "authorization"
                for h in headers
                if isinstance(h, dict)
            ):
                findings.append(
                    _row(
                        "HIGH",
                        label,
                        REMEDIATION_DB["UNPROTECTED_METHOD"]["title"],
                        REMEDIATION_DB["UNPROTECTED_METHOD"]["sol"],
                    )
                )
            if not re.search(r"/v\d+/", url.lower()):
                findings.append(
                    _row(
                        "LOW",
                        label,
                        REMEDIATION_DB["NO_VERSIONING"]["title"],
                        REMEDIATION_DB["NO_VERSIONING"]["sol"],
                    )
                )
            if re.search(r"(limit|offset|sort)=", url, re.IGNORECASE):
                findings.append(
                    _row(
                        "MEDIUM",
                        label,
                        REMEDIATION_DB["INFO_LEAK_QUERY"]["title"],
                        REMEDIATION_DB["INFO_LEAK_QUERY"]["sol"],
                    )
                )

    walk(collection.get("item"))
    return findings


def analyze_dynamic_live(
    endpoints_urls: List[str],
    base_url_input: str,
    *,
    timeout_sec: float = 7.0,
) -> List[FindingRow]:
    live_findings: List[FindingRow] = []
    seen: set[str] = set()
    for raw_url in endpoints_urls:
        url = clean_url(raw_url, base_url_input)
        if url in seen:
            continue
        seen.add(url)
        if not url.startswith("http"):
            continue
        try:
            resp = requests.get(
                url,
                timeout=timeout_sec,
                verify=False,
                headers={"User-Agent": "SecurityReports-Auditor/1.2"},
            )
            h = resp.headers
            if "Strict-Transport-Security" not in h:
                live_findings.append(
                    _row(
                        "MEDIUM",
                        url,
                        REMEDIATION_DB["HSTS"]["title"],
                        REMEDIATION_DB["HSTS"]["sol"],
                    )
                )
            if h.get("Access-Control-Allow-Origin") == "*":
                live_findings.append(
                    _row(
                        "HIGH",
                        url,
                        REMEDIATION_DB["CORS_WILDCARD"]["title"],
                        REMEDIATION_DB["CORS_WILDCARD"]["sol"],
                    )
                )
            if "Referrer-Policy" not in h:
                live_findings.append(
                    _row(
                        "MEDIUM",
                        url,
                        REMEDIATION_DB["REFERRER"]["title"],
                        REMEDIATION_DB["REFERRER"]["sol"],
                    )
                )
            if "X-Content-Type-Options" not in h:
                live_findings.append(
                    _row(
                        "MEDIUM",
                        url,
                        REMEDIATION_DB["X_CONTENT_TYPE"]["title"],
                        REMEDIATION_DB["X_CONTENT_TYPE"]["sol"],
                    )
                )
            if "Server" in h or "X-Powered-By" in h:
                tech = h.get("Server", "") or h.get("X-Powered-By", "")
                live_findings.append(
                    _row(
                        "LOW",
                        url,
                        f"Fingerprinting ({tech})",
                        REMEDIATION_DB["FINGERPRINTING"]["sol"],
                    )
                )
            for cookie in resp.cookies:
                is_h = cookie.has_nonstandard_attr("HttpOnly") or getattr(
                    cookie, "httponly", False
                )
                if not cookie.secure or not is_h:
                    live_findings.append(
                        _row(
                            "HIGH",
                            url,
                            f"Cookie Insegura ({cookie.name})",
                            REMEDIATION_DB["COOKIE_INSECURE"]["sol"],
                        )
                    )
        except requests.RequestException:
            pass
    return live_findings


def count_by_severity(rows: List[FindingRow]) -> Dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in rows:
        sev = str(r.get("severity", "")).upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def _rows_to_tuples(rows: List[FindingRow]) -> List[Tuple[str, str, str, str]]:
    return [
        (
            r.get("severity", ""),
            r.get("endpoint", ""),
            r.get("finding", ""),
            r.get("solution", ""),
        )
        for r in rows
    ]


def build_pdf_bytes(
    static_rows: List[FindingRow],
    live_rows: Optional[List[FindingRow]] = None,
) -> bytes:
    if FPDF is None:
        raise RuntimeError(
            "fpdf2 no instalado. Ejecuta: pip install fpdf2"
        )

    class PDFReport(FPDF):
        def header(self) -> None:
            self.set_font("Arial", "B", 14)
            self.set_text_color(26, 35, 126)
            self.cell(0, 10, "Reporte de Auditoria de Seguridad API 360", 0, 1, "C")
            self.ln(5)

        def chapter_title(self, label: str) -> None:
            self.set_font("Arial", "B", 11)
            self.set_fill_color(230, 230, 230)
            self.cell(0, 8, label, 0, 1, "L", True)
            self.ln(3)

        def draw_table(self, header: List[str], data: List[Tuple[str, str, str, str]]) -> None:
            w_sev, w_end, w_hal, w_sol = 20, 50, 50, 70
            self.set_font("Arial", "B", 8)
            self.set_fill_color(26, 35, 126)
            self.set_text_color(255, 255, 255)
            self.cell(w_sev, 8, header[0], 1, 0, "C", True)
            self.cell(w_end, 8, header[1], 1, 0, "C", True)
            self.cell(w_hal, 8, header[2], 1, 0, "C", True)
            self.cell(w_sol, 8, header[3], 1, 0, "C", True)
            self.ln()
            self.set_font("Arial", "", 7)
            self.set_text_color(0, 0, 0)
            for row in data:
                c0 = str(row[0]).encode("latin-1", "ignore").decode("latin-1")
                c1 = str(row[1]).encode("latin-1", "ignore").decode("latin-1")
                c2 = str(row[2]).encode("latin-1", "ignore").decode("latin-1")
                c3 = str(row[3]).encode("latin-1", "ignore").decode("latin-1")
                lines_c1 = len(self.multi_cell(w_end, 5, c1, split_only=True))
                lines_c2 = len(self.multi_cell(w_hal, 5, c2, split_only=True))
                lines_c3 = len(self.multi_cell(w_sol, 5, c3, split_only=True))
                max_lines = max(1, lines_c1, lines_c2, lines_c3)
                row_height = max_lines * 5
                if self.get_y() + row_height > 260:
                    self.add_page()
                x = self.get_x()
                y = self.get_y()
                if row[0] == "CRITICAL":
                    self.set_fill_color(255, 200, 200)
                elif row[0] == "HIGH":
                    self.set_fill_color(255, 230, 180)
                elif row[0] == "MEDIUM":
                    self.set_fill_color(255, 250, 200)
                else:
                    self.set_fill_color(255, 255, 255)
                self.cell(w_sev, row_height, c0, 1, 0, "C", True)
                self.set_fill_color(255, 255, 255)
                self.multi_cell(w_end, 5, c1, 1, "L")
                self.set_xy(x + w_sev + w_end, y)
                self.multi_cell(w_hal, 5, c2, 1, "L")
                self.set_xy(x + w_sev + w_end + w_hal, y)
                self.multi_cell(w_sol, 5, c3, 1, "L")
                self.set_xy(x, y + row_height)

    pdf = PDFReport()
    pdf.add_page()
    pdf.chapter_title("1. Hallazgos Estaticos")
    if static_rows:
        pdf.draw_table(
            ["Sev", "Endpoint", "Vulnerabilidad", "Solucion"],
            _rows_to_tuples(static_rows),
        )
    pdf.ln(10)
    pdf.chapter_title("2. Hallazgos Dinamicos")
    live = live_rows or []
    if live:
        pdf.draw_table(
            ["Sev", "Endpoint", "Vulnerabilidad", "Solucion"],
            _rows_to_tuples(live),
        )
    raw = pdf.output(dest="S")
    if isinstance(raw, bytearray):
        return bytes(raw)
    if isinstance(raw, str):
        return raw.encode("latin-1")
    return bytes(raw)
