#!/usr/bin/env python3
"""
Security Report Generator - Ethical Hacking Report Format (v3)
Uses Jinja2 templates for HTML generation.
Includes audit-style fields, manual-assisted findings, retest diff and technical annexes.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .infer_api_url import _infer_noise_netloc, _url_is_infer_noise
from .vuln_filters import filter_vulnerabilities_for_report, is_lan_insecure_http_finding, url_is_non_public

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# Resolve templates directory relative to this file
_TEMPLATES_DIR = Path(__file__).parent / "templates"


@dataclass
class VulnerabilityReport:
    id: str
    title: str
    severity: str
    cvss: float
    status: str
    category: str
    description: str
    recommendation: str
    endpoint: str = ""
    impact: str = ""
    cvss_vector: str = ""
    poc: str = ""
    steps_to_reproduce: List[str] = field(default_factory=list)
    evidence: str = ""
    cwe_id: str = ""
    references: List[str] = field(default_factory=list)
    exploit_text: str = ""
    false_positive_note: str = ""


class EthicalHackingReportGenerator:
    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    def __init__(self, project_name: str, target_url: str = ""):
        self.project_name = project_name
        self.target_url = target_url
        self.vulnerabilities: List[VulnerabilityReport] = []
        self.scan_date = datetime.now()
        self.version = "3.1"
        self.retest_diff: Dict[str, Any] = {}
        self.manual_assisted: List[Dict[str, Any]] = []
        self.technical_annex: Dict[str, Any] = {}
        self.api_endpoint_report: List[Dict[str, Any]] = []
        self.executive_summary: Dict[str, Any] = {}
        self.external_checks_summary: List[Dict[str, Any]] = []
        self.scan_scope: Dict[str, Any] = {}
        self.endpoint_report_meta: Dict[str, Any] = {}

    def add_vulnerability(self, vuln: VulnerabilityReport):
        self.vulnerabilities.append(vuln)

    @staticmethod
    def _severity_to_cvss(severity: str) -> float:
        return {"CRITICAL": 9.0, "HIGH": 8.0, "MEDIUM": 6.0, "LOW": 3.0}.get(
            (severity or "").upper(), 5.0
        )

    @staticmethod
    def _default_references(cwe_id: str) -> List[str]:
        refs = ["https://owasp.org/API-Security/"]
        if cwe_id and cwe_id.startswith("CWE-"):
            refs.append(f"https://cwe.mitre.org/data/definitions/{cwe_id[4:]}.html")
        return refs

    @staticmethod
    def _endpoint_from_vuln(v: Dict[str, Any], target_url: str) -> str:
        """URL de contexto para PDF/tabla; ignora mirrors npm/CDN en snippets."""
        ep_field = str(v.get("endpoint") or "").strip()
        if ep_field and not _url_is_infer_noise(ep_field):
            return ep_field
        blob = f"{v.get('code_snippet', '')} {v.get('description', '')} {v.get('recommendation', '')}"
        for m in re.finditer(r"https?://[^\s\"'`<\])]+", str(blob), re.I):
            u = m.group(0).rstrip(".,);'\"")
            try:
                p = urlparse(u)
            except ValueError:
                continue
            if (
                p.scheme in ("http", "https")
                and p.netloc
                and not _infer_noise_netloc(p.netloc)
                and not url_is_non_public(u)
            ):
                return u
        file_p = str(v.get("file") or "").strip()
        line = v.get("line")
        if file_p and file_p not in ("N/A", "<dynamic:api>", "<dynamic:advanced>", "<dynamic:bola>"):
            loc = f"{file_p}" + (f":{line}" if line not in (None, "", "N/A", 0) else "")
            return loc
        if v.get("file") == "<dynamic:api>":
            return (target_url or "").strip()
        return (target_url or "").strip()

    @staticmethod
    def _impact_text(title: str, category: str, impact_default: str) -> str:
        t = (title or "").lower()
        if "token" in t or "jwt" in t:
            return (
                "La exposicion de tokens o claims sensibles puede habilitar suplantacion, "
                "acceso no autorizado y abuso de sesion."
            )
        if "authentication" in t or "idor" in t or "authorization" in t:
            return (
                "Una validacion deficiente de autenticacion/autorizacion puede permitir acceso "
                "a recursos de terceros o ejecucion de acciones no autorizadas."
            )
        if "storage" in t:
            return (
                "El almacenamiento inseguro en cliente puede exponer datos sensibles ante "
                "compromiso del dispositivo o extraccion local."
            )
        if "transport" in (category or "").lower() or "tls" in t:
            return (
                "Configuraciones debiles de transporte pueden facilitar interceptacion de datos "
                "y degradacion de seguridad de canal."
            )
        return impact_default or "El hallazgo puede afectar confidencialidad, integridad o disponibilidad."

    @staticmethod
    def _exploit_text(poc: str, evidence: str) -> str:
        snippet = (poc or evidence or "").strip()
        if snippet:
            return (
                "Durante el retest se identifico evidencia tecnica del comportamiento vulnerable. "
                "La siguiente PoC resume el patron observado en la aplicacion/backend."
            )
        return (
            "Se observo un comportamiento potencialmente explotable en pruebas de retest. "
            "Se recomienda validacion manual complementaria para confirmar explotabilidad."
        )

    @classmethod
    def _max_endpoint_severity(cls, findings: List[Dict[str, Any]]) -> str:
        if not findings:
            return "INFORMATIVO"
        ordered = sorted(
            (str(f.get("severity", "LOW")).upper() for f in findings if isinstance(f, dict)),
            key=lambda s: cls.SEVERITY_ORDER.get(s, 99),
        )
        return ordered[0] if ordered else "INFORMATIVO"

    @staticmethod
    def _max_endpoint_cvss(findings: List[Dict[str, Any]]) -> str:
        scores = []
        for f in findings:
            if isinstance(f, dict):
                try:
                    scores.append(float(f.get("cvss", 0)))
                except (TypeError, ValueError):
                    pass
        return f"{max(scores):.1f}" if scores else "N/A"

    @staticmethod
    def _endpoint_status(findings: List[Dict[str, Any]]) -> str:
        return "Con hallazgos" if findings else "Sin hallazgos automaticos"

    @staticmethod
    def _endpoint_recommendation(findings: List[Dict[str, Any]]) -> str:
        if findings:
            recs = []
            for f in findings:
                if isinstance(f, dict) and f.get("recommendation"):
                    recs.append(str(f["recommendation"]))
            if recs:
                return " ".join(dict.fromkeys(recs))
        return (
            "Mantener validaciones server-side por endpoint, autenticacion y autorizacion por "
            "recurso, controles anti-enumeracion, limites de tasa, registro de auditoria y "
            "respuestas sin informacion sensible."
        )

    def load_from_scan(self, scan_file: str):
        with open(scan_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.retest_diff = data.get("retest_diff", {}) or {}
        self.manual_assisted = data.get("manual_assisted", []) or []
        self.technical_annex = data.get("technical_annex", {}) or {}
        api_rep = data.get("api_endpoint_report")
        self.api_endpoint_report = api_rep if isinstance(api_rep, list) else []
        self.executive_summary = data.get("executive_summary", {}) or {}
        self.external_checks_summary = data.get("external_checks_summary", []) or []
        self.scan_scope = data.get("scan_scope", {}) or {}
        erm = data.get("endpoint_report_meta")
        self.endpoint_report_meta = erm if isinstance(erm, dict) else {}

        if not self.target_url:
            self.target_url = data.get("dynamic_api_url", "") or self.target_url

        raw_vulns = filter_vulnerabilities_for_report(
            [x for x in data.get("vulnerabilities", []) if isinstance(x, dict)]
        )
        for v in raw_vulns:
            if not isinstance(v, dict):
                continue
            cwe_id = str(v.get("cwe_id", "")).strip()
            endpoint = self._endpoint_from_vuln(v, self.target_url)
            sev = str(v.get("severity", "MEDIUM")).upper()
            if sev not in self.SEVERITY_ORDER:
                sev = "MEDIUM"
            file_p = str(v.get("file", "N/A"))
            line = v.get("line", "N/A")
            status = "Persistente"
            if file_p == "<manual-check>":
                desc = str(v.get("description", ""))
                if "Estado retest:" in desc:
                    status = desc.split("Estado retest:", 1)[1].strip().split("|")[0].strip()

            poc_text = str(v.get("code_snippet", ""))
            impact = self._impact_text(
                str(v.get("title", "")),
                str(v.get("category", "")),
                f"Hallazgo {sev} que puede afectar confidencialidad/integridad/disponibilidad.",
            )
            exploit = self._exploit_text(poc_text, poc_text)
            fp_note = str(v.get("false_positive_note", "")).strip()

            try:
                cvss = float(v.get("cvss", self._severity_to_cvss(sev)))
            except (TypeError, ValueError):
                cvss = self._severity_to_cvss(sev)

            vuln = VulnerabilityReport(
                id=file_p.replace("/", "_").replace(".", "_") + f"_{line}",
                title=str(v.get("title", "Unknown")),
                severity=sev,
                cvss=cvss,
                status=status,
                category=str(v.get("category", "Security")),
                description=str(v.get("description", "")),
                recommendation=str(v.get("recommendation", "")),
                endpoint=endpoint,
                impact=impact,
                cvss_vector=str(v.get("cvss_vector", "")),
                poc=poc_text,
                steps_to_reproduce=[
                    f"Revisar archivo: {file_p}" + (f" (línea {line})" if line not in (None, "", "N/A") else ""),
                    "Confirmar en el repositorio con búsqueda o IDE (contexto ampliado en el bloque de código del hallazgo).",
                    "Validar con request/replay controlado o prueba unitaria de seguridad si aplica.",
                ],
                evidence=poc_text,
                cwe_id=cwe_id,
                references=self._default_references(cwe_id),
                exploit_text=exploit,
                false_positive_note=fp_note,
            )
            self.add_vulnerability(vuln)

    def _raw_vuln_to_display_dict(
        self, v: Dict[str, Any], target_url: str = ""
    ) -> Dict[str, Any]:
        """Mismo formato que la sección 6 para bloques 5.2.1 por endpoint."""
        cwe_id = str(v.get("cwe_id", "")).strip()
        sev = str(v.get("severity", "MEDIUM")).upper()
        if sev not in self.SEVERITY_ORDER:
            sev = "MEDIUM"
        file_p = str(v.get("file", "N/A"))
        line = v.get("line", "N/A")
        poc_text = str(v.get("code_snippet", ""))
        try:
            cvss = float(v.get("cvss", self._severity_to_cvss(sev)))
        except (TypeError, ValueError):
            cvss = self._severity_to_cvss(sev)
        return {
            "title": str(v.get("title", "Unknown")),
            "severity": sev,
            "cvss": cvss,
            "status": "Persistente",
            "category": str(v.get("category", "Security")),
            "description": str(v.get("description", "")),
            "recommendation": str(v.get("recommendation", "")),
            "endpoint": self._endpoint_from_vuln(v, target_url or self.target_url),
            "impact": self._impact_text(
                str(v.get("title", "")),
                str(v.get("category", "")),
                f"Hallazgo {sev} que puede afectar confidencialidad/integridad/disponibilidad.",
            ),
            "cvss_vector": str(v.get("cvss_vector", "")),
            "poc": poc_text,
            "steps_to_reproduce": [
                f"Revisar archivo: {file_p}"
                + (f" (línea {line})" if line not in (None, "", "N/A") else ""),
                "Confirmar en el repositorio con búsqueda o IDE.",
                "Validar con request/replay controlado si aplica.",
            ],
            "cwe_id": cwe_id,
            "references": self._default_references(cwe_id),
            "exploit_text": self._exploit_text(poc_text, poc_text),
            "false_positive_note": str(v.get("false_positive_note", "")).strip(),
        }

    def _enrich_api_endpoint_report(self) -> List[Dict[str, Any]]:
        enriched: List[Dict[str, Any]] = []
        for ep in self.api_endpoint_report:
            if not isinstance(ep, dict):
                continue
            raw_findings = [
                x
                for x in (ep.get("findings") or [])
                if isinstance(x, dict) and not is_lan_insecure_http_finding(x)
            ]
            detail_vulns = [
                self._raw_vuln_to_display_dict(v, str(ep.get("url") or self.target_url))
                for v in raw_findings
            ]
            detail_vulns.sort(
                key=lambda x: self.SEVERITY_ORDER.get(str(x.get("severity", "")).upper(), 99)
            )
            item = dict(ep)
            item["detail_vulns"] = detail_vulns
            item["scoped_finding_count"] = len(detail_vulns)
            enriched.append(item)
        return enriched

    def _get_summary(self) -> Dict[str, int]:
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for vuln in self.vulnerabilities:
            if vuln.severity in summary:
                summary[vuln.severity] += 1
        return summary

    def generate_html(self, output_file: str):
        """Render the HTML report using the Jinja2 template."""
        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.get_template("report.html")

        summary = self._get_summary()
        sorted_vulns = sorted(
            self.vulnerabilities,
            key=lambda v: self.SEVERITY_ORDER.get(v.severity, 99),
        )

        api_endpoint_report = self._enrich_api_endpoint_report()

        context = {
            "project_name": self.project_name,
            "target_url": self.target_url or "",
            "scan_date": self.scan_date.strftime("%d/%m/%Y %H:%M UTC"),
            "version": self.version,
            "summary": summary,
            "total_vulns": sum(summary.values()),
            "vulnerabilities": [asdict(v) for v in sorted_vulns],
            "retest_diff": self.retest_diff,
            "manual_assisted": self.manual_assisted,
            "technical_annex": self.technical_annex,
            "api_endpoint_report": api_endpoint_report,
            "executive_summary": self.executive_summary,
            "external_checks_summary": self.external_checks_summary,
            "scan_scope": self.scan_scope,
            "endpoint_report_meta": self.endpoint_report_meta,
        }

        html = template.render(**context)
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"Reporte generado: {output_file}")

    def save_json(self, output_file: str):
        data = {
            "project_name": self.project_name,
            "target_url": self.target_url,
            "scan_date": self.scan_date.isoformat(),
            "version": self.version,
            "summary": self._get_summary(),
            "retest_diff": self.retest_diff,
            "manual_assisted": self.manual_assisted,
            "technical_annex": self.technical_annex,
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
        }
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"JSON guardado: {output_file}")

    def generate_pdf(self, output_file: str):
        summary = self._get_summary()
        sorted_vulns = sorted(
            self.vulnerabilities, key=lambda v: self.SEVERITY_ORDER.get(v.severity, 99)
        )
        doc = SimpleDocTemplate(output_file, pagesize=A4, leftMargin=30, rightMargin=30)
        styles = getSampleStyleSheet()
        story = []
        story.append(Paragraph("RETEST ETHICAL HACKING", styles["Title"]))
        story.append(
            Paragraph(
                f"Proyecto: {escape(self.project_name)} | Fecha: {self.scan_date.strftime('%d/%m/%Y')}",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 12))
        story.append(
            Paragraph(
                f"Target API: {escape(self.target_url or 'N/A')} | Total hallazgos: {len(sorted_vulns)}",
                styles["Normal"],
            )
        )
        story.append(
            Paragraph(
                f"Critica: {summary['CRITICAL']} | Alta: {summary['HIGH']} | Media: {summary['MEDIUM']} | Baja: {summary['LOW']}",
                styles["Normal"],
            )
        )
        if self.executive_summary.get("headline"):
            story.append(
                Paragraph(
                    f"Priorizacion: {escape(str(self.executive_summary.get('headline', '')))}",
                    styles["Normal"],
                )
            )
        for act in self.executive_summary.get("recommended_actions") or []:
            story.append(Paragraph(f"- {escape(str(act))}", styles["Normal"]))
        if self.scan_scope.get("extensions"):
            story.append(
                Paragraph(
                    f"Extensiones analizadas: {escape(', '.join(str(x) for x in self.scan_scope['extensions'][:20]))}",
                    styles["Normal"],
                )
            )
        story.append(Spacer(1, 12))
        meta = self.endpoint_report_meta or {}
        if meta.get("report_lists_full_collection") and meta.get("inventory_total"):
            story.append(
                Paragraph(
                    f"Colección importada: {escape(str(meta.get('inventory_total')))} rutas en total; "
                    f"este informe detalla solo las {escape(str(meta.get('dynamic_scope_total')))} "
                    f"seleccionadas para el análisis.",
                    styles["Normal"],
                )
            )
            story.append(Spacer(1, 8))
        if self.api_endpoint_report:
            story.append(Paragraph("Endpoints analizados", styles["Heading2"]))
            endpoint_table_data = [["#", "Metodo", "Path", "Hallazgos"]]
            for i, e in enumerate(self.api_endpoint_report, 1):
                endpoint_table_data.append(
                    [
                        str(i),
                        str(e.get("method", "GET")),
                        str(e.get("path", ""))[:85],
                        str(e.get("finding_count", 0)),
                    ]
                )
            endpoint_table = Table(endpoint_table_data, repeatRows=1)
            endpoint_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a365d")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(endpoint_table)
            story.append(Spacer(1, 14))

        table_data = [["#", "Vulnerabilidad", "Riesgo", "CVSS", "Estado", "Endpoint"]]
        for i, v in enumerate(sorted_vulns, 1):
            table_data.append(
                [str(i), v.title[:70], v.severity, f"{v.cvss}", v.status, (v.endpoint or "N/A")[:60]]
            )
        table = Table(table_data, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a365d")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 14))
        story.append(Paragraph("Detalle tecnico", styles["Heading2"]))
        for i, v in enumerate(sorted_vulns, 1):
            story.append(Paragraph(f"{i}. {escape(v.title)} ({escape(v.severity)})", styles["Heading4"]))
            story.append(Paragraph(f"Estado: {escape(v.status)} | CWE: {escape(v.cwe_id or 'N/A')}", styles["Normal"]))
            story.append(Paragraph(f"Endpoint: {escape(v.endpoint or 'N/A')}", styles["Normal"]))
            story.append(Paragraph(f"Descripcion: {escape(v.description)}", styles["Normal"]))
            story.append(Paragraph(f"Recomendacion: {escape(v.recommendation)}", styles["Normal"]))
            if v.false_positive_note:
                story.append(Paragraph(f"Nota FP: {escape(v.false_positive_note)}", styles["Normal"]))
            story.append(Spacer(1, 8))
        doc.build(story)
        print(f"PDF generado: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Generador de reportes de Ethical Hacking")
    parser.add_argument("--project", "-p", default="Mini Program", help="Nombre del proyecto")
    parser.add_argument("--target", "-t", default="", help="URL del objetivo")
    parser.add_argument("--input", "-i", action="append", help="Archivo de scan JSON")
    parser.add_argument("--output", "-o", default="security-report.html", help="Archivo de salida")
    parser.add_argument("--json", "-j", help="Guardar datos JSON")
    args = parser.parse_args()

    generator = EthicalHackingReportGenerator(args.project, args.target)
    if args.input:
        for input_file in args.input:
            generator.load_from_scan(input_file)
    generator.generate_html(args.output)
    if args.json:
        generator.save_json(args.json)


if __name__ == "__main__":
    main()
