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
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

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

    @staticmethod
    def _pdf_table_style() -> TableStyle:
        return TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a365d")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ]
        )

    @staticmethod
    def _vuln_record_as_dict(v: Any) -> Dict[str, Any]:
        if isinstance(v, VulnerabilityReport):
            return asdict(v)
        if isinstance(v, dict):
            return v
        return {}

    def _pdf_cell(self, text: str, cell_style: ParagraphStyle) -> Paragraph:
        safe = escape(str(text or "")).replace("\n", "<br/>")
        return Paragraph(safe or "—", cell_style)

    def _pdf_append_vuln_detail(
        self,
        story: List[Any],
        v: Any,
        label: str,
        styles: Any,
        body_style: ParagraphStyle,
        small_style: ParagraphStyle,
    ) -> None:
        d = self._vuln_record_as_dict(v)
        if not d:
            return
        story.append(
            Paragraph(
                f"<b>{escape(label)} {escape(str(d.get('title', 'Unknown')))}</b> "
                f"({escape(str(d.get('severity', '')))})",
                styles["Heading4"],
            )
        )
        story.append(
            Paragraph(
                f"Estado: {escape(str(d.get('status', '')))} | "
                f"CWE: {escape(str(d.get('cwe_id') or 'N/A'))} | "
                f"CVSS: {escape(str(d.get('cvss', '')))} | "
                f"Categoria: {escape(str(d.get('category', '')))}",
                small_style,
            )
        )
        story.append(
            Paragraph(f"Endpoint: {escape(str(d.get('endpoint') or 'N/A'))}", small_style)
        )
        story.append(Paragraph(f"<b>Descripcion:</b> {escape(str(d.get('description', '')))}", body_style))
        if d.get("impact"):
            story.append(Paragraph(f"<b>Impacto:</b> {escape(str(d.get('impact', '')))}", body_style))
        if d.get("exploit_text"):
            story.append(
                Paragraph(f"<b>Explotacion / evidencia:</b> {escape(str(d.get('exploit_text', '')))}", body_style)
            )
        if d.get("poc"):
            poc = escape(str(d.get("poc", ""))).replace("\n", "<br/>")
            story.append(Paragraph(f"<b>PoC:</b><br/><font face='Courier' size='7'>{poc}</font>", body_style))
        steps = d.get("steps_to_reproduce") or []
        if steps:
            steps_html = "".join(f"<li>{escape(str(s))}</li>" for s in steps)
            story.append(Paragraph(f"<b>Pasos:</b><ol>{steps_html}</ol>", body_style))
        story.append(
            Paragraph(f"<b>Mitigacion:</b> {escape(str(d.get('recommendation', '')))}", body_style)
        )
        refs = d.get("references") or []
        if refs:
            refs_html = "".join(f"<li>{escape(str(r))}</li>" for r in refs)
            story.append(Paragraph(f"<b>Referencias:</b><ul>{refs_html}</ul>", small_style))
        if d.get("false_positive_note"):
            story.append(
                Paragraph(
                    f"<b>Nota FP:</b> {escape(str(d.get('false_positive_note', '')))}",
                    small_style,
                )
            )
        story.append(Spacer(1, 10))

    def generate_pdf(self, output_file: str):
        summary = self._get_summary()
        sorted_vulns = sorted(
            self.vulnerabilities, key=lambda v: self.SEVERITY_ORDER.get(v.severity, 99)
        )
        api_endpoint_report = self._enrich_api_endpoint_report()
        doc = SimpleDocTemplate(
            output_file,
            pagesize=A4,
            leftMargin=28,
            rightMargin=28,
            topMargin=36,
            bottomMargin=36,
        )
        styles = getSampleStyleSheet()
        body_style = ParagraphStyle(
            "PdfBody",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
            spaceAfter=4,
        )
        small_style = ParagraphStyle(
            "PdfSmall",
            parent=styles["Normal"],
            fontSize=7,
            leading=9,
            spaceAfter=3,
        )
        cell_style = ParagraphStyle(
            "PdfCell",
            parent=styles["Normal"],
            fontSize=7,
            leading=9,
        )
        story: List[Any] = []
        scan_label = self.scan_date.strftime("%d/%m/%Y %H:%M UTC")

        story.append(Paragraph("RETEST ETHICAL HACKING", styles["Title"]))
        story.append(
            Paragraph(
                f"Proyecto: {escape(self.project_name)} | Fecha: {escape(scan_label)} | v{escape(self.version)}",
                body_style,
            )
        )
        story.append(
            Paragraph(
                f"Target API: {escape(self.target_url or 'N/A')} | Total hallazgos: {len(sorted_vulns)}",
                body_style,
            )
        )
        story.append(
            Paragraph(
                f"Critica: {summary['CRITICAL']} | Alta: {summary['HIGH']} | "
                f"Media: {summary['MEDIUM']} | Baja: {summary['LOW']}",
                body_style,
            )
        )
        if self.executive_summary.get("headline"):
            story.append(
                Paragraph(
                    f"Priorizacion: {escape(str(self.executive_summary.get('headline', '')))}",
                    body_style,
                )
            )
        for act in self.executive_summary.get("recommended_actions") or []:
            story.append(Paragraph(f"- {escape(str(act))}", body_style))
        if self.scan_scope.get("files_scanned") is not None:
            story.append(
                Paragraph(
                    f"Archivos escaneados en repo: {escape(str(self.scan_scope.get('files_scanned', 0)))}",
                    body_style,
                )
            )
        if self.scan_scope.get("extensions"):
            story.append(
                Paragraph(
                    f"Extensiones analizadas: {escape(', '.join(str(x) for x in self.scan_scope['extensions'][:20]))}",
                    body_style,
                )
            )
        if self.external_checks_summary:
            story.append(Paragraph("<b>Checks externos:</b>", body_style))
            for row in self.external_checks_summary[:12]:
                if isinstance(row, dict):
                    story.append(
                        Paragraph(
                            f"- {escape(str(row.get('tool', row.get('id', 'check'))))}: "
                            f"{escape(str(row.get('status', row.get('reason', ''))))}",
                            small_style,
                        )
                    )

        story.append(Spacer(1, 10))
        story.append(Paragraph("4.1 Retest diff (antes vs despues)", styles["Heading2"]))
        rd = self.retest_diff or {}
        if rd.get("has_previous"):
            story.append(
                Paragraph(
                    f"Delta total: {escape(str(rd.get('delta_total', 0)))} | "
                    f"Nuevos: {len(rd.get('new_titles') or [])} | "
                    f"Resueltos: {len(rd.get('resolved_titles') or [])}",
                    body_style,
                )
            )
            for title in (rd.get("new_titles") or [])[:15]:
                story.append(Paragraph(f"+ {escape(str(title))}", small_style))
            for title in (rd.get("resolved_titles") or [])[:15]:
                story.append(Paragraph(f"- {escape(str(title))}", small_style))
        else:
            story.append(Paragraph("Sin baseline previo en la base de datos para comparar.", body_style))

        story.append(Spacer(1, 8))
        story.append(Paragraph("4.2 Cuadro resumen", styles["Heading2"]))
        table_data: List[List[Any]] = [
            [
                Paragraph("<b>#</b>", cell_style),
                Paragraph("<b>Vulnerabilidad</b>", cell_style),
                Paragraph("<b>Riesgo</b>", cell_style),
                Paragraph("<b>CVSS</b>", cell_style),
                Paragraph("<b>Estado</b>", cell_style),
                Paragraph("<b>Endpoint</b>", cell_style),
            ]
        ]
        for i, v in enumerate(sorted_vulns, 1):
            table_data.append(
                [
                    str(i),
                    self._pdf_cell(v.title, cell_style),
                    self._pdf_cell(v.severity, cell_style),
                    self._pdf_cell(f"{v.cvss}", cell_style),
                    self._pdf_cell(v.status, cell_style),
                    self._pdf_cell(v.endpoint or "N/A", cell_style),
                ]
            )
        summary_table = Table(
            table_data,
            colWidths=[22, 150, 42, 32, 52, 140],
            repeatRows=1,
        )
        summary_table.setStyle(self._pdf_table_style())
        story.append(summary_table)

        story.append(Spacer(1, 12))
        story.append(Paragraph("5.1 Manual checks asistidos", styles["Heading2"]))
        if self.manual_assisted:
            manual_rows: List[List[Any]] = [
                [
                    Paragraph("<b>Check</b>", cell_style),
                    Paragraph("<b>Estado</b>", cell_style),
                    Paragraph("<b>Endpoint</b>", cell_style),
                    Paragraph("<b>Severidad</b>", cell_style),
                ]
            ]
            for x in self.manual_assisted:
                if not isinstance(x, dict):
                    continue
                manual_rows.append(
                    [
                        self._pdf_cell(x.get("check_id", ""), cell_style),
                        self._pdf_cell(x.get("status", ""), cell_style),
                        self._pdf_cell(x.get("endpoint", ""), cell_style),
                        self._pdf_cell(x.get("severity", ""), cell_style),
                    ]
                )
            manual_table = Table(manual_rows, colWidths=[90, 70, 180, 60], repeatRows=1)
            manual_table.setStyle(self._pdf_table_style())
            story.append(manual_table)
        else:
            story.append(Paragraph("Sin evidencias manuales cargadas.", body_style))

        meta = self.endpoint_report_meta or {}
        if api_endpoint_report:
            story.append(Spacer(1, 12))
            story.append(Paragraph("5.2 Alcance por endpoint", styles["Heading2"]))
            if meta.get("report_lists_full_collection") and meta.get("inventory_total"):
                story.append(
                    Paragraph(
                        f"Coleccion importada: {escape(str(meta.get('inventory_total')))} rutas en total; "
                        f"este informe detalla las {escape(str(meta.get('dynamic_scope_total')))} "
                        f"seleccionadas para el analisis.",
                        body_style,
                    )
                )
            endpoint_rows: List[List[Any]] = [
                [
                    Paragraph("<b>#</b>", cell_style),
                    Paragraph("<b>Metodo</b>", cell_style),
                    Paragraph("<b>Path</b>", cell_style),
                    Paragraph("<b>URL</b>", cell_style),
                    Paragraph("<b>Sonda</b>", cell_style),
                    Paragraph("<b>Hallazgos</b>", cell_style),
                ]
            ]
            for i, e in enumerate(api_endpoint_report, 1):
                probe = e.get("probe") if isinstance(e.get("probe"), dict) else {}
                probe_txt = str(probe.get("message") or "—")
                if probe.get("get_status") is not None:
                    probe_txt = f"GET {probe.get('get_status')}; {probe_txt}"
                finding_n = e.get("scoped_finding_count", e.get("finding_count", 0))
                endpoint_rows.append(
                    [
                        str(i),
                        self._pdf_cell(e.get("method", "GET"), cell_style),
                        self._pdf_cell(e.get("path", ""), cell_style),
                        self._pdf_cell(e.get("url", ""), cell_style),
                        self._pdf_cell(probe_txt, cell_style),
                        str(finding_n),
                    ]
                )
            endpoint_table = Table(
                endpoint_rows,
                colWidths=[18, 38, 78, 130, 95, 42],
                repeatRows=1,
            )
            endpoint_table.setStyle(self._pdf_table_style())
            story.append(endpoint_table)

            story.append(PageBreak())
            story.append(Paragraph("5.2.1 Detalle por endpoint seleccionado", styles["Heading2"]))
            for i, e in enumerate(api_endpoint_report, 1):
                method = str(e.get("method", "GET"))
                path = str(e.get("path", ""))
                url = str(e.get("url", ""))
                story.append(
                    Paragraph(
                        f"<b>{i}. {escape(method)} {escape(path)}</b>",
                        styles["Heading3"],
                    )
                )
                story.append(Paragraph(escape(url), small_style))
                probe = e.get("probe") if isinstance(e.get("probe"), dict) else None
                if probe:
                    story.append(
                        Paragraph(
                            f"<b>Analisis HTTP (sonda):</b> {escape(str(probe.get('message', '')))}",
                            body_style,
                        )
                    )
                files = e.get("files") or []
                if files:
                    file_bits = []
                    for sf in files[:5]:
                        if isinstance(sf, dict):
                            loc = str(sf.get("file", ""))
                            if sf.get("line"):
                                loc += f":{sf.get('line')}"
                            file_bits.append(loc)
                    if file_bits:
                        story.append(
                            Paragraph(
                                f"Fuente en repo: {escape(', '.join(file_bits))}",
                                small_style,
                            )
                        )
                detail_vulns = e.get("detail_vulns") or []
                if detail_vulns:
                    for j, v in enumerate(detail_vulns, 1):
                        self._pdf_append_vuln_detail(
                            story, v, f"{i}.{j}", styles, body_style, small_style
                        )
                else:
                    story.append(
                        Paragraph(
                            "Sin hallazgos vinculados a este endpoint en el alcance del scan.",
                            body_style,
                        )
                    )
                story.append(Spacer(1, 8))

        story.append(PageBreak())
        story.append(Paragraph("6. Vulnerabilidades — detalle tecnico", styles["Heading2"]))
        if sorted_vulns:
            for i, v in enumerate(sorted_vulns, 1):
                self._pdf_append_vuln_detail(story, v, f"6.{i}", styles, body_style, small_style)
        else:
            story.append(Paragraph("No se encontraron vulnerabilidades.", body_style))

        annex = self.technical_annex or {}
        openapi_specs = annex.get("openapi_specs_discovered") or []
        commands = annex.get("commands") or []
        references = annex.get("references") or [
            "https://owasp.org/API-Security/",
            "https://cwe.mitre.org/",
        ]
        if openapi_specs or commands or references:
            story.append(PageBreak())
            story.append(Paragraph("8. Anexos tecnicos", styles["Heading2"]))
            if openapi_specs:
                story.append(Paragraph("<b>8.0 OpenAPI / Swagger en repositorio</b>", body_style))
                for p in openapi_specs[:20]:
                    story.append(Paragraph(f"- {escape(str(p))}", small_style))
            if commands:
                story.append(Paragraph("<b>8.1 Comandos y scripts utilizados</b>", body_style))
                for c in commands[:20]:
                    story.append(Paragraph(f"- <font face='Courier' size='7'>{escape(str(c))}</font>", small_style))
            story.append(Paragraph("<b>8.2 Referencias OWASP / CWE</b>", body_style))
            for r in references[:20]:
                story.append(Paragraph(f"- {escape(str(r))}", small_style))

        story.append(Spacer(1, 16))
        story.append(
            Paragraph(
                f"Generado por API Security Scanner v{escape(self.version)} — {escape(scan_label)}",
                small_style,
            )
        )
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
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
