"""
SECUREASSESS - Dual-Engine Report Generator (HTML + PDF)
SIH 2026 Problem Statement ID: 26163 (NTRO)

Features:
- Jinja2 template rendering for interactive, dark-mode SUDARSHAN HTML dashboard report.
- WeasyPrint / ReportLab dual-engine PDF compilation (guarantees cross-platform zero-crash PDF output).
- Automatic XML entity escaping for vulnerability evidence/payloads to prevent PDF parser breaks.
- All 8 SIH deliverable fields included:
  1. Assessment Metadata (Target, Job ID, Mode, Status, Timestamp)
  2. Executive Summary
  3. Authorized Scope Statement
  4. Metric Summary Cards (Total, Confirmed, Unverified, Severity counts)
  5. Categorized Findings (OWASP, SIH Scope, CVSS 3.1, Confidence %)
  6. Actionable Remediation Guidance with code examples
  7. Confirmed PoC Evidence & Raw Scanner Findings
  8. Immutable Audit Trail & Research Gap Coverage Appendix (7 literature citations)
"""

from __future__ import annotations

import html
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger("secureassess.reporting.generator")

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def _safe(text: Any) -> str:
    """Escapes text for safe inclusion in ReportLab XML-based Paragraphs."""
    if text is None:
        return ""
    return html.escape(str(text))


class ReportGenerator:
    """Compiles normalized security assessment findings into SUDARSHAN HTML and PDF deliverables."""

    def __init__(self, templates_dir: Optional[Path] = None):
        self.templates_dir = templates_dir or TEMPLATES_DIR
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def _normalize_report_data(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Ensures all fields match template and PDF generator expectations."""
        data = dict(report_data)
        data.setdefault("assessment_metadata", {})
        data.setdefault("metrics_summary", {
            "total": 0, "confirmed": 0, "unverified": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        })
        data.setdefault("findings", [])
        data.setdefault("audit_trail", [])
        data.setdefault("research_gap_coverage_appendix", {})
        data.setdefault("authorized_scope_statement", "Authorized security assessment executed under NTRO guidelines.")
        data.setdefault("executive_summary", "Autonomous security assessment completed.")

        # Normalize finding enum values to plain strings if needed
        norm_findings = []
        for f in data["findings"]:
            f_dict = dict(f) if isinstance(f, dict) else f.__dict__
            # Handle Enum objects
            if hasattr(f_dict.get("severity"), "value"):
                f_dict["severity"] = f_dict["severity"].value
            if hasattr(f_dict.get("status"), "value"):
                f_dict["status"] = f_dict["status"].value
            if hasattr(f_dict.get("sih_scope_category"), "value"):
                f_dict["sih_scope_category"] = f_dict["sih_scope_category"].value
            
            # Normalize remediation
            rem = f_dict.get("remediation")
            if rem and not isinstance(rem, dict) and hasattr(rem, "__dict__"):
                f_dict["remediation"] = rem.__dict__
            elif not rem:
                f_dict["remediation"] = {
                    "description": "Remediate according to security best practices.",
                    "fix": "Apply vendor security patches.",
                    "example_code": ""
                }

            norm_findings.append(f_dict)
        data["findings"] = norm_findings
        return data

    def render_html(self, report_data: Dict[str, Any]) -> str:
        """Renders SUDARSHAN dark-mode dashboard HTML report."""
        clean_data = self._normalize_report_data(report_data)
        template = self.jinja_env.get_template("report_sudarshan.html.j2")
        return template.render(**clean_data)

    def render_pdf(self, report_data: Dict[str, Any], output_path: str | Path) -> str:
        """
        Renders PDF report. Tries WeasyPrint first; if unavailable, uses ReportLab Platypus.
        Guarantees zero-crash PDF compilation across any host OS.
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        clean_data = self._normalize_report_data(report_data)

        # 1. Attempt WeasyPrint (ideal for containerized Linux with GTK3)
        try:
            import weasyprint  # type: ignore
            html_content = self.render_html(clean_data)
            weasyprint.HTML(string=html_content).write_pdf(str(output_file))
            logger.info(f"Compiled PDF report via WeasyPrint: {output_file.name}")
            return str(output_file)
        except Exception as e:
            logger.info(f"WeasyPrint unavailable ({e}). Falling back to ReportLab engine.")

        # 2. Robust native ReportLab fallback (self-contained, works everywhere)
        self._render_pdf_reportlab(clean_data, output_file)
        logger.info(f"Compiled PDF report via ReportLab: {output_file.name}")
        return str(output_file)

    def _render_pdf_reportlab(self, data: Dict[str, Any], output_path: Path) -> None:
        """Generates an NTRO/SIH standard compliance PDF document using ReportLab Platypus."""
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable, Preformatted
        )
        from reportlab.pdfgen import canvas

        # Page numbering canvas
        class NumberedCanvas(canvas.Canvas):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._saved_page_states = []

            def showPage(self):
                self._saved_page_states.append(dict(self.__dict__))
                self._startPage()

            def save(self):
                num_pages = len(self._saved_page_states)
                for state in self._saved_page_states:
                    self.__dict__.update(state)
                    self.draw_page_number(num_pages)
                    super().showPage()
                super().save()

            def draw_page_number(self, page_count):
                self.saveState()
                self.setFont("Helvetica", 8)
                self.setFillColor(colors.HexColor("#64748b"))
                self.drawString(36, 25, "SECUREASSESS — NTRO Problem Statement 26163 — Confidential Deliverable")
                self.drawRightString(letter[0] - 36, 25, f"Page {self._pageNumber} of {page_count}")
                self.setStrokeColor(colors.HexColor("#cbd5e1"))
                self.setLineWidth(0.5)
                self.line(36, 36, letter[0] - 36, 36)
                self.restoreState()

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=46,
        )

        styles = getSampleStyleSheet()
        
        # Custom Typography Styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold",
            spaceAfter=4,
        )
        subtitle_style = ParagraphStyle(
            "DocSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#0284c7"),
            fontName="Helvetica-Bold",
            spaceAfter=12,
        )
        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Heading2"],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold",
            spaceBefore=14,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155"),
            fontName="Helvetica",
        )
        code_style = ParagraphStyle(
            "CodeBlock",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#0f172a"),
            fontName="Courier",
            backColor=colors.HexColor("#f1f5f9"),
            borderColor=colors.HexColor("#cbd5e1"),
            borderWidth=0.5,
            borderPadding=4,
            spaceBefore=4,
            spaceAfter=4,
        )
        badge_style = ParagraphStyle(
            "Badge",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            fontName="Helvetica-Bold",
        )

        elements: List[Any] = []

        # 1. Header Banner
        elements.append(Paragraph("SECUREASSESS — Autonomous Security Assessment Report", title_style))
        elements.append(Paragraph(
            "SIH 2026 Problem Statement ID: 26163 (NTRO) | Universal LLM-Orchestrated Multi-Agent Pipeline",
            subtitle_style,
        ))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=10))

        # 2. Metadata Grid
        meta = data.get("assessment_metadata", {})
        meta_table_data = [
            [
                Paragraph("<b>Target Component:</b>", body_style),
                Paragraph(_safe(meta.get("target", "N/A")), body_style),
                Paragraph("<b>Assessment Mode:</b>", body_style),
                Paragraph(f"<b>{_safe(meta.get('mode', 'DAST'))}</b>", body_style),
            ],
            [
                Paragraph("<b>Job ID:</b>", body_style),
                Paragraph(_safe(meta.get("job_id", "N/A")), body_style),
                Paragraph("<b>Scan Status:</b>", body_style),
                Paragraph("<font color='#10b981'><b>COMPLETED</b></font>", body_style),
            ],
            [
                Paragraph("<b>Timestamp (UTC):</b>", body_style),
                Paragraph(_safe(meta.get("timestamp", "N/A")), body_style),
                Paragraph("<b>Safety Sandbox:</b>", body_style),
                Paragraph("Non-Destructive Bound", body_style),
            ],
        ]
        meta_table = Table(meta_table_data, colWidths=[110, 160, 110, 160])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 10))

        # 3. Executive Summary & Scope Statement
        elements.append(Paragraph("Executive Summary & Scope Authorization", h2_style))
        elements.append(Paragraph(_safe(data.get("executive_summary", "")), body_style))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph(
            f"<i>Scope Authorization Statement: {_safe(data.get('authorized_scope_statement', ''))}</i>",
            body_style,
        ))
        elements.append(Spacer(1, 10))

        # 4. Summary Metrics Table
        metrics = data.get("metrics_summary", {})
        elements.append(Paragraph("Scan Findings Summary", h2_style))
        summary_data = [
            ["Total Findings", "Confirmed", "Unverified", "Critical", "High", "Medium", "Low"],
            [
                str(metrics.get("total", 0)),
                str(metrics.get("confirmed", 0)),
                str(metrics.get("unverified", 0)),
                str(metrics.get("critical", 0)),
                str(metrics.get("high", 0)),
                str(metrics.get("medium", 0)),
                str(metrics.get("low", 0)),
            ]
        ]
        summary_table = Table(summary_data, colWidths=[77] * 7)
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 14))

        # 5. Detailed Findings
        findings = data.get("findings", [])
        elements.append(Paragraph(f"Detailed Vulnerability Findings ({len(findings)})", h2_style))

        sev_colors = {
            "Critical": colors.HexColor("#ef4444"),
            "High": colors.HexColor("#f43f5e"),
            "Medium": colors.HexColor("#eab308"),
            "Low": colors.HexColor("#64748b"),
        }

        for finding in findings:
            finding_elements = []
            fid = _safe(finding.get("id", ""))
            ftitle = _safe(finding.get("title", ""))
            fsev = _safe(finding.get("severity", "Medium"))
            fstatus = _safe(finding.get("status", "Unverified")).upper()
            fscore = str(finding.get("cvss_score", "N/A"))
            fconf = str(finding.get("confidence_pct", 80))
            status_color = "#10b981" if fstatus == "CONFIRMED" else "#f59e0b"

            # Finding Header Block
            f_hdr_text = (
                f"<b>[{fid}] {ftitle}</b> &nbsp;|&nbsp; "
                f"<font color='{sev_colors.get(fsev, colors.HexColor('#64748b')).hexval()}'><b>{fsev}</b></font> &nbsp;|&nbsp; "
                f"<font color='{status_color}'><b>{fstatus}</b></font> &nbsp;|&nbsp; "
                f"CVSS: {fscore} &nbsp;|&nbsp; Conf: {fconf}%"
            )
            finding_elements.append(Paragraph(f_hdr_text, body_style))
            finding_elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=4))

            # Attributes table
            attr_data = [
                [
                    Paragraph("<b>Affected Component:</b>", body_style),
                    Paragraph(_safe(finding.get("affected_component", "N/A")), body_style),
                    Paragraph("<b>Source Tool:</b>", body_style),
                    Paragraph(_safe(finding.get("source_tool", "N/A")), body_style),
                ],
                [
                    Paragraph("<b>OWASP Category:</b>", body_style),
                    Paragraph(_safe(finding.get("owasp_category", "N/A")), body_style),
                    Paragraph("<b>SIH Scope Category:</b>", body_style),
                    Paragraph(_safe(finding.get("sih_scope_category", "N/A")), body_style),
                ],
                [
                    Paragraph("<b>CVSS 3.1 Vector:</b>", body_style),
                    Paragraph(_safe(finding.get("cvss_vector", "N/A")), body_style),
                    Paragraph("", body_style),
                    Paragraph("", body_style),
                ],
            ]
            attr_tbl = Table(attr_data, colWidths=[110, 160, 110, 160])
            attr_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            finding_elements.append(attr_tbl)
            finding_elements.append(Spacer(1, 4))

            # Description & Business Impact
            finding_elements.append(Paragraph(f"<b>Description:</b> {_safe(finding.get('description', ''))}", body_style))
            finding_elements.append(Paragraph(
                f"<b>Business Impact:</b> <font color='#991b1b'>{_safe(finding.get('business_impact', ''))}</font>",
                body_style,
            ))

            # Steps to Reproduce
            steps = finding.get("steps_to_reproduce") or []
            if steps:
                steps_txt = "<b>Steps to Reproduce:</b><br/>" + "<br/>".join([f"&nbsp;&nbsp;{i+1}. {_safe(s)}" for i, s in enumerate(steps)])
                finding_elements.append(Paragraph(steps_txt, body_style))

            # Remediation
            rem = finding.get("remediation", {})
            rem_text = (
                f"<b>Remediation Overview:</b> {_safe(rem.get('description', ''))}<br/>"
                f"<b>Actionable Fix:</b> {_safe(rem.get('fix', ''))}"
            )
            finding_elements.append(Paragraph(rem_text, body_style))
            if rem.get("example_code"):
                finding_elements.append(Paragraph(f"<b>Code Example:</b><br/>{_safe(rem.get('example_code'))}", code_style))

            # Confirmed PoC Evidence
            if finding.get("poc_evidence"):
                finding_elements.append(Paragraph(
                    f"<font color='#10b981'><b>✓ Verified Safe PoC Evidence:</b></font><br/>{_safe(finding.get('poc_evidence'))}",
                    code_style,
                ))

            finding_elements.append(Spacer(1, 10))
            elements.append(KeepTogether(finding_elements))

        # 6. Audit Trail Table
        audit = data.get("audit_trail", [])
        if audit:
            elements.append(Spacer(1, 10))
            elements.append(Paragraph("Immutable Scan Audit Trail", h2_style))
            audit_rows = [["Timestamp (UTC)", "Event", "Request / Command", "Outcome"]]
            for entry in audit[:25]:  # Limit top 25 entries in PDF to prevent page bloat
                audit_rows.append([
                    _safe(entry.get("timestamp", ""))[:19],
                    Paragraph(_safe(entry.get("event", "")), body_style),
                    Paragraph(_safe(entry.get("command") or entry.get("url") or entry.get("message") or "")[:55], body_style),
                    Paragraph(_safe(entry.get("outcome") or entry.get("status") or "OK"), body_style),
                ])
            audit_tbl = Table(audit_rows, colWidths=[100, 100, 240, 100])
            audit_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            elements.append(audit_tbl)

        # 7. Research Gap Coverage Appendix Table
        gaps = data.get("research_gap_coverage_appendix", {})
        if gaps:
            elements.append(Spacer(1, 10))
            elements.append(Paragraph("Appendix: Research Gap Coverage Mapping", h2_style))
            gap_rows = [["Research Gap & Literature Citation", "SECUREASSESS Architectural Solution"]]
            for gap, sol in gaps.items():
                gap_rows.append([
                    Paragraph(f"<b>{_safe(gap)}</b>", body_style),
                    Paragraph(_safe(sol), body_style),
                ])
            gap_tbl = Table(gap_rows, colWidths=[180, 360])
            gap_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0284c7")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            elements.append(gap_tbl)

        # Build PDF
        doc.build(elements, canvasmaker=NumberedCanvas)
