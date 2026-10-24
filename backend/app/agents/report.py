"""
SECUREASSESS - Reporting Agent
SIH 2026 Problem Statement ID: 26163 (NTRO)

Responsibilities:
- Synthesizes business impact and remediation code via LLM for each finding.
- Assembles full SIH 26163 compliant security assessment report (JSON export).
- Embeds executive summary, authorized scope statement, audit trail, and Research Gap Appendix.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

from app.models import ScanMode, ScanPhase, Remediation
from app.state import StateManager
from app.audit import AuditLogger
from app.llm_client import LLMClient

logger = logging.getLogger("secureassess.agent.report")

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"


def run_report(
    job_id: str,
    target: str,
    mode: ScanMode,
    state_mgr: StateManager,
    audit_logger: AuditLogger,
    llm_client: LLMClient,
) -> Dict[str, Any]:
    """Generates the final comprehensive assessment report JSON."""
    state_mgr.append_log(job_id, "Report Agent assembling final security assessment deliverable...", "ReportAgent")

    scan_state = state_mgr.get_scan(job_id)
    findings = state_mgr.get_findings(job_id)
    summary = state_mgr.get_findings_summary(job_id)

    state_mgr.append_log(
        job_id,
        f"Enriching business impact and remediation guidelines for {len(findings)} findings...",
        "ReportAgent",
    )

    enriched_findings = []
    for finding in findings:
        # LLM enrichment for impact and actionable code remediation
        prompt = (
            f"Generate concise business impact and actionable remediation for this vulnerability:\n"
            f"Title: {finding.title}\n"
            f"Component: {finding.affected_component}\n"
            f"Severity: {finding.severity.value} (CVSS {finding.cvss_score})\n"
            f"Description: {finding.description}\n"
        )
        enrichment = llm_client.generate(prompt=prompt, task_type="report")

        if enrichment.get("business_impact"):
            finding.business_impact = enrichment["business_impact"]
        if enrichment.get("remediation"):
            rem = enrichment["remediation"]
            finding.remediation = Remediation(
                description=rem.get("description", finding.remediation.description),
                fix=rem.get("fix", finding.remediation.fix),
                example_code=rem.get("example_code", finding.remediation.example_code),
            )

        # Update SQLite finding
        state_mgr.save_finding(job_id, finding)
        enriched_findings.append(finding.model_dump())

    # Build SIH 26163 compliant Report structure
    audit_entries = audit_logger.get_audit_entries(job_id)

    report_data = {
        "assessment_metadata": {
            "platform": "SECUREASSESS - Autonomous Web-Application Security Assessment Platform",
            "audit_framework": "Autonomous Enterprise Security Assessment Standard",
            "job_id": job_id,
            "target": target,
            "mode": mode.value.upper(),
            "scan_status": "COMPLETED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "demo_mode_active": True,
        },
        "authorized_scope_statement": (
            f"Authorized Security Assessment executed under Enterprise Cybersecurity Assessment guidelines. "
            f"Assessment restricted to target '{target}'. All validation checks adhered strictly to the "
            f"non-destructive Validator Playbook with pre-packet allowlist gating."
        ),
        "executive_summary": (
            f"SECUREASSESS conducted an autonomous {mode.value.upper()} assessment of target '{target}'. "
            f"A total of {summary.total} vulnerability candidates were discovered across scanner tools. "
            f"Through safe, evidence-gated non-destructive validation probes, {summary.confirmed} finding(s) "
            f"were confirmed with reproducible proof of existence. Key risks include {summary.critical} Critical, "
            f"{summary.high} High, and {summary.medium} Medium severity issue(s)."
        ),
        "metrics_summary": summary.model_dump(),
        "findings": enriched_findings,
        "audit_trail": audit_entries,
        "research_gap_coverage_appendix": {
            "#1/#17 AutoPT Context Loss": "Per-job SQLite persistent state machine; agents access isolated slices to prevent LLM token exhaustion.",
            "#8 Peng et al. Hallucination": "Confirmed/Unverified split with mandatory non-destructive evidence gating.",
            "#11 Deng et al. Planning Traps": "Fixed sequential 5-agent pipeline; exactly one bounded HTTP check per finding.",
            "#16/#20 PTFusion Heterogeneous Output": "Deterministic per-tool normalization layer feeding a unified LLM deduplication pass.",
            "#13/#19 Alazmi Scanner Limits": "Multi-tool fusion integrating OWASP ZAP + Nikto (DAST) and Semgrep + Gitleaks (SAST).",
            "#4 EvoMaster Policy Violations": "Explicit classification of authorization/RBAC and auth & session scope categories.",
            "#3 Kalopisis Browser/DOM Blind Spot": "Client-side DOM XSS covered via Semgrep TS/JS rules today; headless browser agent marked as Future Work."
        }
    }

    # Save report.json to disk
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    report_file = DATA_DIR / f"report_{job_id}.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    # Also write standard report.json copy for immediate access
    standard_report = DATA_DIR / "report.json"
    with open(standard_report, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    # Compile HTML and PDF deliverables via ReportGenerator
    try:
        from app.reporting.generator import ReportGenerator
        report_gen = ReportGenerator()

        # Render and save HTML deliverable
        html_content = report_gen.render_html(report_data)
        html_file = DATA_DIR / f"report_{job_id}.html"
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        with open(DATA_DIR / "report.html", "w", encoding="utf-8") as f:
            f.write(html_content)

        # Render and save PDF deliverable (WeasyPrint / ReportLab dual engine)
        pdf_file = DATA_DIR / f"secureassess_{job_id}.pdf"
        report_gen.render_pdf(report_data, pdf_file)
        
        import shutil
        shutil.copyfile(pdf_file, DATA_DIR / "secureassess.pdf")
        
        state_mgr.append_log(
            job_id,
            f"Deliverables compiled: report_{job_id}.json, report_{job_id}.html, secureassess_{job_id}.pdf",
            "ReportAgent",
        )
    except Exception as e:
        logger.warning(f"Error compiling HTML/PDF deliverables: {e}", exc_info=True)
        state_mgr.append_log(
            job_id,
            f"Notice: JSON deliverable saved; HTML/PDF engine encountered: {e}",
            "ReportAgent",
        )

    state_mgr.append_log(job_id, f"Security assessment deliverable successfully assembled.", "ReportAgent")
    return report_data

