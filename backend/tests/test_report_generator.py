"""
SECUREASSESS - Phase 6 Test Suite: Report Generator Engine
SIH 2026 Problem Statement ID: 26163 (NTRO)

Tests:
1. HTML SUDARSHAN template rendering (metric cards, finding cards, remediation, audit trail, research gaps).
2. ReportLab PDF compilation (generates valid multi-page PDF with PDF magic header %PDF-).
3. Payload safety (XSS payloads and XML entities safely escaped without parser crash).
4. Full ReportAgent artifact generation (report_<id>.json, report_<id>.html, secureassess_<id>.pdf).
5. FastAPI endpoints for deliverable download (GET /scan/{id}/report.json, .html, .pdf and standard routes).
"""

import json
from pathlib import Path
import pytest
from starlette.testclient import TestClient

from app.models import ScanMode, ScanPhase, Finding, FindingStatus, FindingSeverity, Remediation, SIHScopeCategory

from app.state import StateManager
from app.audit import AuditLogger
from app.llm_client import LLMClient
from app.reporting.generator import ReportGenerator
from app.agents.report import run_report
from app.main import app, DATA_DIR


@pytest.fixture
def mock_report_data():
    return {
        "assessment_metadata": {
            "platform": "SECUREASSESS - Autonomous Web-Application Security Assessment Platform",
            "sih_problem_statement": "SIH 2026 - Problem Statement ID 26163 (NTRO)",
            "job_id": "test-job-phase6-001",
            "target": "http://localhost:3000",
            "mode": "DAST",
            "scan_status": "COMPLETED",
            "timestamp": "2026-09-28T09:00:00Z",
            "demo_mode_active": True,
        },
        "authorized_scope_statement": "Assessment executed under NTRO guidelines restricted to authorized target.",
        "executive_summary": "Autonomous security assessment identified 2 vulnerability candidates.",
        "metrics_summary": {
            "total": 2, "confirmed": 1, "unverified": 1,
            "critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0
        },
        "findings": [
            {
                "id": "SEC-DAST-001",
                "title": "Cross-Site Scripting (Reflected in Search Query)",
                "severity": "High",
                "status": "Confirmed",
                "confidence_pct": 95,
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "owasp_category": "A03:2021-Injection",
                "sih_scope_category": "Injection & Input Validation",
                "affected_component": "GET /api/search?q=<script>alert(1)</script>",
                "source_tool": "OWASP ZAP",
                "description": "Reflected parameter rendered directly in DOM without HTML entity encoding.",
                "business_impact": "Allows attackers to execute arbitrary JS in user browser context.",
                "steps_to_reproduce": ["Send GET to /api/search with script tag", "Observe raw reflect in response"],
                "remediation": {
                    "description": "Sanitize and encode all untrusted user input before reflection.",
                    "fix": "Use DOMPurify and context-aware HTML entity encoding.",
                    "example_code": "const clean = DOMPurify.sanitize(userInput);"
                },
                "poc_evidence": "HTTP 200 OK with reflected <script> tag verified via safe non-destructive check.",
                "evidence": ["OWASP ZAP Plugin 40012 alert matched"]
            },
            {
                "id": "SEC-DAST-002",
                "title": "Missing Strict-Transport-Security Header",
                "severity": "Medium",
                "status": "Unverified",
                "confidence_pct": 85,
                "cvss_score": 5.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "sih_scope_category": "Security Misconfiguration",
                "affected_component": "HTTP Response Headers",
                "source_tool": "Nikto",
                "description": "The web server does not send an HSTS header.",
                "business_impact": "Exposes connection to SSL stripping downgrade attacks.",
                "steps_to_reproduce": ["Inspect response headers on port 443"],
                "remediation": {
                    "description": "Add Strict-Transport-Security header to web server configuration.",
                    "fix": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    "example_code": "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;"
                },
                "poc_evidence": None,
                "evidence": ["Nikto check 999951 reported missing HSTS"]
            }
        ],
        "audit_trail": [
            {"timestamp": "2026-09-28T09:00:01Z", "event": "RECON_START", "message": "Recon probe sent", "outcome": "ACTIVE"},
            {"timestamp": "2026-09-28T09:00:05Z", "event": "VALIDATION_PROBE", "command": "GET /api/search", "outcome": "CONFIRMED"}
        ],
        "research_gap_coverage_appendix": {
            "#1/#17 AutoPT Context Loss": "Per-job SQLite state machine isolates agent slices.",
            "#8 Peng et al. Hallucination": "Confirmed/Unverified split with safe validation evidence gating."
        }
    }


def test_html_rendering_sudarshan_theme(mock_report_data):
    """Verifies that Jinja2 generates complete SUDARSHAN dashboard HTML."""
    gen = ReportGenerator()
    html = gen.render_html(mock_report_data)

    assert "SECUREASSESS" in html
    assert "SIH 2026 PS ID 26163" in html
    assert "test-job-phase6-001" in html
    assert "Cross-Site Scripting" in html
    assert "CONFIRMED" in html
    assert "UNVERIFIED" in html
    assert "Immutable Scan Audit Trail" in html
    assert "Research Gap Coverage Mapping" in html
    assert "#1/#17 AutoPT Context Loss" in html


def test_pdf_compilation_reportlab(mock_report_data, tmp_path):
    """Verifies that ReportLab compiles a valid PDF deliverable with valid PDF header."""
    gen = ReportGenerator()
    pdf_out = tmp_path / "test_report.pdf"
    
    res = gen.render_pdf(mock_report_data, pdf_out)
    assert Path(res).exists()
    assert pdf_out.stat().st_size > 2000

    # Verify standard PDF magic header
    with open(pdf_out, "rb") as f:
        header = f.read(5)
        assert header == b"%PDF-"


def test_safe_escaping_no_xml_parser_crash(tmp_path):
    """Verifies that arbitrary payloads (script tags, ampersands, angle brackets) don't crash ReportLab XML parser."""
    gen = ReportGenerator()
    malicious_data = {
        "assessment_metadata": {"job_id": "job_xss_test", "target": "http://target/<script>alert(1)</script>"},
        "executive_summary": "Testing & validating <evil> & 'dangerous' \"strings\".",
        "findings": [
            {
                "id": "XSS-999",
                "title": "<script>alert('XSS')</script> & Injection Test",
                "severity": "Critical",
                "status": "Confirmed",
                "affected_component": "/endpoint?a=<b>bold</b>&b=<script>",
                "description": "Unescaped XML tags <foo> <bar> & &amp; must not crash parser.",
                "remediation": {"description": "Fix & sanitize", "fix": "Use escape()", "example_code": "if a < b and c > d:"},
                "poc_evidence": "Payload: <script>document.cookie</script>"
            }
        ],
        "audit_trail": [{"event": "PROBE", "message": "GET /?q=<test>&ok=1", "outcome": "CONFIRMED"}]
    }
    pdf_out = tmp_path / "xss_safe_test.pdf"
    res = gen.render_pdf(malicious_data, pdf_out)
    assert Path(res).exists()
    assert pdf_out.stat().st_size > 1000


def test_report_agent_full_artifact_generation(tmp_path):
    """Verifies run_report creates report_<id>.json, report_<id>.html, and secureassess_<id>.pdf."""
    state_mgr = StateManager(db_path=str(tmp_path / "state.db"))
    audit_logger = AuditLogger(log_dir=str(tmp_path / "audit"))
    llm_client = LLMClient()

    job_id = "test_agent_rep_001"
    target = "http://localhost:3000"
    mode = ScanMode.DAST

    state_mgr.create_scan(job_id=job_id, target=target, mode=mode)
    
    # Save a finding to state
    finding = Finding(
        id="SA-DAST-001",
        title="Cross-Site Scripting",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.CONFIRMED,
        confidence_pct=95,
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        owasp_category="A03:2021-Injection",
        sih_scope_category=SIHScopeCategory.INPUT_VALIDATION,
        affected_component="/api/v1/search",
        source_tool="OWASP ZAP",
        description="Reflected input vulnerability.",
        business_impact="Client-side session compromise.",
        remediation=Remediation(
            description="Sanitize input.",
            fix="Use DOMPurify.",
            example_code="DOMPurify.sanitize(input);"
        ),
        poc_evidence="HTTP 200 OK safe reflection proof"
    )
    state_mgr.save_finding(job_id, finding)
    audit_logger.log_scan_init(job_id, target, mode.value)

    report_result = run_report(job_id, target, mode, state_mgr, audit_logger, llm_client)

    assert report_result["assessment_metadata"]["job_id"] == job_id
    assert len(report_result["findings"]) == 1
    assert "research_gap_coverage_appendix" in report_result

    # Check generated files in DATA_DIR
    json_path = DATA_DIR / f"report_{job_id}.json"
    html_path = DATA_DIR / f"report_{job_id}.html"
    pdf_path = DATA_DIR / f"secureassess_{job_id}.pdf"

    assert json_path.exists()
    assert html_path.exists()
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 1500


def test_api_report_endpoints(tmp_path):
    """Verifies that FastAPI delivers report.json, report.html, and report.pdf over HTTP."""
    client = TestClient(app)

    # 1. Start a scan to create state
    res = client.post("/scan", json={"target": "http://localhost:3000", "mode": "dast"})
    assert res.status_code == 202
    job_id = res.json()["job_id"]

    # 2. Query /scan/{job_id}/report.json
    res_json = client.get(f"/scan/{job_id}/report.json")
    assert res_json.status_code == 200
    data = res_json.json()
    assert "assessment_metadata" in data
    assert "metrics_summary" in data

    # 3. Query /scan/{job_id}/report.html
    res_html = client.get(f"/scan/{job_id}/report.html")
    assert res_html.status_code == 200
    assert "text/html" in res_html.headers.get("content-type", "")
    assert "SECUREASSESS" in res_html.text

    # 4. Query /scan/{job_id}/report.pdf
    res_pdf = client.get(f"/scan/{job_id}/report.pdf")
    assert res_pdf.status_code == 200
    assert res_pdf.headers.get("content-type") == "application/pdf"
    assert res_pdf.content[:5] == b"%PDF-"
