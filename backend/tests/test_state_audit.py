"""
Unit Tests for Phase 2: Models, SQLite Persistence Engine, and Audit Logger.
Satisfies Phase 2 Acceptance Criteria:
"Done = unit test: create job → write finding → reload from DB."
"""

import os
import shutil
import tempfile
import pytest

from app.models import (
    ScanMode,
    ScanPhase,
    FindingSeverity,
    FindingStatus,
    SIHScopeCategory,
    Remediation,
    Finding,
)
from app.state import StateManager
from app.audit import AuditLogger


@pytest.fixture
def temp_workspace():
    """Provides an isolated temporary directory for SQLite database and audit logs."""
    temp_dir = tempfile.mkdtemp()
    db_file = os.path.join(temp_dir, "test_secureassess.db")
    audit_dir = os.path.join(temp_dir, "audit_logs")
    yield db_file, audit_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_create_job_and_phase_progression(temp_workspace):
    """Verifies scan job creation and phase transitions in SQLite."""
    db_file, _ = temp_workspace
    state = StateManager(db_path=db_file)

    job_id = "test-job-001"
    target = "http://localhost:3000"
    scan_state = state.create_scan(job_id=job_id, target=target, mode=ScanMode.DAST)

    assert scan_state.job_id == job_id
    assert scan_state.target == target
    assert scan_state.mode == ScanMode.DAST
    assert scan_state.phase == ScanPhase.IDLE

    # Reload from DB
    reloaded = state.get_scan(job_id)
    assert reloaded is not None
    assert reloaded.job_id == job_id
    assert reloaded.phase == ScanPhase.IDLE

    # Update phase to SCANNING
    state.update_phase(job_id, ScanPhase.SCANNING)
    reloaded2 = state.get_scan(job_id)
    assert reloaded2.phase == ScanPhase.SCANNING


def test_agent_log_streaming(temp_workspace):
    """Verifies atomic sequential logging for the UI log stream."""
    db_file, _ = temp_workspace
    state = StateManager(db_path=db_file)

    job_id = "test-job-002"
    state.create_scan(job_id=job_id, target="http://localhost:3000", mode=ScanMode.DAST)

    seq1 = state.append_log(job_id, "Recon agent started", agent_name="ReconAgent")
    seq2 = state.append_log(job_id, "Probed port 3000: HTTP 200 OK", agent_name="ReconAgent")
    seq3 = state.append_log(job_id, "Scan agent starting ZAP baseline", agent_name="ScanAgent")

    assert seq1 == 1
    assert seq2 == 2
    assert seq3 == 3

    logs = state.get_logs(job_id, since_seq=0)
    assert len(logs) == 3
    assert logs[0].line == "Recon agent started"
    assert logs[0].agent_name == "ReconAgent"
    assert logs[2].seq == 3

    # Delta polling test
    delta_logs = state.get_logs(job_id, since_seq=2)
    assert len(delta_logs) == 1
    assert delta_logs[0].seq == 3


def test_tool_outputs_persistence(temp_workspace):
    """
    Verifies raw tool outputs are isolated in SQLite.
    Addresses Research Gap #1/#17 (AutoPT): Prevents token exhaustion in LLM context.
    """
    db_file, _ = temp_workspace
    state = StateManager(db_path=db_file)

    job_id = "test-job-003"
    state.create_scan(job_id=job_id, target="http://localhost:3000", mode=ScanMode.DAST)

    raw_zap_output = '{"@version": "2.14.0", "site": [{"@name": "http://localhost:3000", "alerts": []}]}'
    out_id = state.save_tool_output(job_id=job_id, tool_name="zap", raw_output=raw_zap_output, exit_code=0)
    assert out_id is not None

    outputs = state.get_tool_outputs(job_id=job_id, tool_name="zap")
    assert len(outputs) == 1
    assert outputs[0].tool_name == "zap"
    assert outputs[0].raw_output == raw_zap_output
    assert outputs[0].exit_code == 0


def test_write_finding_and_reload_from_db(temp_workspace):
    """
    Core Acceptance Test for Phase 2:
    Create Job -> Write Finding -> Reload from DB.
    Verifies all 15 Finding schema fields, nested objects, and types.
    """
    db_file, _ = temp_workspace
    state = StateManager(db_path=db_file)

    job_id = "test-job-004"
    state.create_scan(job_id=job_id, target="http://localhost:3000", mode=ScanMode.DAST)

    sample_finding = Finding(
        id="DAST-002",
        title="Cross-Site Scripting (XSS) Detection in Search Query",
        description="The 'q' parameter reflects unsanitized user input in the response body without HTML entity encoding.",
        affected_component="http://localhost:3000/?q=test",
        owasp_category="A03:2021-Injection",
        sih_scope_category=SIHScopeCategory.INPUT_VALIDATION,
        severity=FindingSeverity.HIGH,
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        status=FindingStatus.UNVERIFIED,
        confidence_pct=95,
        steps_to_reproduce=[
            "1. Navigate to http://localhost:3000/?q=<script>alert(1)</script>",
            "2. Observe unencoded script execution in the response body DOM context."
        ],
        poc_evidence=None,
        business_impact="An attacker can execute arbitrary JavaScript in the victim's session, potentially hijacking tokens or interacting with sensitive dashboard telemetry.",
        remediation=Remediation(
            description="Escape all user-controlled input before rendering into HTML templates.",
            fix="Employ context-aware contextual auto-escaping or encode special characters using html.escape().",
            example_code="from html import escape\nsafe_output = escape(user_input)"
        ),
        source_tool="owasp-zap",
        evidence=["Matched reflection in body: <script>alert(1)</script>"]
    )

    # 1. Write finding to SQLite
    state.save_finding(job_id=job_id, finding=sample_finding)

    # 2. Reload finding from SQLite
    reloaded_finding = state.get_finding(job_id=job_id, finding_id="DAST-002")
    assert reloaded_finding is not None

    # 3. Assert all 15 fields match exactly
    assert reloaded_finding.id == "DAST-002"
    assert reloaded_finding.title == sample_finding.title
    assert reloaded_finding.description == sample_finding.description
    assert reloaded_finding.affected_component == "http://localhost:3000/?q=test"
    assert reloaded_finding.owasp_category == "A03:2021-Injection"
    assert reloaded_finding.sih_scope_category == SIHScopeCategory.INPUT_VALIDATION
    assert reloaded_finding.severity == FindingSeverity.HIGH
    assert reloaded_finding.cvss_score == 7.5
    assert reloaded_finding.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    assert reloaded_finding.status == FindingStatus.UNVERIFIED
    assert reloaded_finding.confidence_pct == 95
    assert len(reloaded_finding.steps_to_reproduce) == 2
    assert reloaded_finding.poc_evidence is None
    assert "arbitrary JavaScript" in reloaded_finding.business_impact
    assert reloaded_finding.remediation.fix == sample_finding.remediation.fix
    assert reloaded_finding.remediation.example_code == sample_finding.remediation.example_code
    assert reloaded_finding.source_tool == "owasp-zap"
    assert len(reloaded_finding.evidence) == 1

    # 4. Update status to CONFIRMED with safe PoC verification proof (Research Gap #8)
    poc_proof = "HTTP/1.1 200 OK\nContent-Type: text/html\n\n...<div>sa_marker_7f3a</div>..."
    state.update_finding_status(
        job_id=job_id,
        finding_id="DAST-002",
        status=FindingStatus.CONFIRMED,
        poc_evidence=poc_proof,
        new_evidence="Verified safe marker reflection via GET /?q=sa_marker_7f3a"
    )

    confirmed_finding = state.get_finding(job_id=job_id, finding_id="DAST-002")
    assert confirmed_finding.status == FindingStatus.CONFIRMED
    assert confirmed_finding.poc_evidence == poc_proof
    assert len(confirmed_finding.evidence) == 2

    # 5. Check Summary metrics for SUDARSHAN counter cards
    summary = state.get_findings_summary(job_id=job_id)
    assert summary.total == 1
    assert summary.confirmed == 1
    assert summary.unverified == 0
    assert summary.high == 1


def test_audit_logger(temp_workspace):
    """
    Verifies Hard Safety Constraint #4:
    Audit log tracks target, timestamps, tool commands, and validation requests.
    """
    _, audit_dir = temp_workspace
    audit = AuditLogger(log_dir=audit_dir)

    job_id = "test-job-005"
    target = "http://localhost:3000"

    # Log scan initialization
    audit.log_scan_init(job_id=job_id, target=target, mode="dast")

    # Log tool command execution
    audit.log_tool_execution(
        job_id=job_id,
        tool_name="zap-baseline",
        command_line="zap-baseline.py -t http://localhost:3000 -J zap.json",
        exit_code=0,
        duration_s=12.4
    )

    # Log non-destructive validation request
    audit.log_validation_request(
        job_id=job_id,
        finding_id="DAST-001",
        playbook_check="missing-security-headers",
        method="GET",
        url="http://localhost:3000/",
        status_code=200,
        latency_ms=18.5,
        outcome="CONFIRMED",
        details={"missing_headers": ["Content-Security-Policy", "X-Frame-Options"]}
    )

    # Log scan completion
    audit.log_scan_completion(
        job_id=job_id,
        target=target,
        duration_s=45.2,
        summary={"total": 1, "confirmed": 1}
    )

    entries = audit.get_audit_entries(job_id)
    assert len(entries) == 4
    assert entries[0]["event"] == "SCAN_INIT"
    assert entries[0]["allowlist_gate_passed"] is True
    assert entries[1]["event"] == "TOOL_EXECUTION"
    assert "zap-baseline.py" in entries[1]["command"]
    assert entries[2]["event"] == "VALIDATION_REQUEST"
    assert entries[2]["outcome"] == "CONFIRMED"
    assert entries[3]["event"] == "SCAN_COMPLETION"
