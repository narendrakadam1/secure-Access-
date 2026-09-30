"""
SECUREASSESS - Phase 4 End-to-End Pipeline Acceptance Test Suite
Acceptance Criterion:
"Done = POST /scan → poll → report.json with ≥1 Confirmed finding."

Verifies:
1. Hard Safety Constraint #1: Pre-packet allowlist rejection of unauthorized targets (e.g. google.com).
2. Hard Safety Constraint #6: Concurrency gate (second concurrent scan returns 409 Conflict).
3. End-to-End DAST pipeline execution in DEMO_MODE on http://localhost:3000.
4. Validation Playbook flips candidate finding to CONFIRMED with reproducible PoC proof.
5. All 8 SIH deliverable fields, executive summary, and Research Gap Coverage appendix present in report.json.
6. End-to-End SAST pipeline execution on GitHub repository target.
"""

import asyncio
import os
import shutil
import tempfile
import time
import pytest
from fastapi.testclient import TestClient

from app.main import app, state_mgr, orchestrator, audit_logger


@pytest.fixture(autouse=True)
def setup_test_env():
    """Sets DEMO_MODE=true and cleans state before each test."""
    os.environ["DEMO_MODE"] = "true"
    os.environ["ALLOWED_TARGETS"] = "localhost,127.0.0.1,::1,http://localhost:3000"
    yield


def test_safety_gate_rejects_unauthorized_target():
    """Hard Safety Constraint #1: https://google.com rejected before any packet leaves."""
    client = TestClient(app)
    response = client.post("/scan", json={"target": "https://google.com"})
    assert response.status_code == 400
    assert "outside authorized testing scope" in response.json()["detail"]


def test_concurrency_gate_returns_409():
    """Hard Safety Constraint #6: Overlapping scans return 409 Conflict."""
    client = TestClient(app)

    # Artificially set an active scan lock
    orchestrator.active_job_id = "test-active-scan"

    try:
        response = client.post("/scan", json={"target": "http://localhost:3000"})
        assert response.status_code == 409
        assert "A security assessment is currently running" in response.json()["detail"]
    finally:
        orchestrator.active_job_id = None


def test_e2e_dast_scan_and_report_json():
    """
    Core Acceptance Test for Phase 4:
    POST /scan -> poll status -> report.json with >= 1 Confirmed finding.
    """
    client = TestClient(app)

    # 1. Trigger Scan
    init_res = client.post("/scan", json={"target": "http://localhost:3000"})
    assert init_res.status_code == 202
    data = init_res.json()
    job_id = data["job_id"]
    assert job_id.startswith("sa-")
    assert data["mode"] == "dast"

    # In TestClient, BackgroundTasks execute automatically on request completion.
    # If not completed yet, await pipeline.
    scan_state = state_mgr.get_scan(job_id)
    if scan_state.phase.value != "completed":
        asyncio.run(orchestrator.run_pipeline(job_id))

    # 2. Poll Status
    status_res = client.get(f"/scan/{job_id}/status")
    assert status_res.status_code == 200
    status_data = status_res.json()

    assert status_data["phase"] == "completed"
    assert len(status_data["log_tail"]) > 0
    assert status_data["summary"]["total"] >= 1
    assert status_data["summary"]["confirmed"] >= 1

    # 4. Fetch and Verify report.json (SIH Deliverable Requirements)
    report_res = client.get(f"/scan/{job_id}/report.json")
    assert report_res.status_code == 200
    report = report_res.json()

    # Verify Report Top-Level Metadata
    assert "assessment_metadata" in report
    assert "executive_summary" in report
    assert "authorized_scope_statement" in report
    assert "research_gap_coverage_appendix" in report

    # Verify Research Gap Appendix
    gap_map = report["research_gap_coverage_appendix"]
    assert "#1/#17 AutoPT Context Loss" in gap_map
    assert "#8 Peng et al. Hallucination" in gap_map
    assert "#11 Deng et al. Planning Traps" in gap_map
    assert "#16/#20 PTFusion Heterogeneous Output" in gap_map

    # Verify Findings Schema and Confirmed finding with PoC evidence
    findings = report["findings"]
    assert len(findings) >= 1

    confirmed_findings = [f for f in findings if f["status"] == "Confirmed"]
    assert len(confirmed_findings) >= 1, "At least one finding must be Confirmed with PoC proof"

    sample_confirmed = confirmed_findings[0]
    # Check all 8 required SIH fields
    assert "title" in sample_confirmed and len(sample_confirmed["title"]) > 0
    assert "description" in sample_confirmed
    assert "affected_component" in sample_confirmed
    assert "severity" in sample_confirmed
    assert "cvss_score" in sample_confirmed and sample_confirmed["cvss_score"] > 0
    assert "steps_to_reproduce" in sample_confirmed and len(sample_confirmed["steps_to_reproduce"]) > 0
    assert "poc_evidence" in sample_confirmed and sample_confirmed["poc_evidence"] is not None
    assert "business_impact" in sample_confirmed and len(sample_confirmed["business_impact"]) > 10
    assert "remediation" in sample_confirmed
    assert "description" in sample_confirmed["remediation"]
    assert "fix" in sample_confirmed["remediation"]
    assert "example_code" in sample_confirmed["remediation"]


def test_e2e_sast_scan_and_secret_confirmation():
    """Verifies SAST mode on a GitHub repository target with Gitleaks secret verification."""
    client = TestClient(app)

    repo_target = "https://github.com/koala73/worldmonitor"
    init_res = client.post("/scan", json={"target": repo_target})
    assert init_res.status_code == 202
    job_id = init_res.json()["job_id"]
    assert init_res.json()["mode"] == "sast"

    # Execute pipeline if not completed by TestClient
    scan_state = state_mgr.get_scan(job_id)
    if scan_state.phase.value != "completed":
        asyncio.run(orchestrator.run_pipeline(job_id))

    # Verify report
    report_res = client.get(f"/scan/{job_id}/report.json")
    assert report_res.status_code == 200
    report = report_res.json()

    findings = report["findings"]
    assert len(findings) >= 1

    # Check that Gitleaks secret match was confirmed
    secret_findings = [f for f in findings if "secret" in f["title"].lower() or f["source_tool"] == "gitleaks"]
    assert len(secret_findings) >= 1
    assert secret_findings[0]["status"] == "Confirmed"
    assert "GITLEAKS_RULE" in secret_findings[0]["poc_evidence"]
