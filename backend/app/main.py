"""
SECUREASSESS - FastAPI Backend Application Entrypoint
SIH 2026 Problem Statement ID: 26163 (NTRO)

Endpoints:
- POST /scan              Initiates scan pipeline after allowlist & concurrency gate
- GET  /scan/{id}/status  Real-time phase stepper and agent log tail for SUDARSHAN UI
- GET  /scan/{id}/report.json  Normalized SIH deliverable JSON report
- GET  /scan/{id}/report.html  SUDARSHAN-styled HTML report
- GET  /scan/{id}/report.pdf   Downloadable PDF report (secureassess_<id>.pdf)
"""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse, Response

from app.models import (
    ScanInitRequest,
    ModelSelectionRequest,
    StatusResponse,
    ScanPhase,
    ScanMode,
)
from app.state import StateManager
from app.audit import AuditLogger
from app.llm_client import LLMClient
from app.safety import validate_target_allowed
from app.orchestrator import Orchestrator
from app.reporting.generator import ReportGenerator

app = FastAPI(
    title="SECUREASSESS API",
    description="Autonomous Web-Application Security Assessment Platform (SIH 2026 PS 26163)",
    version="0.1.0",
)

# Enable CORS for frontend dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auto-load variables from .env if present
def _load_env_config():
    for candidate in [
        Path(__file__).resolve().parent.parent.parent / ".env",
        Path(__file__).resolve().parent.parent / ".env",
        Path.cwd() / ".env",
    ]:
        if candidate.exists():
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    for line in f:
                        sline = line.strip()
                        if sline and not sline.startswith("#") and "=" in sline:
                            k, v = sline.split("=", 1)
                            k, v = k.strip(), v.strip().strip('"').strip("'")
                            if k and k not in os.environ:
                                os.environ[k] = v
                break
            except Exception:
                pass

_load_env_config()

# Initialize singletons
state_mgr = StateManager()
audit_logger = AuditLogger()
llm_client = LLMClient()
orchestrator = Orchestrator(state_mgr=state_mgr, audit_logger=audit_logger, llm_client=llm_client)
report_generator = ReportGenerator()

DATA_DIR = Path(__file__).resolve().parent.parent / "data"



@app.get("/health")
def health_check():
    """Service health check endpoint."""
    return {
        "status": "healthy",
        "demo_mode": os.getenv("DEMO_MODE", "true").lower() in ("true", "1", "yes"),
        "scan_running": orchestrator.is_scan_running(),
        "active_model": llm_client.get_active_model_description(),
    }


@app.get("/models")
def get_available_models():
    """
    Returns detected local Ollama models (e.g. qwen3.5:4b, gemma2:9b)
    and cloud model readiness status.
    """
    return llm_client.get_model_catalog()


@app.post("/models/select")
def select_model(payload: ModelSelectionRequest):
    """
    Switches active AI model dynamically or configures cloud API key.
    """
    if payload.cloud_api_key:
        llm_client.set_cloud_key(payload.cloud_api_key)
    if payload.model:
        llm_client.set_model(payload.model)
    return {
        "status": "success",
        "active_model": llm_client.get_active_model_description(),
        "catalog": llm_client.get_model_catalog(),
    }


@app.post("/scan", status_code=202)
async def start_scan(request: ScanInitRequest, background_tasks: BackgroundTasks):
    """
    Initiates an autonomous security assessment.
    
    Hard Safety Constraints Enforced:
    1. Pre-Packet Allowlist Gate: Disallows external unlisted targets before transmission.
    6. Concurrency Gate: Rejects overlapping scans with 409 Conflict.
    """
    raw_target = request.target.strip()
    target = raw_target
    digits_only = re.sub(r"[^\d]", "", target)
    if target.isdigit() or (target.startswith(":") and target[1:].isdigit()):
        target = f"http://localhost:{target.lstrip(':')}"
    elif target.lower().startswith("port") and digits_only:
        target = f"http://localhost:{digits_only}"
    elif not target.startswith("http://") and not target.startswith("https://") and "github.com" not in target.lower():
        target = f"http://{target}"

    # Configure selected model if provided
    if request.model:
        llm_client.set_model(request.model)

    # 1. Allowlist Gate (Constraint #1)
    is_allowed, reason, mode = validate_target_allowed(target)
    if not is_allowed:
        audit_logger.log_target_rejected(target, reason)
        raise HTTPException(status_code=400, detail=reason)

    # 2. Concurrency Check (Constraint #6)
    job_id = f"sa-{uuid.uuid4().hex[:8]}"
    acquired = await orchestrator.acquire_scan_slot(job_id)
    if not acquired:
        raise HTTPException(
            status_code=409,
            detail="A security assessment is currently running. Under Safety Constraint #6, only one scan at a time is permitted.",
        )

    # 3. Create Scan State in SQLite (Research Gap #1/#17)
    state_mgr.create_scan(job_id=job_id, target=target, mode=mode)

    # 4. Launch 5-Agent Background Pipeline
    background_tasks.add_task(orchestrator.run_pipeline, job_id)

    return {
        "job_id": job_id,
        "status": "initiated",
        "mode": mode.value,
        "target": target,
        "model": llm_client.get_active_model_description(),
        "message": f"Scan pipeline queued for target: {target} (Mode: {mode.value.upper()}) using {llm_client.get_active_model_description()}",
    }


@app.post("/scan/{job_id}/cancel")
async def cancel_scan(job_id: str):
    """Cancels a currently active scan job immediately."""
    cancelled = await orchestrator.cancel_scan(job_id)
    if not cancelled:
        scan = state_mgr.get_scan(job_id)
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan job '{job_id}' not found.")
        return {
            "status": "not_running",
            "job_id": job_id,
            "message": "Assessment is not currently running or already completed.",
        }
    return {
        "status": "cancelled",
        "job_id": job_id,
        "message": "Assessment cancelled successfully.",
    }


@app.get("/scan/{job_id}/status", response_model=StatusResponse)
def get_scan_status(
    job_id: str,
    since_seq: int = Query(default=0, ge=0, description="Retrieve log items with sequence greater than this"),
):
    """
    Streams phase state and sequential log lines to the SUDARSHAN dashboard UI.
    Polled every 2 seconds by frontend.
    """
    scan = state_mgr.get_scan(job_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan job '{job_id}' not found.")

    log_tail = state_mgr.get_logs(job_id=job_id, since_seq=since_seq, limit=500)
    summary = state_mgr.get_findings_summary(job_id)

    return StatusResponse(
        job_id=scan.job_id,
        phase=scan.phase,
        mode=scan.mode,
        target=scan.target,
        log_tail=log_tail,
        summary=summary,
        error_message=scan.error_message,
    )


def _get_or_build_report_data(job_id: str) -> dict:
    """Helper to retrieve existing report JSON or construct normalized report data on demand."""
    report_file = DATA_DIR / f"report_{job_id}.json"
    if report_file.exists():
        with open(report_file, "r", encoding="utf-8") as f:
            return json.load(f)

    scan = state_mgr.get_scan(job_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan job '{job_id}' not found.")

    findings = [f.model_dump() for f in state_mgr.get_findings(job_id)]
    summary = state_mgr.get_findings_summary(job_id)
    audit_entries = audit_logger.get_audit_entries(job_id)

    return {
        "assessment_metadata": {
            "platform": "SECUREASSESS - Autonomous Web-Application Security Assessment Platform",
            "framework": "Autonomous Enterprise Security Assessment Standard",
            "job_id": scan.job_id,
            "target": scan.target,
            "mode": scan.mode.value.upper(),
            "scan_status": scan.phase.value,
            "timestamp": scan.created_at.isoformat(),
            "demo_mode_active": True,
        },
        "authorized_scope_statement": (
            f"Authorized Security Assessment executed under Enterprise Cybersecurity Guidelines. "
            f"Assessment restricted to target '{scan.target}'."
        ),
        "executive_summary": (
            f"SECUREASSESS conducted an autonomous {scan.mode.value.upper()} assessment of target '{scan.target}'. "
            f"Total findings: {summary.total} ({summary.confirmed} confirmed, {summary.unverified} unverified)."
        ),
        "metrics_summary": summary.model_dump(),
        "findings": findings,
        "audit_trail": audit_entries,
        "research_gap_coverage_appendix": {
            "#1/#17 AutoPT Context Loss": "Per-job SQLite persistent state machine; agents access isolated slices to prevent LLM token exhaustion.",
            "#8 Peng et al. Hallucination": "Confirmed/Unverified split with mandatory non-destructive evidence gating.",
            "#11 Deng et al. Planning Traps": "Fixed sequential 5-agent pipeline; exactly one bounded HTTP check per finding.",
            "#16/#20 PTFusion Heterogeneous Output": "Deterministic per-tool normalization layer feeding a unified LLM deduplication pass.",
            "#13/#19 Alazmi Scanner Limits": "Multi-tool fusion integrating OWASP ZAP + Nikto (DAST) and Semgrep + Gitleaks (SAST).",
            "#4 EvoMaster Policy Violations": "Explicit classification of authorization/RBAC and auth & session scope categories.",
            "#3 Kalopisis Browser/DOM Blind Spot": "Client-side DOM XSS covered via Semgrep TS/JS rules today; headless browser agent marked as Future Work."
        },
    }


@app.get("/scan/{job_id}/report.json")
def get_report_json(job_id: str):
    """
    Returns full normalized SIH deliverable report JSON.
    Contains all 8 deliverable fields, evidence, audit trail, and research gap appendix.
    """
    return _get_or_build_report_data(job_id)


@app.get("/scan/{job_id}/report.html")
def get_report_html(job_id: str):
    """Returns HTML representation of report rendered with SUDARSHAN styling."""
    html_file = DATA_DIR / f"report_{job_id}.html"
    if html_file.exists():
        with open(html_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())

    report_data = _get_or_build_report_data(job_id)
    html_content = report_generator.render_html(report_data)
    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    return HTMLResponse(content=html_content)


@app.get("/scan/{job_id}/report.pdf")
def get_report_pdf(job_id: str):
    """Downloads report PDF (filename secureassess_<jobid>.pdf)."""
    pdf_filename = f"secureassess_{job_id}.pdf"
    pdf_path = DATA_DIR / pdf_filename

    if not pdf_path.exists():
        report_data = _get_or_build_report_data(job_id)
        report_generator.render_pdf(report_data, pdf_path)

    return FileResponse(
        path=str(pdf_path),
        filename=pdf_filename,
        media_type="application/pdf",
    )


# Convenience routes for latest/standard reports
@app.get("/report.json")
def get_latest_report_json():
    """Serves latest standard report JSON deliverable."""
    standard_file = DATA_DIR / "report.json"
    if standard_file.exists():
        with open(standard_file, "r", encoding="utf-8") as f:
            return json.load(f)
    raise HTTPException(status_code=404, detail="No scan report JSON has been generated yet.")


@app.get("/report.html")
def get_latest_report_html():
    """Serves latest standard report HTML deliverable."""
    standard_file = DATA_DIR / "report.html"
    if standard_file.exists():
        with open(standard_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    
    # Dynamic generation from latest report.json
    json_file = DATA_DIR / "report.json"
    if json_file.exists():
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        html_content = report_generator.render_html(data)
        with open(standard_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        return HTMLResponse(content=html_content)

    raise HTTPException(status_code=404, detail="No scan report HTML has been generated yet.")


@app.get("/report.pdf")
def get_latest_report_pdf():
    """Serves latest standard report PDF deliverable."""
    standard_file = DATA_DIR / "secureassess.pdf"
    if not standard_file.exists():
        json_file = DATA_DIR / "report.json"
        if json_file.exists():
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            report_generator.render_pdf(data, standard_file)

    if standard_file.exists():
        return FileResponse(
            path=str(standard_file),
            filename="secureassess.pdf",
            media_type="application/pdf",
        )
    raise HTTPException(status_code=404, detail="No scan report PDF has been generated yet.")

