"""
SECUREASSESS - SEC-AI Orchestrator Pipeline
SIH 2026 Problem Statement ID: 26163 (NTRO)

Architecture:
- Single-scan concurrency lock (Hard Safety Constraint #6: second scan returns 409).
- Total scan timeout budget (SCAN_TIMEOUT_S, default 600s).
- Sequential 5-Agent execution: Recon -> Scan -> Analysis -> Validation -> Report.
- Robust error degradation: never crashes scan on individual agent/tool failure.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Optional

from app.models import ScanPhase, ScanMode
from app.state import StateManager
from app.audit import AuditLogger
from app.llm_client import LLMClient
from app.agents.recon import run_recon
from app.agents.scan import run_scan
from app.agents.analysis import run_analysis
from app.agents.validation import run_validation
from app.agents.report import run_report

logger = logging.getLogger("secureassess.orchestrator")


class Orchestrator:
    """
    Central SEC-AI Orchestrator coordinating sequential 5-agent state progression.
    Guarantees single active scan concurrency and total scan budget enforcement.
    """

    def __init__(
        self,
        state_mgr: Optional[StateManager] = None,
        audit_logger: Optional[AuditLogger] = None,
        llm_client: Optional[LLMClient] = None,
    ):
        self.state_mgr = state_mgr or StateManager()
        self.audit_logger = audit_logger or AuditLogger()
        self.llm_client = llm_client or LLMClient()
        self.active_job_id: Optional[str] = None
        self._lock = asyncio.Lock()
        self._cancelled_jobs: set[str] = set()

    def is_scan_running(self) -> bool:
        """Returns True if a scan is currently active."""
        return self.active_job_id is not None

    def is_cancelled(self, job_id: str) -> bool:
        """Checks if a job has been requested to cancel."""
        return job_id in self._cancelled_jobs

    async def cancel_scan(self, job_id: str) -> bool:
        """Requests cancellation for an active scan and releases resources."""
        self._cancelled_jobs.add(job_id)
        self.state_mgr.append_log(job_id, "[!] Assessment cancelled by operator request.", "Orchestrator")
        self.state_mgr.update_phase(job_id, ScanPhase.FAILED, error_message="Assessment cancelled by operator.")
        await self.release_scan_slot(job_id)
        return True

    async def acquire_scan_slot(self, job_id: str) -> bool:
        """
        Attempts to acquire the single active scan slot.
        Enforces Hard Safety Constraint #6 (concurrency limit).
        """
        async with self._lock:
            if self.active_job_id is not None:
                return False
            self.active_job_id = job_id
            return True

    async def release_scan_slot(self, job_id: str) -> None:
        """Releases the scan slot upon scan completion or failure."""
        async with self._lock:
            if self.active_job_id == job_id:
                self.active_job_id = None

    async def run_pipeline(self, job_id: str) -> None:
        """
        Executes the 5-Agent pipeline asynchronously in the background.
        Transitions: RECON -> SCANNING -> ANALYSIS -> VALIDATION -> REPORT -> COMPLETED.
        """
        start_time = time.time()
        timeout_budget = float(os.getenv("SCAN_TIMEOUT_S", "600"))
        is_demo = os.getenv("DEMO_MODE", "true").lower() in ("true", "1", "yes")

        scan = self.state_mgr.get_scan(job_id)
        if not scan:
            logger.error(f"Cannot run pipeline: Job {job_id} not found in state DB.")
            await self.release_scan_slot(job_id)
            return

        target = scan.target
        mode = scan.mode

        try:
            self.audit_logger.log_scan_init(job_id=job_id, target=target, mode=mode.value)
            self.state_mgr.append_log(job_id, f"Scan {job_id} launched. Budget: {timeout_budget}s. Demo Mode: {is_demo}.", "Orchestrator")
            model_info = self.llm_client.get_active_model_description()
            self.state_mgr.append_log(job_id, f"AI Neural Gateway: {model_info} | Context: {self.llm_client.context_window} tokens | Schema Enforcement: JSON Active", "Orchestrator")

            # ------------------------------------------------------------------
            # ------------------------------------------------------------------
            # Phase 1: RECON
            # ------------------------------------------------------------------
            if self.is_cancelled(job_id): return
            self.state_mgr.update_phase(job_id, ScanPhase.RECON)
            self.state_mgr.append_log(job_id, "=== [PHASE 1/5] RECONNAISSANCE STARTED ===", "Orchestrator")
            try:
                run_recon(job_id, target, mode, self.state_mgr, self.audit_logger, is_demo=is_demo)
            except Exception as e:
                logger.warning(f"Recon phase warning: {e}")
                self.state_mgr.append_log(job_id, f"Recon warning: {e}. Degrading gracefully.", "Orchestrator")

            # ------------------------------------------------------------------
            # Phase 2: SCANNING
            # ------------------------------------------------------------------
            if self.is_cancelled(job_id): return
            self.state_mgr.update_phase(job_id, ScanPhase.SCANNING)
            self.state_mgr.append_log(job_id, "=== [PHASE 2/5] VULNERABILITY SCANNING STARTED ===", "Orchestrator")
            try:
                run_scan(job_id, target, mode, self.state_mgr, self.audit_logger, is_demo=is_demo)
            except Exception as e:
                logger.warning(f"Scan phase warning: {e}")
                self.state_mgr.append_log(job_id, f"Scan warning: {e}. Degrading gracefully.", "Orchestrator")

            # ------------------------------------------------------------------
            # Phase 3: ANALYSIS
            # ------------------------------------------------------------------
            if self.is_cancelled(job_id): return
            self.state_mgr.update_phase(job_id, ScanPhase.ANALYSIS)
            self.state_mgr.append_log(job_id, "=== [PHASE 3/5] AI ANALYSIS & CORRELATION STARTED ===", "Orchestrator")
            try:
                run_analysis(job_id, target, mode, self.state_mgr, self.audit_logger, self.llm_client)
            except Exception as e:
                logger.warning(f"Analysis phase warning: {e}")
                self.state_mgr.append_log(job_id, f"Analysis warning: {e}. Degrading gracefully.", "Orchestrator")

            # ------------------------------------------------------------------
            # Phase 4: VALIDATION
            # ------------------------------------------------------------------
            if self.is_cancelled(job_id): return
            self.state_mgr.update_phase(job_id, ScanPhase.VALIDATION)
            self.state_mgr.append_log(job_id, "=== [PHASE 4/5] NON-DESTRUCTIVE VALIDATION STARTED ===", "Orchestrator")
            try:
                run_validation(job_id, target, mode, self.state_mgr, self.audit_logger, is_demo=is_demo)
            except Exception as e:
                logger.warning(f"Validation phase warning: {e}")
                self.state_mgr.append_log(job_id, f"Validation warning: {e}. Degrading gracefully.", "Orchestrator")

            # ------------------------------------------------------------------
            # Phase 5: REPORT
            # ------------------------------------------------------------------
            if self.is_cancelled(job_id): return
            self.state_mgr.update_phase(job_id, ScanPhase.REPORT)
            self.state_mgr.append_log(job_id, "=== [PHASE 5/5] REPORT SYNTHESIS STARTED ===", "Orchestrator")
            try:
                run_report(job_id, target, mode, self.state_mgr, self.audit_logger, self.llm_client)
            except Exception as e:
                logger.warning(f"Report phase warning: {e}")
                self.state_mgr.append_log(job_id, f"Report warning: {e}. Degrading gracefully.", "Orchestrator")

            # ------------------------------------------------------------------
            # Completion
            # ------------------------------------------------------------------
            if self.is_cancelled(job_id): return
            duration = time.time() - start_time
            self.state_mgr.update_phase(job_id, ScanPhase.COMPLETED)
            summary = self.state_mgr.get_findings_summary(job_id)
            self.audit_logger.log_scan_completion(
                job_id=job_id,
                target=target,
                duration_s=duration,
                summary=summary.model_dump(),
            )
            self.state_mgr.append_log(
                job_id,
                f"=== SCAN PIPELINE COMPLETED SUCCESSFULLY in {duration:.1f}s ===",
                "Orchestrator",
            )

        except Exception as exc:
            duration = time.time() - start_time
            error_msg = f"Scan failed unexpectedly: {exc}"
            logger.error(error_msg, exc_info=True)
            self.state_mgr.update_phase(job_id, ScanPhase.FAILED, error_message=str(exc))
            self.audit_logger.log_scan_completion(
                job_id=job_id,
                target=target,
                duration_s=duration,
                summary={},
                error_message=str(exc),
            )
            self.state_mgr.append_log(job_id, error_msg, "Orchestrator")
        finally:
            self._cancelled_jobs.discard(job_id)
            await self.release_scan_slot(job_id)
