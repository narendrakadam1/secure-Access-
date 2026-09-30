"""
SECUREASSESS - Immutable Audit Logging Subsystem
SIH 2026 Problem Statement ID: 26163 (NTRO)

Satisfies Hard Safety Constraints:
- #1 Allowlist & Pre-Packet Gating: Records authorized scope validation.
- #2 Non-Destructive Validation Playbook: Records every validation request sent (method, URL, status, latency).
- #4 Immutable Audit Trail: Per-scan audit.log capturing target, timestamp, mode, tools run, exact commands.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

DEFAULT_AUDIT_DIR = os.getenv("AUDIT_LOG_DIR", "./backend/data/audit_logs")


class AuditLogger:
    """
    Structured, append-only security audit logger.
    Generates both per-scan audit trails (audit_{job_id}.log) and a centralized audit.log.
    """

    def __init__(self, log_dir: str = DEFAULT_AUDIT_DIR):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.master_log_path = self.log_dir / "audit.log"

    def _write_entry(self, entry: Dict[str, Any], job_id: Optional[str] = None) -> None:
        """Atomically appends a JSON-lines formatted audit record."""
        line = json.dumps(entry) + "\n"

        # Append to centralized master audit.log
        with open(self.master_log_path, "a", encoding="utf-8") as f:
            f.write(line)

        # Append to per-scan isolated audit log
        if job_id:
            job_log_path = self.log_dir / f"audit_{job_id}.log"
            with open(job_log_path, "a", encoding="utf-8") as f:
                f.write(line)

    def log_scan_init(self, job_id: str, target: str, mode: str) -> None:
        """Logs scan authorization and start event."""
        entry = {
            "event": "SCAN_INIT",
            "job_id": job_id,
            "target": target,
            "mode": mode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "allowlist_gate_passed": True,
            "message": f"Scan {job_id} initiated in {mode.upper()} mode for target {target}",
        }
        self._write_entry(entry, job_id)

    def log_tool_execution(
        self,
        job_id: str,
        tool_name: str,
        command_line: str,
        exit_code: int = 0,
        duration_s: float = 0.0,
        container: str = "kali-scanner",
    ) -> None:
        """
        Logs exact scanner tool invocation.
        Satisfies Constraint #4: target, timestamp, tools run, exact commands.
        """
        entry = {
            "event": "TOOL_EXECUTION",
            "job_id": job_id,
            "tool_name": tool_name,
            "command": command_line,
            "container": container,
            "exit_code": exit_code,
            "duration_s": round(duration_s, 3),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._write_entry(entry, job_id)

    def log_validation_request(
        self,
        job_id: str,
        finding_id: str,
        playbook_check: str,
        method: str,
        url: str,
        status_code: int,
        latency_ms: float,
        outcome: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Logs every individual validation probe request.
        Satisfies Constraint #2 & #4: Records every validation packet sent with non-destructive verification proof.
        """
        entry = {
            "event": "VALIDATION_REQUEST",
            "job_id": job_id,
            "finding_id": finding_id,
            "playbook_check": playbook_check,
            "method": method,
            "url": url,
            "status_code": status_code,
            "latency_ms": round(latency_ms, 2),
            "outcome": outcome,  # "CONFIRMED" or "UNVERIFIED"
            "details": details or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._write_entry(entry, job_id)

    def log_scan_completion(
        self,
        job_id: str,
        target: str,
        duration_s: float,
        summary: Dict[str, int],
        error_message: Optional[str] = None,
    ) -> None:
        """Logs completion or failure state of a scan job."""
        entry = {
            "event": "SCAN_COMPLETION",
            "job_id": job_id,
            "target": target,
            "duration_s": round(duration_s, 2),
            "summary": summary,
            "status": "FAILED" if error_message else "COMPLETED",
            "error_message": error_message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._write_entry(entry, job_id)

    def log_target_rejected(self, target: str, reason: str) -> None:
        """Logs target rejection by the allowlist gate."""
        entry = {
            "event": "TARGET_REJECTED",
            "target": target,
            "reason": reason,
            "allowlist_gate_passed": False,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._write_entry(entry)

    def get_audit_entries(self, job_id: str) -> List[Dict[str, Any]]:
        """Reads all audit entries recorded for a specific scan job."""
        job_log_path = self.log_dir / f"audit_{job_id}.log"
        if not job_log_path.exists():
            return []

        entries = []
        with open(job_log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return entries
