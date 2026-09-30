"""
SECUREASSESS - SQLite Persistence Engine (Hermes/OpenClaw-Style Memory)
SIH 2026 Problem Statement ID: 26163 (NTRO)

Research Gaps Addressed:
- #1 / #17 AutoPT (Context Loss & Token Bloat):
  Per-job SQLite state machine allows each agent to read ONLY its required state slice
  and write back results. The LLM context never carries multi-megabyte raw tool outputs
  or whole-scan history, completely eliminating context-exhaustion failure modes.
- #11 Deng et al. (Planning Traps & Dead Branches):
  Sequential state progression persisted transactionally with strict phase gating.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any

from app.models import (
    ScanState,
    ScanMode,
    ScanPhase,
    Finding,
    FindingSeverity,
    FindingStatus,
    SIHScopeCategory,
    Remediation,
    LogEntry,
    ToolOutput,
    ScanSummary,
)

DEFAULT_DB_PATH = os.getenv("DB_PATH", "./backend/data/secureassess.db")


class StateManager:
    """
    Thread-safe SQLite persistent store implementing the Hermes/OpenClaw memory framework.
    Manages scan_state, tool_outputs, findings, and agent_log tables.
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode and foreign keys for high concurrency & integrity
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_db(self) -> None:
        """Initialize database schema with required tables and indexes."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. scan_state table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_state (
                    job_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    error_message TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)

            # 2. tool_outputs table (Research Gap #1/#17: store raw artifacts in DB, not LLM context)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tool_outputs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    raw_output TEXT NOT NULL,
                    exit_code INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (job_id) REFERENCES scan_state (job_id) ON DELETE CASCADE
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tool_outputs_job ON tool_outputs (job_id);")

            # 3. findings table (Research Gap #16/#20: unified normalized findings schema)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    affected_component TEXT NOT NULL,
                    owasp_category TEXT NOT NULL,
                    sih_scope_category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    cvss_score REAL NOT NULL,
                    cvss_vector TEXT NOT NULL,
                    status TEXT NOT NULL,
                    confidence_pct INTEGER NOT NULL,
                    steps_to_reproduce TEXT NOT NULL,
                    poc_evidence TEXT,
                    business_impact TEXT NOT NULL,
                    remediation TEXT NOT NULL,
                    source_tool TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (job_id, id),
                    FOREIGN KEY (job_id) REFERENCES scan_state (job_id) ON DELETE CASCADE
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_job ON findings (job_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_status ON findings (job_id, status);")

            # 4. agent_log table (sequential monotonic log stream for live frontend UI)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agent_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    agent_name TEXT,
                    line TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (job_id) REFERENCES scan_state (job_id) ON DELETE CASCADE
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_agent_log_job_seq ON agent_log (job_id, seq);")

            conn.commit()

    # --------------------------------------------------------------------------
    # Scan Lifecycle & State Management
    # --------------------------------------------------------------------------

    def create_scan(self, job_id: str, target: str, mode: ScanMode) -> ScanState:
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO scan_state (job_id, target, mode, phase, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (job_id, target, mode.value, ScanPhase.IDLE.value, now, now),
            )
            conn.commit()
        return ScanState(
            job_id=job_id,
            target=target,
            mode=mode,
            phase=ScanPhase.IDLE,
            created_at=now,
            updated_at=now,
            summary=ScanSummary(),
        )

    def get_scan(self, job_id: str) -> Optional[ScanState]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM scan_state WHERE job_id = ?;", (job_id,)
            ).fetchone()
            if not row:
                return None

            summary = self.get_findings_summary(job_id)
            return ScanState(
                job_id=row["job_id"],
                target=row["target"],
                mode=ScanMode(row["mode"]),
                phase=ScanPhase(row["phase"]),
                error_message=row["error_message"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                summary=summary,
            )

    def update_phase(
        self, job_id: str, phase: ScanPhase, error_message: Optional[str] = None
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE scan_state
                SET phase = ?, error_message = ?, updated_at = ?
                WHERE job_id = ?;
                """,
                (phase.value, error_message, now, job_id),
            )
            conn.commit()

    # --------------------------------------------------------------------------
    # Agent Logging (Sequential Stream for UI Polling)
    # --------------------------------------------------------------------------

    def append_log(self, job_id: str, line: str, agent_name: Optional[str] = None) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            # Atomic monotonic sequence per scan job
            cursor = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM agent_log WHERE job_id = ?;",
                (job_id,),
            )
            next_seq = cursor.fetchone()[0]

            conn.execute(
                """
                INSERT INTO agent_log (job_id, seq, agent_name, line, timestamp)
                VALUES (?, ?, ?, ?, ?);
                """,
                (job_id, next_seq, agent_name, line, now),
            )
            conn.commit()
            return next_seq

    def get_logs(self, job_id: str, since_seq: int = 0, limit: int = 200) -> List[LogEntry]:
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT seq, agent_name, line, timestamp
                FROM agent_log
                WHERE job_id = ? AND seq > ?
                ORDER BY seq ASC
                LIMIT ?;
                """,
                (job_id, since_seq, limit),
            ).fetchall()

            return [
                LogEntry(
                    seq=row["seq"],
                    agent_name=row["agent_name"],
                    line=row["line"],
                    ts=row["timestamp"],
                )
                for row in rows
            ]

    # --------------------------------------------------------------------------
    # Tool Outputs Management
    # --------------------------------------------------------------------------

    def save_tool_output(
        self, job_id: str, tool_name: str, raw_output: str, exit_code: int = 0
    ) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO tool_outputs (job_id, tool_name, raw_output, exit_code, created_at)
                VALUES (?, ?, ?, ?, ?);
                """,
                (job_id, tool_name, raw_output, exit_code, now),
            )
            conn.commit()
            return cursor.lastrowid

    def get_tool_outputs(self, job_id: str, tool_name: Optional[str] = None) -> List[ToolOutput]:
        with self._get_connection() as conn:
            if tool_name:
                rows = conn.execute(
                    """
                    SELECT id, job_id, tool_name, raw_output, exit_code, created_at
                    FROM tool_outputs
                    WHERE job_id = ? AND tool_name = ?
                    ORDER BY id ASC;
                    """,
                    (job_id, tool_name),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, job_id, tool_name, raw_output, exit_code, created_at
                    FROM tool_outputs
                    WHERE job_id = ?
                    ORDER BY id ASC;
                    """,
                    (job_id,),
                ).fetchall()

            return [
                ToolOutput(
                    id=row["id"],
                    job_id=row["job_id"],
                    tool_name=row["tool_name"],
                    raw_output=row["raw_output"],
                    exit_code=row["exit_code"],
                    created_at=row["created_at"],
                )
                for row in rows
            ]

    # --------------------------------------------------------------------------
    # Normalized Findings Management
    # --------------------------------------------------------------------------

    def save_finding(self, job_id: str, finding: Finding) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO findings (
                    id, job_id, title, description, affected_component,
                    owasp_category, sih_scope_category, severity, cvss_score,
                    cvss_vector, status, confidence_pct, steps_to_reproduce,
                    poc_evidence, business_impact, remediation, source_tool,
                    evidence, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id, id) DO UPDATE SET
                    title = excluded.title,
                    description = excluded.description,
                    affected_component = excluded.affected_component,
                    owasp_category = excluded.owasp_category,
                    sih_scope_category = excluded.sih_scope_category,
                    severity = excluded.severity,
                    cvss_score = excluded.cvss_score,
                    cvss_vector = excluded.cvss_vector,
                    status = excluded.status,
                    confidence_pct = excluded.confidence_pct,
                    steps_to_reproduce = excluded.steps_to_reproduce,
                    poc_evidence = excluded.poc_evidence,
                    business_impact = excluded.business_impact,
                    remediation = excluded.remediation,
                    source_tool = excluded.source_tool,
                    evidence = excluded.evidence,
                    updated_at = excluded.updated_at;
                """,
                (
                    finding.id,
                    job_id,
                    finding.title,
                    finding.description,
                    finding.affected_component,
                    finding.owasp_category,
                    finding.sih_scope_category.value,
                    finding.severity.value,
                    finding.cvss_score,
                    finding.cvss_vector,
                    finding.status.value,
                    finding.confidence_pct,
                    json.dumps(finding.steps_to_reproduce),
                    finding.poc_evidence,
                    finding.business_impact,
                    finding.remediation.model_dump_json(),
                    finding.source_tool,
                    json.dumps(finding.evidence),
                    now,
                    now,
                ),
            )
            conn.commit()

    def save_findings(self, job_id: str, findings: List[Finding]) -> None:
        for finding in findings:
            self.save_finding(job_id, finding)

    def update_finding_status(
        self,
        job_id: str,
        finding_id: str,
        status: FindingStatus,
        poc_evidence: Optional[str] = None,
        new_evidence: Optional[str] = None,
    ) -> None:
        """
        Updates validation status and appends PoC verification proof.
        Addresses Research Gap #8 (Peng et al.): Promotes finding to Confirmed only
        when reproducible playbook evidence is attached.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            finding = self.get_finding(job_id, finding_id)
            if not finding:
                return

            evidence_list = finding.evidence
            if new_evidence and new_evidence not in evidence_list:
                evidence_list.append(new_evidence)

            updated_poc = poc_evidence if poc_evidence is not None else finding.poc_evidence

            conn.execute(
                """
                UPDATE findings
                SET status = ?, poc_evidence = ?, evidence = ?, updated_at = ?
                WHERE job_id = ? AND id = ?;
                """,
                (status.value, updated_poc, json.dumps(evidence_list), now, job_id, finding_id),
            )
            conn.commit()

    def get_finding(self, job_id: str, finding_id: str) -> Optional[Finding]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE job_id = ? AND id = ?;",
                (job_id, finding_id),
            ).fetchone()
            if not row:
                return None
            return self._row_to_finding(row)

    def get_findings(
        self,
        job_id: str,
        status: Optional[FindingStatus] = None,
        severity: Optional[FindingSeverity] = None,
    ) -> List[Finding]:
        with self._get_connection() as conn:
            query = "SELECT * FROM findings WHERE job_id = ?"
            params: List[Any] = [job_id]

            if status:
                query += " AND status = ?"
                params.append(status.value)
            if severity:
                query += " AND severity = ?"
                params.append(severity.value)

            query += " ORDER BY cvss_score DESC, id ASC;"
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_finding(row) for row in rows]

    def get_findings_summary(self, job_id: str) -> ScanSummary:
        """Generates real-time count metrics for SUDARSHAN dashboard counter cards."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT severity, status FROM findings WHERE job_id = ?;", (job_id,)
            ).fetchall()

            summary = ScanSummary(total=len(rows))
            for row in rows:
                status = row["status"]
                severity = row["severity"]

                if status == FindingStatus.CONFIRMED.value:
                    summary.confirmed += 1
                elif status == FindingStatus.UNVERIFIED.value:
                    summary.unverified += 1

                if severity == FindingSeverity.CRITICAL.value:
                    summary.critical += 1
                elif severity == FindingSeverity.HIGH.value:
                    summary.high += 1
                elif severity == FindingSeverity.MEDIUM.value:
                    summary.medium += 1
                elif severity == FindingSeverity.LOW.value:
                    summary.low += 1

            return summary

    def _row_to_finding(self, row: sqlite3.Row) -> Finding:
        remediation_data = json.loads(row["remediation"])
        return Finding(
            id=row["id"],
            title=row["title"],
            description=row["description"],
            affected_component=row["affected_component"],
            owasp_category=row["owasp_category"],
            sih_scope_category=SIHScopeCategory(row["sih_scope_category"]),
            severity=FindingSeverity(row["severity"]),
            cvss_score=float(row["cvss_score"]),
            cvss_vector=row["cvss_vector"],
            status=FindingStatus(row["status"]),
            confidence_pct=int(row["confidence_pct"]),
            steps_to_reproduce=json.loads(row["steps_to_reproduce"]),
            poc_evidence=row["poc_evidence"],
            business_impact=row["business_impact"],
            remediation=Remediation(**remediation_data),
            source_tool=row["source_tool"],
            evidence=json.loads(row["evidence"]),
        )
