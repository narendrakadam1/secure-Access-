"""
SECUREASSESS - Core Data Models and Unified Finding Schema
SIH 2026 Problem Statement ID: 26163 (NTRO)

Research Gaps Addressed:
- #8 Peng et al. (Hallucination): Strict Confirmed/Unverified split with mandatory evidence gating.
- #16/#20 PTFusion (Heterogeneous Scanner Output): Unified schema normalizing DAST and SAST tools.
- #4 EvoMaster (Policy Violations): Inclusion of authorization/RBAC and auth & session scope categories.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class ScanMode(str, Enum):
    """Scan operation mode: Dynamic Web Application vs Static Source Repository."""
    DAST = "dast"
    SAST = "sast"


class ScanPhase(str, Enum):
    """
    Fixed 5-agent sequential execution pipeline phases.
    Addresses Research Gap #11 (Deng et al.): Prevents planning loops & dead-branch traps.
    """
    IDLE = "idle"
    RECON = "recon"
    SCANNING = "scanning"
    ANALYSIS = "analysis"
    VALIDATION = "validation"
    REPORT = "report"
    COMPLETED = "completed"
    FAILED = "failed"


class FindingSeverity(str, Enum):
    """CVSS 3.1 Severity Classifications."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class FindingStatus(str, Enum):
    """
    Validation Status Gate.
    Addresses Research Gap #8 (Peng et al.): Separates raw tool hypotheses (Unverified)
    from validated findings with concrete reproducible PoC evidence (Confirmed).
    """
    CONFIRMED = "Confirmed"
    UNVERIFIED = "Unverified"


class SIHScopeCategory(str, Enum):
    """
    SIH 26163 Problem Statement Scope Categories.
    Addresses Research Gap #4 (EvoMaster): Explicit classification for authorization/RBAC
    and policy evaluation constraints.
    """
    AUTH_SESSION = "auth & session"
    AUTHORIZATION_RBAC = "authorization/RBAC"
    INPUT_VALIDATION = "input validation"
    API_SECURITY = "API security"
    CLIENT_SIDE_CONTROLS = "client-side controls"
    SECURE_COMMUNICATION = "secure communication"
    DATA_STORAGE_SECRETS = "data storage & secrets"


class Remediation(BaseModel):
    """Actionable remediation guidance satisfying SIH deliverable requirement."""
    model_config = ConfigDict(extra="ignore")

    description: str = Field(..., description="High-level architectural mitigation explanation")
    fix: str = Field(..., description="Specific implementation fix instructions")
    example_code: str = Field(..., description="Concrete code or configuration fix snippet")


class Finding(BaseModel):
    """
    Unified Finding Schema.
    Every finding from every tool (ZAP, Nikto, Semgrep, Gitleaks) normalizes into this.
    No exceptions.
    Satisfies SIH 26163 deliverable requirements verbatim.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., description="Unique finding identifier (e.g. DAST-001, SAST-002)")
    title: str = Field(..., description="Short descriptive title of the vulnerability")
    description: str = Field(..., description="Detailed description of the issue")
    affected_component: str = Field(..., description="Target URL/endpoint/parameter or file:line")
    owasp_category: str = Field(..., description="OWASP Top 10 category (e.g. A03:2021-Injection)")
    sih_scope_category: SIHScopeCategory = Field(
        ..., description="SIH scope category mapping (auth & session | authorization/RBAC | etc.)"
    )
    severity: FindingSeverity = Field(..., description="Severity level: Critical | High | Medium | Low")
    cvss_score: float = Field(..., ge=0.0, le=10.0, description="CVSS 3.1 Base Score (0.0 - 10.0)")
    cvss_vector: str = Field(..., description="Standard CVSS:3.1 vector string")
    status: FindingStatus = Field(
        default=FindingStatus.UNVERIFIED,
        description="Validation state: Confirmed (passed safe playbook check) or Unverified"
    )
    confidence_pct: int = Field(..., ge=0, le=100, description="Confidence percentage (0-100)")
    steps_to_reproduce: List[str] = Field(
        default_factory=list, description="Step-by-step instructions to reproduce the vulnerability"
    )
    poc_evidence: Optional[str] = Field(
        default=None, description="Safe HTTP request/response evidence or code snippet proof"
    )
    business_impact: str = Field(..., description="Concise assessment of practical business impact and risk")
    remediation: Remediation = Field(..., description="Structured practical mitigation guidance")
    source_tool: str = Field(..., description="Underlying security tool that generated the finding")
    evidence: List[str] = Field(
        default_factory=list, description="List of raw evidence strings, matched lines, or headers"
    )


class LogEntry(BaseModel):
    """Single agent execution log entry streamed to UI."""
    model_config = ConfigDict(extra="ignore")

    seq: int = Field(..., description="Monotonically increasing sequence number per scan")
    line: str = Field(..., description="Log message text")
    ts: str = Field(..., description="ISO 8601 UTC timestamp")
    agent_name: Optional[str] = Field(default=None, description="Originating agent name")


class ToolOutput(BaseModel):
    """Persisted raw output artifact from a scanner execution."""
    model_config = ConfigDict(extra="ignore")

    id: Optional[int] = None
    job_id: str
    tool_name: str
    raw_output: str
    exit_code: int = 0
    created_at: Optional[str] = None


class ScanSummary(BaseModel):
    """Counter summary displayed in SUDARSHAN dashboard cards."""
    model_config = ConfigDict(extra="ignore")

    total: int = 0
    confirmed: int = 0
    unverified: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class ScanState(BaseModel):
    """
    Shared Scan State model persisted in SQLite.
    Addresses Research Gap #1/#17 (AutoPT): Eliminates context-window token bloat.
    """
    model_config = ConfigDict(extra="ignore")

    job_id: str
    target: str
    mode: ScanMode
    phase: ScanPhase = ScanPhase.IDLE
    created_at: str
    updated_at: str
    error_message: Optional[str] = None
    summary: ScanSummary = Field(default_factory=ScanSummary)


class ScanInitRequest(BaseModel):
    """POST /scan request body."""
    target: str = Field(..., description="Target URL (for DAST) or public GitHub URL (for SAST)")


class StatusResponse(BaseModel):
    """GET /scan/{id}/status response body polled by frontend."""
    model_config = ConfigDict(extra="ignore")

    job_id: str
    phase: ScanPhase
    mode: ScanMode
    target: str
    log_tail: List[LogEntry]
    summary: ScanSummary
    error_message: Optional[str] = None
