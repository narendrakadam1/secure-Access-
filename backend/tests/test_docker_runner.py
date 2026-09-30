"""
SECUREASSESS - Phase 5 Docker Scanner Runner Unit & Integration Tests
Acceptance Criterion:
"Done = live scan of a local dummy target completes; failure degrades to warning if Docker absent."

Verifies:
1. DockerScannerRunner reports False and degrades when Docker daemon/container is offline.
2. Graceful degradation to fallback artifacts when Docker is absent (Constraint #6).
3. Mock container execution verifying DAST (ZAP, Nikto) and SAST (Semgrep, Gitleaks) command dispatch.
"""

import io
import tarfile
import pytest
from unittest.mock import patch, MagicMock

from app.models import ScanMode
from app.state import StateManager
from app.audit import AuditLogger
from app.scanners.docker_runner import DockerScannerRunner
from app.agents.scan import run_scan


def test_docker_runner_degrades_when_docker_absent(tmp_path):
    """Verifies runner safely returns False when Docker daemon is not running."""
    runner = DockerScannerRunner(container_name="nonexistent-kali-container")
    assert runner.is_available() is False

    exit_code, output = runner.exec_in_container("whoami")
    assert exit_code == -1
    assert "unavailable" in output.lower()

    artifact = runner.read_artifact_from_container("/tmp/workspace/zap.json")
    assert artifact is None


def test_scan_agent_graceful_degradation_when_docker_absent(tmp_path):
    """
    Core Acceptance Test for Phase 5:
    When is_demo=False but Docker is absent, scan agent logs warning and falls back
    without crashing the pipeline.
    """
    db_file = str(tmp_path / "test_deg.db")
    audit_dir = str(tmp_path / "audit_logs")
    state_mgr = StateManager(db_path=db_file)
    audit_logger = AuditLogger(log_dir=audit_dir)

    job_id = "test-deg-001"
    target = "http://localhost:3000"
    state_mgr.create_scan(job_id=job_id, target=target, mode=ScanMode.DAST)

    # Invoke run_scan with is_demo=False in an environment where Docker is absent
    run_scan(
        job_id=job_id,
        target=target,
        mode=ScanMode.DAST,
        state_mgr=state_mgr,
        audit_logger=audit_logger,
        is_demo=False,
    )

    # Verify tool outputs were recorded via fallback
    outputs = state_mgr.get_tool_outputs(job_id)
    assert len(outputs) == 2
    tool_names = [o.tool_name for o in outputs]
    assert "zap" in tool_names
    assert "nikto" in tool_names

    # Verify notice in agent log
    logs = state_mgr.get_logs(job_id)
    warning_logs = [l for l in logs if "degrad" in l.line.lower() or "not active" in l.line.lower()]
    assert len(warning_logs) >= 1


def test_docker_runner_mock_container_execution():
    """Verifies DAST and SAST command dispatch and artifact extraction when container is running."""
    runner = DockerScannerRunner(container_name="kali-scanner")

    mock_docker_client = MagicMock()
    mock_container = MagicMock()
    mock_container.status = "running"
    mock_container.exec_run.return_value = MagicMock(exit_code=0, output=b"Execution succeeded")

    # Create dummy tar stream with sample JSON artifact
    tar_stream = io.BytesIO()
    sample_content = b'{"status": "scan_complete", "alerts": []}'
    with tarfile.open(fileobj=tar_stream, mode="w") as tar:
        tarinfo = tarfile.TarInfo(name="zap.json")
        tarinfo.size = len(sample_content)
        tar.addfile(tarinfo, io.BytesIO(sample_content))
    tar_stream.seek(0)

    mock_container.get_archive.return_value = ([tar_stream.getvalue()], None)
    mock_docker_client.containers.get.return_value = mock_container

    with patch("docker.from_env", return_value=mock_docker_client):
        assert runner.is_available() is True

        # Test ZAP
        code, out = runner.run_zap_baseline("http://localhost:3000")
        assert code == 0
        assert "scan_complete" in out

        # Test Nikto
        code, out = runner.run_nikto("http://localhost:3000")
        assert code == 0

        # Test SAST
        code, out = runner.clone_repository("https://github.com/koala73/worldmonitor")
        assert code == 0

        code, out = runner.run_semgrep()
        assert code == 0

        code, out = runner.run_gitleaks()
        assert code == 0
