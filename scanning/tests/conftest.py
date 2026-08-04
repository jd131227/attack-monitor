"""
Shared pytest fixtures for the attack-monitor Python tests.

Hard rule (spec 5.2 / 7): the real firewall is NEVER touched. Every test that
exercises firewall code monkeypatches monitor.run_cmd, and the dry-run tests
assert that run_cmd is not called at all.
"""
import os
import sys

import pytest

# Make monitor.py importable regardless of where pytest is invoked from.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import monitor  # noqa: E402


@pytest.fixture
def cfg(tmp_path):
    """A config dict pointed entirely at a temp dir (no system paths)."""
    c = dict(monitor.DEFAULTS)
    c["ALLOWED_IPS_FILE"] = str(tmp_path / "allowed_ips.conf")
    c["LOG_FILE"] = str(tmp_path / "monitor.log")
    c["AUDIT_LOG_FILE"] = str(tmp_path / "audit.log")
    c["FW_BACKUP_DIR"] = str(tmp_path / "backups")
    c["FW_STATE_FILE"] = str(tmp_path / "enforced.json")
    return c


@pytest.fixture
def core():
    """A real Core (the C lib must be built first: `make`)."""
    if not os.path.exists(monitor.LIB_PATH):
        pytest.skip("libmonitor_core.so not built; run `make` first")
    c = monitor.Core(monitor.DEFAULTS["WINDOW"])
    yield c
    c.close()


class CmdRecorder:
    """Records run_cmd invocations so tests can assert what would have run
    without ever executing a real command."""

    def __init__(self):
        self.calls = []

    def __call__(self, argv, input_text=None, check=True):
        self.calls.append({"argv": list(argv), "input": input_text})

        class _R:
            returncode = 0
            stdout = ""
            stderr = ""
        return _R()


@pytest.fixture
def recorder(monkeypatch):
    """Patch monitor.run_cmd with a recorder; assert real FW is never run."""
    rec = CmdRecorder()
    monkeypatch.setattr(monitor, "run_cmd", rec)
    return rec
