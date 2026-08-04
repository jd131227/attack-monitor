"""Config parsing, log rotation, and notify-hook tests (spec 5.2 / 5.3 / 6)."""
import os

import monitor


def test_load_config_types(tmp_path):
    conf = tmp_path / "monitor.conf"
    conf.write_text(
        "INTERVAL=5\n"
        "WINDOW=120\n"
        "ENABLE_IPV6=false\n"
        "EXPECTED_PORTS=22 80 8443\n"
        "WHITELIST_IPS=203.0.113.5, 198.51.100.7\n"
        "PROC_CPU_THRESHOLD=75.5\n"
        "FW_BACKEND=nft\n"
        "# a comment\n"
        "\n",
        encoding="utf-8",
    )
    cfg = monitor.load_config(str(conf))
    assert cfg["INTERVAL"] == 5
    assert cfg["WINDOW"] == 120
    assert cfg["ENABLE_IPV6"] is False
    assert cfg["EXPECTED_PORTS"] == [22, 80, 8443]
    assert cfg["WHITELIST_IPS"] == ["203.0.113.5", "198.51.100.7"]
    assert cfg["PROC_CPU_THRESHOLD"] == 75.5
    assert cfg["FW_BACKEND"] == "nft"


def test_load_config_missing_file_uses_defaults():
    cfg = monitor.load_config("/nonexistent/path.conf")
    assert cfg["INTERVAL"] == monitor.DEFAULTS["INTERVAL"]


def test_log_rotation(tmp_path):
    log = tmp_path / "monitor.log"
    # Pre-fill beyond the max so the next write rotates.
    log.write_text("x" * 200, encoding="utf-8")
    monitor.log_line(str(log), "after rotation", max_bytes=100)
    assert os.path.exists(str(log) + ".1")          # old content moved aside
    assert "after rotation" in log.read_text(encoding="utf-8")


def test_no_rotation_under_limit(tmp_path):
    log = tmp_path / "monitor.log"
    monitor.log_line(str(log), "first", max_bytes=10_000_000)
    monitor.log_line(str(log), "second", max_bytes=10_000_000)
    assert not os.path.exists(str(log) + ".1")
    body = log.read_text(encoding="utf-8")
    assert "first" in body and "second" in body


def test_notify_writes_log_and_runs_hook(cfg, monkeypatch):
    cfg["NOTIFY_CMD"] = "/opt/attack-monitor/notify.sh"
    calls = []
    monkeypatch.setattr(monitor, "run_cmd",
                        lambda argv, input_text=None, check=True:
                        calls.append((argv, input_text)))
    monitor.notify(cfg, {"type": "ssh_bruteforce", "detail": "boom"})
    # The alert is logged...
    body = open(cfg["LOG_FILE"], encoding="utf-8").read()
    assert "ssh_bruteforce" in body
    # ...and the external hook is invoked with the event as JSON on stdin.
    assert len(calls) == 1
    assert calls[0][0] == ["/opt/attack-monitor/notify.sh"]
    assert "ssh_bruteforce" in calls[0][1]


def test_notify_without_hook_only_logs(cfg, monkeypatch):
    cfg["NOTIFY_CMD"] = ""
    called = {"n": 0}
    monkeypatch.setattr(monitor, "run_cmd",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    monitor.notify(cfg, {"type": "x", "detail": "y"})
    assert called["n"] == 0
    assert "x" in open(cfg["LOG_FILE"], encoding="utf-8").read()


def test_notify_hook_failure_does_not_raise(cfg, monkeypatch):
    cfg["NOTIFY_CMD"] = "/bin/false"

    def boom(*a, **k):
        raise RuntimeError("hook blew up")

    monkeypatch.setattr(monitor, "run_cmd", boom)
    # Must not propagate - the loop has to keep running.
    monitor.notify(cfg, {"type": "x", "detail": "y"})
