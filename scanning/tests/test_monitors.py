"""Extended-monitor tests: connection flood, listening ports, processes, and
the diff-log reader (spec 3.2 / 3.3 / 3.4 / 5.4)."""
import monitor


# ---- ss / ps parsers -------------------------------------------------------
SS_ESTABLISHED = """\
ESTAB 0 0 10.0.0.1:22 198.51.100.10:51000
ESTAB 0 0 10.0.0.1:22 198.51.100.10:51001
ESTAB 0 0 10.0.0.1:443 203.0.113.9:40000
ESTAB 0 0 10.0.0.1:22 [2001:db8::1]:51002
"""

SS_LISTEN = """\
LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
LISTEN 0 128 0.0.0.0:80 0.0.0.0:*
LISTEN 0 128 0.0.0.0:31337 0.0.0.0:*
LISTEN 0 128 [::]:443 [::]:*
"""

PS_OUT = """\
  101 99.5  2.0 xmrig
  102  1.0  1.0 sshd
  103  0.1 95.0 leaky
"""


def test_parse_ss_peer_ips():
    peers = monitor.parse_ss_peer_ips(SS_ESTABLISHED)
    assert peers.count("198.51.100.10") == 2
    assert "203.0.113.9" in peers
    assert "2001:db8::1" in peers


def test_parse_ss_listen_ports():
    ports = monitor.parse_ss_listen_ports(SS_LISTEN)
    assert ports == {22, 80, 31337, 443}


def test_strip_ss_host_variants():
    assert monitor._strip_ss_host("1.2.3.4:22") == "1.2.3.4"
    assert monitor._strip_ss_host("[2001:db8::1]:22") == "2001:db8::1"


def test_strip_ss_host_normalizes_v4_mapped():
    # IPv4-mapped IPv6 must reduce to the bare IPv4 so it matches a plain
    # allow-list entry (lockout-safeguard correctness).
    assert monitor._strip_ss_host("::ffff:1.2.3.4:22") == "1.2.3.4"
    assert monitor._strip_ss_host("[::ffff:1.2.3.4]:22") == "1.2.3.4"
    assert monitor._normalize_host("::ffff:203.0.113.5") == "203.0.113.5"
    assert monitor._normalize_host("2001:db8::1") == "2001:db8::1"


def test_detect_ssh_client_ip_v4_mapped_matches_allow(cfg, core, monkeypatch):
    # A connected admin seen as ::ffff:203.0.113.5 must match a plain
    # 203.0.113.5 allow entry, so apply-firewall does not falsely flag at-risk.
    monkeypatch.setenv("SSH_CONNECTION", "::ffff:203.0.113.5 50000 10.0.0.1 22")
    monkeypatch.setattr(monitor, "_capture", lambda argv: "")
    detected = monitor.detect_ssh_client_ips(cfg)
    assert "203.0.113.5" in detected
    assert core.ip_allowed("203.0.113.5", "203.0.113.5\n")


def test_detect_ssh_client_ip_whitespace_env_does_not_crash(cfg, monkeypatch):
    # A whitespace-only SSH_CONNECTION must not raise IndexError (which would
    # crash apply-firewall --yes); it should simply contribute no IP.
    monkeypatch.setenv("SSH_CONNECTION", "   ")
    monkeypatch.setattr(monitor, "_capture", lambda argv: "")
    assert monitor.detect_ssh_client_ips(cfg) == set()


def test_ssh_alert_suppressed_for_trusted_source(cfg, core):
    # spec 4.6.2: a work-mode / whitelisted IP over the SSH fail threshold must
    # NOT raise an alert, but a normal attacker IP still must.
    monitor.cmd_allow_ip(cfg, core, "203.0.113.5", "work-mode")
    cfg["WHITELIST_IPS"] = ["198.51.100.7"]
    detail = "203.0.113.5 (50)\n198.51.100.7 (40)\n45.9.9.9 (99)\n"
    alertable, suppressed = monitor.split_suppressed(
        core, detail, monitor.trusted_text(cfg))
    assert any("45.9.9.9" in a for a in alertable)        # attacker alerts
    assert all("203.0.113.5" not in a for a in alertable)  # work-mode suppressed
    assert all("198.51.100.7" not in a for a in alertable)  # whitelist suppressed
    assert len(suppressed) == 2


def test_connection_flood_detect(cfg, core, monkeypatch):
    cfg["CONN_THRESHOLD"] = 2
    monkeypatch.setattr(monitor, "_capture", lambda argv: SS_ESTABLISHED)
    events = []
    monkeypatch.setattr(monitor, "notify", lambda c, e: events.append(e))
    monitor.check_connection_flood(cfg, core)
    assert len(events) == 1
    assert events[0]["type"] == "conn_flood"
    assert "198.51.100.10" in events[0]["detail"]


def test_connection_flood_excludes_whitelist(cfg, core, monkeypatch):
    cfg["CONN_THRESHOLD"] = 2
    cfg["WHITELIST_IPS"] = ["198.51.100.10"]
    monkeypatch.setattr(monitor, "_capture", lambda argv: SS_ESTABLISHED)
    events = []
    monkeypatch.setattr(monitor, "notify", lambda c, e: events.append(e))
    monitor.check_connection_flood(cfg, core)
    assert events == []   # the only flooder is whitelisted


def test_unexpected_port_detect(cfg, monkeypatch):
    cfg["EXPECTED_PORTS"] = [22, 80, 443]
    monkeypatch.setattr(monitor, "_capture", lambda argv: SS_LISTEN)
    events = []
    monkeypatch.setattr(monitor, "notify", lambda c, e: events.append(e))
    monitor.check_listening_ports(cfg)
    assert len(events) == 1
    assert events[0]["type"] == "unexpected_port"
    assert "31337" in events[0]["detail"]


def test_no_unexpected_port(cfg, monkeypatch):
    cfg["EXPECTED_PORTS"] = [22, 80, 443, 31337]
    monkeypatch.setattr(monitor, "_capture", lambda argv: SS_LISTEN)
    events = []
    monkeypatch.setattr(monitor, "notify", lambda c, e: events.append(e))
    monitor.check_listening_ports(cfg)
    assert events == []


def test_suspicious_process_detect(cfg, monkeypatch):
    cfg["PROC_CPU_THRESHOLD"] = 90.0
    cfg["PROC_MEM_THRESHOLD"] = 90.0
    monkeypatch.setattr(monitor, "_capture", lambda argv: PS_OUT)
    events = []
    monkeypatch.setattr(monitor, "notify", lambda c, e: events.append(e))
    monitor.check_suspicious_processes(cfg)
    assert len(events) == 1
    detail = events[0]["detail"]
    assert "xmrig" in detail        # high CPU
    assert "leaky" in detail        # high MEM
    assert "sshd" not in detail     # normal usage


def test_process_whitelist(cfg, monkeypatch):
    cfg["PROC_CPU_THRESHOLD"] = 90.0
    cfg["PROC_MEM_THRESHOLD"] = 90.0
    cfg["PROC_WHITELIST"] = ["xmrig"]   # pretend it's known-good here
    monkeypatch.setattr(monitor, "_capture", lambda argv: PS_OUT)
    events = []
    monkeypatch.setattr(monitor, "notify", lambda c, e: events.append(e))
    monitor.check_suspicious_processes(cfg)
    # Only "leaky" remains.
    assert len(events) == 1
    assert "xmrig" not in events[0]["detail"]
    assert "leaky" in events[0]["detail"]


def test_monitor_toggle_off(cfg, monkeypatch):
    cfg["ENABLE_PORT_MON"] = False
    called = {"n": 0}
    monkeypatch.setattr(monitor, "_capture",
                        lambda argv: called.__setitem__("n", called["n"] + 1) or "")
    monitor.check_listening_ports(cfg)
    assert called["n"] == 0   # disabled monitor does no work


# ---- diff-log reader (spec 5.4) -------------------------------------------
def test_diff_log_reads_only_new_lines(cfg, core, tmp_path, monkeypatch):
    log = tmp_path / "auth.log"
    log.write_text("line1\nline2\n", encoding="utf-8")
    cfg["AUTH_LOG"] = str(log)

    # Avoid Core re-init touching the real lib path twice: build Monitor lazily.
    monkeypatch.setattr(monitor, "Core", lambda w: core)
    mon = monitor.Monitor(cfg)

    first = mon.read_new_lines()
    assert first == ["line1\n", "line2\n"]

    # Append; only the new line should come back.
    with open(log, "a", encoding="utf-8") as f:
        f.write("line3\n")
    second = mon.read_new_lines()
    assert second == ["line3\n"]


def test_diff_log_handles_rotation(cfg, core, tmp_path, monkeypatch):
    log = tmp_path / "auth.log"
    log.write_text("old1\nold2\n", encoding="utf-8")
    cfg["AUTH_LOG"] = str(log)
    monkeypatch.setattr(monitor, "Core", lambda w: core)
    mon = monitor.Monitor(cfg)
    mon.read_new_lines()                       # consume initial content

    # Simulate rotation: smaller file (truncated/replaced).
    log.write_text("fresh\n", encoding="utf-8")
    after = mon.read_new_lines()
    assert after == ["fresh\n"]                # read from the top again
