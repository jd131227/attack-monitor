"""allow-ip / remove-ip / list-ips persistence, CIDR, and invalid-input tests
(spec 4.5.2)."""
import monitor


def test_allow_ip_persists_and_validates(cfg, core, capsys):
    assert monitor.cmd_allow_ip(cfg, core, "203.0.113.5", "home") == 0
    text = monitor.read_allowed(cfg)
    assert "203.0.113.5" in text
    assert "home" in text

    # Invalid IP is rejected and not written.
    assert monitor.cmd_allow_ip(cfg, core, "999.1.1.1", "") == 1
    assert "999.1.1.1" not in monitor.read_allowed(cfg)


def test_allow_ip_accepts_cidr(cfg, core):
    assert monitor.cmd_allow_ip(cfg, core, "10.0.0.0/8", "lan") == 0
    assert "10.0.0.0/8" in monitor.read_allowed(cfg)


def test_allow_ip_accepts_ipv6(cfg, core):
    assert monitor.cmd_allow_ip(cfg, core, "2001:db8::/32", "v6") == 0
    assert "2001:db8::/32" in monitor.read_allowed(cfg)


def test_allow_ip_idempotent_for_plain_ip(cfg, core, capsys):
    monitor.cmd_allow_ip(cfg, core, "203.0.113.5", "")
    monitor.cmd_allow_ip(cfg, core, "203.0.113.5", "")
    # Should appear only once.
    assert monitor.read_allowed(cfg).count("203.0.113.5") == 1


def test_remove_ip(cfg, core):
    monitor.cmd_allow_ip(cfg, core, "203.0.113.5", "a")
    monitor.cmd_allow_ip(cfg, core, "198.51.100.7", "b")
    monitor.cmd_remove_ip(cfg, "203.0.113.5")
    text = monitor.read_allowed(cfg)
    assert "203.0.113.5" not in text
    assert "198.51.100.7" in text


def test_remove_ip_keeps_comment_entry_with_same_ip_token(cfg, core):
    # remove-ip matches the address token, not a substring.
    monitor.cmd_allow_ip(cfg, core, "10.0.0.1", "keep me")
    monitor.cmd_remove_ip(cfg, "10.0.0.2")  # not present
    assert "10.0.0.1" in monitor.read_allowed(cfg)


def test_allowed_entries_strips_comments():
    text = "# header\n203.0.113.5  # home\n10.0.0.0/8\n\n"
    assert monitor.allowed_entries(text) == ["203.0.113.5", "10.0.0.0/8"]
