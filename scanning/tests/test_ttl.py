"""TTL auto-expiry tests (spec 4.3 / 5.5)."""
from datetime import datetime

import monitor


def test_expired_entry_removed_and_audited(cfg, core):
    # One expired entry, one still valid.
    monitor.cmd_allow_ip(cfg, core, "203.0.113.5", "work",
                         expires="2000-01-01T00:00:00")
    monitor.cmd_allow_ip(cfg, core, "198.51.100.7", "permanent")

    now = datetime(2026, 1, 1, 12, 0, 0)
    expired = monitor.expire_temporary_allows(cfg, core, now=now)

    assert "203.0.113.5" in expired
    text = monitor.read_allowed(cfg)
    assert "203.0.113.5" not in text       # removed
    assert "198.51.100.7" in text          # kept

    audit = open(cfg["AUDIT_LOG_FILE"], encoding="utf-8").read()
    assert "ttl-expire 203.0.113.5" in audit


def test_future_expiry_is_kept(cfg, core):
    monitor.cmd_allow_ip(cfg, core, "203.0.113.5", "work",
                         expires="2999-01-01T00:00:00")
    now = datetime(2026, 1, 1, 12, 0, 0)
    expired = monitor.expire_temporary_allows(cfg, core, now=now)
    assert expired == []
    assert "203.0.113.5" in monitor.read_allowed(cfg)


def test_entry_without_expiry_never_removed(cfg, core):
    monitor.cmd_allow_ip(cfg, core, "203.0.113.5", "permanent")
    expired = monitor.expire_temporary_allows(cfg, core,
                                              now=datetime(2999, 1, 1))
    assert expired == []
    assert "203.0.113.5" in monitor.read_allowed(cfg)


def test_work_mode_start_adds_ttl_entry(cfg, core):
    monitor.cmd_work_mode(cfg, core, "start", ip="198.51.100.7",
                          duration="1h", reason="ticket#1")
    text = monitor.read_allowed(cfg)
    assert "198.51.100.7" in text
    assert "expires=" in text
    assert "work-mode:ticket#1" in text


def test_parse_duration():
    assert monitor.parse_duration("2h") == 7200
    assert monitor.parse_duration("30m") == 1800
    assert monitor.parse_duration("45s") == 45
    assert monitor.parse_duration("1d") == 86400
    assert monitor.parse_duration("90") == 90


def test_parse_expires_empty_marker_is_safe():
    # A hand-edited "expires=" with no value must yield None, not raise
    # IndexError (which would abort the loop's expiry pass before detection).
    assert monitor._parse_expires("1.2.3.4  # expires=") is None
    assert monitor._parse_expires("1.2.3.4  # expires=   ") is None
    assert monitor._parse_expires("1.2.3.4  # expires=garbage") is None
    parsed = monitor._parse_expires("1.2.3.4  # expires=2026-01-01T00:00:00")
    assert parsed == datetime(2026, 1, 1, 0, 0, 0)


def test_expire_pass_survives_malformed_expires_line(cfg, core):
    # The whole expiry pass must not raise on a malformed allow-file line.
    monitor.cmd_allow_ip(cfg, core, "203.0.113.5", "manual")
    # Inject a malformed line directly.
    text = monitor.read_allowed(cfg) + "198.51.100.7  # expires=\n"
    monitor.write_allowed(cfg, text)
    expired = monitor.expire_temporary_allows(cfg, core,
                                              now=datetime(2026, 1, 1))
    assert expired == []                       # nothing expired, no exception
    assert "198.51.100.7" in monitor.read_allowed(cfg)


def test_work_mode_refreshes_ttl_on_existing_permanent_ip(cfg, core):
    # work-mode start on an IP that is ALREADY permanently allowed must add a
    # real expires= marker (not silently no-op), so the reported TTL is enforced.
    monitor.cmd_allow_ip(cfg, core, "203.0.113.5", "permanent")
    assert "expires=" not in monitor.read_allowed(cfg)
    monitor.cmd_work_mode(cfg, core, "start", ip="203.0.113.5",
                          duration="1h", reason="ticket#9")
    text = monitor.read_allowed(cfg)
    assert text.count("203.0.113.5") == 1      # not duplicated
    assert "expires=" in text                  # TTL actually written
    assert "work-mode:ticket#9" in text


def test_work_mode_stop_removes_entries_now(cfg, core):
    # stop must actually end the work mode by removing the temporary entry,
    # not defer entirely to TTL auto-expiry (spec 4.6.2).
    monitor.cmd_work_mode(cfg, core, "start", ip="198.51.100.7",
                          duration="8h", reason="audit")
    monitor.cmd_allow_ip(cfg, core, "203.0.113.5", "permanent")
    monitor.cmd_work_mode(cfg, core, "stop")
    text = monitor.read_allowed(cfg)
    assert "198.51.100.7" not in text          # work-mode entry cleared
    assert "203.0.113.5" in text               # permanent entry untouched
    audit = open(cfg["AUDIT_LOG_FILE"], encoding="utf-8").read()
    assert "work-mode stop removed 198.51.100.7" in audit


def test_work_mode_stop_specific_ip_only(cfg, core):
    monitor.cmd_work_mode(cfg, core, "start", ip="198.51.100.7",
                          duration="8h", reason="a")
    monitor.cmd_work_mode(cfg, core, "start", ip="198.51.100.8",
                          duration="8h", reason="b")
    monitor.cmd_work_mode(cfg, core, "stop", ip="198.51.100.7")
    text = monitor.read_allowed(cfg)
    assert "198.51.100.7" not in text          # only the named IP removed
    assert "198.51.100.8" in text
