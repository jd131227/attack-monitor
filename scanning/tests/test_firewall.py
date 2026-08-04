"""Firewall apply tests (spec 4.1 / 4.2 / 4.5.3).

The real firewall is NEVER touched: state-changing calls go through
monitor.run_cmd, which is replaced by the `recorder` fixture. Dry-run tests
assert run_cmd is never called.
"""
import monitor


def _force_backend(monkeypatch, name):
    monkeypatch.setattr(monitor, "fw_detect_backend", lambda cfg: name)
    # capture_state is read-only; stub it so backups don't shell out.
    monkeypatch.setattr(monitor, "fw_capture_state", lambda backend, cfg: "DUMP")


def test_dry_run_calls_no_subprocess(cfg, core, monkeypatch, recorder, capsys):
    _force_backend(monkeypatch, "nft")
    monitor.cmd_allow_ip(cfg, core, "203.0.113.5", "")
    rc = monitor.apply_firewall(cfg, dry_run=True)
    assert rc == 0
    # The whole point: dry-run changes nothing.
    assert recorder.calls == []
    out = capsys.readouterr().out
    assert "dry-run" in out
    assert "203.0.113.5" in out


def test_apply_requires_yes(cfg, monkeypatch, recorder):
    _force_backend(monkeypatch, "nft")
    # dry_run False but assume_yes False -> refuse, no commands.
    rc = monitor.apply_firewall(cfg, dry_run=False, assume_yes=False)
    assert rc == 1
    assert recorder.calls == []


def test_empty_list_blocks_apply_without_force(cfg, monkeypatch, recorder):
    _force_backend(monkeypatch, "nft")
    rc = monitor.apply_firewall(cfg, dry_run=False, assume_yes=True, force=False)
    assert rc == 1
    assert recorder.calls == []


def test_connected_unallowed_ip_aborts_without_force(cfg, core, monkeypatch,
                                                     recorder):
    _force_backend(monkeypatch, "nft")
    monitor.cmd_allow_ip(cfg, core, "203.0.113.5", "")
    # Inject a connected client IP that is NOT in the allow list.
    monkeypatch.setattr(monitor, "detect_ssh_client_ips",
                        lambda c: {"198.51.100.99"})
    rc = monitor.apply_firewall(cfg, dry_run=False, assume_yes=True, force=False,
                                core=core)
    assert rc == 2                 # aborted for safety
    assert recorder.calls == []    # nothing applied


def test_force_applies_despite_risky_ip(cfg, core, monkeypatch, recorder):
    _force_backend(monkeypatch, "nft")
    monitor.cmd_allow_ip(cfg, core, "203.0.113.5", "")
    monkeypatch.setattr(monitor, "detect_ssh_client_ips",
                        lambda c: {"198.51.100.99"})
    rc = monitor.apply_firewall(cfg, dry_run=False, assume_yes=True, force=True,
                                core=core)
    assert rc == 0
    # A backup + the nft load should have run.
    argvs = [" ".join(c["argv"]) for c in recorder.calls]
    assert any("nft" in a for a in argvs)


def test_connected_allowed_ip_proceeds(cfg, core, monkeypatch, recorder):
    _force_backend(monkeypatch, "nft")
    monitor.cmd_allow_ip(cfg, core, "203.0.113.5", "")
    # Connected IP is allowed -> not at risk -> proceeds without --force.
    monkeypatch.setattr(monitor, "detect_ssh_client_ips",
                        lambda c: {"203.0.113.5"})
    rc = monitor.apply_firewall(cfg, dry_run=False, assume_yes=True, force=False,
                                core=core)
    assert rc == 0
    assert any("nft" in " ".join(c["argv"]) for c in recorder.calls)


def test_allow_rules_precede_deny_ufw(cfg, core):
    # spec 4.5.3: allow rules must be applied BEFORE the deny.
    monitor.cmd_allow_ip(cfg, core, "203.0.113.5", "")
    entries = monitor.allowed_entries(monitor.read_allowed(cfg))
    steps = monitor.fw_plan("ufw", cfg, entries, [22])
    descs = [s["desc"] for s in steps]
    allow_idx = next(i for i, d in enumerate(descs) if d.startswith("allow"))
    deny_idx = next(i for i, d in enumerate(descs) if d.startswith("deny"))
    assert allow_idx < deny_idx


def test_ufw_reapply_clears_prior_deny_first(cfg, core):
    # Re-apply safety: a prior deny is deleted (check=False) BEFORE allows, and
    # the deny is re-added LAST so a newly-allowed IP is never behind the deny.
    monitor.cmd_allow_ip(cfg, core, "203.0.113.5", "")
    entries = monitor.allowed_entries(monitor.read_allowed(cfg))
    steps = monitor.fw_plan("ufw", cfg, entries, [22])
    descs = [s["desc"] for s in steps]
    clear_idx = next(i for i, d in enumerate(descs) if d.startswith("clear"))
    allow_idx = next(i for i, d in enumerate(descs) if d.startswith("allow"))
    deny_idx = next(i for i, d in enumerate(descs) if d.startswith("deny"))
    assert clear_idx < allow_idx < deny_idx
    # The clearing step must not abort the apply if no prior deny exists.
    clear_step = steps[clear_idx]
    assert clear_step["check"] is False
    assert clear_step["argv"][:3] == ["ufw", "delete", "deny"]


def test_firewalld_accept_priority_beats_reject(cfg, core):
    # firewalld evaluates rich rules by priority; accepts must out-rank rejects.
    monitor.cmd_allow_ip(cfg, core, "203.0.113.5", "")
    entries = monitor.allowed_entries(monitor.read_allowed(cfg))
    steps = monitor.fw_plan("firewalld", cfg, entries, [22])
    accept = next(s for s in steps if "accept" in " ".join(s["argv"]))
    reject = next(s for s in steps if "reject" in " ".join(s["argv"]))
    assert 'priority="-100"' in " ".join(accept["argv"])   # higher precedence
    assert 'priority="100"' in " ".join(reject["argv"])     # lower precedence
    # Every firewalld rule is applied to runtime AND permanent.
    assert any("--permanent" in s["argv"] for s in steps)
    assert any("--permanent" not in s["argv"]
               and "--add-rich-rule" in " ".join(s["argv"]) for s in steps)


def test_firewalld_rollback_removes_exact_rules(cfg, core, monkeypatch, recorder):
    # The firewalld rollback must REMOVE the rich rules it added, not just
    # reload (which would re-assert the persisted deny -> lockout).
    monkeypatch.setattr(monitor, "fw_capture_state", lambda b, c: "DUMP")
    monitor.cmd_allow_ip(cfg, core, "203.0.113.5", "")
    entries = monitor.allowed_entries(monitor.read_allowed(cfg))
    steps = monitor.fw_plan("firewalld", cfg, entries, [22])

    backup_path = monitor.fw_backup(cfg, "firewalld", steps)
    monitor.fw_restore(cfg, backup_path)

    removed = [" ".join(c["argv"]) for c in recorder.calls
               if "--remove-rich-rule" in " ".join(c["argv"])]
    # Both the accept and the reject rules are removed.
    assert any("accept" in r for r in removed)
    assert any("reject" in r for r in removed)
    # And from both runtime and permanent config.
    assert any("--permanent" in r for r in removed)


def test_nft_ruleset_accepts_established_first(cfg):
    rs = monitor._nft_ruleset(["203.0.113.5"], [], [22])
    est = rs.index("established")
    drop = rs.index("dport { 22 } drop")
    accept = rs.index("203.0.113.5")
    # established + allowed source accepted before the catch-all drop.
    assert est < drop
    assert accept < drop


def test_apply_rolls_back_on_failure(cfg, core, monkeypatch, capsys):
    _force_backend(monkeypatch, "nft")
    monitor.cmd_allow_ip(cfg, core, "203.0.113.5", "")
    monkeypatch.setattr(monitor, "detect_ssh_client_ips", lambda c: set())

    calls = {"restore": 0}

    def boom(steps):
        raise RuntimeError("simulated apply failure")

    def fake_restore(cfg_, path):
        calls["restore"] += 1
        return "nft"

    monkeypatch.setattr(monitor, "fw_execute", boom)
    monkeypatch.setattr(monitor, "fw_restore", fake_restore)
    rc = monitor.apply_firewall(cfg, dry_run=False, assume_yes=True, force=True,
                                core=core)
    assert rc == 1
    assert calls["restore"] == 1   # rollback was attempted


def test_no_backend_detected(cfg, monkeypatch, recorder):
    monkeypatch.setattr(monitor, "fw_detect_backend", lambda cfg: None)
    rc = monitor.apply_firewall(cfg, dry_run=True)
    assert rc == 1
    assert recorder.calls == []
