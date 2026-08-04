# attack-monitor — server attack-detection & SSH access-control tool

A blue-team tool for **Linux servers you administer**. It continuously watches
for signs of attack (SSH brute force, connection floods, unexpected open ports,
runaway processes), and provides **SSH (port 22) access control that allows only
listed IPs**, plus a **work mode** that lets you do maintenance without turning
the defenses off.

- **Core logic is in C** (`monitor_core.c`): aggregation, IP validation, and
  allow-list matching, implemented with pointers and recursion.
- **A Python driver** (`monitor.py`) calls the C library via `ctypes` and owns
  the loop, the CLI, the config, the firewall enforcement, and TTL expiry.

> ⚠️ **Read before running (lockout warning)**
> This tool can **rewrite your firewall and restrict SSH**. A mistake can lock
> you (or your team) out of the server.
> - Only target servers you **administer or are formally authorized** to manage.
> - Get sign-off from your lead / security team before production, and **test in
>   a staging environment / disposable VM first**.
> - Keep a non-SSH recovery path (console / KVM / cloud serial console).
> - Always preview access-control changes with `apply-firewall` (dry-run by
>   default) before applying.

---

## 1. Build

```bash
make            # builds libmonitor_core.so
make test       # C unit tests
make pytest     # Python tests (firewall fully mocked)
make check      # both test suites
```

Dependencies: `gcc`, `python3` (standard library only). For the firewall feature
you need one of `ufw`, `firewalld`, or `nft` on the target host. For the extended
monitors you need `ss` and `ps` (present on virtually all Linux systems).

To run the Python tests you need `pytest`:

```bash
# Debian/Kali:
sudo apt-get install -y python3-pytest
# or in a virtualenv:
python3 -m venv .venv && . .venv/bin/activate && pip install pytest
```

## 2. Configure

```bash
cp monitor.conf.example monitor.conf
# Edit paths and thresholds for your environment.
```

Key settings: `INTERVAL` (loop seconds), `WINDOW` (aggregation window seconds),
`SSH_FAIL_THRESHOLD` (failures allowed in the window), `CONN_THRESHOLD`,
`EXPECTED_PORTS`, `ALLOWED_SSH_PORTS`, `FW_BACKEND` (`auto`/`ufw`/`firewalld`/`nft`),
`ALLOWED_IPS_FILE`, `AUTH_LOG` (`auto` detects the path), `LOG_MAX_BYTES`. See the
full table in `server-attack-monitor-spec.md` §6 and the comments in
`monitor.conf.example`.

## 3. Run the monitor

```bash
sudo python3 monitor.py --config monitor.conf run
```

- Prints status each loop and appends it to `LOG_FILE`.
- `Ctrl+C` (SIGINT) / SIGTERM stops it safely.
- It reads **only new log bytes since last time** and re-reads from the top when
  it detects rotation (inode change / truncation).
- Each tick also runs the extended monitors (connection flood, unexpected
  ports, suspicious processes) and expires any temporary allow entries.

## 4. SSH allow-IP management

```bash
python3 monitor.py allow-ip 203.0.113.5 "home office"   # add (CIDR ok: 10.0.0.0/8, 2001:db8::/32)
python3 monitor.py list-ips                              # list
python3 monitor.py remove-ip 203.0.113.5                # remove
python3 monitor.py apply-firewall                        # preview (dry-run)
python3 monitor.py apply-firewall --yes                  # apply for real
python3 monitor.py apply-firewall --yes --force          # apply even if a connected IP is at risk
```

Invalid IP/CIDR values are rejected on add. The allow list is the single source
of truth; `apply-firewall` rebuilds the firewall rules from it.

### How `apply-firewall` protects you (spec 4.5.3)

On a real apply (`--yes`), in this order:

1. Detect the source IPs of currently connected SSH sessions
   (`SSH_CONNECTION` + `ss`).
2. If any connected IP is **not** in the allow list, warn and **abort** unless
   `--force` is given (so you don't cut your own session).
3. Back up the current firewall state to `FW_BACKUP_DIR/fw_backup_<timestamp>.json`.
4. Insert **allow rules before** the default-deny so existing sessions survive.
5. On any failure, **roll back** automatically from the backup.

Manual rollback:

```bash
python3 monitor.py rollback --list           # show available backups
python3 monitor.py rollback                   # restore the most recent
python3 monitor.py rollback --file <path>     # restore a specific backup
```

The rollback (automatic on failure, or via the `rollback` command) restores the
pre-apply state for each backend: `nft` re-loads the saved ruleset, `firewalld`
removes exactly the rich rules this apply added (from both runtime and permanent
config), and `ufw` removes the managed deny and reloads.

Backends:
- **ufw**: deletes any prior managed deny, adds per-IP `allow` rules, then re-adds
  the port `deny` **last** so a newly-allowed IP is never stuck behind the deny
  (correct even when `apply-firewall` is re-run).
- **firewalld**: per-IP accept rich-rules at high precedence (`priority=-100`)
  plus a default port reject at low precedence (`priority=100`), written to both
  runtime and permanent config (accepts before rejects, no reload that could
  activate a half-applied state).
- **nft**: loads a dedicated `inet attack_monitor` table that accepts established
  connections and listed sources before dropping the SSH ports for everyone else
  (other ports untouched).

## 5. Work mode (stay protected while you work)

Temporarily allow your workstation **without stopping the monitor**.

```bash
python3 monitor.py work-mode start --ip 198.51.100.7 --duration 2h --reason "audit#123"
python3 monitor.py work-mode status
python3 monitor.py work-mode stop                 # end all work-mode exceptions now
python3 monitor.py work-mode stop --ip 198.51.100.7   # end just one
```

The IP is added to the allow list with a TTL (`--duration`), and every work-mode
action is written to the audit log. The loop **auto-expires** the entry when the
TTL passes; if `FW_AUTO_SYNC=true` and the firewall is currently enforced, the
firewall is rebuilt so the expired IP loses access. `work-mode stop` **ends the
exception immediately** — it removes the work-mode allow entries (optionally just
the `--ip` you name) and re-syncs the firewall when enforcing — rather than
waiting for the TTL. Starting work mode for an IP that is already allowed
refreshes that entry with the new TTL, so the reported expiry is always real.

While an IP is in the allow list (work mode) or in `WHITELIST_IPS`, its SSH
brute-force and connection-flood **alerts are suppressed** — the events are still
recorded to the log (as `suppressed`), but no warning is raised — so your own
maintenance traffic doesn't bury real attacks (spec 4.6.2). All other IPs are
monitored normally.

## 6. Alerts and notifications (spec 5.3)

All alerts flow through a single `notify()` hook (stdout + log by default). To
forward them (Slack / email / webhook), set `NOTIFY_CMD` to a command; the alert
event is delivered as JSON on stdin:

```ini
NOTIFY_CMD=/opt/attack-monitor/notify-slack.sh
```

The actual network send is left to that external command, so you can integrate
with anything without modifying `monitor.py`.

## 7. Run as a service (systemd)

```bash
sudo cp -r . /opt/attack-monitor
sudo cp /opt/attack-monitor/monitor.conf.example /opt/attack-monitor/monitor.conf  # then edit
sudo cp attack-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now attack-monitor
sudo systemctl status attack-monitor
journalctl -u attack-monitor -f
```

---

## Architecture (C ↔ Python)

- **C core** (`monitor_core.c` / `.h`): linked-list aggregation of per-IP SSH
  failures with recursive walk/expire/count; `ip_classify` (IPv4/IPv6/CIDR);
  `ip_allowed` (exact match + IPv4 **and** IPv6 CIDR, recursive); and
  `conn_over_threshold` for connection-flood tallying. Pointers and recursion are
  used throughout, with comments at each site, and every allocation is freed.
- **Python driver** (`monitor.py`): `ctypes` bindings, config, diff-log reader
  with rotation handling, the main loop, the CLI, firewall enforcement with
  lockout safeguards/backup/rollback, TTL expiry, and the extended monitors.
- Bridge mode: **ctypes** (the C core is built as `libmonitor_core.so`).

## Testing

- `make test` — C unit tests (`test_core.c`): aggregation, window expiry,
  IP classification, allow matching (incl. IPv6 CIDR), connection tally, and
  NULL/empty robustness.
- `make pytest` — Python tests under `tests/`. **The real firewall is never
  touched**: state-changing calls go through `monitor.run_cmd`, which the tests
  replace with a recorder; dry-run tests assert it is never called.
- `bash tests/smoke.sh` — end-to-end: feeds a fake `auth.log`, runs the loop for
  a few seconds, and confirms detection + safe stop.

See `VERIFICATION.md` for the full verification procedure and where to paste the
output you get on the target host.

## Out of scope (what this tool will NOT do)

It performs no scanning or attacks against others' systems. It does **not** do
dynamic IP blocking in response to detected attacks — that is delegated to
`fail2ban`. For deeper intrusion detection use `Suricata` / `Snort`; for file
integrity use `AIDE`. The only active control here is the **static, explicit**
SSH allow list (§4).
