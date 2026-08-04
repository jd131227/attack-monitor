attack-monitor — User Manual (English)
A defensive ("blue team") tool for a Linux server you own or are formally
authorised to manage. It continuously watches for signs of attack (SSH
brute-force, suspicious connections, unexpected open ports, suspicious
processes) and can lock SSH down to an allow-list of IPs, while letting you keep
working during maintenance.
Core logic is in C (`monitor_core.c`) — aggregation, IP validation, allow-list matching.
A Python driver (`monitor.py`) calls the C shared library via `ctypes` and runs the loop, CLI and config.
---
⚠️ Read this first (lockout warning)
This tool can modify your firewall and restrict SSH to specific IPs. A wrong
setting can lock you (and your team) out of the server. Before using
`apply-firewall --yes` on a real server:
Only target a server you own / are formally authorised to manage.
Get manager / security-team approval for production use.
Test in a throwaway VM or staging environment first.
Keep a non-SSH recovery path (console / KVM / cloud serial access).
Always run `apply-firewall` (dry-run) and check the output before `--yes`.
The plain `run` (monitoring) command is safe — it only reads logs and prints alerts.
---
❗ Permissions rule: run every command with `sudo`
By default this tool reads `/var/log/auth.log` and writes to `/etc/attack-monitor/`
and `/var/log/`, which are root-owned. Without `sudo` you will hit:
```
PermissionError: [Errno 13] Permission denied: '/etc/attack-monitor'
```
So prefix every `monitor.py` command in this manual with `sudo` —
`run`, `allow-ip`, `list-ips`, `remove-ip`, `work-mode`, `apply-firewall`,
`rollback`. This matches how it runs under systemd (as root) in production.
The only commands that do not need root are the one-time build/test steps
(`make`, `pytest`). (If you prefer to run without `sudo` for personal testing,
point `ALLOWED_IPS_FILE`, `LOG_FILE` and `AUDIT_LOG_FILE` at a folder you own,
e.g. under your home directory.)
---
1. Requirements
Linux (Debian/Ubuntu or RHEL family). Tested on Kali.
`gcc`, `make`, `python3` (standard library only).
`python3-pytest` (optional, only to run the Python test suite).
Root / sudo (needed to read auth logs and to change the firewall).
---
2. Installation
```bash
# 1) Go to the project folder
cd ~/Projects/kali_scanning

# 2) Build the C shared library
make            # produces libmonitor_core.so (no warnings expected)

# 3) (Optional) run the test suites to confirm everything works
make test               # C unit tests  -> "ALL TESTS PASSED"
python3 -m pytest -q    # Python tests  -> all dots / passed
bash tests/smoke.sh     # end-to-end    -> "ALL CHECKS PASSED"
```
If `pytest` is missing: `sudo apt install -y python3-pytest`.
2.1 Make sure an auth log file exists (important on Kali)
The tool reads a text auth log (`/var/log/auth.log` on Debian/Ubuntu/Kali). On a
modern Kali install, SSH events go to the systemd journal and there may be
no `/var/log/auth.log` file — in that case the tool prints
`cannot read log: /var/log/auth.log`. Fix it by enabling rsyslog so the text log
is written:
```bash
ls -l /var/log/auth.log              # if "No such file or directory":
sudo apt install -y rsyslog
sudo systemctl enable --now rsyslog  # auth.log starts being written from now on
```
You can confirm SSH is logging with `journalctl _COMM=sshd -n 5`. To generate a
test failure, run `ssh baduser@localhost` (answer `yes` to the host-key prompt,
then enter a wrong password a few times) and check
`sudo grep "Failed password" /var/log/auth.log`.
---
3. Configuration
```bash
cp monitor.conf.example monitor.conf
nano monitor.conf        # adjust paths and thresholds for your environment
```
Key settings:
Setting	Meaning	Default
`INTERVAL`	Loop interval (seconds)	`10`
`WINDOW`	Time window aggregated for thresholds (seconds)	`300`
`SSH_FAIL_THRESHOLD`	SSH failures within the window before alerting	`20`
`CONN_THRESHOLD`	Simultaneous connections from one IP before alerting	`50`
`EXPECTED_PORTS`	Ports allowed to be open; others trigger an alert	`22 80 443`
`ALLOWED_SSH_PORTS`	Ports treated as SSH for access control	`22`
`WHITELIST_IPS`	IPs excluded from alerts	empty
`AUTH_LOG`	Auth log to parse (`auto` detects Debian/RHEL paths)	`auto`
`ALLOWED_IPS_FILE`	Where the SSH allow-list is stored	`/etc/attack-monitor/allowed_ips.conf`
`FW_BACKEND`	Firewall backend: `auto`/`ufw`/`firewalld`/`nft`	`auto`
`NOTIFY_CMD`	Optional external alert command (JSON on stdin)	empty
See `monitor.conf.example` for the full list (connection/port/process monitors, IPv6, log rotation, backup paths).
---
4. Running the monitor (start here)
This is the core, non-destructive loop — exactly the "always-running script
watching for attacks" use case.
```bash
sudo python3 monitor.py --config monitor.conf run
```
Prints a status line each cycle and appends to `LOG_FILE`.
Detects SSH brute-force, suspicious source IPs, unexpected open ports and high-usage processes.
Stop safely with `Ctrl+C`.
4.1 Tuning detection speed and noise
React faster: lower `INTERVAL` in `monitor.conf` (e.g. `INTERVAL=2`
checks every 2 seconds instead of 10). Smaller = faster detection but slightly
more CPU; 2–5s is a good balance for everyday use, 5–10s for light load.
Fewer false alerts: the SSH alert only fires once failures reach
`SSH_FAIL_THRESHOLD` within `WINDOW` seconds. Real brute-force attempts produce
many failures, so `20`–`50` is realistic. (Lower it only to test detection,
then restore it.)
Silence an expected port: if a service such as RDP (3389) is legitimately
running, add it to `EXPECTED_PORTS`, e.g. `EXPECTED_PORTS=22 80 443 3389`,
otherwise it is reported as an unexpected open port.
Disable a monitor entirely: set `ENABLE_CONN_MON` / `ENABLE_PORT_MON` /
`ENABLE_PROC_MON` to `false` to make each cycle lighter.
---
5. Managing the SSH allow-list
```bash
sudo python3 monitor.py allow-ip 203.0.113.5 "home"   # add (CIDR ok, e.g. 10.0.0.0/8)
sudo python3 monitor.py list-ips                        # list
sudo python3 monitor.py remove-ip 203.0.113.5           # remove
```
Invalid IP/CIDR values are rejected. Entries are persisted to `ALLOWED_IPS_FILE`.
A comment can be any note (e.g. an owner email): `sudo python3 monitor.py allow-ip 172.16.8.42 "alice@example.com"`.
---
6. Work mode (stay protected while you work)
Keeps the monitoring loop running, but temporarily exempts your work machine so
your own activity is not blocked or buried in alerts. The exception is
time-limited and auto-expires.
```bash
sudo python3 monitor.py work-mode start --ip 198.51.100.7 --duration 2h --reason "audit #123"
sudo python3 monitor.py work-mode status
sudo python3 monitor.py work-mode stop
```
All work-mode actions are written to the audit log.
---
7. Firewall access control (advanced / destructive)
Locks SSH so only allow-listed IPs can connect. Other ports (80/443, …) keep
working. Always dry-run first.
```bash
# 1) Preview — shows the exact rules, changes NOTHING
sudo python3 monitor.py apply-firewall

# 2) Confirm YOUR current IP is in the list before applying
sudo python3 monitor.py list-ips

# 3) Apply for real (only after testing in staging)
sudo python3 monitor.py apply-firewall --yes

#    If a connected IP would be cut off, the tool stops unless you add --force
sudo python3 monitor.py apply-firewall --yes --force   # use with extreme care
```
Safety devices built in: detects currently-connected SSH IPs, adds allow rules
before the default-deny, backs up firewall state before applying.
Rollback
```bash
sudo python3 monitor.py rollback --list      # show available backups
sudo python3 monitor.py rollback             # restore the most recent backup
sudo python3 monitor.py rollback --file <backup-file>
```
---
8. Run permanently with systemd
```bash
sudo cp -r ~/Projects/kali_scanning /opt/attack-monitor
sudo cp /opt/attack-monitor/attack-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now attack-monitor   # start now + on every boot
sudo systemctl status attack-monitor
journalctl -u attack-monitor -f              # follow live logs
```
Adjust the paths inside `attack-monitor.service` if you install elsewhere.
---
9. Quick start (TL;DR)
From a clean machine to a running monitor:
```bash
# 1) Build
cd ~/Projects/kali_scanning
make

# 2) Config
cp monitor.conf.example monitor.conf

# 3) Make sure the auth log exists (Kali logs to journald by default)
ls -l /var/log/auth.log || { sudo apt install -y rsyslog; \
  sudo systemctl enable --now rsyslog; }

# 4) (optional) add an allow IP — note the sudo
sudo python3 monitor.py allow-ip 203.0.113.5 "my laptop"

# 5) Start monitoring (safe; reads logs only)
sudo python3 monitor.py --config monitor.conf run
```
Only move on to `apply-firewall --yes` after testing in a throwaway VM.
---
10. Troubleshooting
`cannot read log: /var/log/auth.log` — the text auth log does not exist
(common on Kali, which logs to journald). Enable rsyslog — see section 2.1.
Also make sure you run with `sudo`.
`make: No rule to make target 'clean'` / `'test_core.c'` — you are in the
wrong directory. Run `make` from the folder that contains the `Makefile`
(the project root, not `tests/`). The clean target is `clean`, not `clear`.
`make: Nothing to be done for 'all'` — already built; this is harmless.
Force a rebuild with `rm -f libmonitor_core.so && make`.
`[ALERT:unexpected_port] ... 3389` keeps firing — a service is listening on
that port. Add it to `EXPECTED_PORTS` if expected, or close it if not.
`No module named pytest` — install it: `sudo apt install -y python3-pytest`.
`libmonitor_core.so` not found — run `make` first.
Permission denied reading the auth log — run with `sudo`.
`__pycache__` folders appear — harmless Python cache; safe to delete
(`rm -rf __pycache__ tests/__pycache__`).
