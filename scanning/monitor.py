#!/usr/bin/env python3
"""
monitor.py - Server attack-detection monitor, Python driver

Role (spec 2.1):
  - Call the C shared library libmonitor_core.so through ctypes and delegate the
    core aggregation to it.
  - Handle loop control, config loading, output formatting, the SSH allow-IP
    management CLI, work mode, firewall enforcement and TTL expiry.

Pointer passing (spec 2.1):
  - The aggregation table is held as a C pointer (void*) and treated as an
    opaque handle from Python.
  - Over-threshold IPs are produced by handing C a pointer to a ctypes string
    buffer for it to write into.

WARNING: this tool can change a real firewall. The default for every firewall
operation is dry-run; real changes require --yes (and --force when a connected
session would be at risk). Satisfy the prerequisites in spec section 0 before
running it for real.
"""

import argparse
import ctypes
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timedelta

# ---- Paths / defaults (overridable via monitor.conf) ----
HERE = os.path.dirname(os.path.abspath(__file__))
LIB_PATH = os.path.join(HERE, "libmonitor_core.so")

DEFAULTS = {
    "INTERVAL": 10,
    "WINDOW": 300,
    "SSH_FAIL_THRESHOLD": 20,
    "CONN_THRESHOLD": 50,
    "WHITELIST_IPS": [],            # alert-exclusion IPs (str list)
    "EXPECTED_PORTS": [22, 80, 443],  # ports that are allowed to be open
    "ALLOWED_SSH_PORTS": [22],      # ports treated as SSH for access control
    "PROC_WHITELIST": [],           # process names excluded from proc detection
    "PROC_CPU_THRESHOLD": 90.0,     # %CPU at/above which a process is flagged
    "PROC_MEM_THRESHOLD": 90.0,     # %MEM at/above which a process is flagged
    "LOG_FILE": "/var/log/attack-monitor.log",
    "AUDIT_LOG_FILE": "/var/log/attack-monitor-audit.log",
    "ALLOWED_IPS_FILE": "/etc/attack-monitor/allowed_ips.conf",
    "AUTH_LOG": "auto",             # auto = detect Debian/RHEL paths
    "FW_BACKEND": "auto",           # auto / ufw / firewalld / nft
    "FW_ZONE": "public",            # firewalld zone to manage
    "FW_BACKUP_DIR": "/var/lib/attack-monitor/backups",
    "FW_STATE_FILE": "/var/lib/attack-monitor/enforced.json",
    "FW_AUTO_SYNC": False,          # re-apply FW automatically when TTLs expire
    "ENABLE_IPV6": True,
    "ENABLE_CONN_MON": True,        # spec 3.2 suspicious source IPs
    "ENABLE_PORT_MON": True,        # spec 3.3 port changes
    "ENABLE_PROC_MON": True,        # spec 3.4 suspicious processes
    "LOG_MAX_BYTES": 10485760,      # rotate LOG_FILE past this size (spec 5.2)
    "NOTIFY_CMD": "",               # optional external notify command (spec 5.3)
}

_INT_KEYS = ("INTERVAL", "WINDOW", "SSH_FAIL_THRESHOLD", "CONN_THRESHOLD",
             "LOG_MAX_BYTES")
_FLOAT_KEYS = ("PROC_CPU_THRESHOLD", "PROC_MEM_THRESHOLD")
_BOOL_KEYS = ("ENABLE_IPV6", "FW_AUTO_SYNC", "ENABLE_CONN_MON",
              "ENABLE_PORT_MON", "ENABLE_PROC_MON")
_INT_LIST_KEYS = ("EXPECTED_PORTS", "ALLOWED_SSH_PORTS")
_STR_LIST_KEYS = ("WHITELIST_IPS", "PROC_WHITELIST")


# ============================================================
# Config loading
# ============================================================
def _as_bool(v):
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _as_int_list(v):
    return [int(x) for x in str(v).replace(",", " ").split()]


def _as_str_list(v):
    return [x for x in str(v).replace(",", " ").split()]


def load_config(path):
    cfg = dict(DEFAULTS)
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k in _INT_KEYS:
                    cfg[k] = int(v)
                elif k in _FLOAT_KEYS:
                    cfg[k] = float(v)
                elif k in _BOOL_KEYS:
                    cfg[k] = _as_bool(v)
                elif k in _INT_LIST_KEYS:
                    cfg[k] = _as_int_list(v)
                elif k in _STR_LIST_KEYS:
                    cfg[k] = _as_str_list(v)
                else:
                    cfg[k] = v
    return cfg


def detect_auth_log(cfg):
    if cfg["AUTH_LOG"] != "auto":
        return cfg["AUTH_LOG"]
    for p in ("/var/log/auth.log", "/var/log/secure"):
        if os.path.exists(p):
            return p
    return "/var/log/auth.log"


# ============================================================
# C library binding (ctypes)
# ============================================================
class Core:
    """Thin wrapper over libmonitor_core.so. Holds the C pointer and calls in."""

    def __init__(self, window_seconds):
        if not os.path.exists(LIB_PATH):
            raise FileNotFoundError(
                f"{LIB_PATH} not found. Build it first with `make`."
            )
        lib = ctypes.CDLL(LIB_PATH)

        # Signature declarations (required for correct pointer passing).
        lib.st_create.restype = ctypes.c_void_p
        lib.st_create.argtypes = [ctypes.c_long]
        lib.st_free.argtypes = [ctypes.c_void_p]
        lib.st_ingest_line.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_long]
        lib.st_ingest_line.restype = ctypes.c_int
        lib.st_expire.argtypes = [ctypes.c_void_p, ctypes.c_long]
        lib.st_count_over_threshold.argtypes = [
            ctypes.c_void_p, ctypes.c_long, ctypes.c_char_p, ctypes.c_size_t
        ]
        lib.st_count_over_threshold.restype = ctypes.c_int
        lib.ip_classify.argtypes = [ctypes.c_char_p]
        lib.ip_classify.restype = ctypes.c_int
        lib.ip_allowed.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.ip_allowed.restype = ctypes.c_int
        lib.conn_over_threshold.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_long,
            ctypes.c_char_p, ctypes.c_size_t
        ]
        lib.conn_over_threshold.restype = ctypes.c_int

        self.lib = lib
        # C-side table pointer (opaque handle).
        self.table = lib.st_create(ctypes.c_long(window_seconds))
        if not self.table:
            raise MemoryError("st_create failed")

    def ingest(self, line, now):
        return self.lib.st_ingest_line(self.table, line.encode("utf-8", "replace"),
                                       ctypes.c_long(int(now)))

    def expire(self, now):
        self.lib.st_expire(self.table, ctypes.c_long(int(now)))

    def over_threshold(self, threshold):
        buf = ctypes.create_string_buffer(4096)  # output buffer pointer for C
        n = self.lib.st_count_over_threshold(
            self.table, ctypes.c_long(threshold), buf, ctypes.c_size_t(len(buf))
        )
        return n, buf.value.decode("utf-8", "replace")

    def ip_classify(self, s):
        return self.lib.ip_classify(s.encode("utf-8", "replace"))

    def ip_allowed(self, ip, list_text):
        return bool(self.lib.ip_allowed(
            ip.encode("utf-8", "replace"), list_text.encode("utf-8", "replace")
        ))

    def conn_over_threshold(self, ip_list_text, whitelist_text, threshold):
        buf = ctypes.create_string_buffer(8192)
        n = self.lib.conn_over_threshold(
            ip_list_text.encode("utf-8", "replace"),
            whitelist_text.encode("utf-8", "replace"),
            ctypes.c_long(threshold), buf, ctypes.c_size_t(len(buf))
        )
        return n, buf.value.decode("utf-8", "replace")

    def close(self):
        if self.table:
            self.lib.st_free(self.table)
            self.table = None


# ============================================================
# Logging
# ============================================================
def _rotate_if_needed(path, max_bytes):
    """Simple rotation (spec 5.2): if `path` exceeds max_bytes, move it to .1."""
    if max_bytes and max_bytes > 0:
        try:
            if os.path.exists(path) and os.path.getsize(path) > max_bytes:
                os.replace(path, path + ".1")
        except OSError:
            pass  # never let rotation crash the loop


def log_line(path, msg, max_bytes=None):
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{stamp} {msg}"
    print(line, flush=True)
    try:
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        _rotate_if_needed(path, max_bytes)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError as e:
        print(f"(failed to write log: {e})", file=sys.stderr)


def audit(cfg, msg):
    log_line(cfg["AUDIT_LOG_FILE"], "[AUDIT] " + msg, cfg.get("LOG_MAX_BYTES"))


# ============================================================
# Alert notification hook (spec 5.3)
# ============================================================
def notify(cfg, event):
    """
    Single place every alert flows through. Default behaviour is stdout + log.
    `event` is a dict like {"type": "ssh_bruteforce", "detail": "..."}.

    Extension point: set NOTIFY_CMD in the config to an external command. The
    event is delivered to it as JSON on stdin, so you can wire up Slack / email /
    a Discord or generic webhook without touching this file. For example a tiny
    wrapper script could read stdin and POST it:

        NOTIFY_CMD=/opt/attack-monitor/notify-slack.sh

    (The network send itself is intentionally left to that external command.)
    """
    msg = f"[ALERT:{event.get('type', 'generic')}] {event.get('detail', '')}"
    log_line(cfg["LOG_FILE"], "⚠️ " + msg, cfg.get("LOG_MAX_BYTES"))

    cmd = cfg.get("NOTIFY_CMD", "")
    if cmd:
        try:
            run_cmd([cmd], input_text=json.dumps(event), check=False)
        except Exception as e:  # a broken hook must never kill the loop
            log_line(cfg["LOG_FILE"], f"(notify hook failed: {e})",
                     cfg.get("LOG_MAX_BYTES"))


# ============================================================
# External-command seams (kept tiny so tests can monkeypatch them)
# ============================================================
def run_cmd(argv, input_text=None, check=True):
    """
    Run a STATE-CHANGING external command (firewall edits, notify hook).
    Tests monkeypatch this and assert it is never called during a dry-run.
    """
    return subprocess.run(argv, input=input_text, text=True,
                          capture_output=True, check=check)


def _capture(argv):
    """
    Run a READ-ONLY command and return its stdout (empty string on error).
    Used for `ss`, `who`, `ps`, and firewall state backups.
    """
    try:
        r = subprocess.run(argv, text=True, capture_output=True, check=False)
        return r.stdout or ""
    except (OSError, ValueError):
        return ""


# ============================================================
# Allow-IP management (spec 4.5)
# ============================================================
def read_allowed(cfg):
    p = cfg["ALLOWED_IPS_FILE"]
    if not os.path.exists(p):
        return ""
    with open(p, encoding="utf-8") as f:
        return f.read()


def write_allowed(cfg, text):
    p = cfg["ALLOWED_IPS_FILE"]
    d = os.path.dirname(p)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(text)


def _entry_address(line):
    """Return the bare address token of an allow-file line (comment stripped),
    or "" for blank/comment-only lines."""
    addr = line.split("#", 1)[0].strip()
    return addr


def allowed_entries(text):
    """All address tokens (IP/CIDR) in the allow text, in file order."""
    out = []
    for ln in text.splitlines():
        addr = _entry_address(ln)
        if addr:
            out.append(addr)
    return out


def cmd_allow_ip(cfg, core, ip, comment, expires=None):
    if core.ip_classify(ip) == 0:
        print(f"Invalid IP/CIDR: {ip}", file=sys.stderr)
        return 1
    text = read_allowed(cfg)
    if expires:
        # A TTL was requested (work mode). Never short-circuit on "already
        # allowed": drop any existing EXACT entry for this IP and re-add it with
        # the new expires= marker, so the TTL we report is actually written and
        # enforced (a pre-existing permanent line would otherwise keep the IP
        # allowed forever while we claimed it auto-expires).
        kept = [ln for ln in text.splitlines()
                if ln.strip() and _entry_address(ln) != ip]
        text = "\n".join(kept) + ("\n" if kept else "")
    elif core.ip_allowed(ip, text) and "/" not in ip:
        print(f"Already allowed: {ip}")
        return 0
    suffix = f"  # {comment}" if comment else ""
    if expires:
        suffix += f"  # expires={expires}"
    if text and not text.endswith("\n"):
        text += "\n"
    write_allowed(cfg, text + f"{ip}{suffix}\n")
    audit(cfg, f"allow-ip {ip} comment={comment!r} expires={expires}")
    # The list is the source of truth. Firewall rules are (re)built from it by
    # apply-firewall; if FW is already enforced and FW_AUTO_SYNC is on the loop
    # keeps it in sync. We do not silently touch the firewall here.
    print(f"Added to allow list: {ip}")
    return 0


def cmd_remove_ip(cfg, ip):
    text = read_allowed(cfg)
    kept = [ln for ln in text.splitlines()
            if ln.strip() and _entry_address(ln) != ip]
    write_allowed(cfg, "\n".join(kept) + ("\n" if kept else ""))
    audit(cfg, f"remove-ip {ip}")
    print(f"Removed from allow list: {ip}")
    return 0


def cmd_list_ips(cfg):
    text = read_allowed(cfg).strip()
    print(text if text else "(no allowed IPs registered)")
    return 0


# ============================================================
# TTL auto-expiry (spec 4.3 / 5.5)
# ============================================================
def _parse_expires(line):
    """Return the datetime in a '# expires=<ISO8601>' marker, or None."""
    marker = "expires="
    idx = line.find(marker)
    if idx < 0:
        return None
    # A hand-edited line may carry the marker with nothing after it
    # ("1.2.3.4  # expires="); split() then yields [] and [0] would raise. Guard
    # it so one malformed allow-file line can never abort the loop's expiry pass
    # (which runs before all detection each tick).
    parts = line[idx + len(marker):].strip().split()
    if not parts:
        return None
    val = parts[0].strip("#").strip()
    try:
        return datetime.fromisoformat(val)
    except ValueError:
        return None


def expire_temporary_allows(cfg, core, now=None):
    """
    Drop allow-list entries whose TTL has passed, record each in the audit log,
    and (when FW is enforced and FW_AUTO_SYNC is on) rebuild the firewall so the
    expired IP loses access. Called once per loop tick. `now` is injectable for
    tests. Returns the list of expired address tokens.
    """
    now = now or datetime.now()
    text = read_allowed(cfg)
    if not text:
        return []
    kept, expired = [], []
    for ln in text.splitlines():
        if not ln.strip():
            continue
        exp = _parse_expires(ln)
        if exp is not None and exp <= now:
            expired.append(_entry_address(ln))
        else:
            kept.append(ln)
    if not expired:
        return []
    write_allowed(cfg, "\n".join(kept) + ("\n" if kept else ""))
    for addr in expired:
        audit(cfg, f"ttl-expire {addr} (temporary allow expired)")
    # Re-sync the firewall only when we are actively enforcing and asked to.
    if cfg.get("FW_AUTO_SYNC") and os.path.exists(cfg.get("FW_STATE_FILE", "")):
        try:
            apply_firewall(cfg, dry_run=False, assume_yes=True, force=True,
                           core=core, quiet=True)
        except Exception as e:
            log_line(cfg["LOG_FILE"], f"⚠️ FW re-sync after expiry failed: {e}",
                     cfg.get("LOG_MAX_BYTES"))
    return expired


# ============================================================
# Connected-SSH-client detection (spec 4.5.3 lockout safeguard)
# ============================================================
def _normalize_host(host):
    """Normalize an IPv4-mapped IPv6 address ('::ffff:1.2.3.4') down to its bare
    IPv4 form so it compares equal to a plain '1.2.3.4' allow-list entry. Other
    addresses are returned unchanged."""
    host = host.strip()
    low = host.lower()
    if low.startswith("::ffff:") and "." in host:
        return host[len("::ffff:"):]
    return host


def _strip_ss_host(token):
    """Extract the host from an `ss` address token like '1.2.3.4:22',
    '[2001:db8::1]:22', '[::ffff:1.2.3.4]:22' or '::ffff:1.2.3.4:22'.
    IPv4-mapped IPv6 is normalized to the bare IPv4 address."""
    token = token.strip()
    if token.startswith("["):
        end = token.find("]")
        if end > 0:
            return _normalize_host(token[1:end])
    # IPv4 (or a token with a single colon): host is before the LAST colon.
    if token.count(":") <= 1:
        host = token.rsplit(":", 1)[0] if ":" in token else token
        return _normalize_host(host)
    # Bare IPv6 with a trailing :port and no brackets - rsplit once.
    return _normalize_host(token.rsplit(":", 1)[0])


def parse_ss_peer_ips(text):
    """Parse peer (remote) IPs from `ss -tnH` output. One IP per established
    connection (duplicates kept so connection counts are meaningful)."""
    ips = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        peer = parts[4]            # Peer Address:Port column for -tnH
        host = _strip_ss_host(peer)
        if host:
            ips.append(host)
    return ips


def parse_ss_listen_ports(text):
    """Parse the set of LISTEN ports from `ss -tlnH` output."""
    ports = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]           # Local Address:Port column
        host = local.rsplit(":", 1)
        if len(host) == 2 and host[1].isdigit():
            ports.add(int(host[1]))
    return ports


def detect_ssh_client_ips(cfg):
    """
    Best-effort detection of the source IPs of currently connected SSH sessions,
    used to avoid locking ourselves out. Combines:
      - the SSH_CONNECTION env var (the session running this command), and
      - established connections to the SSH ports as seen by `ss`.
    """
    ips = set()
    # SSH_CONNECTION is normally "<client_ip> <client_port> <server_ip>
    # <server_port>", but a malformed/whitespace-only export would make
    # env.split()[0] raise IndexError and crash apply-firewall --yes; guard it.
    env_parts = os.environ.get("SSH_CONNECTION", "").split()
    if env_parts:
        ips.add(_normalize_host(env_parts[0]))

    ssh_ports = set(cfg.get("ALLOWED_SSH_PORTS", [22]))
    text = _capture(["ss", "-tnH", "state", "established"])
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        local, peer = parts[3], parts[4]
        lport = local.rsplit(":", 1)
        if len(lport) == 2 and lport[1].isdigit() and int(lport[1]) in ssh_ports:
            host = _strip_ss_host(peer)
            if host:
                ips.add(host)
    return ips


# ============================================================
# Trusted-source handling (spec 4.6.2 alert suppression)
# ============================================================
def trusted_text(cfg):
    """The combined trusted set: allow-list entries (incl. work-mode TTL IPs)
    plus WHITELIST_IPS, as newline-separated text for the C ip_allowed()."""
    return read_allowed(cfg) + "\n" + "\n".join(cfg.get("WHITELIST_IPS", []))


def split_suppressed(core, detail, trusted):
    """Split "ip (count)" lines from a C over-threshold buffer into
    (alertable, suppressed) line lists. A source that matches the trusted set
    (work-mode/whitelist/allow-list) is suppressed: per spec 4.6.2 the record is
    kept but no warning is raised for it."""
    alertable, suppressed = [], []
    for line in detail.splitlines():
        line = line.strip()
        if not line:
            continue
        ip = line.split(" ", 1)[0]
        if core.ip_allowed(ip, trusted):
            suppressed.append(line)
        else:
            alertable.append(line)
    return alertable, suppressed


# ============================================================
# Monitoring extensions (spec 3.2 / 3.3 / 3.4)
# ============================================================
def check_connection_flood(cfg, core):
    """spec 3.2 - too many simultaneous connections from one source IP.
    Allow-list and WHITELIST_IPS are excluded as trusted peers."""
    if not cfg.get("ENABLE_CONN_MON", True):
        return
    text = _capture(["ss", "-tnH", "state", "established"])
    peers = parse_ss_peer_ips(text)
    if not peers:
        return
    n, detail = core.conn_over_threshold("\n".join(peers), trusted_text(cfg),
                                         cfg["CONN_THRESHOLD"])
    if n > 0:
        notify(cfg, {"type": "conn_flood",
                     "detail": f"{n} source IP(s) over CONN_THRESHOLD="
                               f"{cfg['CONN_THRESHOLD']}:\n{detail.strip()}"})


def check_listening_ports(cfg):
    """spec 3.3 - an unexpected port has started LISTENing."""
    if not cfg.get("ENABLE_PORT_MON", True):
        return
    text = _capture(["ss", "-tlnH"])
    ports = parse_ss_listen_ports(text)
    expected = set(cfg.get("EXPECTED_PORTS", []))
    unexpected = sorted(p for p in ports if p not in expected)
    if unexpected:
        notify(cfg, {"type": "unexpected_port",
                     "detail": f"unexpected LISTEN port(s): "
                               f"{', '.join(str(p) for p in unexpected)}"})


def parse_ps_high_usage(text, cpu_th, mem_th, whitelist):
    """Parse `ps -eo pid,pcpu,pmem,comm` (no header) and return processes whose
    %CPU or %MEM is at/above threshold and not whitelisted."""
    hits = []
    for line in text.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        pid, pcpu, pmem, comm = parts
        try:
            cpu, mem = float(pcpu), float(pmem)
        except ValueError:
            continue
        name = comm.strip()
        if name in whitelist:
            continue
        if cpu >= cpu_th or mem >= mem_th:
            hits.append((pid, cpu, mem, name))
    return hits


def check_suspicious_processes(cfg):
    """spec 3.4 - processes burning CPU/RAM (possible miner/backdoor)."""
    if not cfg.get("ENABLE_PROC_MON", True):
        return
    text = _capture(["ps", "-eo", "pid,pcpu,pmem,comm", "--no-headers"])
    hits = parse_ps_high_usage(text, cfg["PROC_CPU_THRESHOLD"],
                               cfg["PROC_MEM_THRESHOLD"],
                               set(cfg.get("PROC_WHITELIST", [])))
    if hits:
        detail = "\n".join(f"pid={p} cpu={c}% mem={m}% {n}"
                           for p, c, m, n in hits)
        notify(cfg, {"type": "suspicious_proc",
                     "detail": f"{len(hits)} high-usage process(es):\n{detail}"})


# ============================================================
# Firewall enforcement (spec 4.1 / 4.2)
# ============================================================
def fw_detect_backend(cfg):
    """Honor FW_BACKEND, else auto-detect in the order ufw -> firewalld -> nft."""
    want = cfg.get("FW_BACKEND", "auto")
    if want and want != "auto":
        return want
    for name, probe in (("ufw", "ufw"), ("firewalld", "firewall-cmd"),
                        ("nft", "nft")):
        if shutil.which(probe):
            return name
    return None


def _split_families(entries):
    """Split allow entries (IP/CIDR tokens) into (v4_list, v6_list)."""
    v4, v6 = [], []
    for e in entries:
        (v6 if ":" in e else v4).append(e)
    return v4, v6


def _step(desc, argv, stdin=None, check=True):
    return {"desc": desc, "argv": argv, "stdin": stdin, "check": check}


def _plan_ufw(cfg, v4, v6, ports):
    """ufw plan. ufw matches first-rule-wins by position, so the allow rules
    must sit BEFORE the deny. On a re-apply the deny may already exist with a
    low rule number while a newly-added allow would be appended at the end
    (after the deny) and never match - locking out the new IP. To stay correct
    across re-applies we first delete any prior managed deny (tolerated if
    absent), then add the allows, then re-add the deny LAST so it is always the
    final rule."""
    steps = []
    # Remove any prior managed deny so it can be re-added after all allows.
    for port in ports:
        steps.append(_step(f"clear prior deny {port}/tcp",
                           ["ufw", "delete", "deny", f"{port}/tcp"],
                           check=False))
    for ip in v4 + v6:
        for port in ports:
            steps.append(_step(
                f"allow {ip} -> {port}/tcp",
                ["ufw", "allow", "from", ip, "to", "any",
                 "port", str(port), "proto", "tcp"]))
    for port in ports:
        steps.append(_step(f"deny {port}/tcp (default)",
                           ["ufw", "deny", f"{port}/tcp"]))
    steps.append(_step("reload", ["ufw", "reload"]))
    return steps


def _plan_firewalld(cfg, v4, v6, ports):
    """firewalld plan. Each per-IP accept rich rule gets a high precedence (low
    priority number) and each default reject a low precedence, so an accept
    always wins over the reject regardless of insertion order - no lockout of a
    listed IP. Every rule is applied to BOTH runtime (effective immediately) and
    permanent (survives reboot), accepts before rejects, so a partial failure
    can never leave a live reject without its matching accepts. No reload is
    needed because runtime is updated directly."""
    zone = cfg.get("FW_ZONE", "public")
    steps = []

    def add_rule(desc, rich):
        # Runtime first (takes effect now), then permanent (persists).
        steps.append(_step(f"{desc} [runtime]",
                           ["firewall-cmd", f"--zone={zone}",
                            f"--add-rich-rule={rich}"]))
        steps.append(_step(f"{desc} [permanent]",
                           ["firewall-cmd", "--permanent", f"--zone={zone}",
                            f"--add-rich-rule={rich}"]))

    for ip in v4 + v6:
        fam = "ipv6" if ":" in ip else "ipv4"
        for port in ports:
            rich = (f'rule priority="-100" family="{fam}" source address="{ip}" '
                    f'port port="{port}" protocol="tcp" accept')
            add_rule(f"allow {ip} -> {port}/tcp", rich)
    # Default-reject the SSH ports for any source the accepts did not match.
    for port in ports:
        for fam in ("ipv4", "ipv6"):
            rich = (f'rule priority="100" family="{fam}" port port="{port}" '
                    f'protocol="tcp" reject')
            add_rule(f"reject {port}/tcp ({fam}) default", rich)
    return steps


def _nft_ruleset(v4, v6, ports):
    """Build an idempotent nftables ruleset for a dedicated table. Established
    connections and listed sources are accepted before the SSH ports are dropped
    for everyone else; non-SSH traffic is untouched (policy accept)."""
    portset = "{ " + ", ".join(str(p) for p in ports) + " }"
    lines = [
        "add table inet attack_monitor",
        "delete table inet attack_monitor",
        "table inet attack_monitor {",
        "    chain input {",
        "        type filter hook input priority -10; policy accept;",
        "        ct state established,related accept",
    ]
    if v4:
        lines.append(f"        ip saddr {{ {', '.join(v4)} }} "
                     f"tcp dport {portset} accept")
    if v6:
        lines.append(f"        ip6 saddr {{ {', '.join(v6)} }} "
                     f"tcp dport {portset} accept")
    lines.append(f"        tcp dport {portset} drop")
    lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _plan_nft(cfg, v4, v6, ports):
    """nft plan: a single atomic `nft -f -` load of the ruleset on stdin."""
    ruleset = _nft_ruleset(v4, v6, ports)
    return [_step("load attack_monitor ruleset", ["nft", "-f", "-"],
                  stdin=ruleset)]


def fw_plan(backend, cfg, entries, ports):
    v4, v6 = _split_families(entries)
    if not cfg.get("ENABLE_IPV6", True):
        v6 = []
    if backend == "ufw":
        return _plan_ufw(cfg, v4, v6, ports)
    if backend == "firewalld":
        return _plan_firewalld(cfg, v4, v6, ports)
    if backend == "nft":
        return _plan_nft(cfg, v4, v6, ports)
    raise ValueError(f"unknown firewall backend: {backend}")


def fw_capture_state(backend, cfg):
    """Read-only snapshot text of the current firewall, for backups."""
    if backend == "ufw":
        return _capture(["ufw", "status", "verbose"])
    if backend == "firewalld":
        zone = cfg.get("FW_ZONE", "public")
        return _capture(["firewall-cmd", f"--zone={zone}", "--list-all"])
    if backend == "nft":
        return _capture(["nft", "list", "ruleset"])
    return ""


def _rich_rules_in_plan(steps):
    """Extract the unique --add-rich-rule=<...> values from a firewalld plan, so
    rollback can remove exactly what apply added (deduped, runtime+permanent
    steps collapse to one)."""
    rules = []
    for s in steps:
        for arg in s["argv"]:
            if arg.startswith("--add-rich-rule="):
                rich = arg[len("--add-rich-rule="):]
                if rich not in rules:
                    rules.append(rich)
    return rules


def fw_backup(cfg, backend, steps=None):
    """Snapshot current FW state to FW_BACKUP_DIR/fw_backup_<ts>.json and return
    the backup file path. For firewalld we also record the exact rich rules this
    apply will add, so rollback can remove precisely those."""
    d = cfg.get("FW_BACKUP_DIR")
    os.makedirs(d, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(d, f"fw_backup_{ts}.json")
    manifest = {
        "timestamp": ts,
        "backend": backend,
        "zone": cfg.get("FW_ZONE", "public"),
        "ssh_ports": cfg.get("ALLOWED_SSH_PORTS", [22]),
        "dump": fw_capture_state(backend, cfg),
        # Rich rules this apply adds (firewalld only); used for precise rollback.
        "applied_rich_rules": _rich_rules_in_plan(steps or []),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return path


def fw_restore(cfg, backup_path):
    """Restore firewall state from a backup manifest produced by fw_backup()."""
    with open(backup_path, encoding="utf-8") as f:
        manifest = json.load(f)
    backend = manifest["backend"]
    dump = manifest.get("dump", "")
    if backend == "nft":
        # Re-apply the saved ruleset atomically (flush first so it is exact).
        run_cmd(["nft", "-f", "-"], input_text="flush ruleset\n" + dump)
    elif backend == "ufw":
        # ufw's textual status cannot be replayed directly; remove our managed
        # deny rules and reload so the prior persistent rules take effect again.
        for port in manifest.get("ssh_ports", cfg.get("ALLOWED_SSH_PORTS", [22])):
            run_cmd(["ufw", "delete", "deny", f"{port}/tcp"], check=False)
        run_cmd(["ufw", "reload"], check=False)
    elif backend == "firewalld":
        # Remove EXACTLY the rich rules this apply added, from both runtime and
        # permanent config, so access returns to its pre-apply state. A bare
        # --reload would re-assert the persisted rules, so we must delete them.
        zone = manifest.get("zone", cfg.get("FW_ZONE", "public"))
        for rich in manifest.get("applied_rich_rules", []):
            run_cmd(["firewall-cmd", f"--zone={zone}",
                     f"--remove-rich-rule={rich}"], check=False)
            run_cmd(["firewall-cmd", "--permanent", f"--zone={zone}",
                     f"--remove-rich-rule={rich}"], check=False)
        run_cmd(["firewall-cmd", "--reload"], check=False)
    return backend


def fw_execute(steps):
    """Run each plan step via run_cmd. Raises on the first failure of a step
    whose check flag is set (clean-up steps use check=False)."""
    for s in steps:
        run_cmd(s["argv"], input_text=s.get("stdin"), check=s.get("check", True))


def _print_plan(steps, header):
    print(header)
    for s in steps:
        print(f"  $ {' '.join(s['argv'])}")
        if s.get("stdin"):
            for ln in s["stdin"].splitlines():
                print(f"      | {ln}")


def apply_firewall(cfg, dry_run=True, assume_yes=False, force=False,
                   core=None, quiet=False):
    """
    Apply SSH access control from the allow list (spec 4.1 / 4.2).

    Order of operations on a real apply:
      1. detect connected SSH client IPs;
      2. if any are NOT in the allow list, warn and abort unless --force;
      3. back up the current firewall state;
      4. apply allow rules BEFORE the default-deny (never cut existing sessions);
      5. on any failure, roll back from the backup.
    dry_run (default) only prints the plan and runs no external command.
    """
    entries = allowed_entries(read_allowed(cfg))
    ports = cfg.get("ALLOWED_SSH_PORTS", [22])
    backend = fw_detect_backend(cfg)
    if backend is None:
        print("No supported firewall backend found (ufw/firewalld/nft).",
              file=sys.stderr)
        return 1

    steps = fw_plan(backend, cfg, entries, ports)

    if dry_run:
        _print_plan(steps, f"== apply-firewall (dry-run, backend={backend}) ==")
        if not entries:
            print("  NOTE: allow list is empty - applying would deny all SSH.")
        print("  (dry-run: nothing was changed)")
        return 0

    if not assume_yes:
        print("Refusing to apply without --yes (use --dry-run to preview).",
              file=sys.stderr)
        return 1

    if not entries:
        if not force:
            print("Allow list is empty: applying would lock out ALL SSH. "
                  "Re-run with --force if you really mean it.", file=sys.stderr)
            return 1

    # --- Safety: connected-IP lockout check (spec 4.5.3) ---
    own_core = core or Core(cfg["WINDOW"])
    try:
        allowed_text = read_allowed(cfg)
        connected = detect_ssh_client_ips(cfg)
        if connected:
            print(f"Currently connected SSH client IP(s): "
                  f"{', '.join(sorted(connected))}")
        at_risk = [ip for ip in sorted(connected)
                   if not own_core.ip_allowed(ip, allowed_text)]
        if at_risk and not force:
            print("⚠️ These connected IP(s) are NOT in the allow list and "
                  "could be disconnected:", file=sys.stderr)
            for ip in at_risk:
                print(f"   - {ip}", file=sys.stderr)
            print("Aborting. Add them with allow-ip, or re-run with --force "
                  "if you are certain (e.g. you have console/KVM access).",
                  file=sys.stderr)
            audit(cfg, f"apply-firewall ABORTED (at-risk connected IPs: "
                       f"{','.join(at_risk)})")
            return 2
    finally:
        if core is None:
            own_core.close()

    # --- Backup, then apply allow-before-deny; roll back on failure ---
    backup_path = None
    try:
        backup_path = fw_backup(cfg, backend, steps)
        if not quiet:
            print(f"Backed up current firewall state to {backup_path}")
        fw_execute(steps)
    except Exception as e:
        msg = f"apply-firewall FAILED ({e})"
        print(f"⚠️ {msg}", file=sys.stderr)
        audit(cfg, msg)
        if backup_path:
            try:
                fw_restore(cfg, backup_path)
                print(f"Rolled back from {backup_path}", file=sys.stderr)
                audit(cfg, f"rolled back from {backup_path}")
            except Exception as re:
                print(f"⚠️ ROLLBACK ALSO FAILED: {re}", file=sys.stderr)
                audit(cfg, f"ROLLBACK FAILED: {re}")
        return 1

    # Record that we are now enforcing, so TTL re-sync knows it may act.
    try:
        sf = cfg.get("FW_STATE_FILE")
        if sf:
            os.makedirs(os.path.dirname(sf), exist_ok=True)
            with open(sf, "w", encoding="utf-8") as f:
                json.dump({"backend": backend,
                           "applied": datetime.now().isoformat(),
                           "backup": backup_path}, f)
    except OSError:
        pass

    audit(cfg, f"apply-firewall applied (backend={backend}, "
               f"entries={len(entries)}, ports={ports})")
    if not quiet:
        print(f"Applied SSH access control via {backend}.")
    return 0


def cmd_rollback(cfg, list_only=False, backup_file=None):
    """Restore the firewall from a backup (default: the most recent)."""
    d = cfg.get("FW_BACKUP_DIR")
    backups = []
    if d and os.path.isdir(d):
        backups = sorted(f for f in os.listdir(d)
                         if f.startswith("fw_backup_") and f.endswith(".json"))
    if list_only:
        if not backups:
            print("(no firewall backups found)")
        for b in backups:
            print(os.path.join(d, b))
        return 0
    if backup_file:
        path = backup_file
    elif backups:
        path = os.path.join(d, backups[-1])
    else:
        print("No firewall backup to roll back to.", file=sys.stderr)
        return 1
    backend = fw_restore(cfg, path)
    audit(cfg, f"rollback restored {path} (backend={backend})")
    print(f"Rolled back firewall from {path}")
    return 0


# ============================================================
# Work mode (spec 4.6)
# ============================================================
def parse_duration(s):
    s = str(s).strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if s and s[-1] in units:
        return int(float(s[:-1]) * units[s[-1]])
    return int(s)  # bare number = seconds


def cmd_work_mode(cfg, core, action, ip=None, duration="2h", reason=""):
    if action == "start":
        if not ip or core.ip_classify(ip) == 0:
            print("Provide a valid --ip", file=sys.stderr)
            return 1
        secs = parse_duration(duration)
        expires = (datetime.now() + timedelta(seconds=secs)).strftime(
            "%Y-%m-%dT%H:%M:%S")
        cmd_allow_ip(cfg, core, ip, f"work-mode:{reason}", expires=expires)
        audit(cfg, f"work-mode start ip={ip} duration={duration} reason={reason!r}")
        print(f"Work mode started: {ip} allowed for {duration} "
              f"(auto-expires at {expires}). Monitoring keeps running.")
        return 0
    if action == "stop":
        # Actually END the work mode now (spec 4.6.2 lists stop as the explicit
        # end command, distinct from --duration auto-expiry). Remove the entries
        # work-mode start created (comment contains "work-mode:"); if --ip is
        # given, only that one. Auditing each removal; the loop's TTL pass and
        # plain remove-ip remain as fallbacks.
        text = read_allowed(cfg)
        kept, removed = [], []
        for ln in text.splitlines():
            if not ln.strip():
                continue
            is_work = "work-mode:" in ln
            matches_ip = (ip is None) or (_entry_address(ln) == ip)
            if is_work and matches_ip:
                removed.append(_entry_address(ln))
            else:
                kept.append(ln)
        if removed:
            write_allowed(cfg, "\n".join(kept) + ("\n" if kept else ""))
            for addr in removed:
                audit(cfg, f"work-mode stop removed {addr}")
            # Re-sync the firewall if we are enforcing and configured to.
            if cfg.get("FW_AUTO_SYNC") and os.path.exists(
                    cfg.get("FW_STATE_FILE", "")):
                try:
                    apply_firewall(cfg, dry_run=False, assume_yes=True,
                                   force=True, core=core, quiet=True)
                except Exception as e:
                    log_line(cfg["LOG_FILE"],
                             f"⚠️ FW re-sync after work-mode stop failed: {e}",
                             cfg.get("LOG_MAX_BYTES"))
            print(f"Work mode stopped: removed {', '.join(removed)}. "
                  "Monitoring keeps running.")
        else:
            audit(cfg, "work-mode stop (no work-mode entries to remove)")
            print("Work mode stopped: no active work-mode entries found.")
        return 0
    # status
    print("Work mode status: temporary (expires=) entries in the allow list:")
    return cmd_list_ips(cfg)


# ============================================================
# Main loop (spec 5.1 / 5.4 / 5.5)
# ============================================================
class Monitor:
    def __init__(self, cfg):
        self.cfg = cfg
        self.core = Core(cfg["WINDOW"])
        self.auth_log = detect_auth_log(cfg)
        self.offset = 0          # diff-read offset (5.4)
        self.inode = None
        self.running = True

    def read_new_lines(self):
        """Read only what is new since the last offset. On rotation, restart
        from the top."""
        try:
            st = os.stat(self.auth_log)
        except OSError:
            log_line(self.cfg["LOG_FILE"], f"⚠️ cannot read log: {self.auth_log}",
                     self.cfg.get("LOG_MAX_BYTES"))
            return []
        if self.inode is None:
            self.inode = st.st_ino
        if st.st_ino != self.inode or st.st_size < self.offset:
            self.offset = 0       # rotated -> read from the top
            self.inode = st.st_ino
        lines = []
        try:
            with open(self.auth_log, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self.offset)
                lines = f.readlines()
                self.offset = f.tell()
        except OSError as e:
            log_line(self.cfg["LOG_FILE"], f"⚠️ log read error: {e}",
                     self.cfg.get("LOG_MAX_BYTES"))
        return lines

    def tick(self):
        now = time.time()
        added = 0
        for ln in self.read_new_lines():
            added += self.core.ingest(ln, now)
        self.core.expire(now)    # recursively drop out-of-window entries (5.4)

        # 5.5: expire temporary allow entries (work mode TTLs) each tick.
        expired = expire_temporary_allows(self.cfg, self.core)
        if expired:
            log_line(self.cfg["LOG_FILE"],
                     f"TTL expired and removed: {', '.join(expired)}",
                     self.cfg.get("LOG_MAX_BYTES"))

        # 3.1 SSH brute force. Trusted sources (work-mode TTL allows, allow
        # list, WHITELIST_IPS) are suppressed per spec 4.6.2: their record is
        # still logged, but no warning alert is raised for them.
        n, detail = self.core.over_threshold(self.cfg["SSH_FAIL_THRESHOLD"])
        alertable, suppressed = split_suppressed(self.core, detail,
                                                 trusted_text(self.cfg))
        if suppressed:
            log_line(self.cfg["LOG_FILE"],
                     "(suppressed - trusted source over SSH fail threshold): "
                     + "; ".join(suppressed),
                     self.cfg.get("LOG_MAX_BYTES"))
        if alertable:
            notify(self.cfg, {"type": "ssh_bruteforce",
                              "detail": f"{len(alertable)} IP(s) over SSH fail "
                                        f"threshold:\n" + "\n".join(alertable)})
        else:
            log_line(self.cfg["LOG_FILE"],
                     f"OK ingested {added} new line(s) / 0 alertable IP(s) over "
                     f"threshold (window {self.cfg['WINDOW']}s)",
                     self.cfg.get("LOG_MAX_BYTES"))

        # 3.2 / 3.3 / 3.4 extended monitors (each guarded by its own toggle).
        check_connection_flood(self.cfg, self.core)
        check_listening_ports(self.cfg)
        check_suspicious_processes(self.cfg)

    def run(self):
        def stop(*_):
            self.running = False
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
        log_line(self.cfg["LOG_FILE"],
                 f"monitor started log={self.auth_log} "
                 f"interval={self.cfg['INTERVAL']}s",
                 self.cfg.get("LOG_MAX_BYTES"))
        while self.running:
            try:
                self.tick()
            except Exception as e:   # keep running, just warn (5.1 / 8)
                log_line(self.cfg["LOG_FILE"], f"⚠️ tick exception: {e}",
                         self.cfg.get("LOG_MAX_BYTES"))
            for _ in range(self.cfg["INTERVAL"]):
                if not self.running:
                    break
                time.sleep(1)
        self.core.close()
        log_line(self.cfg["LOG_FILE"], "monitor stopped safely.",
                 self.cfg.get("LOG_MAX_BYTES"))


# ============================================================
# CLI
# ============================================================
def build_parser():
    ap = argparse.ArgumentParser(description="Server attack-detection monitor")
    ap.add_argument("--config", default=os.path.join(HERE, "monitor.conf"))
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("run", help="start the monitoring loop")

    p = sub.add_parser("allow-ip", help="add an SSH allow IP")
    p.add_argument("ip")
    p.add_argument("comment", nargs="?", default="")

    p = sub.add_parser("remove-ip", help="remove an allow IP")
    p.add_argument("ip")
    sub.add_parser("list-ips", help="list allow IPs")

    p = sub.add_parser("apply-firewall", help="apply the allow list to the FW")
    p.add_argument("--dry-run", action="store_true", default=True)
    p.add_argument("--yes", dest="dry_run", action="store_false",
                   help="actually apply (disables dry-run)")
    p.add_argument("--force", action="store_true",
                   help="apply even if a connected IP would be cut off")

    p = sub.add_parser("rollback", help="restore the firewall from a backup")
    p.add_argument("--list", dest="list_only", action="store_true",
                   help="list available backups")
    p.add_argument("--file", default=None, help="restore a specific backup file")

    p = sub.add_parser("work-mode", help="work mode start/stop/status")
    p.add_argument("action", choices=["start", "stop", "status"])
    p.add_argument("--ip")
    p.add_argument("--duration", default="2h")
    p.add_argument("--reason", default="")
    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    cfg = load_config(args.config)

    if args.cmd == "run":
        Monitor(cfg).run()
        return 0

    if args.cmd == "rollback":
        return cmd_rollback(cfg, list_only=args.list_only, backup_file=args.file)

    if args.cmd == "apply-firewall":
        return apply_firewall(cfg, dry_run=args.dry_run, assume_yes=not args.dry_run,
                              force=args.force)

    # Remaining commands need a Core for IP validation.
    core = Core(cfg["WINDOW"])
    try:
        if args.cmd == "allow-ip":
            return cmd_allow_ip(cfg, core, args.ip, args.comment)
        if args.cmd == "remove-ip":
            return cmd_remove_ip(cfg, args.ip)
        if args.cmd == "list-ips":
            return cmd_list_ips(cfg)
        if args.cmd == "work-mode":
            return cmd_work_mode(cfg, core, args.action, args.ip,
                                 args.duration, args.reason)
        ap.print_help()
        return 1
    finally:
        core.close()


if __name__ == "__main__":
    sys.exit(main())
