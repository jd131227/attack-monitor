#!/usr/bin/env bash
# tests/smoke.sh - integration smoke test (spec 5.3).
#
# Builds a throwaway environment in a temp dir with a fake auth.log and config,
# runs the monitor loop for a few seconds, and confirms:
#   1. an SSH brute-force burst is detected (alert in the log), and
#   2. the loop stops safely on SIGINT/SIGTERM.
#
# No real firewall, network, or system path is touched.
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$HERE/libmonitor_core.so"

if [ ! -f "$LIB" ]; then
    echo "smoke: libmonitor_core.so missing - run 'make' first" >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

AUTH="$WORK/auth.log"
CONF="$WORK/monitor.conf"
OUT="$WORK/monitor.log"

# Fake auth.log with 25 failed SSH logins from one IP (> threshold of 20).
: > "$AUTH"
for i in $(seq 1 25); do
    echo "Jun 26 00:00:0$((i % 10)) host sshd[1]: Failed password for root from 203.0.113.66 port 2200$i ssh2" >> "$AUTH"
done

cat > "$CONF" <<EOF
INTERVAL=1
WINDOW=300
SSH_FAIL_THRESHOLD=20
AUTH_LOG=$AUTH
LOG_FILE=$OUT
AUDIT_LOG_FILE=$WORK/audit.log
ALLOWED_IPS_FILE=$WORK/allowed_ips.conf
FW_BACKUP_DIR=$WORK/backups
FW_STATE_FILE=$WORK/enforced.json
ENABLE_CONN_MON=false
ENABLE_PORT_MON=false
ENABLE_PROC_MON=false
EOF

echo "smoke: starting monitor for ~3s ..."
python3 "$HERE/monitor.py" --config "$CONF" run &
PID=$!
sleep 3

echo "smoke: sending SIGTERM (safe-stop test) ..."
kill -TERM "$PID" 2>/dev/null
wait "$PID" 2>/dev/null
RC=$?

echo "----- monitor.log -----"
cat "$OUT"
echo "-----------------------"

FAIL=0
if grep -q "ssh_bruteforce" "$OUT" || grep -q "over SSH fail threshold" "$OUT"; then
    echo "smoke: PASS - brute-force burst detected"
else
    echo "smoke: FAIL - detection alert not found" >&2
    FAIL=1
fi

if grep -q "stopped safely" "$OUT"; then
    echo "smoke: PASS - loop stopped safely"
else
    echo "smoke: FAIL - safe-stop message not found" >&2
    FAIL=1
fi

if [ "$FAIL" -eq 0 ]; then
    echo "smoke: ALL CHECKS PASSED"
    exit 0
fi
exit 1
