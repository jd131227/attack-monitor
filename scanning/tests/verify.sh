#!/usr/bin/env bash
# verify.sh - run every acceptance command from IMPLEMENTATION_TASKS.md §6 and
# capture the output. Run this ON THE TARGET KALI HOST, then paste the result
# into VERIFICATION.md (or run: bash verify.sh | tee verify-output.txt).
#
# Nothing here touches the real firewall: apply-firewall is run in dry-run only.
set -u
cd "$(dirname "$0")"

hr() { printf '\n===== %s =====\n' "$1"; }

hr "1. make clean && make (warning-free build)"
make clean && make

hr "2. make test (C tests -> ALL TESTS PASSED)"
make test

hr "3. pytest -q (Python tests -> all passed)"
python3 -m pytest -q

hr "4. grep for leftover TODO/FIXME/未実装 (expect: NO TODO LEFT)"
if grep -rn "TODO\|FIXME\|未実装" --include=*.c --include=*.h --include=*.py .; then
    echo "!! leftover markers found above"
else
    echo "NO TODO LEFT"
fi

hr "5. tests/smoke.sh (detection + safe stop)"
bash tests/smoke.sh

hr "6. apply-firewall dry-run (no firewall change)"
python3 monitor.py --config monitor.conf.example apply-firewall || true

hr "done"
