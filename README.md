# attack-monitor
A blue-team tool for Linux servers you administer: continuously watches for signs of attack (SSH brute force, connection floods, unexpected open ports, runaway processes) and provides IP-allowlist-based SSH access control, plus a "work mode" that lets you perform maintenance without disabling the defenses.

## Architecture

- **Core logic in C** (`monitor_core.c`) — log aggregation, IP validation, and allow-list matching, compiled into a shared library
- **Python driver** (`monitor.py`) — calls the C library via `ctypes` and owns the monitoring loop, CLI, configuration, firewall enforcement, and TTL-based expiry of temporary allow-list entries

## Features

- **Attack detection** — SSH brute-force detection via auth-log monitoring, connection-flood detection, unexpected-open-port alerts, and suspicious-process monitoring
- **SSH access control** — restrict SSH (port 22) to an explicit IP/CIDR allowlist, enforced through `ufw`, `firewalld`, or `nft` (auto-detected)
- **Work mode** — temporarily allow a specific IP for a bounded duration so maintenance doesn't require disabling defenses
- **Log-rotation aware** — reads only new log bytes since the last check, and correctly re-reads from the top on rotation (inode change or truncation)
- **Dry-run by default** — firewall changes are previewed before being applied
- **Fully tested** — C unit tests plus a Python test suite with the firewall layer mocked out

## ⚠️ Before You Run This

This tool rewrites firewall rules and restricts SSH access. Misconfiguration can lock you (or your team) out of a server.

- Only run this against servers you administer or are formally authorized to manage
- Test in a staging environment or disposable VM before touching production
- Keep a non-SSH recovery path available (console access, KVM, or your cloud provider's serial console)
- Always preview access-control changes with dry-run mode before applying them for real

## Build & Run

```bash
make            # builds libmonitor_core.so
make test       # C unit tests
make pytest     # Python tests (firewall fully mocked)
make check      # both test suites

cp monitor.conf.example monitor.conf
# edit thresholds/paths for your environment

sudo python3 monitor.py --config monitor.conf run
```

## SSH Allow-List Management

```bash
python3 monitor.py allow-ip 203.0.113.5 "home office"   # add (CIDR supported: 10.0.0.0/8, 2001:db8::/32)
python3 monitor.py list-ips                              # list current entries
python3 monitor.py remove-ip 203.0.113.5                 # remove
```

## Requirements

- `gcc`, `python3` (standard library only)
- One of `ufw`, `firewalld`, or `nft` for the firewall-enforcement feature
- `ss` and `ps` for the extended monitors (present on virtually all Linux systems)

## License

MIT License — see [LICENSE](LICENSE) for details.

## Author

Yuto Sugihara — Security Engineer specializing in enterprise cybersecurity operations, SIEM tooling, and IT infrastructure automation.
