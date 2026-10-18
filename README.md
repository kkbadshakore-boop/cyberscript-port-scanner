# CyberScript AI - Python Network Port Scanner

A beginner-friendly **TCP connect port scanner** written with only the Python standard library.
Built as a learning project for VAPT / Junior Penetration Tester roles.

> ## Legal & ethical notice
> Scan **only** your own machines, localhost, or lab targets where you have **written permission**.
> Unauthorized scanning can be illegal (e.g. India's IT Act 2000). This tool intentionally has
> **no** stealth, evasion, exploitation, brute-force, or DoS features.

## Features
- IPv4 or hostname targets (DNS resolution with clear errors)
- Authorization confirmation for non-local targets
- `--demo` mode: safe, repeatable localhost demonstration
- Single port or range, validated 1-65535, max 10,000 ports per scan
- Configurable timeout (0.1-10 s) and bounded threads (max 200)
- Progress, elapsed time, results table
- JSON and CSV export
- pytest unit tests

## Setup (Kali Linux)
```bash
cd cyberscript-port-scanner
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt     # only for pytest
```

## Usage
```bash
python -m scanner --help
python -m scanner --demo
python -m scanner -t 127.0.0.1 -p 1-1024
python -m scanner -t localhost -p 22 --timeout 0.5
python -m scanner -t 192.168.56.101 -p 1-1000 --authorized --json results.json --csv results.csv
```

| Option | Meaning |
|---|---|
| `-t, --target` | IPv4 or hostname |
| `-p, --ports` | `80` or `1-1024` (default `1-1024`) |
| `--timeout` | seconds per port (default 1.0) |
| `--workers` | parallel threads (default 50) |
| `--authorized` | confirm permission for a non-local target |
| `--demo` | localhost demo |
| `--json / --csv FILE` | export results |

## Demo
```bash
python -m scanner --demo --json demo.json --csv demo.csv
```
It opens 3 temporary local servers, scans them plus 1 closed port, and shows **3 open, 1 closed**.

A manual test:
```bash
python3 -m http.server 8000 &          # start a test web server
python -m scanner -t 127.0.0.1 -p 8000
kill %1
```

## Run tests
```bash
pytest -v
```

## How it works
1. `validator.py` checks all input first.
2. `port_scanner.py` tries a TCP connection per port: success = **open**, refused = **closed**,
   no reply = **filtered** (often a firewall).
3. A `ThreadPoolExecutor` scans many ports at once, but never more than `--workers`.
4. `reporter.py` builds the report and writes JSON/CSV.
5. `cli.py` connects everything with `argparse`.

## Limitations
IPv4 only, TCP only, no banner grabbing or OS detection. Results can vary with firewalls.

## Ideas for next versions
Banner grabbing, UDP scan, HTML report, IPv6 support.

## Git / GitHub
```bash
git init && git add . && git commit -m "Initial commit: CyberScript port scanner"
git branch -M main
git remote add origin https://github.com/<your-username>/cyberscript-port-scanner.git
git push -u origin main
```
