"""cli.py - the command-line interface that ties everything together."""

import argparse
import socket
import sys
import time

from scanner import __version__
from scanner.port_scanner import scan_ports
from scanner.reporter import build_report, save_json, save_csv, format_open_ports
from scanner.validator import (
    ValidationError, DEFAULT_TIMEOUT, DEFAULT_WORKERS, MAX_PORTS_PER_SCAN, MAX_WORKERS,
    parse_port_range, resolve_target, validate_timeout, validate_workers, is_loopback,
)

EPILOG = f"""
examples:
  python -m scanner --demo
  python -m scanner -t 127.0.0.1 -p 1-1024
  python -m scanner -t localhost -p 22 --timeout 0.5
  python -m scanner -t 192.168.56.101 -p 1-1000 --authorized --json out.json --csv out.csv

limits: max {MAX_PORTS_PER_SCAN} ports per scan, max {MAX_WORKERS} workers.
Only scan systems you own or have WRITTEN permission to test.
"""

BANNER = "CyberScript AI Port Scanner v" + __version__


def build_parser():
    p = argparse.ArgumentParser(
        prog="scanner",
        description="Simple TCP connect port scanner for authorized testing only.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-t", "--target", help="IPv4 address or hostname to scan")
    p.add_argument("-p", "--ports", default="1-1024",
                   help="single port (80) or range (1-1024). Default: 1-1024")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                   help=f"seconds to wait per port (default {DEFAULT_TIMEOUT})")
    p.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                   help=f"parallel threads (default {DEFAULT_WORKERS}, max {MAX_WORKERS})")
    p.add_argument("--authorized", action="store_true",
                   help="confirm you have permission to scan a non-local target")
    p.add_argument("--demo", action="store_true",
                   help="run a safe, repeatable demo on localhost")
    p.add_argument("--json", metavar="FILE", help="save results to a JSON file")
    p.add_argument("--csv", metavar="FILE", help="save results to a CSV file")
    p.add_argument("--version", action="version", version=BANNER)
    return p


def confirm_authorization(ip, flag_given):
    """Localhost is always fine. Anything else needs explicit confirmation."""
    if is_loopback(ip) or flag_given:
        return True
    print("\n[!] This target is NOT localhost.")
    print("    Scanning systems without permission is illegal in many countries.")
    try:
        answer = input("    Type 'I AUTHORIZE' if you own it or have written permission: ")
    except EOFError:
        return False
    return answer.strip() == "I AUTHORIZE"


def make_progress_printer():
    def show(done, total):
        percent = done * 100 // total
        sys.stderr.write(f"\r[*] Progress: {done}/{total} ports ({percent}%)")
        sys.stderr.flush()
        if done == total:
            sys.stderr.write("\n")
    return show


def run_scan(target, ip, start, end, timeout, workers, ports=None):
    """Run the scan, print the summary, and return the report dict."""
    ports = list(ports) if ports is not None else list(range(start, end + 1))
    print(f"[*] Target : {target} ({ip})")
    print(f"[*] Ports  : {start}-{end} ({len(ports)} ports)")
    print(f"[*] Timeout: {timeout}s | Workers: {workers}\n")

    began = time.perf_counter()
    results = scan_ports(ip, ports, timeout, workers, make_progress_printer())
    elapsed = time.perf_counter() - began

    report = build_report(target, ip, start, end, timeout, workers, results, elapsed)
    print("\n" + format_open_ports(report))
    print(f"\n[+] Done: {report['open_count']} open / {report['total_scanned']} scanned "
          f"in {report['elapsed_seconds']}s")
    return report


def export(report, json_path, csv_path):
    if json_path:
        print(f"[+] JSON saved to {save_json(report, json_path)}")
    if csv_path:
        print(f"[+] CSV saved to {save_csv(report, csv_path)}")


def run_demo(json_path=None, csv_path=None):
    """
    Repeatable demo: open 3 temporary listeners on 127.0.0.1, then scan them
    plus one closed port. Expected result: 3 open, 1 closed.
    """
    print("[*] DEMO MODE - creating 3 temporary local servers...\n")
    listeners = []
    try:
        for _ in range(3):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", 0))  # port 0 = let the OS choose a free port
            s.listen()
            listeners.append(s)
        open_ports = [s.getsockname()[1] for s in listeners]

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tmp:
            tmp.bind(("127.0.0.1", 0))
            closed_port = tmp.getsockname()[1]  # freed right after this block

        ports = sorted(open_ports + [closed_port])
        report = run_scan("localhost", "127.0.0.1", ports[0], ports[-1],
                          0.5, 4, ports=ports)
        export(report, json_path, csv_path)
        print(f"[i] Demo servers were on ports {sorted(open_ports)}; "
              f"{closed_port} was left closed on purpose.")
        return 0
    finally:
        for s in listeners:
            s.close()


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    print(BANNER + "\n")

    if args.demo:
        return run_demo(args.json, args.csv)

    if not args.target:
        parser.error("the following argument is required: -t/--target (or use --demo)")

    try:
        start, end = parse_port_range(args.ports)
        timeout = validate_timeout(args.timeout)
        workers = validate_workers(args.workers)
        ip = resolve_target(args.target)
    except ValidationError as err:
        print(f"[-] Error: {err}", file=sys.stderr)
        return 1

    if not confirm_authorization(ip, args.authorized):
        print("[-] Authorization not confirmed. Scan cancelled.", file=sys.stderr)
        return 1

    try:
        report = run_scan(args.target, ip, start, end, timeout, workers)
        export(report, args.json, args.csv)
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user.", file=sys.stderr)
        return 130
    except OSError as err:
        print(f"[-] File or network error: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
