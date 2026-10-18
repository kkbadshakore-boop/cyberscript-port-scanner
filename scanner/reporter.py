"""reporter.py - builds the report and saves it as JSON or CSV."""

import csv
import json
import os
from datetime import datetime, timezone

from scanner.port_scanner import OPEN

CSV_FIELDS = ["target", "ip", "port", "status", "service"]


def build_report(target, ip, start_port, end_port, timeout, workers, results, elapsed):
    """Combine scan settings and results into one dictionary."""
    return {
        "tool": "CyberScript AI Port Scanner",
        "scan_time_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": target,
        "ip": ip,
        "port_range": f"{start_port}-{end_port}",
        "timeout_seconds": timeout,
        "workers": workers,
        "elapsed_seconds": round(elapsed, 3),
        "total_scanned": len(results),
        "open_count": sum(1 for r in results if r.status == OPEN),
        "results": [r.to_dict() for r in results],
    }


def _prepare(path):
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)


def save_json(report, path):
    _prepare(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return path


def save_csv(report, path):
    _prepare(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for row in report["results"]:
            writer.writerow({
                "target": report["target"],
                "ip": report["ip"],
                "port": row["port"],
                "status": row["status"],
                "service": row["service"],
            })
    return path


def format_open_ports(report):
    """Return a printable table of the open ports."""
    open_rows = [r for r in report["results"] if r["status"] == OPEN]
    if not open_rows:
        return "No open ports found in the scanned range."
    lines = [f"{'PORT':<8}{'STATE':<8}SERVICE", "-" * 28]
    for r in open_rows:
        lines.append(f"{r['port']:<8}{r['status']:<8}{r['service'] or 'unknown'}")
    return "\n".join(lines)
