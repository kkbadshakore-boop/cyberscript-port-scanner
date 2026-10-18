import csv
import json

from scanner.port_scanner import PortResult
from scanner.reporter import build_report, save_csv, save_json, format_open_ports


def sample_report():
    results = [PortResult(22, "open", "ssh"), PortResult(23, "closed")]
    return build_report("localhost", "127.0.0.1", 22, 23, 1.0, 10, results, 0.1234)


def test_report_fields():
    r = sample_report()
    assert r["open_count"] == 1
    assert r["total_scanned"] == 2
    assert r["port_range"] == "22-23"
    assert r["elapsed_seconds"] == 0.123


def test_json_roundtrip(tmp_path):
    path = save_json(sample_report(), tmp_path / "sub" / "out.json")
    data = json.loads(open(path, encoding="utf-8").read())
    assert data["results"][0] == {"port": 22, "status": "open", "service": "ssh"}


def test_csv_content(tmp_path):
    path = save_csv(sample_report(), tmp_path / "out.csv")
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    assert len(rows) == 2
    assert rows[0]["port"] == "22" and rows[0]["status"] == "open"


def test_open_table():
    assert "ssh" in format_open_ports(sample_report())
    empty = build_report("x", "1.1.1.1", 1, 1, 1, 1, [PortResult(1, "closed")], 0)
    assert "No open ports" in format_open_ports(empty)
