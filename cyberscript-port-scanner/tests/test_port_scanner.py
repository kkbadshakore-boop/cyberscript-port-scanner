import json
import socket

from scanner.cli import main
from scanner.port_scanner import check_port, scan_ports


def free_closed_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_detects_open_and_closed():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        assert check_port("127.0.0.1", port, 1).status == "open"
    assert check_port("127.0.0.1", free_closed_port(), 1).status == "closed"


def test_scan_ports_sorted_and_progress():
    calls = []
    ports = [free_closed_port(), free_closed_port()]
    results = scan_ports("127.0.0.1", ports, 0.5, 2, lambda d, t: calls.append((d, t)))
    assert len(results) == 2
    assert [r.port for r in results] == sorted(ports)
    assert calls[-1] == (2, 2)


def test_cli_demo_exports(tmp_path, capsys):
    out = tmp_path / "demo.json"
    assert main(["--demo", "--json", str(out), "--csv", str(tmp_path / "d.csv")]) == 0
    data = json.loads(out.read_text())
    assert data["open_count"] == 3 and data["total_scanned"] == 4


def test_cli_rejects_bad_input(capsys):
    assert main(["-t", "127.0.0.1", "-p", "99999"]) == 1
    assert main(["-t", "nope.invalid", "-p", "80"]) == 1


def test_cli_requires_authorization_for_remote(monkeypatch):
    # 192.0.2.1 is a reserved documentation address; we refuse before any scan.
    monkeypatch.setattr("builtins.input", lambda _: "no")
    assert main(["-t", "192.0.2.1", "-p", "80"]) == 1
