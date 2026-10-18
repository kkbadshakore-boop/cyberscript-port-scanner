"""
port_scanner.py - the scanning engine.

Technique: "TCP connect scan". We simply try to open a normal TCP connection.
  - Connection succeeds        -> port is OPEN
  - Connection refused         -> port is CLOSED (host answered "no")
  - No answer before timeout   -> FILTERED (often a firewall dropping packets)
This is the same handshake any program (like a web browser) uses, so it is
simple, reliable, and needs no special privileges.
"""

import errno
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict

OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"
ERROR = "error"

_TIMEOUT_CODES = {errno.EAGAIN, errno.EWOULDBLOCK, errno.ETIMEDOUT}


@dataclass
class PortResult:
    port: int
    status: str
    service: str = ""

    def to_dict(self):
        return asdict(self)


def get_service_name(port):
    """Look up the common service for a port (80 -> 'http'). Empty if unknown."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def check_port(host, port, timeout):
    """Try ONE connection and return a PortResult. Never raises on network errors."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex((host, port))  # 0 means success
    except socket.timeout:
        return PortResult(port, FILTERED)
    except OSError:
        return PortResult(port, ERROR)

    if code == 0:
        return PortResult(port, OPEN, get_service_name(port))
    if code == errno.ECONNREFUSED:
        return PortResult(port, CLOSED)
    if code in _TIMEOUT_CODES:
        return PortResult(port, FILTERED)
    return PortResult(port, ERROR)


def scan_ports(host, ports, timeout=1.0, workers=50, progress=None):
    """
    Scan many ports using a bounded thread pool (max `workers` at once).

    progress: optional function called as progress(done, total) after each port.
    Returns a list of PortResult sorted by port number.
    """
    ports = list(ports)
    total = len(ports)
    results = []
    executor = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = [executor.submit(check_port, host, p, timeout) for p in ports]
        for done, future in enumerate(as_completed(futures), start=1):
            results.append(future.result())
            if progress:
                progress(done, total)
    except KeyboardInterrupt:
        # Ctrl+C: stop queued work and bubble up so the CLI can exit cleanly.
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        executor.shutdown(wait=True)
    return sorted(results, key=lambda r: r.port)
