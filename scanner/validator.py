"""
validator.py - checks everything the user types BEFORE we touch the network.

Rule of thumb in security tools: never trust input. Validate first, act later.
"""

import ipaddress
import re
import socket

MIN_PORT = 1
MAX_PORT = 65535

# Safety limits so nobody accidentally floods a network.
MAX_PORTS_PER_SCAN = 10000
DEFAULT_WORKERS = 50
MAX_WORKERS = 200
DEFAULT_TIMEOUT = 1.0
MIN_TIMEOUT = 0.1
MAX_TIMEOUT = 10.0


class ValidationError(ValueError):
    """Raised when user input is not acceptable. The message is user-friendly."""


def validate_port(value):
    """Return `value` as an int if it is a valid port (1-65535)."""
    try:
        port = int(str(value).strip())
    except ValueError:
        raise ValidationError(f"'{value}' is not a number. Ports must be whole numbers.")
    if not MIN_PORT <= port <= MAX_PORT:
        raise ValidationError(f"Port {port} is out of range. Use {MIN_PORT}-{MAX_PORT}.")
    return port


def parse_port_range(text):
    """
    Turn '80' or '20-100' into (start, end).
    Also enforces the maximum number of ports per scan.
    """
    text = str(text).strip()
    if not text:
        raise ValidationError("Port value is empty. Example: 80 or 1-1024.")

    if "-" in text:
        parts = text.split("-")
        if len(parts) != 2:
            raise ValidationError(f"'{text}' is not a valid range. Example: 1-1024.")
        start, end = validate_port(parts[0]), validate_port(parts[1])
        if start > end:
            raise ValidationError(f"Range start ({start}) must not be bigger than end ({end}).")
    else:
        start = end = validate_port(text)

    count = end - start + 1
    if count > MAX_PORTS_PER_SCAN:
        raise ValidationError(
            f"Range has {count} ports; the limit is {MAX_PORTS_PER_SCAN} per scan. "
            "Scan in smaller chunks."
        )
    return start, end


def validate_timeout(value):
    """Timeout (seconds) must be a number between MIN_TIMEOUT and MAX_TIMEOUT."""
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        raise ValidationError(f"Timeout '{value}' is not a number.")
    if not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        raise ValidationError(f"Timeout must be between {MIN_TIMEOUT} and {MAX_TIMEOUT} seconds.")
    return timeout


def validate_workers(value):
    """Number of parallel threads must be between 1 and MAX_WORKERS."""
    try:
        workers = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"Workers '{value}' is not a whole number.")
    if not 1 <= workers <= MAX_WORKERS:
        raise ValidationError(f"Workers must be between 1 and {MAX_WORKERS}.")
    return workers


def resolve_target(target):
    """
    Accept an IPv4 address or a hostname and return the IPv4 address as text.
    Raises ValidationError for bad input or DNS failures.
    """
    target = str(target).strip()
    if not target:
        raise ValidationError("Target is empty. Example: 127.0.0.1 or localhost.")

    # Case 1: it is an IP address.
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.version != 4:
            raise ValidationError("Only IPv4 targets are supported in this version.")
        return str(ip)

    # Looks like an IP (digits and dots) but failed above -> typo like 999.1.1.1
    if re.fullmatch(r"[0-9.]+", target):
        raise ValidationError(f"'{target}' is not a valid IPv4 address.")

    # Case 2: treat it as a hostname and ask DNS.
    if len(target) > 253 or " " in target:
        raise ValidationError(f"'{target}' is not a valid hostname.")
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValidationError(f"DNS error: could not resolve hostname '{target}'.")
    except UnicodeError:
        raise ValidationError(f"'{target}' is not a valid hostname.")


def is_loopback(ip_text):
    """True for 127.x.x.x addresses (the machine you are sitting at)."""
    return ipaddress.ip_address(ip_text).is_loopback
