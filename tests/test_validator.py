import pytest

from scanner.validator import (
    ValidationError, parse_port_range, validate_port, validate_timeout,
    validate_workers, resolve_target, is_loopback, MAX_PORTS_PER_SCAN,
)


@pytest.mark.parametrize("value,expected", [("1", 1), (" 80 ", 80), (65535, 65535)])
def test_validate_port_ok(value, expected):
    assert validate_port(value) == expected


@pytest.mark.parametrize("bad", ["0", "65536", "-1", "abc", "", "80.5"])
def test_validate_port_bad(bad):
    with pytest.raises(ValidationError):
        validate_port(bad)


def test_range_and_single():
    assert parse_port_range("80") == (80, 80)
    assert parse_port_range("20-100") == (20, 100)


@pytest.mark.parametrize("bad", ["100-20", "1-2-3", "-5", "a-b", "", "0-10", "1-70000"])
def test_range_bad(bad):
    with pytest.raises(ValidationError):
        parse_port_range(bad)


def test_range_limit():
    with pytest.raises(ValidationError):
        parse_port_range(f"1-{MAX_PORTS_PER_SCAN + 1}")
    assert parse_port_range(f"1-{MAX_PORTS_PER_SCAN}") == (1, MAX_PORTS_PER_SCAN)


def test_timeout_and_workers():
    assert validate_timeout("0.5") == 0.5
    for bad in ["0", "99", "x"]:
        with pytest.raises(ValidationError):
            validate_timeout(bad)
    assert validate_workers("10") == 10
    for bad in ["0", "9999", "x"]:
        with pytest.raises(ValidationError):
            validate_workers(bad)


def test_resolve_target():
    assert resolve_target("127.0.0.1") == "127.0.0.1"
    assert resolve_target("localhost") == "127.0.0.1"
    assert is_loopback("127.0.0.1")
    assert not is_loopback("8.8.8.8")


@pytest.mark.parametrize("bad", ["", "999.1.1.1", "::1", "no such host", "invalid.invalid"])
def test_resolve_target_bad(bad):
    with pytest.raises(ValidationError):
        resolve_target(bad)
