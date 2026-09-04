"""Port-range parsing tests (delegates to the CLI parser)."""

import pytest

from audit_tool.cli import parse_ports


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("80", [80]),
        ("1-3", [1, 2, 3]),
        ("80,443", [80, 443]),
        ("1-2,4,6-7", [1, 2, 4, 6, 7]),
    ],
)
def test_parse_ports_valid(spec, expected):
    assert parse_ports(spec) == expected


def test_parse_ports_top_preset():
    from audit_tool.scanner import TOP_PORTS

    assert parse_ports("top") == sorted(set(TOP_PORTS))


def test_parse_ports_invalid_range():
    with pytest.raises(ValueError):
        parse_ports("1024-1")


def test_parse_ports_out_of_bounds():
    with pytest.raises(ValueError):
        parse_ports("0-70000")
