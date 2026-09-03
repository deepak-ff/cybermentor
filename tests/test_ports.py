import pytest

from audit_tool.cli import _parse_ports


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
    assert _parse_ports(spec) == expected


def test_parse_ports_invalid_range():
    with pytest.raises(ValueError):
        _parse_ports("1024-1")


def test_parse_ports_out_of_bounds():
    with pytest.raises(ValueError):
        _parse_ports("0-70000")
