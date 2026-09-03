import types
from unittest import mock

import audit_tool.scanner as scanner


class FakeSocket:
    def __init__(self, port_map):
        self._port_map = port_map

    def settimeout(self, t):
        pass

    def connect_ex(self, addr):
        host, port = addr
        return 0 if port in self._port_map else 1

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_scan_ports_opens_and_closes():
    ports = [80, 81, 443]

    def fake_socket_factory(*args, **kwargs):
        # simulate open ports 80 and 443
        return FakeSocket({80, 443})

    with mock.patch("socket.socket", new=fake_socket_factory):
        results = scanner.scan_ports(
            "example.com", ports, timeout=0.1, threads=4, batch_size=2
        )
        found = sorted([p["port"] for p in results])
        assert found == [80, 443]
