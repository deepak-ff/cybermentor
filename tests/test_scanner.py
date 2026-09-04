"""Tests for the multithreaded TCP port scanner (fake sockets)."""

from __future__ import annotations

import threading
import time
from typing import Optional, Set

import audit_tool.scanner as scanner


class FakeSocket:
    """Simulates connect_ex: ports in the map are 'open'."""

    def __init__(self, open_ports: Set[int], tracker: Optional["Tracker"] = None):
        self._open = open_ports
        self._tracker = tracker
        self._host = None
        self._port = None

    def settimeout(self, t):
        pass

    def connect_ex(self, addr):
        host, port = addr
        self._host, self._port = host, port
        if self._tracker is not None:
            self._tracker.enter()
            time.sleep(0.01)
            self._tracker.exit()
        return 0 if port in self._open else 111  # ECONNREFUSED

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class Tracker:
    """Tracks peak concurrency of live sockets."""

    def __init__(self):
        self._lock = threading.Lock()
        self._current = 0
        self.peak = 0

    def enter(self):
        with self._lock:
            self._current += 1
            self.peak = max(self.peak, self._current)

    def exit(self):
        with self._lock:
            self._current -= 1


def make_socket_factory(open_ports: Set[int], tracker: Optional[Tracker] = None):
    def factory(*args, **kwargs):
        return FakeSocket(open_ports, tracker)

    return factory


def test_scan_ports_finds_open_only(monkeypatch):
    monkeypatch.setattr(scanner.socket, "socket", make_socket_factory({80, 443}))
    results = scanner.scan_ports("h", [22, 80, 443, 8080], threads=4, batch_size=2)
    assert [p["port"] for p in results] == [80, 443]
    assert {p["service"] for p in results} == {"http", "https"}


def test_scan_ports_empty_input(monkeypatch):
    monkeypatch.setattr(scanner.socket, "socket", make_socket_factory(set()))
    assert scanner.scan_ports("h", [], threads=4) == []


def test_scan_ports_sorted_output(monkeypatch):
    monkeypatch.setattr(scanner.socket, "socket", make_socket_factory({443, 80, 22}))
    results = scanner.scan_ports("h", [80, 22, 443, 8000], threads=8)
    assert [p["port"] for p in results] == [22, 80, 443]


def test_scan_ports_progress_callback(monkeypatch):
    monkeypatch.setattr(scanner.socket, "socket", make_socket_factory({80}))
    calls: list = []
    results = scanner.scan_ports(
        "h",
        list(range(80, 88)),  # 8 ports, 80 is open
        threads=4,
        batch_size=4,
        progress=lambda done, total: calls.append((done, total)),
    )
    assert calls == [(4, 8), (8, 8)]
    assert [p["port"] for p in results] == [80]


def test_scan_ports_respects_thread_bound(monkeypatch):
    tracker = Tracker()
    monkeypatch.setattr(scanner.socket, "socket", make_socket_factory(set(), tracker))
    scanner.scan_ports("h", list(range(1, 17)), threads=3, batch_size=16)
    assert 1 <= tracker.peak <= 3


def test_scan_ports_batch_bound(monkeypatch):
    tracker = Tracker()
    monkeypatch.setattr(scanner.socket, "socket", make_socket_factory(set(), tracker))
    # With batch_size=5, at most 5 in-flight sockets even with many threads.
    scanner.scan_ports("h", list(range(1, 21)), threads=32, batch_size=5)
    assert tracker.peak <= 5


def test_sequential_scan(monkeypatch):
    monkeypatch.setattr(scanner.socket, "socket", make_socket_factory({22}))
    results = scanner.sequential_scan("h", [22, 80])
    assert [p["port"] for p in results] == [22]
    assert results[0]["service"] == "ssh"


def test_timed_scan_returns_elapsed_ms(monkeypatch):
    monkeypatch.setattr(scanner.socket, "socket", make_socket_factory({80}))
    results, elapsed = scanner.timed_scan("h", [80, 81], threads=4)
    assert elapsed >= 0
    assert isinstance(elapsed, int)
    assert [p["port"] for p in results] == [80]


def test_service_name_known_and_unknown():
    assert scanner._service_name(22) == "ssh"
    assert scanner._service_name(65530) in ("unknown",)


def test_top_ports_are_valid_and_unique():
    assert len(scanner.TOP_PORTS) >= 30
    assert len(set(scanner.TOP_PORTS)) == len(scanner.TOP_PORTS)
    for p in scanner.TOP_PORTS:
        assert 1 <= p <= 65535


def test_probe_timeout_returns_none(monkeypatch):
    class TimeoutSocket:
        def __init__(self, *a, **k):
            pass

        def settimeout(self, t):
            pass

        def connect_ex(self, addr):
            raise scanner.socket.timeout()

        def close(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(scanner.socket, "socket", TimeoutSocket)
    assert scanner._probe("h", 80, 0.01) is None
