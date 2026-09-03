"""Multithreaded TCP port scanner.

Scanning a large port range sequentially is slow because almost every port
times out. By scanning concurrently with a bounded thread pool we overlap the
waits, giving a substantial speed-up (typically ~10x on real networks).

Ports are processed in bounded batches so even 1-65535 does not spawn an
unbounded number of simultaneous sockets. An optional progress callback is
invoked after each batch with (done, total) for progress reporting.
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional, Sequence

# Common service names to enrich results (IANA-ish).
SERVICE_NAMES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    514: "syslog",
    587: "submission",
    631: "ipp",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}

#: Most commonly scanned ports (Shodan/Censys-style "top" preset).
TOP_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    389,
    443,
    445,
    465,
    514,
    587,
    631,
    993,
    995,
    1080,
    1433,
    1521,
    2049,
    3000,
    3306,
    3389,
    5000,
    5432,
    5900,
    6379,
    8000,
    8080,
    8443,
    8888,
    9090,
    9200,
    9300,
    10000,
    10443,
    27017,
    50000,
    54321,
    54322,
]

ProgressFn = Callable[[int, int], None]


def _service_name(port: int) -> str:
    """Best-effort service name: static table first, then system services."""
    if port in SERVICE_NAMES:
        return SERVICE_NAMES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def _probe(host: str, port: int, timeout: float) -> Optional[int]:
    """Return the port if it is open, else None (closed/filtered/timeout)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                return port
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return None


def scan_ports(
    host: str,
    ports: Sequence[int],
    timeout: float = 1.0,
    threads: int = 256,
    batch_size: int = 1024,
    progress: Optional[ProgressFn] = None,
) -> List[dict]:
    """Scan many TCP ports concurrently and return the open ones.

    *progress*, when given, is called once per completed batch with
    ``(done, total)`` so callers can report progress without per-port
    contention.
    """
    open_ports: List[dict] = []
    total = len(ports)

    def run_batch(batch: Sequence[int]) -> List[int]:
        results: List[int] = []
        with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
            futures = {pool.submit(_probe, host, p, timeout): p for p in batch}
            for future in as_completed(futures):
                port = future.result()
                if port is not None:
                    results.append(port)
        return results

    for i in range(0, total, max(1, batch_size)):
        batch = ports[i : i + batch_size]
        found = run_batch(batch)
        open_ports.extend(
            {"port": p, "service": _service_name(p)} for p in sorted(found)
        )
        done = min(i + batch_size, total)
        if progress is not None:
            progress(done, total)

    return sorted(open_ports, key=lambda d: d["port"])


def sequential_scan(
    host: str, ports: Sequence[int], timeout: float = 1.0
) -> List[dict]:
    """Reference, sequential implementation used to demonstrate speed-up."""
    open_ports: List[dict] = []
    for p in ports:
        if _probe(host, p, timeout) is not None:
            open_ports.append({"port": p, "service": _service_name(p)})
    return open_ports


def timed_scan(
    host: str,
    ports: Sequence[int],
    timeout: float = 1.0,
    threads: int = 256,
    batch_size: int = 1024,
    progress: Optional[ProgressFn] = None,
):
    """Run the concurrent scan and time it (returns ports and elapsed ms)."""
    start = time.perf_counter()
    results = scan_ports(
        host,
        ports,
        timeout=timeout,
        threads=threads,
        batch_size=batch_size,
        progress=progress,
    )
    elapsed = int(round((time.perf_counter() - start) * 1000))
    return results, elapsed
