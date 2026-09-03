"""Multithreaded TCP port scanner.

Scanning a large port range sequentially is slow because almost every port
times out. By scanning concurrently with a bounded thread pool we overlap the
waits, giving a substantial speed-up (typically ~10x on real networks).
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Sequence

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


def _probe(host: str, port: int, timeout: float) -> Optional[int]:
    """Return the port if it is open, else None (closed/filtered/timeout)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            rc = s.connect_ex((host, port))
            if rc == 0:
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
) -> List[dict]:
    """Scan many TCP ports concurrently and return the open ones.

    Ports are processed in bounded batches so a very large range (e.g. 1-65535)
    does not spawn a massive number of simultaneous sockets.
    """
    open_ports: List[dict] = []

    def run_batch(batch: Sequence[int]) -> List[int]:
        results = []
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(_probe, host, p, timeout): p for p in batch}
            for future in as_completed(futures):
                port = future.result()
                if port is not None:
                    results.append(port)
        return results

    for i in range(0, len(ports), batch_size):
        batch = ports[i : i + batch_size]
        open_ports.extend(
            {"port": p, "service": SERVICE_NAMES.get(p, "unknown")}
            for p in sorted(run_batch(batch))
        )
    return open_ports


def sequential_scan(
    host: str, ports: Sequence[int], timeout: float = 1.0
) -> List[dict]:
    """Reference, sequential implementation used to demonstrate speed-up."""
    open_ports = []
    for p in ports:
        if _probe(host, p, timeout) is not None:
            open_ports.append({"port": p, "service": SERVICE_NAMES.get(p, "unknown")})
    return open_ports


def timed_scan(
    host: str, ports: Sequence[int], timeout: float = 1.0, threads: int = 256
):
    """Run the concurrent scan and time it (returns ports and elapsed ms)."""
    start = time.perf_counter()
    results = scan_ports(host, ports, timeout=timeout, threads=threads)
    elapsed = int(round((time.perf_counter() - start) * 1000))
    return results, elapsed
