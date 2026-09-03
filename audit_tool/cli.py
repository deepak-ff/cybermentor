"""Command-line entry point for the security audit tool."""

from __future__ import annotations

import argparse
import sys
import logging
from datetime import datetime

from .checks import run_all_checks
from .models import Level, ScanResult
from .reporter import write_reports
from .scanner import timed_scan


def _parse_ports(spec: str):
    """Parse '80' or '1-1024' or a comma list into a sorted list of ints."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi or hi > 65535 or lo < 1:
                raise ValueError(f"invalid port range: {part}")
            ports.update(range(lo, hi + 1))
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"invalid port: {part}")
            ports.add(p)
    return sorted(ports)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="security-audit-tool",
        description="Non-intrusive host security audit with CIS-aligned checks, "
        "a multithreaded TCP port scanner, and JSON/HTML reporting.",
    )
    p.add_argument(
        "--host",
        default="127.0.0.1",
        help="target host to port-scan (default 127.0.0.1)",
    )
    p.add_argument(
        "--ports",
        default="1-1024",
        help="port range or list, e.g. '80' or '1-1024' (default 1-1024)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="socket connect timeout seconds (default 1.0)",
    )
    p.add_argument(
        "--threads", type=int, default=256, help="scanning threads (default 256)"
    )
    p.add_argument("--skip-scan", action="store_true", help="skip the TCP port scan")
    p.add_argument(
        "--show-speedup",
        action="store_true",
        help="compare concurrent vs sequential scanning",
    )
    p.add_argument(
        "--out",
        default="reports",
        help="output directory for reports (default 'reports')",
    )
    p.add_argument(
        "--hostname",
        default="localhost",
        help="label used in the report (default localhost)",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="increase verbosity (use -v or -vv)",
    )
    p.add_argument(
        "--fail-exit",
        action="store_true",
        help="exit with code 1 if any FAIL results are present",
    )
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    hostname = args.host

    # Logging
    level = logging.INFO
    if args.verbose >= 1:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s")
    log = logging.getLogger(__name__)

    started = datetime.now().isoformat(timespec="seconds")
    start_ts = datetime.now()

    try:
        ports = _parse_ports(args.ports)
    except ValueError as exc:
        log.error(str(exc))
        return 2

    log.info(f"Running configuration checks on {hostname} ...")
    checks = run_all_checks(hostname)

    open_ports = []
    speedup_ms = None
    if not args.skip_scan:
        log.info(f"Scanning {args.host}:{args.ports} (threads={args.threads}) ...")
        open_ports, elapsed_ms = timed_scan(
            args.host, ports, timeout=args.timeout, threads=args.threads
        )
        log.info(
            f"Port scan complete in {elapsed_ms} ms; {len(open_ports)} open port(s)."
        )
        if args.show_speedup:
            from .scanner import sequential_scan

            seq_start = datetime.now()
            sequential_scan(args.host, ports, timeout=args.timeout)
            seq_ms = int((datetime.now() - seq_start).total_seconds() * 1000)
            speedup_ms = seq_ms
            log.info(
                f"Speed-up vs sequential: {seq_ms} ms -> {elapsed_ms} ms "
                f"({seq_ms / max(elapsed_ms, 1):.1f}x faster)"
            )
    else:
        log.info("Port scan skipped.")

    finished = datetime.now().isoformat(timespec="seconds")
    duration_ms = int((datetime.now() - start_ts).total_seconds() * 1000)

    result = ScanResult(
        host=hostname,
        started_at=started,
        finished_at=finished,
        duration_ms=duration_ms,
        checks=checks,
        open_ports=open_ports,
        scan_targets=(
            {
                "target": args.host,
                "ports": args.ports,
                "threads": args.threads,
                "timeout": args.timeout,
                "speedup_ms_sequential": speedup_ms,
            }
            if not args.skip_scan
            else {"target": args.host, "skipped": True}
        ),
    )

    paths = write_reports(result, args.out)
    log.info(f"\nHardening score: {result.score}/100")
    counts = {lvl: sum(1 for c in checks if c.level == lvl) for lvl in Level}
    log.info(
        "Summary: %s",
        ", ".join(f"{lvl.value}: {counts[lvl]}" for lvl in Level if counts[lvl]),
    )
    log.info("JSON report : %s", paths["json"])
    log.info("HTML report : %s", paths["html"])

    if args.fail_exit:
        has_fail = any(c.level == Level.FAIL for c in checks)
        if has_fail:
            log.warning(
                "One or more checks returned FAIL; exiting with code 1 due to --fail-exit"
            )
            return 1
    return 0
