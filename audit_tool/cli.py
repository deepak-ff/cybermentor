"""Command-line entry point for the security audit tool."""

from __future__ import annotations

import argparse
import logging
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import __version__
from .checks import current_platform, run_all_checks
from .models import Level, ScanResult
from .reporter import WRITE_FORMATS, write_reports
from .scanner import TOP_PORTS, sequential_scan, timed_scan

log = logging.getLogger("audit_tool")


def parse_ports(spec: str) -> List[int]:
    """Parse '80', '1-1024', '80,443', or 'top' into a sorted list of ints."""
    if spec.strip().lower() == "top":
        return sorted(set(TOP_PORTS))
    ports: set = set()
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
    if not ports:
        raise ValueError("empty port spec")
    return sorted(ports)


def parse_csv_list(value: Optional[str]) -> Optional[Sequence[str]]:
    """Split a comma-separated CLI value into a clean list (or None)."""
    if value is None:
        return None
    items = [x.strip() for x in value.split(",") if x.strip()]
    return items or None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="security-audit-tool",
        description=(
            "Non-intrusive host security audit with CIS/MS-SCC-aligned checks, "
            "a multithreaded TCP port scanner, and JSON/HTML/CSV/SARIF reporting."
        ),
    )
    p.add_argument(
        "--host",
        default="127.0.0.1",
        help="target host to port-scan (default 127.0.0.1)",
    )
    p.add_argument(
        "--ports",
        default="1-1024",
        help="port range/list, e.g. '80' or '1-1024', or 'top' (default 1-1024)",
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
    p.add_argument(
        "--batch-size",
        type=int,
        default=1024,
        help="ports per concurrent batch (default 1024)",
    )
    p.add_argument("--skip-scan", action="store_true", help="skip the TCP port scan")
    p.add_argument(
        "--show-speedup",
        action="store_true",
        help="compare concurrent vs sequential scanning timings",
    )
    p.add_argument(
        "--out",
        default="reports",
        help="output directory for reports (default 'reports')",
    )
    p.add_argument(
        "--hostname",
        default=None,
        help="label used in the report (default: the --host target)",
    )
    p.add_argument(
        "--formats",
        default="json,html",
        help="comma list of report formats to write: "
        + ",".join(WRITE_FORMATS)
        + " (default json,html)",
    )
    p.add_argument(
        "--only",
        default=None,
        help="only run checks in these categories (comma list, case-insensitive)",
    )
    p.add_argument(
        "--exclude",
        default=None,
        help="exclude checks by id (comma list, case-insensitive)",
    )
    p.add_argument(
        "--list-checks",
        action="store_true",
        help="print the registered checks and exit",
    )
    p.add_argument(
        "--fail-exit",
        action="store_true",
        help="exit with code 1 if any FAIL results are present",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="increase verbosity (use -v or -vv)",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _print_check_table(
    categories: Optional[Sequence[str]] = None,
    exclude: Optional[Sequence[str]] = None,
) -> None:
    from .checks import iter_specs

    rows = []
    for _cid, spec in iter_specs(categories, exclude):
        rows.append(
            (
                spec.id,
                spec.category,
                spec.title,
                spec.severity.value,
                spec.cis_ref,
            )
        )
    rows.sort()
    id_w = max(len(r[0]) for r in rows) if rows else 2
    cat_w = max(len(r[1]) for r in rows) if rows else 8
    sev_w = max(len(r[3]) for r in rows) if rows else 4
    print(f"{'ID':<{id_w}}  {'CATEGORY':<{cat_w}}  {'SEV':<{sev_w}}  TITLE / REF")
    for cid, cat, title, sev, ref in rows:
        suffix = f"  [{ref}]" if ref else ""
        print(f"{cid:<{id_w}}  {cat:<{cat_w}}  {sev:<{sev_w}}  {title}{suffix}")
    print(f"\n{len(rows)} check(s) registered.")


def _configure_logging(verbose: int) -> None:
    level = logging.INFO
    if verbose >= 1:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s")


def _run_scan(
    host: str,
    ports_spec: str,
    timeout: float,
    threads: int,
    batch_size: int,
    show_speedup: bool,
) -> Tuple[List[dict], Optional[int]]:
    """Run the TCP port scan (and optional sequential comparison).

    Returns (open_ports, sequential_elapsed_ms or None).
    """
    log.info(
        "Scanning %s:%s (threads=%d, batch=%d) ...",
        host,
        ports_spec,
        threads,
        batch_size,
    )
    ports = parse_ports(ports_spec)
    open_ports, elapsed_ms = timed_scan(
        host,
        ports,
        timeout=timeout,
        threads=threads,
        batch_size=batch_size,
    )
    log.info(
        "Port scan complete in %d ms; %d open port(s).",
        elapsed_ms,
        len(open_ports),
    )
    speedup_ms: Optional[int] = None
    if show_speedup:
        seq_start = time.time()
        sequential_scan(host, ports, timeout=timeout)
        speedup_ms = int((time.time() - seq_start) * 1000)
        log.info(
            "Speed-up vs sequential: %d ms -> %d ms (%.1fx faster)",
            speedup_ms,
            elapsed_ms,
            speedup_ms / max(elapsed_ms, 1),
        )
    return open_ports, speedup_ms


def run_audit(
    host: str,
    ports_spec: str = "1-1024",
    timeout: float = 1.0,
    threads: int = 256,
    batch_size: int = 1024,
    skip_scan: bool = False,
    show_speedup: bool = False,
    out_dir: str = "reports",
    hostname: Optional[str] = None,
    formats: Optional[Sequence[str]] = None,
    categories: Optional[Sequence[str]] = None,
    exclude: Optional[Sequence[str]] = None,
) -> Tuple[ScanResult, Dict[str, str]]:
    """Run a full audit (configuration checks + port scan) and write reports.

    Shared by the CLI and the web backend.

    Raises:
        ValueError: invalid port spec or no usable report formats.
        RuntimeError: a generated report failed JSON schema validation.
    """
    label = hostname or host
    parse_ports(ports_spec)  # validate early so bad input fails fast
    if formats is None:
        formats = ["json", "html"]
    clean = [f.strip().lower() for f in formats if f and f.strip()]
    if not clean:
        raise ValueError("invalid --formats value")

    started = datetime.now().isoformat(timespec="seconds")
    start_ts = time.time()
    log.info("Running configuration checks on %s ...", label)
    checks = run_all_checks(label, categories=categories, exclude=exclude)

    if skip_scan:
        log.info("Port scan skipped.")
        open_ports: List[dict] = []
        speedup_ms: Optional[int] = None
        scan_targets: Dict[str, Any] = {"target": host, "skipped": True}
    else:
        open_ports, speedup_ms = _run_scan(
            host, ports_spec, timeout, threads, batch_size, show_speedup
        )
        scan_targets = {
            "target": host,
            "ports": ports_spec,
            "threads": threads,
            "batch_size": batch_size,
            "timeout": timeout,
            "speedup_ms_sequential": speedup_ms,
        }

    finished = datetime.now().isoformat(timespec="seconds")
    duration_ms = int((time.time() - start_ts) * 1000)

    result = ScanResult(
        host=label,
        started_at=started,
        finished_at=finished,
        duration_ms=duration_ms,
        checks=checks,
        open_ports=open_ports,
        scan_targets=scan_targets,
        tool=f"security-audit-tool {__version__}",
        platform=current_platform().value,
    )
    paths = write_reports(result, out_dir, formats=clean)
    return result, paths


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    _configure_logging(args.verbose)

    if args.list_checks:
        _print_check_table(parse_csv_list(args.only), parse_csv_list(args.exclude))
        return 0

    try:
        # The report is labelled with --hostname when given, otherwise with
        # the scan target. The port scan itself always targets --host.
        result, paths = run_audit(
            host=args.host,
            ports_spec=args.ports,
            timeout=args.timeout,
            threads=args.threads,
            batch_size=args.batch_size,
            skip_scan=args.skip_scan,
            show_speedup=args.show_speedup,
            out_dir=args.out,
            hostname=args.hostname,
            formats=args.formats.split(","),
            categories=parse_csv_list(args.only),
            exclude=parse_csv_list(args.exclude),
        )
    except ValueError as exc:
        log.error(str(exc))
        return 2
    except RuntimeError as exc:
        log.error("%s", exc)
        return 3

    log.info("\nHardening score: %d/100", result.score)
    counts = {lvl: sum(1 for c in result.checks if c.level == lvl) for lvl in Level}
    log.info(
        "Summary: %s",
        ", ".join(f"{lvl.value}: {counts[lvl]}" for lvl in Level if counts[lvl]),
    )
    for fmt, path in paths.items():
        log.info("%-9s : %s", fmt, path)

    if args.fail_exit and any(c.level == Level.FAIL for c in result.checks):
        log.warning(
            "One or more checks returned FAIL; "
            "exiting with code 1 due to --fail-exit"
        )
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
