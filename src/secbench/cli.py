"""Command-line entry point so the auditor can run headlessly."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from .auth import AuthManager
from .azure_client import ResponseCache
from .config import Settings, reports_dir
from .engine import Context, load_all_benchmarks
from .engine.runner import Runner
from .logging_setup import setup_logging
from .reports import render_csv, render_html, render_json, render_pdf


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secbench", description="CIS Azure / M365 auditor")
    p.add_argument("--list", action="store_true", help="List available benchmarks and exit")
    p.add_argument("--benchmarks", nargs="*", help="Benchmark IDs to run (defaults to all)")
    p.add_argument("--method", choices=["interactive", "device_code", "sp_secret", "sp_cert"], default="interactive")
    p.add_argument("--tenant", default=None)
    p.add_argument("--client-id", default=None)
    p.add_argument("--client-secret", default=None)
    p.add_argument("--cert-path", default=None)
    p.add_argument("--cert-password", default=None)
    p.add_argument("--subscriptions", nargs="*", help="Subscription IDs to evaluate")
    p.add_argument("--profile", choices=["E3", "E5"], default="E3")
    p.add_argument("--level", type=int, choices=[1, 2], default=2)
    p.add_argument("--out", default=None, help="Output folder for reports")
    p.add_argument("--no-manual", action="store_true", help="Skip controls without an automated check")
    p.add_argument("--no-cache", action="store_true", help="Disable in-run response cache")
    return p


def main(argv: list[str] | None = None) -> int:
    setup_logging()
    args = _build_parser().parse_args(argv)
    benches = load_all_benchmarks()

    if args.list:
        for b in benches:
            print(f"{b.id:36s} {b.title} ({b.version}) - {len(b.all_controls())} controls")
        return 0

    selected = [b for b in benches if not args.benchmarks or b.id in args.benchmarks]
    if not selected:
        print("No matching benchmarks", file=sys.stderr)
        return 2

    auth = AuthManager()
    auth.configure(
        args.method,
        tenant_id=args.tenant,
        client_id=args.client_id,
        client_secret=args.client_secret,
        certificate_path=args.cert_path,
        certificate_password=args.cert_password,
    )
    bundle = auth.sign_in()

    sub_ids: list[str] = list(args.subscriptions or [])
    if not sub_ids:
        sub_ids = [s["id"] for s in auth.list_subscriptions() if s.get("id")]

    ctx = Context(
        credential=bundle.credential,
        tenant_id=bundle.tenant_id,
        subscription_ids=sub_ids,
        profile=args.profile,
        cache=ResponseCache(enabled=not args.no_cache),
    )

    runner = Runner()
    run_result = asyncio.run(
        runner.run(
            ctx,
            selected,
            level_max=args.level,
            include_manual=not args.no_manual,
        )
    )

    out_dir = Path(args.out) if args.out else reports_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    base = out_dir / "secbench-report"
    render_html(run_result, base.with_suffix(".html"))
    render_json(run_result, base.with_suffix(".json"))
    render_csv(run_result, base.with_suffix(".csv"))
    try:
        render_pdf(run_result, base.with_suffix(".pdf"))
    except Exception as exc:
        print(f"PDF generation failed: {exc}", file=sys.stderr)

    print(f"Reports saved to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
