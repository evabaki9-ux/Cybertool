"""Command line entry point: ``python -m cybertool``."""

from __future__ import annotations

import argparse
import json
import os
from typing import Sequence

from . import __version__, scanner, vulns, web


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cybertool",
        description="Cybertool %s — port scan, then check selected ports for known issues" % __version__,
    )
    parser.add_argument("--version", action="version", version="cybertool %s" % __version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_cmd = subparsers.add_parser("scan", help="scan open TCP ports")
    scan_cmd.add_argument("target")
    scan_cmd.add_argument("--authorized", action="store_true",
                          help="required confirmation that you may scan the target")
    scan_cmd.add_argument("--profile", choices=("top", "full"), default="top")
    scan_cmd.add_argument("--ports", help="comma-separated ports instead of a profile")
    scan_cmd.add_argument("--timeout", type=float, default=60)

    vuln_cmd = subparsers.add_parser("vulns", help="check one service against local signatures")
    vuln_cmd.add_argument("--port", type=int, required=True)
    vuln_cmd.add_argument("--service", default="")
    vuln_cmd.add_argument("--product", default="")
    vuln_cmd.add_argument("--version", dest="product_version", default="")

    serve_cmd = subparsers.add_parser("serve", help="launch the web interface")
    serve_cmd.add_argument("--host", default="0.0.0.0")
    serve_cmd.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        web.run(args.host, args.port)
        return 0
    try:
        if args.command == "scan":
            ports = [int(part) for part in args.ports.split(",")] if args.ports else None
            result = scanner.scan_target(args.target, authorized=args.authorized,
                                         profile=args.profile, ports=ports, timeout=args.timeout)
        else:
            result = vulns.lookup([{
                "port": args.port, "protocol": "tcp", "service": args.service,
                "product": args.product, "version": args.product_version,
            }])
    except (ValueError, TypeError) as exc:
        print("cybertool: %s" % exc)
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
