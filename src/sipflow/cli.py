"""Command-line entry point: `sipflow capture.pcap`."""

from __future__ import annotations

import argparse
import sys

from .analyzer import analyze_pcap
from .report import issues, json_report, text_report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sipflow", description="Rebuild SIP call flows and RTP quality from a PCAP.")
    p.add_argument("pcap", help="path to a .pcap/.pcapng file")
    p.add_argument("--json", action="store_true", help="output JSON instead of text")
    p.add_argument("--ladder", action="store_true", help="show the SIP message ladder for each call")
    p.add_argument(
        "--fail-on-issues",
        action="store_true",
        help="exit with code 2 if any call has quality issues (useful in CI or monitoring)",
    )
    args = p.parse_args(argv)

    try:
        calls = analyze_pcap(args.pcap)
    except FileNotFoundError:
        print(f"error: file not found: {args.pcap}", file=sys.stderr)
        return 1

    print(json_report(calls) if args.json else text_report(calls, ladder=args.ladder))

    if args.fail_on_issues and any(issues(c) for c in calls):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
