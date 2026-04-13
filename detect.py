#!/usr/bin/env python3
"""
detect.py - SOC Threat Detection System — Entry Point
=======================================================
Command-line interface for the Log-Based Threat Detection System.
Orchestrates log parsing, threat detection, and report generation.

Usage
-----
    python detect.py --file data/sample.log
    python detect.py --file /var/log/auth.log --threshold 10
    python detect.py --file data/sample.log --output output/report

Author: SOC Analyst Toolkit
"""

import argparse
import os
import sys
import time

# Ensure the project root is on the path so the package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from threat_detection.parser   import LogParser
from threat_detection.detector import ThreatDetector
from threat_detection.report   import ReportGenerator, Color


# ─────────────────────────────────────────────
#  CLI Argument Definitions
# ─────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detect.py",
        description=(
            "╔══════════════════════════════════════════════╗\n"
            "║   Log-Based Threat Detection System          ║\n"
            "║   SOC Analyst Toolkit  |  Auth Log Analyser  ║\n"
            "╚══════════════════════════════════════════════╝\n\n"
            "Analyses Linux auth.log files to detect brute-force attacks,\n"
            "credential spraying, and other suspicious SSH activity."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python detect.py --file data/sample.log\n"
            "  python detect.py --file /var/log/auth.log --threshold 10\n"
            "  python detect.py --file data/sample.log --output output/report --no-color\n"
        ),
    )

    parser.add_argument(
        "--file", "-f",
        required=True,
        metavar="PATH",
        help="Path to the auth.log (or equivalent) file to analyse.",
    )
    parser.add_argument(
        "--threshold", "-t",
        type=int,
        default=5,
        metavar="N",
        help="Failed attempts from one IP to trigger BRUTE_FORCE alert. Default: 5.",
    )
    parser.add_argument(
        "--spray-threshold", "-s",
        type=int,
        default=4,
        metavar="N",
        dest="spray_threshold",
        help="Distinct usernames from one IP to trigger CREDENTIAL_SPRAY alert. Default: 4.",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="BASENAME",
        default=None,
        help="Base name for output files. Produces <BASENAME>.csv and <BASENAME>.txt.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI colour codes (useful for piping or logging).",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        default=False,
        help="Suppress terminal report; only write output files.",
    )

    return parser


# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────

def _status(msg: str, no_color: bool = False) -> None:
    prefix = "" if no_color else Color.GREEN
    reset  = "" if no_color else Color.RESET
    dim    = "" if no_color else Color.DIM
    print(f"  {prefix}✔{reset}  {dim}{msg}{reset}")


def _print_startup_banner(args: argparse.Namespace, no_color: bool) -> None:
    def c(color, text):
        return text if no_color else f"{color}{text}{Color.RESET}"

    print()
    print(c(Color.BOLD + Color.BLUE, "  Initialising SOC Threat Detection Engine…"))
    print(c(Color.DIM, f"  Log      : {args.file}"))
    print(c(Color.DIM, f"  Threshold: {args.threshold} failed attempts (brute-force)"))
    print(c(Color.DIM, f"  Spray    : {args.spray_threshold} unique usernames (spraying)"))
    if args.output:
        print(c(Color.DIM, f"  Output   : {args.output}.csv / {args.output}.txt"))
    print()


# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────

def main() -> None:
    arg_parser = build_arg_parser()
    args = arg_parser.parse_args()
    nc = args.no_color

    if args.threshold < 1:
        print("[ERROR] --threshold must be >= 1.", file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        _print_startup_banner(args, nc)

    # ── Stage 1: Parse ────────────────────────
    t0 = time.perf_counter()
    log_parser = LogParser(filepath=args.file)

    try:
        entries = log_parser.parse()
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)

    stats = log_parser.get_stats()
    if not args.quiet:
        _status(
            f"Parsed {stats['total_lines']:,} log lines → "
            f"{stats['parsed_entries']:,} SSH events extracted  "
            f"({time.perf_counter() - t0:.3f}s)", nc,
        )

    if stats["parsed_entries"] == 0:
        print("\n  [!] No recognisable SSH auth events found in the log file.")
        sys.exit(0)

    # ── Stage 2: Detect ───────────────────────
    t1 = time.perf_counter()
    detector = ThreatDetector(threshold=args.threshold, spray_threshold=args.spray_threshold)
    alerts   = detector.analyse(entries)
    summary  = detector.get_summary()

    if not args.quiet:
        _status(
            f"Analysed {summary['total_ips_seen']} unique IPs → "
            f"{len(alerts)} alerts raised  "
            f"({time.perf_counter() - t1:.3f}s)", nc,
        )
        print()

    # ── Stage 3: Report ───────────────────────
    report_gen = ReportGenerator(
        alerts=alerts,
        ip_profiles=detector.ip_profiles,
        summary=summary,
        log_filepath=os.path.abspath(args.file),
        no_color=nc,
    )

    if not args.quiet:
        report_gen.print_terminal_report()

    # ── Stage 4: Files ────────────────────────
    if args.output:
        # Ensure the output directory exists
        out_dir = os.path.dirname(args.output)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        csv_path = f"{args.output}.csv"
        txt_path = f"{args.output}.txt"
        report_gen.write_csv(csv_path)
        report_gen.write_txt(txt_path)

        if not args.quiet:
            prefix = "" if nc else Color.GREEN
            reset  = "" if nc else Color.RESET
            dim    = "" if nc else Color.DIM
            print(f"  {prefix}📄{reset}  {dim}CSV report  →  {os.path.abspath(csv_path)}{reset}")
            print(f"  {prefix}📄{reset}  {dim}TXT report  →  {os.path.abspath(txt_path)}{reset}")
            print()


if __name__ == "__main__":
    main()
