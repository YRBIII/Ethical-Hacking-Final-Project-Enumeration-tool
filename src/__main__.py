"""
__main__.py - program entry point
"""
from __future__ import annotations
import sys
from cli import build_arg_parser, dns_safety_check, normalize_output_filename
from enumerator import expand_all_targets, run_full_scan
from report_builder import build_full_report
from logger_setup import setup_logger

logger = setup_logger("main")


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    targets = expand_all_targets(args.targets, args.exclude)
    if not dns_safety_check(targets):
        sys.exit(1)

    results = []
    for t in targets:
        logger.info("Scanning %s", t)
        parsed = run_full_scan(t)
        results.append(parsed)

    out_path = normalize_output_filename(args.output)
    report = build_full_report(results)
    out_path.write_text(report, encoding="utf-8")

    logger.info("Report written to %s", out_path)


if __name__ == "__main__":
    main()
