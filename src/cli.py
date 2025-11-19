"""
cli.py - argument parsing and DNS safety prompt
"""
from __future__ import annotations
import argparse
import socket
import sys
from typing import List, Optional
from config import REPORT_FILE_EXTENSION
import dns.resolver
from datetime import datetime, timezone
from pathlib import Path

from logger_setup import setup_logger

logger = setup_logger("cli")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="host-enum",
        description="Host enumeration tool (CSCI 4449/6658 final project).",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "targets",
        help="Target specification: IPv4, DNS name, CIDR, or comma-separated list.",
    )
    parser.add_argument(
        "--exclude",
        "-e",
        dest="exclude",
        default="",
        help="Hosts/subnets to exclude (same formats as targets). Comma-separated.",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        default=None,
        help="Override default output path/filename (.md).",
    )
    parser.add_argument(
        "--utc-timestamp",
        dest="utc_timestamp",
        action="store_true",
        help="Include UTC timestamp in runtime metadata (default true for filename).",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="Increase verbosity (repeat to increase).",
    )
    return parser


def get_system_dns() -> Optional[str]:
    try:
        resolver = dns.resolver.get_default_resolver()
        nameserver = resolver.nameservers[0] if resolver.nameservers else None
        return nameserver
    except Exception:
        return None


def dns_safety_check(hosts: List[str]) -> bool:
    need_check = any(any(c.isalpha() for c in t) for t in hosts)
    if not need_check:
        return True
    resolver_ip = get_system_dns()
    print(f"Detected DNS names in targets. Current DNS resolver: {resolver_ip}")
    resp = input("Proceed using this resolver? (y/N) ").strip().lower()
    if resp == "y":
        return True
    print("Aborting per DNS safety policy.")
    return False


def normalize_output_filename(output: Optional[str]) -> Path:
    from config import DEFAULT_REPORT_PREFIX, DEFAULT_OUTPUT_DIR
    from datetime import datetime, timezone

    if output:
        return Path(output)
    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%d_%H%M_%Z")
    filename = f"{DEFAULT_REPORT_PREFIX}_{stamp}{REPORT_FILE_EXTENSION}"
    return DEFAULT_OUTPUT_DIR.joinpath(filename)
