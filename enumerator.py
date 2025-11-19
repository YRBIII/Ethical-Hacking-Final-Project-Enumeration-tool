"""
enumerator.py - combine target expansion, scanning, parsing, and reporting
"""
from __future__ import annotations
from typing import List, Dict
from logger_setup import setup_logger
from targets import expand_targets
from utils import dedupe, expand_cidr
from nmap_handler import nmap_tcp_service_scan, nmap_os_detection
from nmap_parser import parse_nmap_raw

logger = setup_logger("enumerator")


def expand_all_targets(raw_targets: str, raw_exclude: str) -> List[str]:
    t_targets, t_cidrs = expand_targets(raw_targets)
    e_targets, e_cidrs = expand_targets(raw_exclude)

    all_hosts = []
    for t in t_targets:
        all_hosts.append(t)
    for cidr in t_cidrs:
        all_hosts.extend(expand_cidr(cidr))

    exclude_hosts = set()
    for e in e_targets:
        exclude_hosts.add(e)
    for cidr in e_cidrs:
        exclude_hosts.update(expand_cidr(cidr))

    final = [h for h in dedupe(all_hosts) if h not in exclude_hosts]
    return final


def run_full_scan(host: str) -> Dict:
    logger.info("Starting full scan for %s", host)

    raw_services = nmap_tcp_service_scan(host)
    parsed = parse_nmap_raw(raw_services)

    raw_os = nmap_os_detection(host)
    os_data = parse_nmap_raw(raw_os)
    if os_data.get("os"):
        parsed["os"] = os_data["os"]

    parsed["ip"] = parsed.get("ip") or host
    return parsed
