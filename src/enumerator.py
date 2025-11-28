"""
enumerator.py – Backend scanning engine for SonarTrace.
Handles:
- Expanding targets
- Applying exclusions
- Running Nmap scans
"""

from typing import Dict, List

# Pull in your target parsing code
from targets import separate_targets

# Pull in utilities like CIDR expansion and dedupe
from utils import expand_cidr, dedupe

# Functions that actually run Nmap
from nmap_handler import tcp_full, os_detect

# Logger to print helpful information during scans
from logger_setup import get_logger

log = get_logger("engine")  # Create a logger named "engine"


def expand_all(target_raw: str, exclude_raw: str) -> List[str]:
    """
    Turns input strings into a final list of scan targets.
    Steps:
    1. Separate single targets and CIDRs
    2. Expand CIDR ranges
    3. Apply exclusions (also expanded)
    4. Remove duplicates
    """
    # Split targets into single hosts and CIDR ranges
    t_singles, t_cidrs = separate_targets(target_raw)
    e_singles, e_cidrs = separate_targets(exclude_raw)

    hosts = []

    # Add single items (IPs or DNS)
    for t in t_singles:
        hosts.append(t)

    # Expand CIDR ranges into individual host IPs
    for cidr in t_cidrs:
        hosts.extend(expand_cidr(cidr))

    # Build exclusion list
    excludes = set()

    for e in e_singles:
        excludes.add(e)

    for cidr in e_cidrs:
        excludes.update(expand_cidr(cidr))

    # Remove excluded hosts and duplicates
    final = [h for h in dedupe(hosts) if h not in excludes]
    return final


def scan_host(host: str) -> Dict:
    """
    Runs two Nmap scans:
    - Full TCP service scan
    - OS detection scan
    Returns a dictionary with raw output for later parsing.
    """
    log.info("Scanning %s", host)

    # Run full service scan (captures ports & banners)
    raw_services = tcp_full(host)

    # Run OS detection scan
    raw_os = os_detect(host)

    return {
        "ip": host,
        "raw_service_scan": raw_services,
        "raw_os_scan": raw_os
    }