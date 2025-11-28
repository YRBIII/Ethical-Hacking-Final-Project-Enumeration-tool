"""
targets.py – Handles target parsing, classification, and separation.
"""

# Built-in module for working with IP addresses and CIDR ranges
import ipaddress

# Regex to validate DNS hostnames
import re

from typing import List, Tuple


# Regex pattern that checks if a string looks like a valid hostname
HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9\.\-]+$")


def split_items(raw: str) -> List[str]:
    """
    Breaks a comma-separated string into a clean list of items.
    Example: "1.1.1.1, 2.2.2.2" → ["1.1.1.1", "2.2.2.2"]
    """
    return [i.strip() for i in raw.split(",") if i.strip()]


def classify(item: str) -> str:
    """
    Classifies the given target as:
    - IPv4 address
    - CIDR range
    - DNS hostname
    Raises an error if none match.
    """
    try:
        ipaddress.IPv4Address(item)  # Try treating it as a single IP
        return "ipv4"
    except Exception:
        pass

    try:
        ipaddress.IPv4Network(item, strict=False)  # Try CIDR
        return "cidr"
    except Exception:
        pass

    # If it matches the hostname regex, treat as DNS name
    if HOSTNAME_RE.match(item):
        return "dns"

    raise ValueError(f"Unrecognized target: {item}")


def separate_targets(raw: str) -> Tuple[List[str], List[str]]:
    """
    Splits all targets into two lists:
    - singles: IPv4 or DNS names
    - cidrs: networks that need expansion
    """
    items = split_items(raw)
    singles, cidrs = [], []

    for i in items:
        kind = classify(i)

        # DNS and single IPs go here
        if kind != "cidr":
            singles.append(i)
        else:
            cidrs.append(i)

    return singles, cidrs
