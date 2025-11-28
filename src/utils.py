"""
utils.py – Helper functions for CIDR expansion and list cleanup.
"""

import ipaddress
from typing import List


def dedupe(items: List[str]) -> List[str]:
    """
    Removes duplicate entries while keeping original order.
    Useful when expanding CIDR ranges that might repeat.
    """
    seen = set()
    out = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def expand_cidr(cidr: str) -> List[str]:
    """
    Takes a CIDR range like 192.168.1.0/24 and returns
    a list of every usable host address inside that network.
    """
    net = ipaddress.IPv4Network(cidr, strict=False)
    return [str(h) for h in net.hosts()]