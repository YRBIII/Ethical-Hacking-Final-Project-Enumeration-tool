"""
utils.py - helper utilities
"""
from __future__ import annotations
from typing import List
import ipaddress


def dedupe(seq: List[str]) -> List[str]:
    seen = set()
    out = []
    for item in seq:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def expand_cidr(cidr: str) -> List[str]:
    net = ipaddress.IPv4Network(cidr, strict=False)
    return [str(ip) for ip in net.hosts()]
