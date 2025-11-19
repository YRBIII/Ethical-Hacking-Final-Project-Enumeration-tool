"""
targets.py - parse and normalize target and exclusion specifications
"""
from __future__ import annotations
import ipaddress
from typing import List, Tuple
import re
from pathlib import Path

HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9\.\-]+$")


def split_comma_list(s: str) -> List[str]:
    return [item.strip() for item in s.split(",") if item.strip()]


def classify_target(t: str) -> str:
    try:
        ipaddress.IPv4Address(t)
        return "ipv4"
    except Exception:
        pass
    try:
        ipaddress.IPv4Network(t, strict=False)
        return "cidr"
    except Exception:
        pass
    if HOSTNAME_RE.match(t):
        return "dns"
    raise ValueError(f"Unrecognized target format: {t!r}")


def expand_targets(inputs: str) -> Tuple[List[str], List[str]]:
    items = split_comma_list(inputs)
    targets = []
    cidrs = []
    for it in items:
        ttype = classify_target(it)
        if ttype == "cidr":
            cidrs.append(it)
        else:
            targets.append(it)
    return targets, cidrs
