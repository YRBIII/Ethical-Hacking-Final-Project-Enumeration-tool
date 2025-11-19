"""
nmap_parser.py - lightweight parsing of nmap output into structured dicts
"""
from __future__ import annotations
import re
from typing import Dict, Any, List
from logger_setup import setup_logger

logger = setup_logger("nmap_parser")

PORT_LINE_RE = re.compile(r"^(\d+)\/(tcp|udp)\s+(\S+)\s+([^\n]+)")
HOSTNAME_RE = re.compile(r"Nmap scan report for (.+)")
IP_RE = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\)")
OS_RE = re.compile(r"OS details: (.+)")


def parse_nmap_raw(raw: str) -> Dict[str, Any]:
    out = {"hostname": None, "ip": None, "os": None, "services": [], "raw": raw}

    for line in raw.splitlines():

        m_host = HOSTNAME_RE.search(line)
        if m_host:
            host = m_host.group(1).strip()
            out["hostname"] = host
            m_ip = IP_RE.search(line)
            if m_ip:
                out["ip"] = m_ip.group(1)
            continue

        m_os = OS_RE.search(line)
        if m_os:
            out["os"] = m_os.group(1).strip()
            continue

        m_port = PORT_LINE_RE.match(line)
        if m_port:
            port, proto, state, info = m_port.groups()
            out["services"].append(
                {
                    "port": int(port),
                    "proto": proto,
                    "state": state,
                    "info": info.strip(),
                }
            )

    return out
