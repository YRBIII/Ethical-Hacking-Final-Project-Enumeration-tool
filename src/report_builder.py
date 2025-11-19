"""
report_builder.py - markdown report generation
"""
from __future__ import annotations
from typing import Dict, List, Any
from datetime import datetime, timezone


def header(text: str) -> str:
    return f"# {text}\n\n"


def subheader(text: str) -> str:
    return f"## {text}\n\n"


def code_block(content: str) -> str:
    return f"```\n{content}\n```\n\n"


def table(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return "_No data._\n\n"
    cols = list(rows[0].keys())
    out = "| " + " | ".join(cols) + " |\n"
    out += "| " + " | ".join(["---"] * len(cols)) + " |\n"
    for r in rows:
        out += "| " + " | ".join(str(r[c]) for c in cols) + " |\n"
    return out + "\n"


def build_host_section(parsed: Dict[str, Any]) -> str:
    ip = parsed.get("ip") or parsed.get("hostname") or "Unknown host"
    md = subheader(f"Scan Results for {ip}")
    md += "### Services\n\n"
    md += table(parsed.get("services", []))
    if parsed.get("os"):
        md += f"**OS Guess:** {parsed['os']}\n\n"
    md += "### Raw Output\n\n"
    md += code_block(parsed["raw"])
    return md


def build_full_report(results: List[Dict[str, Any]]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    md = header("Host Enumeration Report")
    md += f"Generated: **{now} UTC**\n\n"
    for r in results:
        md += build_host_section(r)
    return md
