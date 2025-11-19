"""
nmap_handler.py - run nmap scans safely and return raw output
"""
from __future__ import annotations
import subprocess
from typing import List, Optional
import shlex
from exceptions import CommandExecutionError
from logger_setup import setup_logger

logger = setup_logger("nmap_handler")


def call_nmap(args: List[str], timeout: Optional[int] = 300) -> str:
    cmd = ["nmap"] + args
    logger.info("Running nmap: %s", " ".join(shlex.quote(p) for p in cmd))
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError as exc:
        raise CommandExecutionError("nmap binary not found. Install nmap.") from exc
    if proc.returncode != 0 and not proc.stdout:
        raise CommandExecutionError(
            f"nmap failed (code {proc.returncode}): {proc.stderr.strip()}"
        )
    return proc.stdout


def nmap_tcp_service_scan(target: str) -> str:
    args = ["-sV", "-sC", "-p-", "--reason", "-oN", "-", target]
    return call_nmap(args)


def nmap_os_detection(target: str) -> str:
    args = ["-O", "--osscan-guess", "-oN", "-", target]
    return call_nmap(args)
