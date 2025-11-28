"""
nmap_handler.py – Handles safe Nmap execution using subprocess.
"""

import subprocess  # Used to execute system commands
import shlex       # Safely formats commands for logging
from typing import List, Optional

from exceptions import CommandFail  # Custom error for failed commands
from logger_setup import get_logger  # Logging

log = get_logger("nmap")  # Logger for Nmap operations


def run_nmap(args: List[str], timeout: Optional[int] = 300) -> str:
    """
    Executes the Nmap command using subprocess.
    Handles:
    - Missing Nmap installation
    - Timeouts
    - Non-zero exit codes
    """
    cmd = ["nmap"] + args  # Final command list

    # Log exact command string for debugging/report
    log.info("Running: %s", " ".join(shlex.quote(a) for a in cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,  # Capture output instead of printing
            text=True,            # Get output as string
            timeout=timeout,      # Prevent infinite hangs
            check=False           # Don't raise on non-zero return
        )
    except FileNotFoundError as e:
        raise CommandFail("Nmap not installed or not in PATH.") from e

    # If Nmap fails AND prints nothing, raise an error
    if proc.returncode != 0 and not proc.stdout:
        raise CommandFail(f"Nmap failed: {proc.stderr.strip()}")

    return proc.stdout  # Return raw scan output text


def tcp_full(host: str) -> str:
    """
    Runs:
    - Full TCP port scan
    - Version detection
    - Default scripts
    """
    return run_nmap(["-sV", "-sC", "-p-", "--reason", "-oN", "-", host])


def os_detect(host: str) -> str:
    """
    Runs Nmap OS detection.
    """
    return run_nmap(["-O", "--osscan-guess", "-oN", "-", host])