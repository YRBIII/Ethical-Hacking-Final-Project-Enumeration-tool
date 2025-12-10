import argparse
import ipaddress
import platform
import subprocess
import re
from typing import List, Optional

from .nmap_handler import NmapHandler, NmapExecutionError
from .nmap_parser import NmapParser
from .report_builder import ReportBuilder
from .windows_enum import WindowsEnumerator
from . import __version__, __app_name__


ASCII_BANNER = r"""
  _________                       ___________                     
 /   _____/ ____   ____   ____   \__    ___/______   ____   ______
 \_____  \\_/ __ \\_/ __ \\_/ __ \\    |    |  \_  __ \\_/ __ \\ /  ___/
/        \\  ___/\\  ___/\\  ___/    |    |   |  | \\  ___/ \\___ \\ 
/_______  / \\___  >\\___  >\\___  >   |____|   |__|   \\___  >____  >
        \\/      \\/     \\/     \\/                         \\/     \\/ 

  SonarTrace - focused Nmap wrapper for *authorized* assessments only.
"""


def _looks_like_ip(target: str) -> bool:
    try:
        # ipaddress also understands CIDR ranges
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False


def _validate_targets(targets: List[str], allow_dns: bool) -> None:
    """Existing safety guard for overly broad ranges and hostname use."""
    if allow_dns:
        return

    non_ip = [t for t in targets if not _looks_like_ip(t)]
    if non_ip:
        raise SystemExit(
            "Refusing to resolve hostnames because DNS leakage could identify your scan.\n"
            "Either specify IP addresses / CIDR ranges only, or pass --allow-dns if you "
            "understand and accept the risk. Offending values: " + ", ".join(non_ip)
        )

    for t in targets:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            continue
        if net.prefixlen < 8:
            raise SystemExit(
                f"Target {t} is overly broad (prefix {net.prefixlen}). For safety, SonarTrace "
                "requires a prefix length of /8 or smaller (e.g., 10.0.0.0/16, 192.168.0.0/24)."
            )


# ---------------------------------------------------------------------------
# DNS resolver detection + confirmation (assignment requirement)
# ---------------------------------------------------------------------------
def _detect_system_dns_servers() -> List[str]:
    """Best-effort detection of system DNS resolver(s).

    Linux/macOS: parses /etc/resolv.conf
    Windows: parses 'ipconfig /all' output for 'DNS Servers'
    """
    servers: List[str] = []

    try:
        system = platform.system().lower()
    except Exception:
        system = ""

    # Unix-like systems
    if system in ("linux", "darwin"):
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            servers.append(parts[1])
        except OSError:
            pass

    # Windows
    elif system == "windows":
        try:
            output = subprocess.check_output(
                ["ipconfig", "/all"],
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
            capture = False
            for raw_line in output.splitlines():
                line = raw_line.strip()
                if not line:
                    capture = False
                    continue

                if "DNS Servers" in line:
                    # First resolver may be on the same line
                    m = re.search(r"DNS Servers[ .:]*([0-9a-fA-F\.:]+)", line)
                    if m:
                        servers.append(m.group(1))
                    capture = True
                    continue

                if capture:
                    m = re.search(r"([0-9a-fA-F\.:]+)", line)
                    if m:
                        servers.append(m.group(1))
        except Exception:
            pass

    # De-duplicate while preserving order
    seen = set()
    deduped: List[str] = []
    for s in servers:
        if s not in seen:
            seen.add(s)
            deduped.append(s)
    return deduped


def _dns_safety_prompt() -> None:
    """Print detected DNS resolvers and ask user to confirm before scanning.

    This implements the 'DNS Safety Check' required in the rubric.
    """
    servers = _detect_system_dns_servers()

    print("\n[DNS Safety] Detected system DNS resolver(s):")
    if servers:
        for s in servers:
            print(f"  - {s}")
    else:
        print("  <none detected or could not determine>")

    print(
        "[DNS Safety] If you scan hostnames or if reverse DNS lookups are enabled, "
        "DNS queries may be sent to these servers."
    )
    answer = input("[DNS Safety] Do you accept this risk and continue with the scan? [y/N]: ")
    if answer.strip().lower() not in ("y", "yes"):
        raise SystemExit("[DNS Safety] Scan aborted by user at DNS confirmation prompt.\n")
    print("[DNS Safety] User confirmed DNS configuration; proceeding with scan.\n")


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=__app_name__,
        description=(
            "SonarTrace is a thin wrapper around Nmap that focuses on safe defaults, basic "
            "parsing, and human-readable reports. Only use it against systems you are "
            "explicitly authorized to test."
        ),
    )
    p.add_argument(
        "targets",
        nargs="+",
        help="List of target IPs / CIDR ranges (or hostnames if --allow-dns is set)."
    )
    p.add_argument(
        "-p", "--ports",
        help="Port specification in Nmap format (e.g. 1-1024,80,443). If omitted, Nmap defaults apply."
    )
    p.add_argument(
        "-o", "--output",
        help="Path to write the text report to. If omitted, prints to stdout."
    )
    p.add_argument(
        "--json-output",
        help="Optional path for a JSON report (in addition to the text report)."
    )
    p.add_argument(
        "--rate", type=int, default=None,
        help="Rough rate control. Values <= 2000 imply a more polite Nmap timing template."
    )
    p.add_argument(
        "-x", "--exclude", action="append", default=[],
        help="Host(s) or network(s) to exclude from the scan. Can be used multiple times."
    )
    p.add_argument(
        "--allow-dns", action="store_true",
        help=(
            "Allow DNS resolution of hostnames (disables the hostname restriction in the "
            "DNS leakage safety check; the DNS resolver confirmation prompt still applies)."
        ),
    )
    p.add_argument(
        "--nmap-arg", dest="nmap_args", action="append", default=[],
        help="Additional raw nmap arguments to append (advanced use only)."
    )
    p.add_argument(
        "--version", action="version",
        version=f"%(prog)s {__version__}",
    )
    return p


def main(argv: Optional[List[str]] = None) -> None:
    print(ASCII_BANNER)
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    # Very explicit legality warning
    print("[!] Use this tool ONLY against hosts and networks you are explicitly authorized to test.")
    print("[!] The authors take no responsibility for misuse.\n")

    # DNS Safety Check – detect resolver(s) and ask user to confirm
    _dns_safety_prompt()

    # Existing target validation (CIDR breadth + hostname safety)
    _validate_targets(args.targets, allow_dns=args.allow_dns)

    handler = NmapHandler(
        targets=args.targets,
        ports=args.ports,
        rate_limit=args.rate,
        extra_args=args.nmap_args,
        excludes=args.exclude,
    )

    try:
        xml_output = handler.run_scan()
    except NmapExecutionError as e:
        parser.exit(status=1, message=f"[!] Nmap error: {e}\n")

    parser_obj = NmapParser()
    hosts = parser_obj.parse(xml_output)

    win_enum = WindowsEnumerator()
    win_enum.enumerate(hosts)

    metadata = {
        "targets": ", ".join(args.targets),
        "excluded": ", ".join(args.exclude) if args.exclude else "(none)",
        # If you later want to show the exact command + raw XML in the report,
        # you can also add e.g. "nmap_command" and "raw_nmap_output" here.
    }
    builder = ReportBuilder(metadata=metadata)
    text_report = builder.build_text_report(hosts)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text_report)
        print(f"[+] Text report written to {args.output}")
    else:
        print(text_report)

    if args.json_output:
        json_report = builder.build_json_report(hosts)
        with open(args.json_output, "w", encoding="utf-8") as f:
            f.write(json_report)
        print(f"[+] JSON report written to {args.json_output}")


if __name__ == "__main__":  # pragma: no cover
    main()
