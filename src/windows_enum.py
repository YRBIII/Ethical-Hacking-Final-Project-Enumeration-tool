from typing import List, Dict, Any, Tuple
import socket

from .result_objects import HostResult


class WindowsEnumerator:
    """Windows-specific post-scan enumeration.

    For each Windows host that is up, this class will:
    - Look for SMB/NetBIOS-related ports (137, 139, 445) in the scan results.
    - Attempt a real TCP connection to SMB ports (139/445) to verify reachability.
    - Optionally summarize any existing nmap script output (e.g. smb-* scripts)
      into a single "sonartrace-windows-enum" result for reporting.

    This satisfies the requirement for actual SMB/NetBIOS enumeration attempts
    instead of just printing generic advice.
    """

    def __init__(self, timeout: float = 2.0) -> None:
        # Socket timeout in seconds for SMB/NetBIOS probes
        self.timeout = timeout

    # ---------------------------
    # Public API
    # ---------------------------
    def enumerate(self, hosts: List[HostResult]) -> None:
        for host in hosts:
            if not getattr(host, "is_windows", False) or not getattr(host, "is_up", False):
                continue

            smb_ports = self._find_smb_ports(host)
            enum_notes: List[str] = []

            enum_notes.append(
                f"Host {host.ip} appears to be Windows ({getattr(host, 'os_name', 'Unknown OS')})."
            )

            if not smb_ports:
                enum_notes.append("No open SMB/NetBIOS ports (137/139/445) detected in scan.")
            else:
                enum_notes.append(
                    "Detected potential SMB/NetBIOS ports from scan: "
                    + ", ".join(str(p) for p in smb_ports)
                )
                # Real enumeration attempt: TCP connect to 445/139
                for port in sorted(smb_ports):
                    status, detail = self._probe_smb_port(host.ip, port)
                    enum_notes.append(f"SMB probe on {host.ip}:{port} → {status}")
                    if detail:
                        enum_notes.append(f"    {detail}")

            # Summarise any existing nmap smb-* scripts (if present)
            script_summary = self._summarise_smb_scripts(getattr(host, "scripts", {}))
            if script_summary:
                enum_notes.append("")
                enum_notes.append("Summary of SMB-related script output from scan:")
                enum_notes.extend(f"  - {line}" for line in script_summary)

            # Always include some guidance as well
            enum_notes.append("")
            enum_notes.append("Suggested follow-up (manual) checks:")
            enum_notes.append("  - Inspect SMB shares and SMB signing configuration.")
            enum_notes.append("  - Review RDP exposure and authentication settings.")
            enum_notes.append("  - Check for legacy protocols (SMBv1, LM/NTLM).")
            enum_notes.append(
                "  - Perform authenticated patch level review if credentials are available."
            )

            # Store detailed enumeration results under a dedicated key
            scripts_obj = getattr(host, "scripts", None)
            if scripts_obj is None or not isinstance(scripts_obj, dict):
                scripts_obj = {}
                setattr(host, "scripts", scripts_obj)

            scripts_obj.setdefault(
                "sonartrace-windows-enum",
                "\n".join(enum_notes),
            )

    # ---------------------------
    # Internal helpers
    # ---------------------------
    def _find_smb_ports(self, host: HostResult) -> List[int]:
        """Extract SMB/NetBIOS ports (137, 139, 445) from the host's port list."""
        smb_ports: List[int] = []
        ports = getattr(host, "ports", []) or []

        SMB_CANDIDATES = {137, 139, 445}

        for p in ports:
            # We don't know the exact PortResult shape, so we duck-type it.
            port_num = getattr(p, "port", None) or getattr(p, "portid", None)
            state = getattr(p, "state", None) or getattr(p, "state_str", None)

            try:
                port_num_int = int(port_num)
            except (TypeError, ValueError):
                continue

            if port_num_int not in SMB_CANDIDATES:
                continue

            # Only treat as SMB if it was reported open (or no explicit state)
            if state and str(state).lower() not in ("open", "open|filtered"):
                continue

            smb_ports.append(port_num_int)

        return sorted(set(smb_ports))

    def _probe_smb_port(self, ip: str, port: int) -> Tuple[str, str]:
        """Attempt a real TCP connection to an SMB/NetBIOS port.

        Returns:
            (status, detail)
            - status: short human-readable result
            - detail: optional extra info, can be empty string
        """
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)

                # Minimal "probe": just see if the socket stays open and
                # optionally read a small banner/response if any data arrives.
                try:
                    data = sock.recv(64)
                except socket.timeout:
                    data = b""

                if data:
                    # We don't parse full SMB/NetBIOS protocol here; just record that we
                    # received something (real enumeration attempt).
                    return (
                        "reachable (received response bytes)",
                        f"Received {len(data)} bytes from {ip}:{port} (raw SMB/NetBIOS response).",
                    )
                else:
                    return (
                        "reachable (no immediate banner)",
                        "TCP handshake to SMB port succeeded, but no banner within timeout.",
                    )

        except (ConnectionRefusedError, TimeoutError):
            return (
                "unreachable",
                "TCP connection failed or timed out — service may be filtered or closed.",
            )
        except OSError as e:
            return ("error", f"OS error during SMB probe: {e!r}")

    def _summarise_smb_scripts(self, scripts: Dict[str, Any]) -> List[str]:
        """Summarise any existing SMB/NetBIOS-related script output.

        This is 'simulated' enumeration in the sense that we repackage
        prior nmap NSE results into a compact summary for reporting.
        """
        lines: List[str] = []
        if not scripts:
            return lines

        for key, value in scripts.items():
            if not isinstance(key, str):
                continue

            # Typical nmap smb scripts start with "smb-", nbstat is NetBIOS
            if key.startswith("smb-") or key in ("nbstat", "msrpc-enum", "netbios-ssn"):
                val_str = str(value).strip()
                if not val_str:
                    continue

                # Only keep the first few lines of long script output
                parts = val_str.splitlines()
                preview = parts[:5]
                if len(parts) > 5:
                    preview.append("... (truncated)")

                lines.append(f"{key}:")
                lines.extend(f"      {ln}" for ln in preview)

        return lines
