# **Backend and Target Processing Limitations**

* **DNS resolver accuracy depends on the system’s configuration.**
  If the user is using a VPN, custom DNS settings, or split DNS, the resolver IP displayed by the tool might not match to the actual DNS server used for lookups.

* **CIDR expansion may generate extremely large host lists.**
  Expanding large subnet ranges can result in thousands of hosts, which may exceed reasonable scan durations or cause rate restrictions on some networks.

* **DNS hostname validation is purely syntactic.**
  The tool ensures that the hostname is appropriately formed but fails to confirm that it resolves or falls within the allowed scope.

* **Nmap execution depends on the host system’s environment.**
  Because scans are performed via subprocess calls, Nmap must be installed and available in the system PATH.  If not, the scanning process will fail instantly.

* **Firewall or IDS filtering can reduce scan accuracy.**
  Hosts behind firewalls may drop or block probes, resulting in incomplete service lists or faulty OS detection.

* **Service and OS parsing is affected by Nmap output variability.**
  SonarTrace examines Nmap's text output, so if the formatting differs from usual patterns, some service or OS data may not be correctly recognized.
