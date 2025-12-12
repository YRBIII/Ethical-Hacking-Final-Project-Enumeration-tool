# SonarTrace – User Guide

SonarTrace is a Python 3.12 network enumeration tool inspired by bat echolocation.  
It sends scan “pulses” into a network and maps hosts, services, and operating systems based on what comes back.

For installation instructions, see the **README.md** file.

---

# 1. Running SonarTrace

Basic usage:

```bash
python -m src <targets>
````

### Supported Target Formats

* **Single IPv4 address**
  Example:

  ```bash
  192.168.1.10
  ```

* **DNS hostname**
  Example:

  ```bash
  server.example.com
  ```

* **CIDR range**
  Example:

  ```bash
  192.168.1.0/24
  ```

* **Comma-separated list**
  Example:

  ```bash
  192.168.1.5,host1.com,10.0.0.0/24
  ```

---

# 2. Excluding Targets

To remove an IP or network from the scan scope:

```bash
python -m src "192.168.1.0/24" -e "192.168.1.10"
```

Exclusions support all the same formats as targets.

---

# 3. DNS Safety Check

When SonarTrace detects DNS hostnames, it will:

1. Detect your system’s DNS resolver

2. Display the resolver address

3. Ask for confirmation:

   ```
   Proceed using this resolver? (y/N)
   ```

4. Stop automatically if you press Enter (default No)

This prevents accidental scans caused by DNS misconfiguration.

---

# 4. Custom Output Filename

By default, SonarTrace creates reports using:

```
host_enumeration_report_YYYYMMDD_HHMM_UTC.md
```

To specify your own filename:

```bash
python -m src 192.168.1.10 -o myreport.md
```

---

# 5. Report Structure

Each scanned host includes:

### Verified Information

* IP address
* Hostname
* Domain (if applicable)
* Active services
* OS type
* Windows-specific info (if detected)

### Unverified Information

* Possible OS guesses
* Version hints from Nmap banners

### Commands & Raw Output

SonarTrace prints the **exact Nmap commands** it used, followed by their **full raw output**.

Example:

```
Command: nmap -sV -sC -p- 192.168.1.10
[Raw Nmap output here]
```

This ensures full traceability of the enumeration process.

---

# 6. Ethical Reminder

SonarTrace is a penetration testing tool.
Only use it on systems you **own** or have **explicit permission** to test.

Unauthorized scanning is prohibited and may violate school, workplace, or legal guidelines.