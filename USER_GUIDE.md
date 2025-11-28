# **SonarTrace – User Guide**

SonarTrace is a Python 3.12 network enumeration tool inspired by bat echolocation.
It sends scan “pulses” into a network and maps hosts, services, and operating systems based on what comes back.

This guide explains how to run and use SonarTrace.
For installation instructions specific to Windows, macOS, or Linux, see the **README.md** in the project.

# **1. Running SonarTrace**

Basic command structure:

python -m src <targets>

### Target formats supported:

* Single IPv4 address
  192.168.1.10
* DNS hostname
  server.example.com
* CIDR range
  192.168.1.0/24
* Comma-separated list
  192.168.1.5,host1.com,10.0.0.0/24

# **2. Excluding Targets**

You can remove out-of-scope hosts:

python -m src "192.168.1.0/24" -e "192.168.1.10"

Exclusions use the same formats as targets.

# **3. DNS Safety Check**

When you include any DNS hostname, SonarTrace will:

1. Detect your system’s DNS resolver
2. Display it
3. Ask for confirmation:
   Proceed using this resolver? (y/N)
4. Stop the scan if you press Enter

This helps prevent scanning the wrong hosts due to DNS issues.

# **4. Custom Output Filename**

By default, SonarTrace creates a file named:

sonartrace_report_YYYYMMDD_HHMM_UTC.md

To choose your own filename:

python -m src 192.168.1.10 -o myreport.md

# **5. Report Structure**

Each scanned host gets its own section in the report.

### Verified Information includes:

* IP address
* Hostname
* Domain
* Open services
* OS type
* Windows-specific info (if found)

### Unverified Information:

Possible OS versions or other guesses based on banners.

### Commands and Raw Output:

SonarTrace shows the exact scan command used, followed by the full raw output. Example:

Command: nmap -sV -sC -p- 192.168.1.10
[Full Nmap output appears below this in the report]

# **6. Ethical Reminder**

Only use SonarTrace on systems you own or have explicit permission to test.
