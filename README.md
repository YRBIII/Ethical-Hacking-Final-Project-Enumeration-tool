# SonarTrace

SonarTrace is a Python 3.12 network enumeration tool inspired by bat echolocation.
It sends scan “pulses” into the environment and maps the network from the responses, providing detailed host, service, and OS information with structured Markdown reporting.

This tool was developed as the final project for CSCI 4449/6658 – Ethical Hacking.

## Features

    IPv4, DNS, and CIDR-based target parsing

    Exclusion rules for out-of-scope hosts

    DNS resolver safety confirmation

    Full-port TCP service scanning (Nmap)

    OS detection + banner extraction

        Windows host identification and enumeration hooks

    Structured Markdown report with:

        Verified information table

        Unverified information

        Full command output sections

Modular multi-file design using Python 3.12

## Installation

SonarTrace requires Python 3.12, Nmap (Network Mapper), and a few Python libraries listed in requirements.txt.
Follow the setup instructions for your operating system below.

## Windows Installation

Step 1 — Install Python 3.12

Download from the official site:
https://www.python.org/downloads/

Make sure to check: [✓] Add Python to PATH

Step 2 — Install Nmap

Download Nmap for Windows:
https://nmap.org/download.html

During installation, ensure: [✓] Add Nmap to the system PATH

Step 3 — Install Git (optional but recommended)

https://git-scm.com/download/win

Step 4 — Clone the Repository

git clone https://github.com/YRBIII/SonarTrace.git
cd SonarTrace

Step 5 — Create Virtual Environment

python -m venv venv
venv\Scripts\activate

Step 6 — Install Dependencies

pip install -r requirements.txt

## MacOS Installation

Step 1 — Install Homebrew (if not installed)

/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

Step 2 — Install Python 3.12

brew install python@3.12

Step 3 — Install Nmap

brew install nmap

Step 4 — Clone the Repository

git clone https://github.com/YRBIII/SonarTrace.git
cd SonarTrace

Step 5 — Create Virtual Environment

python3.12 -m venv venv
source venv/bin/activate

Step 6 — Install Dependencies

pip install -r requirements.txt

## Linux Installation (Ubuntu/Debian/Kali)

Step 1 — Install Python 3.12

(Some distros already include Python 3.x, but ensure 3.12 specifically.)

sudo apt update
sudo apt install python3.12 python3.12-venv

Step 2 — Install Nmap

sudo apt install nmap

Step 3 — Install Git

sudo apt install git

Step 4 — Clone the Repository

git clone https://github.com/YRBIII/SonarTrace.git
cd SonarTrace

Step 5 — Create Virtual Environment

python3.12 -m venv venv
source venv/bin/activate

Step 6 — Install Dependencies

pip install -r requirements.txt

## Additional Dependencies (All Platforms)

SonarTrace installs these automatically through requirements.txt:

Required Python Libraries:

python-dateutil

pytz

python-nmap

dnspython

pyyaml

cryptography

## Optional (Windows Enumeration Features)

If you want SMB + NetBIOS enumeration to work:

impacket

smbprotocol

Install optional dependencies manually if needed:

pip install impacket smbprotocol

## 5. Verifying Installation

python -m src --help

If you see the SonarTrace help menu, everything is installed correctly.

## Help Output
Below is the output of `python -m src --help`:

usage: sonartrace [targets] [options]

SonarTrace - Network enumeration tool inspired by bat echolocation.
Supports IPv4 addresses, DNS names, CIDR ranges, and comma-separated lists.

positional arguments:
  targets               Target hosts to scan. Accepted formats:
                          • IPv4 (e.g., 192.168.1.10)
                          • DNS names (e.g., server.example.com)
                          • CIDR ranges (e.g., 192.168.1.0/24)
                          • Comma-separated lists of any combination

optional arguments:
  -h, --help            Show this help message and exit

  -e EXCLUDE, --exclude EXCLUDE
                        Exclude specific hosts or networks from scanning.
                        Accepts IPv4, DNS, CIDR, or comma-separated lists.

  -o OUTPUT, --output OUTPUT
                        Use a custom output report filename/path (.md).
                        Default name:
                        sonartrace_report_YYYYMMDD_HHMM_UTC.md

  --utc-timestamp       Include UTC timestamp metadata inside the report.
                        Enabled by default for filename generation.

  -v, --verbose         Increase output detail.
                        -v  = INFO level
                        -vv = DEBUG level (most detailed)
