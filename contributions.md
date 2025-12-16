# **SonarTrace – Contributions**

This page explains what each of us worked on for the final project.

---

## Yung

I worked on the project's backend. So, my role was to ensure that the program could understand targets, filter out everything that shouldn't be scanned, and execute Nmap properly. I also handled the parts that prepare the scan, run it, and deal with any mistakes that may occur.

I configured the target parser, CIDR handling (Classless Inter-Domain Routing), DNS safety checks (Domain Name System), and scanning engine, which delivers everything to Nmap.  I also configured all logging and error handling.  In addition, I set up the GitHub repository and the project folder structure.

### **Files I worked on**

* `targets.py`
* `utils.py`
* `enumerator.py`
* `nmap_handler.py`
* `__main__.py`
* `exceptions.py`
* `logger_setup.py`
* `config.py`
* `result_objects.py`

## Sachi

I worked on the user interaction, parsing, reporting, and operating-system-specific enumeration components of the project. My role was to ensure that users could safely and correctly run the tool, that scan results were accurately interpreted, and that all output was presented in a clear and structured format that meets the project requirements.

I implemented the command-line interface, including argument parsing, help output, input validation, and startup behavior. I also integrated DNS safety confirmation prompts to ensure ethical scanning practices before any scan execution. In addition, I handled the parsing of raw Nmap output and converted scan results into structured data objects that could be processed consistently across the application.

I designed and built the reporting engine that generates Markdown reports. These reports include verified information tables, unverified findings, the exact Nmap command executed, and full raw command output, as required by the grading rubric. I also implemented Windows-specific enumeration logic to collect SMB, NetBIOS, and related host information when applicable.

Overall, my work ensures that SonarTrace is usable, well-documented, ethically safe to operate, and capable of producing professional-quality scan reports suitable for analysis and submission.

### Files I worked on

* `cli.py`
* `nmap_parser.py`
* `report_builder.py`
* `windows_enum.py`
* `__main__.py`

-----
