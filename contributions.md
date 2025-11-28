This docdocument describes what each of us worked on for the Final project.

Yung Brinney

Yung - Backend/Core Engine

 I worked on the project's backend.  This covers everything related to processing targets, such as excluding out-of-scope hosts, broader CIDR ranges (Classless Inter-Domain Routing), ensuring DNS safety (Domain Name System), and performing actual scans using Nmap.  I created the main framework, which prepares targets, calls Nmap properly, handles errors, and controls all logging.  I created the GitHub repository and organized the project's structure.

Files I worked on:
targets.py
utils.py
enumerator.py
nmap_handler.py
exceptions.py
logger_setup.py
config.py