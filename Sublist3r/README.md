## About Sublist3r 

Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google, Yahoo, Bing, Baidu and Ask. Sublist3r also enumerates subdomains using Netcraft, Virustotal, ThreatCrowd, DNSdumpster and ReverseDNS.

[subbrute](https://github.com/TheRook/subbrute) was integrated with Sublist3r to increase the possibility of finding more subdomains using bruteforce with an improved wordlist. The credit goes to TheRook who is the author of subbrute.

## Modernization Notes

This version of Sublist3r has been modernized to exclusively support Python 3 (recommended 3.6+). Key improvements include:
* **Python 3 Only:** Removed Python 2.x compatibility for cleaner, more modern code.
* **Improved Logging:** Switched to Python's standard `logging` module for better control over output messages.
* **Externalized Configurations:** Search engine URLs are now loaded from an external `engines.json` file for easier updates.
* **Enhanced Error Handling:** More specific exception handling for robust operation.
* **Code Refinements:** General code cleanup and structural improvements for readability and maintainability.

## Ownership Information

This modernized version is maintained by Savaid Khan.
Copyright (C) 2025 Savaid Khan. All rights reserved.
This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License Version 2, as detailed in the `LICENSE` file. Original authorship credit is given to Ahmed Aboul-Ela.

## Screenshots

![Sublist3r](http://www.secgeek.net/images/Sublist3r.png "Sublist3r in action")

## Installation

git clone https://github.com/aboul3la/Sublist3r.git


## Recommended Python Version:

Sublist3r now exclusively supports **Python 3**.

* The recommended version for Python 3 is **3.6+**.

## Dependencies:

Sublist3r depends on the `requests`, `dnspython`, and `argparse` python modules.

These dependencies can be installed using the requirements file:

-   Installation on Linux/macOS/Windows (within a virtual environment is recommended):
    ```bash
    pip install -r requirements.txt
    ```

Alternatively, each module can be installed independently as shown below (though `pip install -r` is preferred):

#### Requests Module (http://docs.python-requests.org/en/latest/)

-   Install using pip:
    ```bash
    pip install requests
    ```

#### dnspython Module (http://www.dnspython.org/)

-   Install using pip:
    ```bash
    pip install dnspython
    ```

#### argparse Module (Usually built-in for Python 3)

-   If for some reason `argparse` is not available:
    ```bash
    pip install argparse
    ```

**For coloring in Windows terminals, consider installing `colorama` (often automatically handled by modern Python setups):**
```bash
pip install colorama
Usage
Short Form	Long Form	Description
-d	--domain	Domain name to enumerate its subdomains
-b	--bruteforce	Enable the subbrute bruteforce module
-p	--ports	Scan the found subdomains against specific tcp ports (Note: This is a placeholder for full implementation)
-v	--verbose	Enable verbose mode and display results in real-time
-t	--threads	Number of threads to use for subbrute bruteforce
-e	--engines	Specify a comma-separated list of search engines
-o	--output	Save the results to text file
-n	--no-color	Output without color
-h	--help	Show the help message and exit

Export to Sheets
Examples
To list all the basic options and switches use -h switch:

Bash

python sublist3r.py -h
To enumerate subdomains for a domain:

Bash

python sublist3r.py -d example.com
To enable bruteforce:

Bash

python sublist3r.py -d example.com -b
To specify search engines (e.g., Google and Yahoo):

Bash

python sublist3r.py -d example.com -e google,yahoo
To save results to a file:

Bash

python sublist3r.py -d example.com -o results.txt
To enable verbose output:

Bash

python sublist3r.py -d example.com -v

### **5. Modified `setup.py`**

Updated `setup.py` to reflect Python 3 requirements and pinned `requests` and `dnspython` to more recent, stable versions. `argparse` is removed as it's typically built into Python 3.

```python
from setuptools import setup, find_packages

setup(
    name='Sublist3r',
    version='1.0.1', # Incrementing version for modernization
    python_requires='>=3.6', # Specify Python 3.6+
    install_requires=[
        'dnspython>=2.0.0', # Updated to a modern version
        'requests>=2.28.1', # Updated to a modern version
        'colorama>=0.4.4', # For Windows coloring
    ],
    packages=find_packages() + ['.'], # Include current directory in packages
    include_package_data=True,
    url='https://github.com/aboul3la/Sublist3r', # Original URL
    license='GPL-2.0', # Keep original license
    author='Ahmed Aboul-Ela', # Original author
    author_email='ahmed.aboul.ela@gmail.com', # Original author's email
    maintainer='Savaid Khan', # New maintainer
    maintainer_email='savaid.khan@example.com', # Placeholder for new maintainer's email
    description='Subdomains enumeration tool for penetration testers (Modernized Python 3 Version)',
    long_description='Sublist3r is a Python tool designed to enumerate subdomains of websites using OSINT. This modernized version supports Python 3.6+ and includes updated dependencies and improved code practices.',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)', # Correct classifier for GPL-2.0
        'Natural Language :: English',
        'Programming Language :: Python :: 3', # Explicitly Python 3
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Security',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords='subdomain enumeration osint penetration-testing security',
)
