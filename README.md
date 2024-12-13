### Table of Contents

- [About the Project](https://github.com/Diekgbbtt/TLSScanner?tab=readme-ov-file#about-the-project)
- [Pre-requisites](https://github.com/Diekgbbtt/TLSScanner?tab=readme-ov-file#pre-requisities)
- [Installation](https://github.com/Diekgbbtt/TLSScanner?tab=readme-ov-file#installation)
- [Usage](https://github.com/Diekgbbtt/TLSScanner?tab=readme-ov-file#usage)
- [Features](https://github.com/Diekgbbtt/TLSScanner?tab=readme-ov-file#features)

### About the Project

Check for potential common SSL/TLS vulnerabilties. Based on SSL/TLS supported versions, certificate and certificat chain, cipher suites and resiliance to malicious payloads
Get insights of potential threats and countermeasures

Built With
Scapy
OpenSSL

### Pre-requisities

Python3.12+
pip
git

### Installation

Clone the repository:

```bash
git clone https://github.com/Diekgbbtt/TLSScanner.git'
```

Navigate to the project directory
Install dependencies:

```bash
pip install -r requirements.txt
```

### Usage

A target or list of targets to scan is always expected. Multiple targets can be specified separated by a space
Basic usage
'''python [scan.py](http://scan.py/) <target_domain>/<target_domains_list>'''
Additionally an input txt file with domains to be scanned can be specified with option -f. Ensure the current user has read access to the file
'''python [scan.py](http://scan.py/) -f <path_to_input_file>'''

To scan a local web app specify the host default interface address and the port the app is listening on with option -p:
'''python [scan.py](http://scan.py/) -p <port> <local_interface_address>'''

With furhter additional options it's possible to declare custom cipher suites(-c), elliptic curves(-e) for ECDH key suites and signature algorithms(-s). All of these can be specified as a list. With elements separated by commas.

### Example command

python [scan.py](http://scan.py) -t <target_domain>

### Features

Get supported ssl/tls protocol versions, from sslv3.0 to tls1.3
For each supported version, get a classification of related ciphersuites as strong, weak or export-grade.
Get supported elliptic curves and signature algorithms.
Analyze TLS certificate for misleading and unsafe details, including : pkey correctness, signature, self-sign, cipher, CA sign, revocation check(OCSP), full PKI control(subject, target, key usage policies)
Common TLS vulnerabilities:
 - Secure Renegotiation
 - Heartbleed vulnerability with leaked data dump
 - CCS Injection
 - CRIME
 
Additionally the scan ends with a report of further potential vulnerabilities given the ssl/tls configuration retrieved like POODLE, BEAST, ticketBleed.
