# Net Attack Tool

## Overview

Net Attack Tool is an automated attack script designed to scan networks, identify reachable hosts, perform brute-force attacks on Telnet, SSH, and web login pages, and potentially deploy payloads to compromised systems.

## Features

- Reads a list of IP addresses from a file
- Checks if the target IPs are reachable using ICMP ping
- Scans specified ports to check if they are open
- Performs brute-force attacks on:
  - Telnet (port 23)
  - SSH (port 22)
  - Web login pages (default `login.php`)
- Deploys files to compromised machines
- Sends and executes commands on target machines
- Supports local network scanning
- Enables propagation to new targets

## Dependencies

The script requires the following Python libraries:

- `sys`
- `scapy`
- `telnetlib`
- `paramiko`
- `requests`
- `time`
- `socket`

To install missing dependencies, run:

```sh
pip install scapy paramiko requests
```

## Usage

```
usage: net_attack.py [-h] [-t IP ADDRESSES] [-p PORTS] [-u USERNAME] [-f PASSWORDS] [-d FILE]

Attack Automation Tool

options:
  -h, --help        Show this help message and exit
  -t IP ADDRESSES   Filename for a file containing a list of IP addresses
  -p PORTS          Ports to scan on the target host (comma-separated)
  -u USERNAME       A username for brute-force attempts
  -f PASSWORDS      Filename for a file containing a list of passwords
  -d FILE           File to deploy on the target machine
  -L                Local scan
  -P                Enable propagation
```

## Example Usage

```sh
python3 net_attack.py -t targets.txt -p 22,23,80 -u admin -f passwords.txt -d payload.sh
```

## Disclaimer

This tool is for educational and research purposes only. Unauthorized use against any system without permission is illegal and unethical.

