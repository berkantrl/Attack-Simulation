# Attack-Simulation
The net_attack.py script will automate the process of discovering weak usernames and passwords being used for services running on a host. The script will read a file containing a list of IP addresses. For each IP address in the list the script will scan the ports on that host, and attempt to bruteforce the login for detected services.

## usage
net_attack.py [-h] [-t IP ADDRESSES] [-p PORTS] [-u USERNAME] [-f PASSWORDS] [-d FİLE]

-h, --help    show this help message and exit
-t IP ADDRESSES  Filename for a file containing a list of IP addresses
-p PORTS    Ports to scan on the target host
-u USERNAME    A username
-f PASSWORDS   Filename for a file containing a list of passwords
-d File to deploy on target machine
-L Local scan
-P Propagate
