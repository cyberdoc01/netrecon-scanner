import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = [80, 443, 22]  # HTTP, HTTPS, SSH
TIMEOUT = 1


def is_host_alive(ip):
    import os

    # Try ping first
    response = os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1")
    if response == 0:
        return True

    # Try common ports
    for port in COMMON_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((str(ip), port))
            sock.close()

            if result == 0:
                return True
        except:
            pass

    return False

def scan_network(network):
    print(f"[+] Scanning network: {network}")

    live_hosts = []
    net = ipaddress.ip_network(network, strict=False)

    def scan_ip(ip):
        if is_host_alive(ip):
            print(f"[+] Host found: {ip}")
            live_hosts.append(str(ip))

    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(scan_ip, net.hosts())

    return live_hosts


def display_results(hosts):
    print("\n[+] Live Hosts:\n")
    for host in hosts:
        print(host)


if __name__ == "__main__":
    network = input("Enter network (e.g. 192.168.1.0/24): ")

    try:
        ipaddress.ip_network(network)
    except ValueError:
        print("[-] Invalid network format")
        exit()

    hosts = scan_network(network)
    display_results(hosts)
