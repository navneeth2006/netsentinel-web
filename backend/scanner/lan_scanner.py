# LAN discovery using two methods:
# 1) quick TCP connect sweep on given subnet (fast, requires no raw sockets)
# 2) optional ARP scan using scapy if available and user has permissions

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def is_host_up(addr, timeout=0.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        res = s.connect_ex((str(addr), 80))  # try common port quickly
        s.close()
        return res == 0
    except Exception:
        return False

def sweep_subnet_tcp(subnet_cidr, max_workers=80):
    """Non-privileged sweep: try connecting to port 80 to guess live hosts."""
    net = ipaddress.ip_network(subnet_cidr, strict=False)
    live = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(is_host_up, ip): ip for ip in net.hosts()}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                if fut.result():
                    live.append(str(ip))
            except Exception:
                continue
    return live

# Optional ARP method using scapy
def arp_scan(subnet_cidr):
    try:
        from scapy.all import ARP, Ether, srp, conf
    except Exception:
        return {"error":"scapy_not_available_or_privileges_required"}
    conf.verb = 0
    arp = ARP(pdst=subnet_cidr)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    ans, _ = srp(packet, timeout=2, retry=1)
    hosts = []
    for sent, received in ans:
        hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
    return hosts
