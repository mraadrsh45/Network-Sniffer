"""Ultimate Network Packet Sniffer - Task 1
Captures real-time live network traffic on Windows/Linux with automatic elevation,
protocol dissection (IPv4, TCP, UDP, ICMP), payload inspection, and interactive controls.
"""

import argparse
import ctypes
import logging
import os
import socket
import struct
import sys
from datetime import datetime

# Suppress scapy warnings if scapy is imported
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        GREEN = CYAN = YELLOW = RED = MAGENTA = WHITE = BLUE = ""
    class Style:
        BRIGHT = RESET_ALL = ""

# Try importing scapy wrpcap and IP for PCAP export
try:
    from scapy.all import IP as ScapyIP, Ether as ScapyEther, wrpcap
    HAS_SCAPY_PCAP = True
except ImportError:
    HAS_SCAPY_PCAP = False


def is_admin() -> bool:
    """Checks whether the script is running with administrative privileges."""
    if sys.platform == "win32":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.getuid() == 0


def elevate_process() -> bool:
    """Relaunches the current script in an elevated Administrator console window."""
    if sys.platform == "win32":
        params = " ".join(f'"{arg}"' for arg in sys.argv[1:])
        script = os.path.abspath(sys.argv[0])
        # ShellExecute with 'runas' prompts Windows UAC dialog
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1
        )
        return result > 32
    return False


def get_active_ip() -> str:
    """Detects the primary active local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def format_hex_ascii(payload: bytes, max_len: int = 64) -> str:
    """Returns dual hex and ASCII representation of packet payload."""
    if not payload:
        return "None"
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in payload[:max_len])
    hex_str = payload[:16].hex(" ")
    truncated = "..." if len(payload) > max_len else ""
    return f"{Fore.MAGENTA}[Hex: {hex_str}] [ASCII: {text}{truncated}]{Style.RESET_ALL}"


def parse_ipv4(packet_bytes: bytes):
    """Dissects the IPv4 header."""
    version_ihl = packet_bytes[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4
    ttl, proto, src, dst = struct.unpack("!8xBB2x4s4s", packet_bytes[:20])
    src_ip = socket.inet_ntoa(src)
    dst_ip = socket.inet_ntoa(dst)
    return version, ihl, ttl, proto, src_ip, dst_ip, packet_bytes[ihl:]


def parse_tcp(data: bytes):
    """Dissects TCP header and extracts ports and flags."""
    src_port, dst_port, seq, ack, offset_flags = struct.unpack("!HHLLH", data[:14])
    offset = (offset_flags >> 12) * 4
    flags = []
    if offset_flags & 0x01: flags.append("FIN")
    if offset_flags & 0x02: flags.append("SYN")
    if offset_flags & 0x04: flags.append("RST")
    if offset_flags & 0x08: flags.append("PSH")
    if offset_flags & 0x10: flags.append("ACK")
    if offset_flags & 0x20: flags.append("URG")
    flag_str = ",".join(flags) if flags else "NONE"
    return src_port, dst_port, seq, ack, flag_str, data[offset:]


def parse_udp(data: bytes):
    """Dissects UDP header."""
    src_port, dst_port, length = struct.unpack("!HHH2x", data[:8])
    return src_port, dst_port, length, data[8:]


def parse_icmp(data: bytes):
    """Dissects ICMP header."""
    icmp_type, code, checksum = struct.unpack("!BBH", data[:4])
    type_names = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request (Ping)", 11: "Time Exceeded"}
    desc = type_names.get(icmp_type, f"Type {icmp_type}")
    return icmp_type, code, desc, data[8:]


def run_live_sniffer(host_ip: str, proto_filter: str = "all", target_host: str = "", max_packets: int = 0, pcap_file: str = ""):
    """Captures real-time live network packets using native raw sockets."""
    print("\n" + "=" * 80)
    print(f"{Fore.GREEN}{Style.BRIGHT}                 REAL-TIME LIVE NETWORK SNIFFER{Style.RESET_ALL}")
    print("=" * 80)
    print(f"[*] Bound Interface : {Fore.CYAN}{host_ip}{Style.RESET_ALL} (Hostname: {socket.gethostname()})")
    print(f"[*] Protocol Filter : {Fore.YELLOW}{proto_filter.upper()}{Style.RESET_ALL}")
    if target_host:
        print(f"[*] Target Host     : {Fore.YELLOW}{target_host}{Style.RESET_ALL}")
    print(f"[*] Packet Limit    : {Fore.YELLOW}{max_packets if max_packets > 0 else 'Continuous (Press Ctrl+C to stop)'}{Style.RESET_ALL}")
    if pcap_file:
        print(f"[*] PCAP Output     : {Fore.YELLOW}{pcap_file}{Style.RESET_ALL}")
    print("=" * 80)
    print("[*] Listening for live incoming and outgoing packets...\n")

    # Initialize raw socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((host_ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        if sys.platform == "win32":
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except PermissionError:
        print(f"{Fore.RED}[!] Error: Raw sockets require Administrator privileges.{Style.RESET_ALL}")
        return
    except Exception as e:
        print(f"{Fore.RED}[!] Socket Bind Error: {e}{Style.RESET_ALL}")
        return

    stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0, "bytes": 0}
    saved_packets = []

    try:
        while max_packets == 0 or stats["total"] < max_packets:
            raw_data, _ = s.recvfrom(65535)
            stats["bytes"] += len(raw_data)
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

            version, ihl, ttl, proto_num, src_ip, dst_ip, transport_data = parse_ipv4(raw_data)

            # Protocol matching
            proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
            proto_name = proto_map.get(proto_num, f"PROTO-{proto_num}")

            if proto_filter.lower() != "all" and proto_name.lower() != proto_filter.lower():
                continue

            # Host filter matching
            if target_host and target_host not in (src_ip, dst_ip):
                continue

            stats["total"] += 1
            if proto_num == 6: stats["tcp"] += 1
            elif proto_num == 17: stats["udp"] += 1
            elif proto_num == 1: stats["icmp"] += 1
            else: stats["other"] += 1

            # Prepare for PCAP if requested
            if pcap_file and HAS_SCAPY_PCAP:
                try:
                    saved_packets.append(ScapyEther() / ScapyIP(raw_data))
                except Exception:
                    pass

            # Output packet display
            color = Fore.GREEN if proto_name == "TCP" else (Fore.CYAN if proto_name == "UDP" else Fore.YELLOW)
            print("-" * 80)
            print(f"{Fore.WHITE}{Style.BRIGHT}[#{stats['total']}] [{timestamp}] {color}{proto_name:<5}{Style.RESET_ALL} | {len(raw_data)} bytes | TTL: {ttl}")
            print(f"  Network Layer   : IPv4 | {Fore.BLUE}{src_ip}{Style.RESET_ALL} -> {Fore.BLUE}{dst_ip}{Style.RESET_ALL}")

            payload = b""
            if proto_num == 6 and len(transport_data) >= 14:  # TCP
                sport, dport, seq, ack, flags, payload = parse_tcp(transport_data)
                # Detect common services
                svc = " (HTTP)" if 80 in (sport, dport) else (" (HTTPS)" if 443 in (sport, dport) else "")
                print(f"  Transport Layer : {color}TCP{Style.RESET_ALL}  | Port {sport} -> {dport}{svc} | Flags: [{flags}] | Seq: {seq}")
            elif proto_num == 17 and len(transport_data) >= 8:  # UDP
                sport, dport, ulen, payload = parse_udp(transport_data)
                svc = " (DNS)" if 53 in (sport, dport) else ""
                print(f"  Transport Layer : {color}UDP{Style.RESET_ALL}  | Port {sport} -> {dport}{svc} | Length: {ulen}")
            elif proto_num == 1 and len(transport_data) >= 4:  # ICMP
                itype, icode, desc, payload = parse_icmp(transport_data)
                print(f"  Transport Layer : {color}ICMP{Style.RESET_ALL} | {desc} (Type: {itype}, Code: {icode})")
            else:
                payload = transport_data

            print(f"  Payload ({len(payload)}B) : {format_hex_ascii(payload)}")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Sniffing stopped by user.{Style.RESET_ALL}")
    finally:
        if sys.platform == "win32":
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
        s.close()

    # Session Summary Dashboard
    print("\n" + "=" * 80)
    print(f"{Fore.GREEN}{Style.BRIGHT}                    CAPTURE SESSION SUMMARY{Style.RESET_ALL}")
    print("=" * 80)
    print(f"  Total Packets Captured : {Fore.WHITE}{Style.BRIGHT}{stats['total']}{Style.RESET_ALL}")
    print(f"  TCP Packets            : {Fore.GREEN}{stats['tcp']}{Style.RESET_ALL}")
    print(f"  UDP Packets            : {Fore.CYAN}{stats['udp']}{Style.RESET_ALL}")
    print(f"  ICMP Packets           : {Fore.YELLOW}{stats['icmp']}{Style.RESET_ALL}")
    print(f"  Other Protocols        : {stats['other']}")
    print(f"  Total Volume           : {stats['bytes'] / 1024:.2f} KB ({stats['bytes']} bytes)")
    print("=" * 80)

    if pcap_file and saved_packets:
        try:
            wrpcap(pcap_file, saved_packets)
            print(f"{Fore.GREEN}[+] Successfully saved {len(saved_packets)} packets to {pcap_file}{Style.RESET_ALL}")
        except Exception as err:
            print(f"{Fore.RED}[!] Could not save PCAP: {err}{Style.RESET_ALL}")


def run_demo():
    """Demonstrates packet analysis using simulated packets."""
    print("\n" + "=" * 80)
    print(f"{Fore.CYAN}{Style.BRIGHT}             DEMONSTRATION MODE (SIMULATED TRAFFIC){Style.RESET_ALL}")
    print("=" * 80)
    from scapy.all import IP, TCP, UDP, ICMP, ARP, Raw

    samples = [
        IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=52140, dport=80, flags="PA") / Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=55321, dport=53) / Raw(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"),
        IP(src="192.168.1.1", dst="192.168.1.10") / ICMP(type=0, code=0) / Raw(b"abcdefghijklmnopqrstuvwabcdefghi"),
        ARP(op=1, psrc="192.168.1.1", pdst="192.168.1.10"),
    ]

    for idx, pkt in enumerate(samples, 1):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print("-" * 80)
        if pkt.haslayer(IP):
            ip = pkt[IP]
            proto = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "ICMP")
            color = Fore.GREEN if proto == "TCP" else (Fore.CYAN if proto == "UDP" else Fore.YELLOW)
            print(f"{Fore.WHITE}{Style.BRIGHT}[#{idx}] [{timestamp}] {color}{proto:<5}{Style.RESET_ALL} | {len(pkt)} bytes")
            print(f"  Network Layer   : IPv4 | {ip.src} -> {ip.dst}")
            if pkt.haslayer(TCP):
                t = pkt[TCP]
                print(f"  Transport Layer : TCP  | Port {t.sport} -> {t.dport} | Flags: [{t.flags}]")
            elif pkt.haslayer(UDP):
                u = pkt[UDP]
                print(f"  Transport Layer : UDP  | Port {u.sport} -> {u.dport}")
            elif pkt.haslayer(ICMP):
                print(f"  Transport Layer : ICMP | Echo Reply (Type: 0, Code: 0)")
        elif pkt.haslayer(ARP):
            print(f"{Fore.WHITE}{Style.BRIGHT}[#{idx}] [{timestamp}] {Fore.MAGENTA}ARP  {Style.RESET_ALL} | {len(pkt)} bytes")
            print(f"  Network Layer   : ARP Request (Who has 192.168.1.10? Tell 192.168.1.1)")

        if pkt.haslayer(Raw):
            load = pkt[Raw].load
            print(f"  Payload ({len(load)}B) : {format_hex_ascii(load)}")
        else:
            print("  Payload         : None")

    print("=" * 80)
    print(f"{Fore.GREEN}[+] Demo complete! Successfully dissected all 4 packet types.{Style.RESET_ALL}")


def interactive_menu(active_ip: str):
    """Interactive CLI menu allowing the user to provide inputs and control capture."""
    while True:
        print("\n" + "=" * 80)
        print(f"{Fore.GREEN}{Style.BRIGHT}              TASK 1: ADVANCED REAL-TIME NETWORK SNIFFER{Style.RESET_ALL}")
        print("=" * 80)
        print(f"  Active Host IP : {Fore.CYAN}{active_ip}{Style.RESET_ALL} (Host: {socket.gethostname()})")
        print(f"  Privilege Level: {Fore.GREEN if is_admin() else Fore.YELLOW}{'Administrator (Elevated)' if is_admin() else 'Standard User'}{Style.RESET_ALL}")
        print("-" * 80)
        print("  [1] Start Live Capture - All Traffic")
        print("  [2] Start Live Capture - TCP Only (Web, SSH, HTTPS)")
        print("  [3] Start Live Capture - UDP Only (DNS, Streaming)")
        print("  [4] Start Live Capture - ICMP Only (Ping Requests)")
        print("  [5] Custom Live Capture (Filter by IP, Protocol, & Limits)")
        print("  [6] Run Demonstration Mode (Simulated Packets)")
        print("  [0] Exit")
        print("=" * 80)

        choice = input(f"{Fore.WHITE}{Style.BRIGHT}Select an option [0-6]: {Style.RESET_ALL}").strip()

        if choice == "0":
            print("\nExiting Network Sniffer. Goodbye!")
            sys.exit(0)

        if choice == "6":
            run_demo()
            input(f"\n{Fore.CYAN}Press Enter to return to menu...{Style.RESET_ALL}")
            continue

        if choice in ("1", "2", "3", "4", "5"):
            if not is_admin():
                print(f"\n{Fore.YELLOW}[*] Live packet sniffing requires Administrator privileges.{Style.RESET_ALL}")
                print(f"[*] Requesting Administrator elevation window...")
                if elevate_process():
                    print(f"{Fore.GREEN}[+] Opened live sniffer in Administrator terminal!{Style.RESET_ALL}")
                    sys.exit(0)
                else:
                    print(f"{Fore.RED}[!] Elevation declined or unavailable.{Style.RESET_ALL}")
                    print(f"[*] Tip: Run PowerShell / CMD as Administrator, or choose [6] for Demo mode.")
                    input("\nPress Enter to continue...")
                    continue

            # Elevated options
            proto = "all"
            target_ip = ""
            count = 20
            pcap = ""

            if choice == "2": proto = "tcp"
            elif choice == "3": proto = "udp"
            elif choice == "4": proto = "icmp"
            elif choice == "5":
                p_in = input("Enter protocol filter (all/tcp/udp/icmp) [all]: ").strip().lower()
                if p_in in ("all", "tcp", "udp", "icmp"): proto = p_in
                target_ip = input("Enter target IP filter (leave empty for any): ").strip()

            c_in = input(f"Enter packet limit (e.g. 20, or 0 for continuous) [20]: ").strip()
            if c_in.isdigit():
                count = int(c_in)

            save_in = input("Save capture to PCAP file? (Enter filename like capture.pcap, or press Enter to skip): ").strip()
            if save_in:
                pcap = save_in if save_in.endswith(".pcap") else f"{save_in}.pcap"

            run_live_sniffer(host_ip=active_ip, proto_filter=proto, target_host=target_ip, max_packets=count, pcap_file=pcap)
            input(f"\n{Fore.CYAN}Press Enter to return to menu...{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(description="Task 1: Advanced Network Packet Sniffer")
    parser.add_argument("-p", "--protocol", choices=["all", "tcp", "udp", "icmp"], default="all", help="Protocol filter")
    parser.add_argument("-c", "--count", type=int, default=0, help="Packet capture limit (0 = continuous)")
    parser.add_argument("-H", "--host", type=str, default="", help="Filter traffic by target IP address")
    parser.add_argument("-o", "--output", type=str, default="", help="Save captured packets to a .pcap file")
    parser.add_argument("--demo", action="store_true", help="Run simulated demonstration")
    parser.add_argument("--no-elevate", action="store_true", help="Do not attempt automatic elevation")

    args = parser.parse_args()
    active_ip = get_active_ip()

    if args.demo:
        run_demo()
        return

    # If specific CLI flags were provided, execute directly
    if args.count > 0 or args.protocol != "all" or args.host or args.output:
        if not is_admin() and not args.no_elevate:
            print(f"{Fore.YELLOW}[*] Live packet capture requires Administrator rights.{Style.RESET_ALL}")
            print("[*] Launching elevated console window...")
            if elevate_process():
                print(f"{Fore.GREEN}[+] Launched in Administrator window.{Style.RESET_ALL}")
                sys.exit(0)
            else:
                print(f"{Fore.RED}[!] Could not elevate. Running in demo mode:{Style.RESET_ALL}")
                run_demo()
                return

        run_live_sniffer(host_ip=active_ip, proto_filter=args.protocol, target_host=args.host, max_packets=args.count, pcap_file=args.output)
        if is_admin():
            input(f"\n{Fore.CYAN}Press Enter to exit...{Style.RESET_ALL}")
        return

    # Otherwise, open interactive menu
    interactive_menu(active_ip)


if __name__ == "__main__":
    main()
