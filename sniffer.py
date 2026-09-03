import argparse
import logging
import sys
from datetime import datetime

# Suppress scapy loading & runtime warnings
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, Raw, sniff, wrpcap


def format_payload(payload_bytes: bytes, max_len: int = 64) -> str:
    """Returns a readable ASCII/hex representation of the payload."""
    if not payload_bytes:
        return "None"
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in payload_bytes[:max_len])
    hex_str = payload_bytes[:16].hex(" ")
    truncated = "..." if len(payload_bytes) > max_len else ""
    return f"[Hex: {hex_str}] [ASCII: {text}{truncated}]"


def packet_handler(packet, output_list=None):
    """Parses and prints key packet details: IPs, protocol, ports, payload."""
    if output_list is not None:
        output_list.append(packet)

    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print("=" * 75)
    print(f"[{timestamp}] Packet Captured - Length: {len(packet)} bytes")

    # Layer 3 / Network Layer
    if packet.haslayer(IP):
        ip = packet[IP]
        src_ip, dst_ip, proto_num = ip.src, ip.dst, ip.proto
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, f"Proto({proto_num})")
        print(f"  Network Layer   : IPv4 | {src_ip} -> {dst_ip}")
        print(f"  Protocol        : {proto_name} (TTL: {ip.ttl})")

        # Layer 4 / Transport Layer
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = str(tcp.flags)
            print(f"  Transport Layer : TCP  | Port {tcp.sport} -> {tcp.dport} (Flags: {flags})")
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print(f"  Transport Layer : UDP  | Port {udp.sport} -> {udp.dport}")
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            print(f"  Transport Layer : ICMP | Type {icmp.type} (Code: {icmp.code})")

    elif packet.haslayer(ARP):
        arp = packet[ARP]
        op = "Request (Who has?)" if arp.op == 1 else "Reply"
        print(f"  Network Layer   : ARP  | {op} {arp.psrc} -> {arp.pdst}")
    else:
        print(f"  Network Layer   : {packet.summary()}")

    # Payload / Application Data
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        print(f"  Payload ({len(payload)}B) : {format_payload(payload)}")
    else:
        print("  Payload         : None")


def run_demo(output_file: str = ""):
    """Generates synthetic packets to demonstrate dissection without admin rights."""
    print("\n[*] Running in DEMO MODE (generating sample packets for analysis)...")
    sample_packets = [
        Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=52140, dport=80, flags="PA") / Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=55321, dport=53) / Raw(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"),
        Ether() / IP(src="192.168.1.1", dst="192.168.1.10") / ICMP(type=0, code=0) / Raw(b"abcdefghijklmnopqrstuvwabcdefghi"),
        Ether() / ARP(op=1, psrc="192.168.1.1", pdst="192.168.1.10"),
    ]
    for pkt in sample_packets:
        packet_handler(pkt)
    print("=" * 75)
    print("[+] Demo complete! Dissected 4 packet types (HTTP/TCP, DNS/UDP, Ping/ICMP, ARP).")
    if output_file:
        wrpcap(output_file, sample_packets)
        print(f"[+] Saved demo packets to {output_file}")


def build_bpf_filter(protocol: str, host: str) -> str:
    """Builds a Berkeley Packet Filter (BPF) string from arguments."""
    filters = []
    if protocol and protocol.lower() != "all":
        filters.append(protocol.lower())
    if host:
        filters.append(f"host {host}")
    return " and ".join(filters)


def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer - Task 1")
    parser.add_argument("-p", "--protocol", choices=["all", "tcp", "udp", "icmp", "arp"], default="all", help="Protocol filter")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = continuous)")
    parser.add_argument("-H", "--host", type=str, default="", help="Filter traffic by target IP address")
    parser.add_argument("-o", "--output", type=str, default="", help="Save captured packets to a .pcap file")
    parser.add_argument("--demo", action="store_true", help="Run packet analysis on simulated packets (no admin required)")

    args = parser.parse_args()

    if args.demo:
        run_demo(args.output)
        return

    bpf_filter = build_bpf_filter(args.protocol, args.host)
    captured_packets = [] if args.output else None

    print("\n" + "=" * 75)
    print("               BASIC NETWORK SNIFFER")
    print("=" * 75)
    print(f"[*] Filter: {bpf_filter or 'All traffic'}")
    print(f"[*] Packet count limit: {args.count if args.count > 0 else 'Unlimited (Press Ctrl+C to stop)'}")
    if args.output:
        print(f"[*] Output file: {args.output}")
    print("[*] Starting live packet capture...\n")

    try:
        sniff(
            filter=bpf_filter,
            prn=lambda pkt: packet_handler(pkt, captured_packets),
            count=args.count,
            store=bool(args.output),
        )
    except KeyboardInterrupt:
        print("\n[!] Sniffing stopped by user.")
    except (PermissionError, OSError, RuntimeError) as e:
        print(f"\n[!] Live capture unavailable without Admin / Npcap ({e.__class__.__name__}).")
        print("[*] Automatically falling back to DEMO MODE to demonstrate packet dissection:\n")
        run_demo(args.output)
        print("\n[*] Note: To sniff LIVE traffic, open PowerShell / CMD as Administrator with Npcap installed.")

    if args.output and captured_packets:
        wrpcap(args.output, captured_packets)
        print(f"[+] Saved {len(captured_packets)} packets to {args.output}")


if __name__ == "__main__":
    main()
