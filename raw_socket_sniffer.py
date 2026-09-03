"""Basic Network Sniffer (Raw Sockets) - Task 1
Captures and unpacks IPv4, TCP, UDP, and ICMP packets using Python's standard `socket` and `struct` modules.
"""

import socket
import struct
import sys
from datetime import datetime


def format_payload(data: bytes, max_len: int = 48) -> str:
    """Returns formatted Hex and ASCII string of the payload."""
    if not data:
        return "None"
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:max_len])
    hex_str = data[:16].hex(" ")
    truncated = "..." if len(data) > max_len else ""
    return f"[Hex: {hex_str}] [ASCII: {text}{truncated}]"


def parse_ipv4(packet_bytes: bytes):
    """Parses IPv4 packet header."""
    version_ihl = packet_bytes[0]
    ihl = (version_ihl & 0xF) * 4
    ttl, proto, src, dst = struct.unpack("!8xBB2x4s4s", packet_bytes[:20])
    src_ip = socket.inet_ntoa(src)
    dst_ip = socket.inet_ntoa(dst)
    return ihl, proto, src_ip, dst_ip, packet_bytes[ihl:]


def parse_tcp(data: bytes):
    """Parses TCP header."""
    src_port, dst_port, seq, ack, offset_flags = struct.unpack("!HHLLH", data[:14])
    offset = (offset_flags >> 12) * 4
    flags = {
        "FIN": bool(offset_flags & 1),
        "SYN": bool(offset_flags & 2),
        "RST": bool(offset_flags & 4),
        "PSH": bool(offset_flags & 8),
        "ACK": bool(offset_flags & 16),
        "URG": bool(offset_flags & 32),
    }
    flag_str = ",".join(k for k, v in flags.items() if v) or "None"
    return src_port, dst_port, flag_str, data[offset:]


def parse_udp(data: bytes):
    """Parses UDP header."""
    src_port, dst_port, length = struct.unpack("!HHH2x", data[:8])
    return src_port, dst_port, data[8:]


def parse_icmp(data: bytes):
    """Parses ICMP header."""
    icmp_type, code = struct.unpack("!BB4x", data[:6])
    return icmp_type, code, data[8:]


def start_sniffer(host_ip: str = "0.0.0.0", max_packets: int = 10):
    """Starts listening on raw socket and dissects incoming packets."""
    # Determine host IP if default
    if host_ip == "0.0.0.0":
        try:
            host_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            host_ip = "127.0.0.1"

    print("=" * 75)
    print(f"[*] Raw Socket Sniffer starting on interface: {host_ip}")
    print(f"[*] Max packets: {max_packets} (Ctrl+C to stop)")
    print("=" * 75)

    # Initialize raw socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((host_ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Windows promiscuous mode ioctl
        if sys.platform == "win32":
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    except PermissionError:
        print("[!] Error: Raw sockets require Administrator / root privileges.")
        print("[!] On Windows: Open PowerShell / CMD as Administrator.")
        sys.exit(1)

    count = 0
    try:
        while max_packets == 0 or count < max_packets:
            raw_data, addr = s.recvfrom(65535)
            count += 1
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

            ihl, proto_num, src_ip, dst_ip, transport_data = parse_ipv4(raw_data)
            proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
            proto_name = proto_map.get(proto_num, f"Unknown({proto_num})")

            print(f"\n[{timestamp}] Packet #{count} | {len(raw_data)} bytes")
            print(f"  Network Layer   : IPv4 | {src_ip} -> {dst_ip}")
            print(f"  Protocol        : {proto_name}")

            payload = b""
            if proto_num == 6 and len(transport_data) >= 14:  # TCP
                sport, dport, flags, payload = parse_tcp(transport_data)
                print(f"  Transport Layer : TCP  | Port {sport} -> {dport} (Flags: {flags})")
            elif proto_num == 17 and len(transport_data) >= 8:  # UDP
                sport, dport, payload = parse_udp(transport_data)
                print(f"  Transport Layer : UDP  | Port {sport} -> {dport}")
            elif proto_num == 1 and len(transport_data) >= 8:  # ICMP
                itype, icode, payload = parse_icmp(transport_data)
                print(f"  Transport Layer : ICMP | Type: {itype}, Code: {icode}")
            else:
                payload = transport_data

            print(f"  Payload ({len(payload)}B) : {format_payload(payload)}")

    except KeyboardInterrupt:
        print("\n[!] Sniffing stopped by user.")
    finally:
        if sys.platform == "win32":
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
        s.close()


if __name__ == "__main__":
    count_arg = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 5
    start_sniffer(max_packets=count_arg)
