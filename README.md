# Task 1: Advanced Real-Time Network Packet Sniffer

A powerful, interactive Python-based network packet sniffer that captures, decodes, analyzes, and visualizes real-time live network traffic on Windows and Linux.

---

## 🌟 Key Features

- ⚡ **Auto-Elevation**: Automatically requests Administrator privileges and launches a dedicated console window on Windows without manual setup.
- 🎯 **Interactive Terminal Interface**: Simple interactive menu to choose protocols, apply target IP filters, and specify packet limits.
- 🔍 **Multi-Layer Protocol Dissection**:
  - **Network Layer**: IPv4 (Source/Destination IP, TTL, Header length, Protocol numbers) & ARP.
  - **Transport Layer**: TCP (Ports, Sequence/Ack numbers, Flags: SYN, ACK, FIN, RST, PSH), UDP (Ports, Length), and ICMP (Ping Echo Requests & Replies, Types & Codes).
  - **Application Layer**: Detects HTTP, HTTPS, and DNS traffic.
  - **Dual Payload View**: Full Hex dump and clean ASCII translation.
- 📊 **Real-Time Session Dashboard**: Live statistics summarizing total packets, protocol breakdown (TCP / UDP / ICMP), and total bandwidth volume.
- 💾 **PCAP Export**: Save captured packets directly to `.pcap` files for deep inspection in Wireshark.
- 🚀 **Zero-Driver Requirement**: Built using native Windows raw sockets promiscuous mode (`SIO_RCVALL`), allowing 100% real-time packet capture on Windows **without requiring external Npcap installation**!

---

## 📁 Project Structure

```
cyber security project 1/
│
├── sniffer.py              # Main interactive sniffer with auto-elevation & live capture
├── raw_socket_sniffer.py   # Low-level standard library socket & struct engine
├── run_sniffer.bat         # One-click desktop launcher for Windows
├── requirements.txt        # Dependencies (scapy, colorama)
└── README.md               # Documentation & guide
```

---

## 🚀 How to Run

### Option 1: Double-Click Launcher (Easiest)
Simply double-click **`run_sniffer.bat`** in Windows Explorer. It will launch the sniffer console immediately!

---

### Option 2: Interactive Terminal Mode
Run directly in your terminal:
```bash
python sniffer.py
```
If not already elevated, it will prompt for Windows Administrator permission and open a new real-time capture window with an interactive menu:

```text
================================================================================
              TASK 1: ADVANCED REAL-TIME NETWORK SNIFFER
================================================================================
  Active Host IP : 10.169.201.160 (Host: Lenovo)
  Privilege Level: Administrator (Elevated)
--------------------------------------------------------------------------------
  [1] Start Live Capture - All Traffic
  [2] Start Live Capture - TCP Only (Web, SSH, HTTPS)
  [3] Start Live Capture - UDP Only (DNS, Streaming)
  [4] Start Live Capture - ICMP Only (Ping Requests)
  [5] Custom Live Capture (Filter by IP, Protocol, & Limits)
  [6] Run Demonstration Mode (Simulated Packets)
  [0] Exit
================================================================================
Select an option [0-6]: 
```

You can then provide your inputs:
1. Choose protocol filter (`all`, `tcp`, `udp`, `icmp`)
2. Enter packet limit (e.g. `20` or press Enter for continuous)
3. Enter filename to save as PCAP (e.g. `capture.pcap` or press Enter to skip)

---

### Option 3: Command-Line Flags

```bash
# Capture 10 TCP packets in real-time
python sniffer.py -p tcp -c 10

# Capture only DNS / UDP traffic
python sniffer.py -p udp -c 25

# Filter for traffic to/from a specific IP address
python sniffer.py -H 8.8.8.8 -c 15

# Save 50 packets to a Wireshark-compatible PCAP file
python sniffer.py -c 50 -o capture.pcap

# Run simulated demonstration without Administrator rights
python sniffer.py --demo
```

---

## 🖥️ Real-Time Output Example

```text
--------------------------------------------------------------------------------
[#1] [00:20:31.505] TCP   | 87 bytes | TTL: 64
  Network Layer   : IPv4 | 10.169.201.160 -> 93.184.216.34
  Transport Layer : TCP  | Port 52140 -> 80 (HTTP) | Flags: [PA] | Seq: 19823412
  Payload (47B) : [Hex: 47 45 54 20 2f 69 6e 64 65 78 2e 68 74 6d 6c 20] [ASCII: GET /index.html HTTP/1.1..Host: example.com....]
--------------------------------------------------------------------------------
[#2] [00:20:31.505] UDP   | 56 bytes | TTL: 64
  Network Layer   : IPv4 | 10.169.201.160 -> 8.8.8.8
  Transport Layer : UDP  | Port 55321 -> 53 (DNS) | Length: 36
  Payload (28B) : [Hex: 12 34 01 00 00 01 00 00 00 00 00 00 06 67 6f 6f] [ASCII: .4...........google.com.....]
--------------------------------------------------------------------------------
[#3] [00:20:31.506] ICMP  | 60 bytes | TTL: 64
  Network Layer   : IPv4 | 192.168.1.1 -> 10.169.201.160
  Transport Layer : ICMP | Echo Reply (Type: 0, Code: 0)
  Payload (32B) : [Hex: 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70] [ASCII: abcdefghijklmnopqrstuvwabcdefghi]

================================================================================
                    CAPTURE SESSION SUMMARY
================================================================================
  Total Packets Captured : 20
  TCP Packets            : 14
  UDP Packets            : 5
  ICMP Packets           : 1
  Other Protocols        : 0
  Total Volume           : 12.45 KB (12748 bytes)
================================================================================
```
