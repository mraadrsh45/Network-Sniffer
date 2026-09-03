<div align="center">

# 🌐 Advanced Real-Time Network Packet Sniffer
### Task 1: Cyber Security Internship Project

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)
![Cyber Security](https://img.shields.io/badge/domain-Network%20Security-red.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active%20%2F%20verified-brightgreen.svg)

<p align="center">
  A high-performance, interactive Python network packet sniffer designed for real-time packet capture, multi-layer protocol dissection, payload inspection, and network security diagnostics.
</p>

[Key Features](#-key-features) •
[Network Architecture](#-network-protocol-architecture) •
[Installation](#-installation--prerequisites) •
[Usage Guide](#-usage-guide) •
[Sample Output](#-sample-output) •
[Security Insights](#-security--educational-insights)

</div>

---

## 🎯 Task Objectives

This project fulfills **Task 1: Basic Network Sniffer** with enterprise-grade enhancements:
- **Packet Capture**: Intercept live incoming and outgoing packets from local network adapters.
- **Protocol Analysis**: Decode and unpack headers across the OSI and TCP/IP stack.
- **Network Data Flow**: Analyze how data moves between endpoints across network and transport layers.
- **Dual Engine Implementation**: Implemented with both **`scapy`** and Python standard library **`socket` + `struct`**.
- **Data Inspection**: Extract source/destination IP addresses, protocol types, port numbers, flags, and payload contents in dual Hex/ASCII format.

---

## 🌟 Key Features

| Feature | Description |
|---|---|
| ⚡ **Auto-Elevation (UAC)** | Automatically requests Windows Administrator elevation and launches an elevated terminal window seamlessly. |
| 🚀 **Zero External Drivers** | Captures real-time packets using native Windows raw sockets promiscuous mode (`SIO_RCVALL`) — **no Npcap/WinPcap installation required**! |
| 🖥️ **Interactive Menu Interface** | User-friendly interactive terminal menu allowing live input, protocol selection, target IP filters, and packet limits. |
| 🔍 **Multi-Layer Dissection** | Parses IPv4, ARP, TCP (with flags & sequence numbers), UDP, and ICMP (Echo Requests & Replies). |
| 🛡️ **Application Detection** | Identifies common protocols including **HTTP (Port 80)**, **HTTPS (Port 443)**, and **DNS (Port 53)**. |
| 📊 **Dual Payload Inspector** | Visualizes packet payloads with side-by-side Hexadecimal dump and sanitized ASCII text view. |
| 📈 **Live Session Dashboard** | Displays real-time summary statistics: total packets, protocol breakdown, and data volume transferred. |
| 💾 **PCAP Export** | Exports captured traffic to standard `.pcap` files, fully compatible with Wireshark. |
| 🧪 **Demonstration Mode** | Includes `--demo` mode to simulate and dissect traffic immediately without requiring administrative privileges. |

---

## 🧠 Network Protocol Architecture

Data traverses multiple layers of the TCP/IP stack. The sniffer reconstructs each layer in real time:

```
+-----------------------------------------------------------------------+
|  LAYER 2: DATA LINK (Ethernet / ARP)                                  |
|  [Hardware Types, MAC Addresses: Source -> Destination]               |
+-----------------------------------------------------------------------+
                                  │
                                  ▼
+-----------------------------------------------------------------------+
|  LAYER 3: NETWORK (IPv4)                                              |
|  [Version, Header Length (IHL), TTL, Protocol ID, Source IP -> Dest IP]|
+-----------------------------------------------------------------------+
                                  │
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
+-------------------+    +-------------------+    +-------------------+
|  LAYER 4: TCP     |    |  LAYER 4: UDP     |    |  LAYER 4: ICMP    |
|  Ports: Src -> Dst|    |  Ports: Src -> Dst|    |  Type, Code       |
|  Seq, Ack, Flags  |    |  Packet Length    |    |  Echo Req / Reply |
|  [SYN,ACK,PSH,FIN]|    |  Checksum         |    |  Checksum         |
+-------------------+    +-------------------+    +-------------------+
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  ▼
+-----------------------------------------------------------------------+
|  LAYER 7: APPLICATION & PAYLOAD                                       |
|  [HTTP GET/POST, DNS Queries, Encrypted TLS, Hex Dump + ASCII String] |
+-----------------------------------------------------------------------+
```

---

## 📁 Repository Structure

```text
Network-Sniffer/
│
├── sniffer.py              # Main interactive packet sniffer (Auto-elevation & live capture)
├── raw_socket_sniffer.py   # Low-level standard library socket & struct dissection engine
├── run_sniffer.bat         # One-click Windows desktop launcher with automatic elevation
├── requirements.txt        # Python library dependencies (scapy, colorama)
├── .gitignore              # Ignores bytecode, PCAP dumps, and editor caches
└── README.md               # Comprehensive documentation and protocol analysis
```

---

## 💻 Installation & Prerequisites

### 1. Requirements
- **Operating System**: Windows 10/11 or Linux
- **Python**: Version 3.8 or newer (Python 3.13 tested)

### 2. Install Dependencies
Clone the repository and install required packages:
```bash
git clone https://github.com/mraadrsh45/Network-Sniffer.git
cd Network-Sniffer
pip install -r requirements.txt
```

---

## 🚀 Usage Guide

### Method 1: One-Click Desktop Launcher *(Easiest on Windows)*
Double-click **`run_sniffer.bat`** from Windows Explorer.
1. The Windows UAC prompt will appear asking for Administrator permission.
2. Click **Yes**.
3. A dedicated terminal window will open with the interactive menu ready to capture live traffic!

---

### Method 2: Interactive Terminal Menu
Run the main script in your terminal:
```bash
python sniffer.py
```
If your terminal is not running as Administrator, `sniffer.py` will automatically request elevation and launch the interactive sniffer window:

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

#### User Input Prompts:
- **Select Option**: Pick a protocol category (`1` - `6`).
- **Packet Limit**: Enter number of packets (e.g., `20`), or press Enter for continuous stream.
- **Export to PCAP**: Enter filename (e.g., `capture.pcap`), or press Enter to skip.

---

### Method 3: Command-Line Flags
For power users and scripting, execute directly with arguments:

```bash
# Capture 25 TCP packets
python sniffer.py -p tcp -c 25

# Capture only DNS and streaming traffic (UDP)
python sniffer.py -p udp -c 10

# Filter traffic for a specific target host IP
python sniffer.py -H 8.8.8.8 -c 15

# Capture 50 packets and export to Wireshark PCAP
python sniffer.py -c 50 -o live_capture.pcap

# Run demonstration mode without requiring Administrator rights
python sniffer.py --demo
```

---

### Method 4: Low-Level Raw Socket Engine
To inspect packet dissection using pure standard library (`socket` and `struct` with 0 external dependencies):

```bash
# In an Administrator terminal:
python raw_socket_sniffer.py 20
```

---

## 🖥️ Sample Output

### 1. Live Packet Stream

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
```

### 2. Session Summary Dashboard

```text
================================================================================
                    CAPTURE SESSION SUMMARY
================================================================================
  Total Packets Captured : 25
  TCP Packets            : 18
  UDP Packets            : 6
  ICMP Packets           : 1
  Other Protocols        : 0
  Total Volume           : 16.82 KB (17228 bytes)
================================================================================
[+] Successfully saved 25 packets to live_capture.pcap
```

---

## 🔒 Security & Educational Insights

1. **Promiscuous Mode & Raw Sockets**:
   - By default, network interface cards (NICs) only pass frames addressed to their own MAC/IP address up the stack.
   - Enabling promiscuous mode (`SIO_RCVALL`) configures the NIC to capture all passing packets on the local network segment.
2. **Cleartext vs. Encrypted Traffic**:
   - Unencrypted protocols like **HTTP (Port 80)**, **Telnet (Port 23)**, and **FTP (Port 21)** expose raw data and credentials directly in the packet payload.
   - Modern protocols like **HTTPS (TLS / Port 443)** protect payload confidentiality, allowing sniffer tools to see only packet metadata (IPs, Ports, Packet Sizes, and Timing) while securing the actual data.
3. **Defense in Depth**:
   - Packet sniffers are foundational tools for security operations, used to detect port scans (SYN floods, null scans), verify firewall policies, investigate malicious beaconing, and troubleshoot network bottlenecks.

---

## ⚠️ Legal & Ethical Disclaimer

> **Note**: This tool was developed strictly for educational, security analysis, and network diagnostic purposes as part of a cyber security internship assignment. Sniffing network packets on unauthorized networks without prior permission is illegal and violates privacy policies. Only run packet sniffers on networks and systems you own or have explicit authorization to monitor.

---

## 📄 License
This project is licensed under the MIT License — free for educational and personal use.
