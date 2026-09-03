# Task 1: Basic Network Sniffer

A Python-based network packet sniffer that captures, decodes, and analyzes live network traffic in real time.

---

## 🎯 Objectives
- **Capture network traffic packets** across network interfaces.
- **Analyze captured packets** to understand headers, protocols, and data payloads.
- **Understand how data flows** across layers (Network -> Transport -> Application).
- Implement sniffing using both **`scapy`** and standard library **`socket`**.
- Display clear information: **Source/Destination IPs, Protocols, Port numbers, and Payloads**.

---

## 📁 Project Structure

```
cyber security project 1/
│
├── sniffer.py              # Primary sniffer using Scapy (supports filtering, PCAP export & demo mode)
├── raw_socket_sniffer.py   # Low-level sniffer using standard library socket & struct
├── requirements.txt        # Dependencies
└── README.md               # Documentation and protocol guide
```

---

## 🧠 How Network Packets Work

Data flows across layers of the OSI/TCP-IP model:

| Layer | Protocol | Key Fields Extracted |
|---|---|---|
| **Layer 2 (Data Link)** | Ethernet / ARP | MAC Addresses, Hardware Types |
| **Layer 3 (Network)** | IPv4, IPv6 | Source IP, Destination IP, TTL, Protocol ID |
| **Layer 4 (Transport)** | TCP, UDP, ICMP | Source Port, Destination Port, TCP Flags (SYN, ACK, PSH, FIN), ICMP Type |
| **Layer 7 (Application)** | HTTP, DNS, Raw | Text / Binary Payload, Hex & ASCII representation |

---

## 🚀 Installation & Prerequisites

1. **Python 3.8+** (Python 3.13 tested)
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   *(Note: `raw_socket_sniffer.py` uses only Python standard libraries with 0 external dependencies!)*

3. **Administrator Privileges**:
   - **Windows**: Capturing raw network packets requires running PowerShell or Command Prompt as **Administrator**.
   - **Linux / macOS**: Run with `sudo` (e.g., `sudo python sniffer.py`).
   - If Npcap is installed on Windows, make sure "WinPcap API-compatible mode" is enabled.

---

## 💻 Usage

### 1. Using `sniffer.py` (Recommended - Scapy)

#### Run Demo Mode (No Administrator rights required!)
Quickly test and verify packet parsing with simulated realistic HTTP, DNS, Ping, and ARP packets:
```bash
python sniffer.py --demo
```

#### Live Continuous Sniffing (Requires Administrator)
```bash
python sniffer.py
```

#### Capture a Specific Number of Packets
```bash
python sniffer.py -c 10
```

#### Filter by Protocol (`tcp`, `udp`, `icmp`, `arp`)
```bash
# Sniff only TCP packets
python sniffer.py -p tcp

# Sniff only ICMP (ping) packets
python sniffer.py -p icmp
```

#### Filter by Target Host IP
```bash
python sniffer.py -H 8.8.8.8
```

#### Save Captured Packets to a PCAP File (Wireshark compatible)
```bash
python sniffer.py -c 20 -o capture.pcap
```

---

### 2. Using `raw_socket_sniffer.py` (Pure Python `socket` & `struct`)

Demonstrates low-level packet unpacking using Python's native `socket` and `struct` libraries:

```bash
# Run with default 5 packets (in Administrator PowerShell/CMD)
python raw_socket_sniffer.py

# Specify packet count
python raw_socket_sniffer.py 20
```

---

## 🖥️ Sample Output

```text
===========================================================================
[23:36:11.359] Packet Captured - Length: 87 bytes
  Network Layer   : IPv4 | 192.168.1.10 -> 93.184.216.34
  Protocol        : TCP (TTL: 64)
  Transport Layer : TCP  | Port 52140 -> 80 (Flags: PA)
  Payload (47B) : [Hex: 47 45 54 20 2f 69 6e 64 65 78 2e 68 74 6d 6c 20] [ASCII: GET /index.html HTTP/1.1..Host: example.com....]
===========================================================================
[23:36:11.361] Packet Captured - Length: 56 bytes
  Network Layer   : IPv4 | 192.168.1.10 -> 8.8.8.8
  Protocol        : UDP (TTL: 64)
  Transport Layer : UDP  | Port 55321 -> 53
  Payload (28B) : [Hex: 12 34 01 00 00 01 00 00 00 00 00 00 06 67 6f 6f] [ASCII: .4...........google.com.....]
===========================================================================
[23:36:11.362] Packet Captured - Length: 60 bytes
  Network Layer   : IPv4 | 192.168.1.1 -> 192.168.1.10
  Protocol        : ICMP (TTL: 64)
  Transport Layer : ICMP | Type 0 (Code: 0)
  Payload (32B) : [Hex: 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70] [ASCII: abcdefghijklmnopqrstuvwabcdefghi]
===========================================================================
```
