# 🌐 Network Packet Analyzer – Python Sniffer Tool

A powerful TCP packet sniffer with a modern Tkinter GUI built using Python and Scapy. This tool allows real-time monitoring of network traffic, displaying source/destination IPs, ports, and packet payloads in a clean graphical interface.



> ⚠️ **Disclaimer**: This tool is strictly for educational purposes. Unauthorized usage may violate privacy laws and is **strictly prohibited**.

---

## 🔍 Features

- 📡 **Real-Time Packet Capture**  
  Sniffs and analyzes TCP packets live using `scapy`.

- 🧠 **Deep Packet Analysis**  
  Displays key data from each packet:
  - Source and Destination IPs
  - Source and Destination Ports
  - Protocol
  - Payload snippet (first 50 characters)

- 📁 **Logging Results**  
  Captured packet data is saved to `packet_sniffer_results.txt` for offline analysis.

- ✅ **Ethical Consent**  
  Users must read and accept a disclaimer before using the tool.

---

---

## 📥 Installation

```bash
git clone https://github.com/11gurmeet11/packet-sniffer-gui.git
cd packet-sniffer-gui
pip install scapy
