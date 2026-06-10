# 🕵️‍♂️ Pylemetry
> **Advanced Network Analyzer & Intrusion Detection System**

Robust and high-performance network monitoring tool written in pure Python. It allows users to capture, analyze, and geolocate network traffic in real-time using **Scapy** and **Deep Packet Inspection (DPI)**.

The tool features a sleek dark-mode GUI, a background Security Rules Engine for threat alerting, and asynchronous IP resolution to ensure zero packet loss during heavy traffic.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🚨 **Automated IDS Alerts** | The internal engine silently detects DoS floods, port scans, insecure protocols (FTP/Telnet), and exposed sensitive data. |
| 🌍 **Asynchronous GeoIP** | Resolves the physical country of destination IPs in the background using thread pooling. |
| 🔍 **Deep Packet Inspection** | Extracts raw text payloads and DNS query names directly from unencrypted network layers. |
| 💻 **Enterprise GUI** | Custom Dark-Mode interface built with PyQt6, featuring real-time search, live statistics, and a 2000-packet ring buffer to prevent RAM leaks. |
| ⚡ **Auto-Interface Hook** | Automatically detects your active routing interface via dummy sockets. No manual configuration needed. |

---

## 🛠️ Installation & Setup

This project requires **Python 3.8+** and relies on Scapy for low-level packet capture.

### Option 1: Python Script (Recommended for Devs)

1. Clone the repository to your local machine.
2. Open your terminal in the project folder.
3. Install the required dependencies:

```bash
pip install -r requirements.txt
```

### Option 2: Standalone Executable

If you compiled the project using PyInstaller, simply download `pylemetry.exe` from the Releases page. No Python installation is required.

---

## 📖 How to Use

### 1. Prerequisites

**Windows Users MUST install [Npcap](https://npcap.com/).**

> ⚠️ **Critical Step:** During the Npcap installation, you must check the box: **"Install Npcap in WinPcap API-compatible Mode"**.

| ❌ Incorrect | ✅ Correct |
|---|---|
| Standard Npcap Install | WinPcap API-compatible Mode checked |

### 2. Run the Program

Network sniffing requires raw socket access. Launch pylemetry with elevated privileges.

**Windows:** Open Command Prompt as Administrator and run:

```dos
python pylemetry.py
```

*(Or right-click `pylemetry.exe` → Run as Administrator).*

### 3. Capture & Analyze (Sniffing)

- Click **Start Capture**. The table will immediately populate with real-time network packets.
- Click on any row to view the **Raw Metrics** (Layer 2 to Layer 7 breakdown) in the bottom inspection panel.
- Use the **Search Bar** to instantly filter traffic by IP, Country, Protocol, or Payload string.

### 4. Monitor Threats (IDS)

The system silently tracks anomalies in the background. If a threat is detected, the **Alerts** button in the top right will turn **RED**.

Click it to view the detailed **Security Log**, which flags:

```
CRITICAL: Traffic Anomaly: Possible DoS Attack
CRITICAL: Port Scan Detected
WARNING:  Connection to [Suspicious Country]
CRITICAL: Unencrypted sensitive data (Passwords/SQLi)
```

---

## ⚠️ Requirements & Limitations

| Item | Detail |
|---|---|
| **Admin Rights** | The application will fail to bind to the network card without Administrator/Root privileges. |
| **Decryption** | Cannot decrypt TLS/HTTPS traffic. DPI only extracts unencrypted text (HTTP, plain DNS, generic raw bytes). |
| **Operating System** | Cross-platform (Tested and optimized for Windows 10 / 11, compatible with Linux). |

---

## 📄 License

This project is released under the [MIT License](https://opensource.org/licenses/MIT).

---
*© 2026 Lorenzo Sottile. Made by Me with ♡.*
