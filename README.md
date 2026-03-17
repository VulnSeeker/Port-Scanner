# 🔍 Port Scanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Threading](https://img.shields.io/badge/Multi--Threading-100--500-green)
![Scans](https://img.shields.io/badge/Scans-TCP%20|%20SYN%20|%20UDP-orange)
![Output](https://img.shields.io/badge/Output-JSON%20|%20CSV%20|%20HTML-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

### *"See the unseen. Secure the insecure."*

</div>

---

Whether you're a:
- **Security Professional** needing to audit networks
- **System Administrator** managing servers
- **Penetration Tester** in the reconnaissance phase
- **Developer** learning network security

This tool gives you enterprise-grade scanning capabilities in a single Python script.

---

## ✨ Features

### 🚀 **Multiple Scan Types**
| Scan Type | Description | Use Case |
|-----------|-------------|----------|
| **TCP Connect** | Full handshake | Reliable, no root needed |
| **SYN Stealth** | Half-open scan | Faster, less detectable |
| **UDP Scan** | UDP ports | DNS, SNMP, DHCP services |

### 🎯 **Service Detection**
- **Banner Grabbing** - Identifies exact service versions
- **Service Fingerprinting** - Detects Apache, Nginx, MySQL, SSH, FTP, and 50+ services
- **Version Extraction** - Gets detailed version info (e.g., OpenSSH_7.9p1)

### 🛡️ **Vulnerability Assessment**
```
Critical (9.0)  → Ports 21, 23, 3389
High (7.0)      → Ports 445, 5900
Medium (4.0)    → Ports 22, 80, 3306, 5432
Low (0.5)       → Other services
```

### 📊 **Multiple Output Formats**
- **Table** - Beautiful console output with colors
- **JSON** - Machine-readable for automation
- **CSV** - Spreadsheet-friendly
- **HTML** - Professional reports with styling

### ⚡ **Performance Features**
- **Multi-threading** (100-500 concurrent threads)
- **Configurable timeouts**
- **Stealth mode** with delays
- **Host discovery** before scanning

---

## 🧠 How It Works: The Logic Explained

### The 5-Step Investigation Process

```
┌─────────────────────────────────────────────────────────┐
│                    YOUR COMMAND                          │
│  $ python scanner.py 192.168.1.1 -p 1-1000              │
└─────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────┐
│  1. HOST DISCOVERY                                       │
│     • Is the target alive?                               │
│     • Uses ICMP ping, TCP ping, ARP                      │
│     • Saves time by not scanning dead hosts              │
└─────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────┐
│  2. PORT SCANNING                                         │
│     • Opens multiple threads (like 100 detectives)       │
│     • Each thread checks different ports                 │
│     • TCP Connect: "Hello, anyone there?"                │
│     • SYN Stealth: Half-handshake (quieter)              │
└─────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────┐
│  3. SERVICE DETECTION                                     │
│     • When port responds, ask "Who are you?"             │
│     • Send specific probes based on port                 │
│     • Read banner: "I'm Apache 2.4.41"                   │
│     • Extract version numbers                             │
└─────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────┐
│  4. VULNERABILITY SCORING                                 │
│     • FTP (port 21) → High risk (9.0)                    │
│     • Telnet (23) → Critical (9.0)                       │
│     • SSH (22) → Medium (4.0)                             │
│     • Old versions get higher scores                      │
└─────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────┐
│  5. REPORT GENERATION                                     │
│     • Beautiful tables with colors                        │
│     • JSON for automation                                 │
│     • HTML reports for management                         │
│     • CSV for spreadsheets                                │
└─────────────────────────────────────────────────────────┘
```

### 🔬 Deep Dive: Service Detection 

```python
# How we identify services:
1. Connect to port 80
2. Send: "GET / HTTP/1.0\r\n\r\n"
3. Receive: "HTTP/1.1 200 OK\nServer: Apache/2.4.41"
4. Extract: Service = "http", Version = "2.4.41"

# For FTP on port 21:
1. Connect
2. Receive: "220 (vsFTPd 3.0.3)"
3. Extract: Service = "ftp", Version = "3.0.3"
```

### ⚡ Multi-threading Architecture

```
                    YOUR COMMAND
                         │
                         ▼
              ┌─── SCAN MANAGER ───┐
              │   Thread Pool       │
              │   (100 threads)     │
              └──────────┬──────────┘
                         │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   ┌─────────┐    ┌─────────┐    ┌─────────┐
   │Thread 1 │    │Thread 2 │    │Thread 3 │...100
   │Port 22  │    │Port 80  │    │Port 443│
   └────┬────┘    └────┬────┘    └────┬────┘
        ▼              ▼              ▼
   ┌─────────┐    ┌─────────┐    ┌─────────┐
   │SSH      │    │HTTP     │    │HTTPS    │
   │OpenSSH_7│    │Apache   │    │OpenSSL  │
   └─────────┘    └─────────┘    └─────────┘
```



## 🚀 Usage Examples

### Basic Scanning
```bash
# Scan common ports on localhost
python scanner.py 127.0.0.1 -p 22,80,443

# Scan port range
python scanner.py 192.168.1.1 -p 1-1000

# Verbose output
python scanner.py scanme.nmap.org -p 22,80 -v
```

### Advanced Scanning
```bash
# SYN stealth scan (requires root)
sudo python scanner.py 192.168.1.1 -p 1-1000 -t tcp_syn --stealth

# UDP scan
sudo python scanner.py 8.8.8.8 -p 53,123,161 -t udp

# Network range scan
python scanner.py 192.168.1.0/24 -p 22,80,445

# Performance tuning (200 threads)
python scanner.py target.com -p 1-1000 -T 200 --timeout 1
```

### Output Formats
```bash
# JSON output
python scanner.py 127.0.0.1 -p 22,80 -f json -o scan.json

# CSV for spreadsheets
python scanner.py 127.0.0.1 -p 22,80 -f csv -o scan.csv

# HTML report
python scanner.py 127.0.0.1 -p 1-100 -f html -o report.html
```





### Perfect For:
- 🔒 **Security Audits** - Quick vulnerability assessment
- 🌐 **Network Inventory** - Know what's running
- 🛠️ **Penetration Testing** - Reconnaissance phase
- 📚 **Learning** - Understand network protocols
- 📊 **Reporting** - Professional HTML reports

---

## 🔒 Security & Ethics

> **⚠️ IMPORTANT: Use Responsibly**

This tool is for:
- ✅ Your own systems
- ✅ Authorized penetration testing
- ✅ Educational purposes
- ✅ Network administration

**Not for:**
- ❌ Unauthorized scanning
- ❌ Illegal activities
- ❌ Hacking without permission

Always get written authorization before scanning systems you don't own.

---

## 🤝 Contributing

Contributions welcome! Areas to improve:
- Add more service signatures
- Improve OS fingerprinting
- Add vulnerability database
- Create GUI interface
- Add more scan types

---

## 📄 License

MIT License - Use freely, but responsibly.

If you find this useful, please star the repo! It helps others discover it.

---

<div align="center">

**Made with 🔍 by Security Professionals**

*"Know your network. Secure your future."*

[⬆ Back to Top](#-professional-port-scanner)

</div>
