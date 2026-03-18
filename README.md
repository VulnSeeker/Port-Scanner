# 🔍  Port Scanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Version](https://img.shields.io/badge/Version-2.0.0-orange.svg)

*A comprehensive network reconnaissance tool for security professionals and system administrators*

</div>

---

## 📋 Abstract

This tool implements a multi-threaded port scanner with advanced service detection capabilities and vulnerability assessment. Designed for network security auditing, it provides comprehensive information about exposed services, their versions, and associated risk levels.

---

## 🔬 Key Features

### Scan Capabilities
| Feature | Description |
|---------|-------------|
| **Multiple Scan Types** | TCP Connect, SYN Stealth, UDP |
| **Target Specification** | Single IP, CIDR notation, IP ranges |
| **Port Selection** | Single ports, comma-separated lists, ranges |
| **Performance** | Configurable threading (100-500 concurrent) |

### Service Analysis
- **Service Fingerprinting** - Identifies running services using signature matching
- **Banner Grabbing** - Captures and parses service banners
- **Version Extraction** - Regular expression-based version detection
- **OS Fingerprinting** - TCP/IP stack analysis for OS identification

### Security Assessment
- **Vulnerability Scoring** - Quantitative risk assessment (0.5-9.0 scale)
- **Risk Categorization** - Critical, High, Medium, Low classifications
- **Service Risk Analysis** - Context-aware scoring based on service type

### Reporting Formats
- **Terminal Output** - Color-coded, formatted tables
- **JSON Export** - Machine-readable format for automation
- **CSV Export** - Spreadsheet-compatible data
- **HTML Reports** - Professional, styled documentation

---


### Data Flow

```
Raw Input → Target Resolution → Host Discovery → Port Scanning → 
Service Analysis → Vulnerability Assessment → Report Generation
```

---

## 💻 Technical Specifications

### Requirements
- **Python**: Version 3.8 or higher
- **Operating System**: Linux/Unix (recommended), Windows (limited)
- **Privileges**: Root/sudo for SYN and UDP scans
- **Dependencies**:
  ```
  scapy>=2.5.0      # Packet manipulation
  netifaces>=0.11.0 # Network interface information
  colorama>=0.4.6   # Terminal color output
  python-nmap>=0.7.1 # Nmap integration
  requests>=2.31.0  # HTTP requests
  ```

### Installation Methods

#### Standard Installation
```bash
git clone https://github.com/yourusername/port-scanner.git
cd port-scanner
pip install -r requirements.txt
chmod +x scanner.py
```

#### Virtual Environment (Recommended)
```bash
python3 -m venv scanner-env
source scanner-env/bin/activate
pip install -r requirements.txt
```

#### Kali Linux
```bash
sudo apt install python3-scapy python3-netifaces python3-colorama python3-nmap
```

---

## 📊 Usage Documentation

### Command Line Interface

```
usage: scanner.py [-h] [-p PORTS] [-t {tcp_connect,tcp_syn,udp}] 
                  [-o OUTPUT] [-f {table,json,csv,html}] [-T THREADS] 
                  [--timeout TIMEOUT] [--stealth] [--no-service] 
                  [--no-os] [-v] [--version]
                  target
```

### Parameter Specification

| Parameter | Type   | Description | Default |
|-----------|------  |-------------|---------|
| `target`  | string | IP address, hostname, CIDR, or range | Required |
| `-p, --ports` | string | Port specification (e.g., "22,80,443" or "1-1024") | "1-1024" |
| `-t, --type` | string | Scan technique | "tcp_connect" |
| `-f, --format` | string | Output format | "table" |
| `-o, --output` | string | Output file path | None |
| `-T, --threads` | integer | Concurrent threads | 100 |
| `--timeout` | float | Connection timeout (seconds) | 2.0 |
| `--stealth` | flag | Enable inter-packet delay | False |
| `--no-service` | flag | Disable service detection | False |
| `--no-os` | flag | Disable OS fingerprinting | False |
| `-v, --verbose` | flag | Detailed output | False |

### Usage Examples

#### Basic Operations
```bash
# Single host scan
python3 scanner.py 192.168.1.1

# Port range specification
python3 scanner.py 10.0.0.1 -p 1-1000

# Multiple discrete ports
python3 scanner.py server.example.com -p 22,80,443,3306
```

#### Advanced Configurations
```bash
# SYN stealth scan (requires elevated privileges)
sudo python3 scanner.py 192.168.1.0/24 -p 1-1024 -t tcp_syn --stealth

# Comprehensive scan with all features
python3 scanner.py target.com -p 1-65535 -T 200 -v

# UDP service discovery
sudo python3 scanner.py dns-server.local -p 53,123,161 -t udp
```

#### Reporting
```bash
# JSON output for automation
python3 scanner.py 10.0.0.0/24 -p 22,80,445 -f json -o network_audit.json

# Professional HTML report
python3 scanner.py 192.168.1.1 -p 1-1000 -f html -o security_assessment.html

# CSV for analysis
python3 scanner.py target.com -p 1-1024 -f csv -o scan_data.csv
```

---

## 🔬 Technical Analysis

### Service Detection Methodology

The scanner employs a multi-stage service identification process:

1. **Port Connection** - Establishes connection to target port
2. **Probe Transmission** - Sends service-specific probes:
   ```python
   probes = {
       80: [b"HEAD / HTTP/1.0\r\n\r\n"],
       21: [b"HELP\r\n", b"SYST\r\n"],
       22: [b"SSH-2.0-OpenSSH_Test\r\n"]
   }
   ```
3. **Banner Capture** - Receives and decodes service responses
4. **Pattern Matching** - Compares against signature database
5. **Version Extraction** - Applies regex patterns for version identification

### Vulnerability Scoring Algorithm

Scores are calculated using a weighted formula:

```python
base_score = {
    'high_risk': 7.0,   # Ports 21, 23, 445, 3389, 5900
    'medium_risk': 4.0,  # Ports 22, 80, 443, 3306, 5432
    'low_risk': 1.0,     # Ports 53, 123, 161
    'default': 0.5
}

# Risk adjustment based on service
if service in ['ftp', 'telnet', 'smb', 'rdp']:
    score += 2.0

final_score = min(score, 10.0)  # Cap at maximum
```

### Performance Characteristics

| Thread Count | Ports Scanned | Average Time (local) | Memory Usage |
|--------------|---------------|----------------------|--------------|
| 50           | 1000          | 2.3s                 | ~50MB        |
| 100          | 1000          | 1.2s                 | ~75MB        |
| 200          | 1000          | 0.8s                 | ~120MB       |
| 500          | 1000          | 0.5s                 | ~250MB       |

---

## 📈 Output Specifications

### Console Output Format
```
======================================================================
SCAN RESULTS
======================================================================

Host: 192.168.1.100 (webserver.local)
  Open Ports: 3

  PORT     STATE    SERVICE    VERSION              VULN
  ---------------------------------------------------------
  22       open     ssh        OpenSSH_7.9p1        4.0
  80       open     http       Apache 2.4.41        4.0
  3306     open     mysql      MySQL 5.7.35         4.0

Vulnerability Assessment:
  Critical: 0 | High: 0 | Medium: 3 | Low: 0
```

### JSON Structure
```json
{
  "scan_info": {
    "target": "192.168.1.0/24",
    "scan_type": "tcp_connect",
    "duration": 45.67
  },
  "hosts": [
    {
      "ip_address": "192.168.1.1",
      "hostname": "router.local",
      "open_ports": [22, 80, 443],
      "ports": [
        {
          "port": 22,
          "service": "ssh",
          "version": "OpenSSH_7.9p1",
          "vulnerability_score": 4.0
        }
      ]
    }
  ]
}
```

---

## ⚠️ Security Considerations

### Legal Compliance
- Unauthorized port scanning may violate:
  - Computer Fraud and Abuse Act (CFAA) in the US
  - Computer Misuse Act in the UK
  - Similar legislation in other jurisdictions
- Always obtain written authorization before scanning

### Operational Guidelines
1. **Authorization Required** - Only scan systems you own or have permission to test
2. **Rate Limiting** - Use `--stealth` and appropriate thread counts to avoid DoS
3. **Documentation** - Maintain logs of all scanning activities
4. **Disclosure** - Follow responsible disclosure practices for discovered vulnerabilities

### Risk Mitigation
- Use the test target `scanme.nmap.org` for development and testing
- Implement scanning windows during maintenance periods
- Monitor target systems for adverse effects

---

## 🤝 Contributing Guidelines

### Development Areas
- Additional service signatures for `SERVICE_SIGNATURES`
- Enhanced OS fingerprinting algorithms
- New scan technique implementations
- Performance optimizations
- Additional output formats

### Contribution Process
1. Fork the repository
2. Create a feature branch
3. Implement changes with documentation
4. Submit pull request with detailed description

---

## 📚 References

1. **Nmap Network Scanning** - Gordon Lyon (Fyodor)
2. **TCP/IP Illustrated** - W. Richard Stevens
3. **Common Vulnerabilities and Exposures (CVE)** - MITRE Corporation
4. **Scapy Documentation** - Philippe Biondi and contributors

---

## 📄 License

MIT License - See LICENSE file for details

---


<div align="center">

</div>
