
🔍 Port Scanner




![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Threading](https://img.shields.io/badge/Multi--Threading-100--500-green)
![Scans](https://img.shields.io/badge/Scans-TCP%20|%20SYN%20|%20UDP-orange)
![Output](https://img.shields.io/badge/Output-JSON%20|%20CSV%20|%20HTML-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

"See the unseen. Secure the insecure."



---

Whether you're a:
- Security Professional needing to audit networks
System administrator overseeing server operations
- Penetration Tester in the reconnaissance phase
- Developer learning network security

One Python file. That is all it takes to run scans like big companies do. Built right into the code, no extra setup needed. Power sits inside a simple format. Think of how teams check systems at scale - now possible alone. Efficiency without complexity shows up here. A full scanner, yet fits in one place.

---

✨ Features

Multiple Scan Types
Scan Type. Description. Use Case
|-----------|-------------|----------|
TCP Connect Full Handshake Reliable Without Root Access
Syn stealth half open scan faster less detectable
UDP Scan of Ports Running DNS SNMP and DHCP

🎯 Service Detection
Banner Grabbing Reveals Service Versions
Service Fingerprinting Identifies Apache Nginx MySQL SSH FTP and Over 50 Other Services
Version Extraction retrieves detailed version information such as OpenSSH_7.9p1

🛡️ Vulnerability Assessment
```
Critical 9.0 Ports 21 23 3389
High 7.0 vulnerability linked to ports 445 and 5900
Moving on - port numbers like 22, 80, 3306, and also 5432 show up under Medium severity level, rated at 4.0.
Low 0.5 shifts to other services
```

Multiformat Outputs
- Table :- Beautiful console output with colors
JSON is machine readable data format
CSV spreadsheet friendly
- HTML :- Professional reports with styling

⚡ Performance Features
Running several tasks at once, somewhere between a hundred and five hundred things happening together
- Configurable timeouts
- Stealth mode with delays
- Host discovery before scanning

---

How It Works - The Logic Behind It

The Five Step Investigation Process

```
┌─────────────────────────────────────────────────────────┐
│﻿﻿﻿﻿﻿﻿﻿﻿﻿COMMAND﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿│
│﻿$ python scanner.py 192.168.1.1 -p 1-1000﻿﻿﻿﻿﻿﻿﻿│
└─────────────────────────────────────────────────────────┘
|
▼
┌─────────────────────────────────────────────────────────┐
 1. HOST DISCOVERY﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿
Does the person still have a pulse? That one matters most right now
Uses ICMP ping TCP ping ARP
Instead of wasting minutes on lifeless machines, skip straight ahead. One less thing slowing you down happens when nothing answers back. Jump past the silence because waiting serves no purpose here. Move faster since unresponsive systems bring zero value anyway
└─────────────────────────────────────────────────────────┘
|
▼
┌─────────────────────────────────────────────────────────┐
│﻿2. PORT SCANNING﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿│
One hundred investigators start working at once
│﻿﻿﻿• Each thread checks different ports﻿﻿﻿﻿﻿﻿﻿﻿│
TCP Connect Hello Anyone There
SYN Stealth Half Handshake Quieter
└─────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────┐
│﻿3. SERVICE DETECTION﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿│
Once the port replies, say: Tell me who you are
Every now and then, test individual ports using tailored signals
I m Apache 2 4 41
│﻿﻿﻿• Extract version numbers﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿│
└─────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────┐
│﻿4. VULNERABILITY SCORING﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿│
Out on port 21, FTP stands with a 9.0 danger score.
Telnet Port 23 High Severity Vulnerability Score 9.0
SSH port 22 medium severity
Earlier editions earn better ratings
└─────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────┐
│﻿5. REPORT GENERATION﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿│
│﻿﻿﻿• Beautiful tables with colors﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿│
Data format used by machines to handle tasks automatically.
│﻿﻿﻿• HTML reports for management﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿│
CSV for spreadsheets
└─────────────────────────────────────────────────────────┘
```

Exploring How Services Are Identified

```python
How we identify services:
1. Connect to port 80
2. Send: "GET / HTTP/1.0\r\n\r\n"
3. Receive: "HTTP/1.1 200 OK\nServer: Apache/2.4.41"
4. Service http version 2.4.41

Ftp Port 21
1. Connect
2. Receive: "220 (vsFTPd 3.0.3)"
3. Ftp service version 3.0.3
```

⚡ Multi-threading Architecture

```
COMMAND
│
▼
Scan Manager
│﻿﻿Thread Pool﻿﻿﻿│
│﻿﻿(100 threads)﻿﻿│
└──────────┬────────┘
│
┌───────────────┼───────────────┐
▼﻿﻿﻿﻿﻿﻿﻿﻿▼﻿﻿﻿﻿﻿﻿﻿﻿▼
┌─────────┐﻿﻿┌─────────┐﻿﻿┌─────────┐
│Thread 1 │﻿﻿│Thread 2 │﻿﻿│Thread 3 │...100
One way in, number twenty-two. Through eight zero comes another path. Last gate opens at four forty-three
└────┬────┘﻿﻿└────┬────┘﻿﻿└────┬────┘
▼﻿﻿﻿﻿﻿﻿﻿▼﻿﻿﻿﻿﻿﻿﻿▼
┌─────────┐﻿﻿┌─────────┐﻿﻿┌─────────┐
│SSH﻿﻿﻿│﻿﻿│HTTP﻿﻿﻿│﻿﻿│HTTPS﻿﻿│
│OpenSSH_7│﻿﻿│Apache﻿﻿│﻿﻿│OpenSSL﻿│
└─────────┘﻿﻿└─────────┘﻿﻿└─────────┘
```



🚀 Usage Examples

Basic Scanning
```bash
Scan common ports on localhost
python port_scanner.py 127.0.0.1 -p 22,80,443

Scan port range
python port_scanner.py 192.168.1.1 -p 1-1000

Verbose output
python port_scanner.py scanme.nmap.org -p 22,80 -v
```

Advanced Scanning
```bash
Hidden SYN check needs admin rights.
sudo python port_scanner.py 192.168.1.1 -p 1-1000 -t tcp_syn --stealth

UDP scan
sudo python port_scanner.py 8.8.8.8 -p 53,123,161 -t udp

Network range scan
python port_scanner.py 192.168.1.0/24 -p 22,80,445

Fine-tuning under load, two hundred threads active
Run python port_scanner.py against target.com using ports one through a thousand, thread count set to two hundred, each attempt stops after one second.
```

Output Formats
```bash
JSON output
Run python port_scanner.py at 127.000.000.1 using ports 22 plus 80 if output format is json then save result into file named scan.json.

CSV for spreadsheets
Run python port_scanner.py with target 127.0.0.1, then specify ports 22 and 80 using comma separation. After that, choose output format as csv by adding flag -f. Finally, assign filename scan.csv through option -o. Execution begins once all arguments are set in place.

HTML report
Run python port_scanner.py with target 127.0.0.1. Using range 1 through 100 for ports. Output format set to html instead. Save result into file named report.html.
```





Perfect For:
Security Audits Fast Check for Weak Spots
Network Inventory What’s Running
Penetration Testing Reconnaissance Phase
- 📚 Learning :- Understand network protocols
Professional HTML Reports

---

Security and Ethics

Use Responsibly

This tool is for:
- ✅ Your own systems
- ✅ Authorized penetration testing
- ✅ Educational purposes
- ✅ Network administration

Not for:
- ❌ Unauthorized scanning
- ❌ Illegal activities
- ❌ Hacking without permission

Start with permission on paper if the system isn’t yours. Scan only after receiving signed approval from its owner. Written proof comes first when access involves machines outside your control. Before running checks, secure a documented go-ahead. A clear record must exist prior to any inspection of someone else's setup.

---

🤝 Contributing

Got something to add? We’re open to help on these fronts:
- Add more service signatures
Enhanced OS Detection Methods
- Add vulnerability database
Create a graphical user interface
- Add more scan types

---

📄 License

Free to use, just act with care under the MIT License.

Found something helpful here? A star on the repo makes a difference for people looking around. Discovery gets easier when someone takes a moment.

---

