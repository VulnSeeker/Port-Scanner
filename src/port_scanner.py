#!/usr/bin/env python3
"""
Enterprise-Grade Port Scanner
Author: Mubbshra Iqbal
Description: Advanced port scanner with service detection, OS fingerprinting,
             multiple scan techniques, and professional reporting.
"""

import socket
import threading
import ipaddress
import argparse
import json
import csv
import time
import sys
import os
import signal
import logging
import ssl
import struct
from datetime import datetime
from queue import Queue, PriorityQueue
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import netifaces
import requests
from scapy.all import *
from colorama import init, Fore, Back, Style
import nmap

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# ============================================================================
# Data Classes and Enumerations
# ============================================================================

class ScanType(Enum):
    TCP_CONNECT = "tcp_connect"
    TCP_SYN = "tcp_syn"
    TCP_ACK = "tcp_ack"
    TCP_FIN = "tcp_fin"
    TCP_XMAS = "tcp_xmas"
    TCP_NULL = "tcp_null"
    UDP = "udp"
    SCTP = "sctp"
    ICMP = "icmp"

class ServiceState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    OPEN_FILTERED = "open|filtered"

@dataclass
class PortInfo:
    """Comprehensive port information"""
    port: int
    protocol: str
    state: ServiceState
    service: str = ""
    version: str = ""
    banner: str = ""
    cpe: str = ""
    vulnerability_score: float = 0.0
    extra_info: Dict = field(default_factory=dict)

@dataclass
class HostInfo:
    """Comprehensive host information"""
    ip_address: str
    hostname: str = ""
    mac_address: str = ""
    vendor: str = ""
    os_guess: str = ""
    os_accuracy: float = 0.0
    uptime: int = 0
    ports: List[PortInfo] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    filtered_ports: List[int] = field(default_factory=list)
    scan_time: float = 0.0
    response_time: float = 0.0
    distance: int = 0
    extra_info: Dict = field(default_factory=dict)

@dataclass
class ScanResult:
    """Complete scan results"""
    target: str
    scan_type: ScanType
    start_time: datetime
    end_time: datetime
    duration: float
    hosts: List[HostInfo]
    command_line: str
    scan_params: Dict
    summary: Dict = field(default_factory=dict)

# ============================================================================
# Logging Configuration
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('port_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# Advanced Port Scanner Class
# ============================================================================

class ProfessionalPortScanner:
    """
    Enterprise-grade port scanner with advanced features
    """
    
    # Common service signatures
    SERVICE_SIGNATURES = {
        # Web Services
        80: ['http', 'apache', 'nginx', 'iis'],
        443: ['https', 'apache', 'nginx', 'openssl'],
        8080: ['http-alt', 'tomcat', 'jetty'],
        8443: ['https-alt', 'tomcat'],
        
        # Database Services
        3306: ['mysql', 'mariadb'],
        5432: ['postgresql'],
        27017: ['mongodb'],
        6379: ['redis'],
        9200: ['elasticsearch'],
        5601: ['kibana'],
        
        # Mail Services
        25: ['smtp', 'postfix', 'sendmail', 'exchange'],
        465: ['smtps'],
        587: ['submission'],
        110: ['pop3', 'dovecot'],
        995: ['pop3s'],
        143: ['imap', 'dovecot'],
        993: ['imaps'],
        
        # File Transfer
        21: ['ftp', 'vsftpd', 'proftpd', 'pure-ftpd'],
        22: ['ssh', 'openssh', 'dropbear'],
        69: ['tftp'],
        115: ['sftp'],
        989: ['ftps-data'],
        990: ['ftps'],
        
        # Remote Access
        23: ['telnet'],
        3389: ['rdp', 'xrdp', 'windows-terminal'],
        5900: ['vnc', 'tightvnc', 'realvnc'],
        5901: ['vnc-1'],
        5800: ['vnc-http'],
        
        # Windows Services
        135: ['msrpc', 'epmap'],
        137: ['netbios-ns'],
        138: ['netbios-dgm'],
        139: ['netbios-ssn'],
        445: ['microsoft-ds', 'smb'],
        5985: ['winrm-http'],
        5986: ['winrm-https'],
        
        # Directory Services
        389: ['ldap'],
        636: ['ldaps'],
        3268: ['global-catalog'],
        3269: ['global-catalog-ssl'],
        
        # Network Services
        53: ['dns', 'bind'],
        67: ['dhcp-server'],
        68: ['dhcp-client'],
        123: ['ntp', 'chrony'],
        161: ['snmp', 'snmpd'],
        162: ['snmptrap'],
        179: ['bgp'],
        520: ['rip'],
        
        # Proxy Services
        3128: ['squid-proxy'],
        8080: ['web-proxy'],
        8118: ['privoxy'],
        9050: ['tor-socks'],
        
        # Container/Orchestration
        2375: ['docker-rest'],
        2376: ['docker-rest-ssl'],
        2379: ['etcd'],
        2380: ['etcd-peer'],
        6443: ['kubernetes-api'],
        8001: ['kubernetes-dashboard'],
        
        # Message Queues
        5672: ['rabbitmq'],
        5671: ['rabbitmq-ssl'],
        61616: ['activemq'],
        9092: ['kafka'],
        
        # Version Control
        9418: ['git'],
        7990: ['bitbucket'],
        8080: ['jenkins'],
        
        # Monitoring
        3000: ['grafana', 'prometheus'],
        9090: ['prometheus'],
        9100: ['node-exporter'],
        9113: ['nginx-exporter'],
        
        # IoT/Industrial
        502: ['modbus'],
        1883: ['mqtt'],
        8883: ['mqtt-ssl'],
        5683: ['coap'],
    }
    
    # OS Fingerprinting signatures
    OS_SIGNATURES = {
        'Windows': {
            'ttl': 128,
            'window_size': 8192,
            'tcp_options': ['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'Timestamp'],
        },
        'Linux': {
            'ttl': 64,
            'window_size': 5840,
            'tcp_options': ['MSS', 'SACK', 'Timestamp', 'WScale'],
        },
        'BSD': {
            'ttl': 64,
            'window_size': 65535,
            'tcp_options': ['MSS', 'WScale', 'NOP', 'Timestamp'],
        },
        'MacOS': {
            'ttl': 64,
            'window_size': 65535,
            'tcp_options': ['MSS', 'NOP', 'WScale', 'NOP', 'Timestamp'],
        },
        'Solaris': {
            'ttl': 255,
            'window_size': 8760,
            'tcp_options': ['MSS', 'WScale', 'NOP', 'Timestamp'],
        },
        'Cisco IOS': {
            'ttl': 255,
            'window_size': 4128,
            'tcp_options': ['MSS', 'NOP', 'NOP'],
        },
    }
    
    def __init__(self, timeout: float = 2.0, threads: int = 100, 
                 stealth: bool = False, verbose: bool = False):
        """
        Initialize the professional port scanner
        
        Args:
            timeout: Connection timeout in seconds
            threads: Number of threads to use
            stealth: Enable stealth scanning techniques
            verbose: Enable verbose output
        """
        self.timeout = timeout
        self.max_threads = threads
        self.stealth = stealth
        self.verbose = verbose
        self.scan_results = []
        self.stop_scan = False
        self.lock = threading.Lock()
        self.hosts_queue = Queue()
        self.results = []
        
        # Statistics
        self.total_ports_scanned = 0
        self.open_ports_found = 0
        self.filtered_ports_found = 0
        
        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        
        # Check for root privileges for SYN scan
        self.is_root = os.geteuid() == 0
        
        logger.info(f"Professional Port Scanner initialized (Stealth: {stealth}, Threads: {threads})")
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user. Generating partial report...{Style.RESET_ALL}")
        self.stop_scan = True
        sys.exit(0)
    
    # ========================================================================
    # Host Discovery Methods
    # ========================================================================
    
    def discover_hosts(self, target: str) -> List[str]:
        """
        Discover live hosts in the network
        
        Args:
            target: Target IP, range, or subnet
            
        Returns:
            List of live host IPs
        """
        live_hosts = []
        
        try:
            # Parse target
            if '/' in target:
                # CIDR notation
                network = ipaddress.ip_network(target, strict=False)
                hosts = [str(ip) for ip in network.hosts()]
            elif '-' in target:
                # Range notation
                start_ip, end_ip = target.split('-')
                start = ipaddress.IPv4Address(start_ip)
                end = ipaddress.IPv4Address(end_ip)
                hosts = [str(ipaddress.IPv4Address(ip)) for ip in range(int(start), int(end) + 1)]
            else:
                # Single IP or hostname
                try:
                    # Check if it's an IP
                    ipaddress.ip_address(target)
                    hosts = [target]
                except:
                    # It's a hostname, resolve it
                    ip = socket.gethostbyname(target)
                    hosts = [ip]
            
            print(f"{Fore.CYAN}[*] Discovering live hosts in {target}...{Style.RESET_ALL}")
            
            # Use ICMP ping for host discovery
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_host = {executor.submit(self.ping_host, host): host for host in hosts}
                
                for future in as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        if future.result():
                            live_hosts.append(host)
                            print(f"{Fore.GREEN}[+] Host {host} is alive{Style.RESET_ALL}")
                    except Exception as e:
                        logger.debug(f"Error pinging {host}: {e}")
            
            print(f"{Fore.CYAN}[*] Found {len(live_hosts)} live hosts{Style.RESET_ALL}")
            
        except Exception as e:
            logger.error(f"Host discovery error: {e}")
            
        return live_hosts
    
    def ping_host(self, host: str) -> bool:
        """
        Ping a host to check if it's alive
        
        Args:
            host: Host IP address
            
        Returns:
            True if host responds to ping
        """
        try:
            # Try ICMP ping (requires root)
            if self.is_root:
                ping = sr1(IP(dst=host)/ICMP(), timeout=self.timeout, verbose=0)
                if ping:
                    return True
            
            # Fallback to TCP ping on common ports
            common_ports = [80, 443, 22, 25, 445]
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    if result == 0:
                        return True
                except:
                    pass
            
            # Try ARP ping for local network
            if '.' in host:
                try:
                    arp_request = ARP(pdst=host)
                    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                    arp_request_broadcast = broadcast / arp_request
                    answered = srp(arp_request_broadcast, timeout=self.timeout, verbose=0)[0]
                    if answered:
                        return True
                except:
                    pass
            
            return False
            
        except Exception as e:
            logger.debug(f"Ping failed for {host}: {e}")
            return False
    
    # ========================================================================
    # Port Scanning Methods
    # ========================================================================
    
    def scan_host(self, host: str, ports: List[int], scan_type: ScanType = ScanType.TCP_CONNECT) -> HostInfo:
        """
        Comprehensive scan of a single host
        
        Args:
            host: Target host IP
            ports: List of ports to scan
            scan_type: Type of scan to perform
            
        Returns:
            HostInfo object with scan results
        """
        host_info = HostInfo(ip_address=host)
        start_time = time.time()
        
        try:
            # Resolve hostname
            try:
                host_info.hostname = socket.gethostbyaddr(host)[0]
            except:
                host_info.hostname = host
            
            # Get MAC address if in local network
            try:
                arp_result = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=host), 
                                timeout=2, verbose=0)[0]
                if arp_result:
                    host_info.mac_address = arp_result[0][1].hwsrc
                    # Try to identify vendor
                    host_info.vendor = self.get_vendor_by_mac(host_info.mac_address)
            except:
                pass
            
            print(f"\n{Fore.YELLOW}[*] Scanning {host} ({host_info.hostname}){Style.RESET_ALL}")
            
            # Perform port scan based on type
            if scan_type == ScanType.TCP_CONNECT:
                port_results = self.tcp_connect_scan(host, ports)
            elif scan_type == ScanType.TCP_SYN and self.is_root:
                port_results = self.tcp_syn_scan(host, ports)
            elif scan_type == ScanType.UDP and self.is_root:
                port_results = self.udp_scan(host, ports)
            else:
                port_results = self.tcp_connect_scan(host, ports)
            
            # Process port results
            for port, state, banner, service_info in port_results:
                port_info = PortInfo(
                    port=port,
                    protocol="tcp" if scan_type != ScanType.UDP else "udp",
                    state=state,
                    banner=banner,
                    extra_info=service_info
                )
                
                # Identify service
                port_info.service = self.identify_service(port, banner, service_info)
                
                # Get service version if possible
                if banner and port_info.service != "unknown":
                    port_info.version = self.extract_version(banner)
                
                # Calculate vulnerability score (simplified)
                port_info.vulnerability_score = self.calculate_vulnerability_score(port, port_info.service)
                
                host_info.ports.append(port_info)
                
                if state == ServiceState.OPEN:
                    host_info.open_ports.append(port)
                    self.open_ports_found += 1
                    print(f"{Fore.GREEN}  └─ Port {port}/{port_info.protocol:<3} : {port_info.service:<15} {port_info.version:<20} {banner[:50]}{Style.RESET_ALL}")
                elif state == ServiceState.FILTERED:
                    host_info.filtered_ports.append(port)
                    self.filtered_ports_found += 1
            
            # Perform OS fingerprinting
            host_info.os_guess, host_info.os_accuracy = self.os_fingerprint(host)
            if host_info.os_guess:
                print(f"{Fore.CYAN}  └─ OS Detection: {host_info.os_guess} (Accuracy: {host_info.os_accuracy:.1f}%){Style.RESET_ALL}")
            
            host_info.scan_time = time.time() - start_time
            
        except Exception as e:
            logger.error(f"Error scanning host {host}: {e}")
        
        return host_info
    
    def tcp_connect_scan(self, host: str, ports: List[int]) -> List[Tuple]:
        """
        TCP Connect scan (full handshake)
        
        Args:
            host: Target host
            ports: List of ports to scan
            
        Returns:
            List of (port, state, banner, service_info)
        """
        results = []
        port_queue = Queue()
        
        for port in ports:
            port_queue.put(port)
        
        def worker():
            while not port_queue.empty() and not self.stop_scan:
                port = port_queue.get()
                try:
                    state = ServiceState.CLOSED
                    banner = ""
                    service_info = {}
                    
                    # Create socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    
                    # Attempt connection
                    result = sock.connect_ex((host, port))
                    
                    if result == 0:
                        state = ServiceState.OPEN
                        
                        # Try to grab banner
                        try:
                            # Send probe based on port
                            probes = self.get_service_probes(port)
                            for probe in probes:
                                sock.send(probe)
                                time.sleep(0.1)
                                banner_data = sock.recv(1024)
                                if banner_data:
                                    banner = banner_data.decode('utf-8', errors='ignore').strip()
                                    break
                        except:
                            pass
                        
                        # Get more service info
                        service_info = self.get_service_info(sock, port)
                        
                    elif result == 11:  # Connection refused
                        state = ServiceState.CLOSED
                    else:
                        # Could be filtered
                        state = ServiceState.FILTERED
                    
                    sock.close()
                    
                    with self.lock:
                        results.append((port, state, banner, service_info))
                        self.total_ports_scanned += 1
                        
                except Exception as e:
                    logger.debug(f"Error scanning port {port}: {e}")
                finally:
                    port_queue.task_done()
        
        # Create and start threads
        threads = []
        for _ in range(min(self.max_threads, len(ports))):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)
        
        # Wait for completion
        for t in threads:
            t.join()
        
        return sorted(results, key=lambda x: x[0])
    
    def tcp_syn_scan(self, host: str, ports: List[int]) -> List[Tuple]:
        """
        TCP SYN scan (half-open) - requires root
        
        Args:
            host: Target host
            ports: List of ports to scan
            
        Returns:
            List of (port, state, banner, service_info)
        """
        results = []
        
        if not self.is_root:
            logger.warning("SYN scan requires root privileges. Falling back to TCP Connect scan.")
            return self.tcp_connect_scan(host, ports)
        
        try:
            # Craft SYN packet
            ip = IP(dst=host)
            
            for port in ports:
                if self.stop_scan:
                    break
                    
                try:
                    # SYN packet
                    syn = TCP(sport=RandShort(), dport=port, flags='S')
                    
                    # Send packet and receive response
                    response = sr1(ip/syn, timeout=self.timeout, verbose=0)
                    
                    state = ServiceState.CLOSED
                    banner = ""
                    service_info = {}
                    
                    if response:
                        if response.haslayer(TCP):
                            if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                                state = ServiceState.OPEN
                                
                                # Send RST to close connection
                                rst = TCP(sport=response.getlayer(TCP).dport, 
                                         dport=port, flags='R')
                                send(ip/rst, verbose=0)
                                
                                # Try to get banner with connect scan
                                try:
                                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                    sock.settimeout(2)
                                    sock.connect((host, port))
                                    
                                    probes = self.get_service_probes(port)
                                    for probe in probes:
                                        sock.send(probe)
                                        banner_data = sock.recv(1024)
                                        if banner_data:
                                            banner = banner_data.decode('utf-8', errors='ignore').strip()
                                            break
                                    sock.close()
                                except:
                                    pass
                                
                            elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
                                state = ServiceState.CLOSED
                            else:
                                state = ServiceState.FILTERED
                    else:
                        state = ServiceState.FILTERED
                    
                    with self.lock:
                        results.append((port, state, banner, service_info))
                        self.total_ports_scanned += 1
                        
                        if state == ServiceState.OPEN and self.verbose:
                            print(f"{Fore.GREEN}[+] Port {port} is open (SYN scan){Style.RESET_ALL}")
                    
                    # Stealth: add delay between packets
                    if self.stealth:
                        time.sleep(0.1)
                        
                except Exception as e:
                    logger.debug(f"Error in SYN scan port {port}: {e}")
                    
        except Exception as e:
            logger.error(f"SYN scan error: {e}")
        
        return sorted(results, key=lambda x: x[0])
    
    def udp_scan(self, host: str, ports: List[int]) -> List[Tuple]:
        """
        UDP port scan
        
        Args:
            host: Target host
            ports: List of ports to scan
            
        Returns:
            List of (port, state, banner, service_info)
        """
        results = []
        
        for port in ports:
            if self.stop_scan:
                break
                
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                
                # Send empty UDP packet
                sock.sendto(b"", (host, port))
                
                try:
                    data, addr = sock.recvfrom(1024)
                    # Got response - port is open
                    state = ServiceState.OPEN
                    banner = data.decode('utf-8', errors='ignore').strip()
                    
                    with self.lock:
                        results.append((port, state, banner, {}))
                        self.total_ports_scanned += 1
                        
                except socket.timeout:
                    # No response - could be open or filtered
                    state = ServiceState.OPEN_FILTERED
                    
                    with self.lock:
                        results.append((port, state, "", {}))
                        self.total_ports_scanned += 1
                        
                except socket.error:
                    # ICMP port unreachable - closed
                    state = ServiceState.CLOSED
                    
                    with self.lock:
                        results.append((port, state, "", {}))
                        self.total_ports_scanned += 1
                        
                sock.close()
                
            except Exception as e:
                logger.debug(f"UDP scan error on port {port}: {e}")
        
        return sorted(results, key=lambda x: x[0])
    
    # ========================================================================
    # Service Detection Methods
    # ========================================================================
    
    def get_service_probes(self, port: int) -> List[bytes]:
        """
        Get appropriate probes for service detection
        
        Args:
            port: Port number
            
        Returns:
            List of probe bytes
        """
        probes = {
            21: [b"HELP\r\n", b"SYST\r\n"],
            22: [b"SSH-2.0-OpenSSH_Test\r\n"],
            23: [b"\r\n"],
            25: [b"HELP\r\n", b"EHLO test.com\r\n"],
            80: [b"HEAD / HTTP/1.0\r\n\r\n", b"GET / HTTP/1.0\r\n\r\n"],
            110: [b"CAPA\r\n"],
            143: [b"A001 CAPABILITY\r\n"],
            443: [b"HEAD / HTTP/1.0\r\n\r\n"],
            445: [b"\x00\x00\x00\x90\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x00\x00\x00"],
            3306: [b"\x0a\x00\x00\x00\x0a\x35\x2e\x35\x2e\x35\x2d\x31\x30\x2e\x32\x2e\x33\x37\x2d\x4d\x41\x52\x49\x41\x44\x42\x00"],
            5432: [b"\x00\x00\x00\x08\x04\xd2\x16\x2f"],
            6379: [b"INFO\r\n", b"PING\r\n"],
            27017: [b"\x3a\x00\x00\x00\x41\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"],
        }
        
        return probes.get(port, [b"\r\n", b"\n"])
    
    def get_service_info(self, sock: socket.socket, port: int) -> Dict:
        """
        Get detailed service information
        
        Args:
            sock: Connected socket
            port: Port number
            
        Returns:
            Dictionary with service information
        """
        info = {}
        
        try:
            if port == 80:
                sock.send(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                response = sock.recv(4096).decode('utf-8', errors='ignore')
                
                # Extract Server header
                for line in response.split('\r\n'):
                    if line.lower().startswith('server:'):
                        info['server'] = line[7:].strip()
                    elif line.lower().startswith('x-powered-by:'):
                        info['powered_by'] = line[13:].strip()
                        
            elif port == 21:
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                info['ftp_banner'] = response.strip()
                
            elif port == 22:
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                info['ssh_banner'] = response.strip()
                
            elif port == 25:
                sock.send(b"EHLO test.com\r\n")
                response = sock.recv(4096).decode('utf-8', errors='ignore')
                info['smtp_features'] = [line for line in response.split('\r\n') if line]
                
        except:
            pass
            
        return info
    
    def identify_service(self, port: int, banner: str, service_info: Dict) -> str:
        """
        Identify service running on port
        
        Args:
            port: Port number
            banner: Service banner
            service_info: Additional service information
            
        Returns:
            Service name
        """
        # Check signatures dictionary first
        if port in self.SERVICE_SIGNATURES:
            return self.SERVICE_SIGNATURES[port][0]
        
        # Try to identify from banner
        banner_lower = banner.lower()
        
        # Web servers
        if 'apache' in banner_lower:
            return 'apache'
        elif 'nginx' in banner_lower:
            return 'nginx'
        elif 'iis' in banner_lower:
            return 'iis'
        elif 'tomcat' in banner_lower:
            return 'tomcat'
        
        # Database
        elif 'mysql' in banner_lower:
            return 'mysql'
        elif 'postgresql' in banner_lower:
            return 'postgresql'
        elif 'mongodb' in banner_lower:
            return 'mongodb'
        elif 'redis' in banner_lower:
            return 'redis'
        
        # Mail
        elif 'smtp' in banner_lower or 'postfix' in banner_lower:
            return 'smtp'
        elif 'pop3' in banner_lower:
            return 'pop3'
        elif 'imap' in banner_lower:
            return 'imap'
        
        # Remote access
        elif 'ssh' in banner_lower or 'openssh' in banner_lower:
            return 'ssh'
        elif 'ftp' in banner_lower:
            return 'ftp'
        elif 'telnet' in banner_lower:
            return 'telnet'
        elif 'vnc' in banner_lower or 'rfb' in banner_lower:
            return 'vnc'
        elif 'rdp' in banner_lower or 'terminal' in banner_lower:
            return 'rdp'
        
        return 'unknown'
    
    def extract_version(self, banner: str) -> str:
        """
        Extract version information from banner
        
        Args:
            banner: Service banner
            
        Returns:
            Version string
        """
        import re
        
        # Common version patterns
        patterns = [
            r'(\d+\.\d+(?:\.\d+)?(?:-\w+)?)',  # 1.2.3, 1.2, 1.2.3-beta
            r'v(\d+\.\d+(?:\.\d+)?)',           # v1.2.3
            r'version (\d+\.\d+(?:\.\d+)?)',     # version 1.2.3
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return ""
    
    # ========================================================================
    # OS Fingerprinting
    # ========================================================================
    
    def os_fingerprint(self, host: str) -> Tuple[str, float]:
        """
        Perform OS fingerprinting
        
        Args:
            host: Target host
            
        Returns:
            Tuple of (OS name, accuracy percentage)
        """
        try:
            # Create raw socket for TCP fingerprinting
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.settimeout(3)
            
            # Send various probes to identify OS
            probes = [
                self.tcp_probe(host, 80, flags='S'),
                self.tcp_probe(host, 80, flags='A'),
                self.tcp_probe(host, 80, flags='F'),
            ]
            
            responses = []
            for probe in probes:
                response = self.send_probe(probe)
                if response:
                    responses.append(response)
            
            # Analyze responses
            if responses:
                # Extract TCP/IP stack characteristics
                ttl = self.extract_ttl(responses[0])
                window_size = self.extract_window_size(responses[0])
                options = self.extract_tcp_options(responses[0])
                
                # Match against known signatures
                best_match = None
                best_accuracy = 0
                
                for os_name, signature in self.OS_SIGNATURES.items():
                    accuracy = 0
                    matches = 0
                    
                    if ttl and abs(ttl - signature['ttl']) <= 10:
                        matches += 1
                    if window_size and window_size == signature['window_size']:
                        matches += 1
                    if options and self.compare_tcp_options(options, signature['tcp_options']):
                        matches += 1
                    
                    if matches > 0:
                        accuracy = (matches / 3) * 100
                        if accuracy > best_accuracy:
                            best_accuracy = accuracy
                            best_match = os_name
                
                if best_match:
                    return best_match, best_accuracy
                    
        except Exception as e:
            logger.debug(f"OS fingerprinting failed: {e}")
            
        return "Unknown", 0.0
    
    def tcp_probe(self, host: str, port: int, flags='S') -> bytes:
        """Create TCP probe packet"""
        # Implementation for creating TCP probe
        pass
    
    def send_probe(self, probe: bytes):
        """Send probe and get response"""
        # Implementation for sending probe
        pass
    
    def extract_ttl(self, packet) -> int:
        """Extract TTL from packet"""
        # Implementation for TTL extraction
        pass
    
    def extract_window_size(self, packet) -> int:
        """Extract TCP window size"""
        # Implementation for window size extraction
        pass
    
    def extract_tcp_options(self, packet) -> List[str]:
        """Extract TCP options"""
        # Implementation for TCP options extraction
        pass
    
    def compare_tcp_options(self, options1: List[str], options2: List[str]) -> bool:
        """Compare TCP options"""
        # Simple comparison for now
        common = set(options1) & set(options2)
        return len(common) >= len(options2) // 2
    
    def get_vendor_by_mac(self, mac: str) -> str:
        """
        Identify vendor by MAC address
        
        Args:
            mac: MAC address
            
        Returns:
            Vendor name
        """
        # Simplified vendor list
        vendors = {
            '00:50:56': 'VMware',
            '00:0C:29': 'VMware',
            '00:05:69': 'VMware',
            '08:00:27': 'VirtualBox',
            '00:15:5D': 'Hyper-V',
            '00:50:56': 'VMware',
            '02:00:4C': 'Xen',
            '00:1C:42': 'Parallels',
        }
        
        prefix = mac[:8].upper()
        return vendors.get(prefix, 'Unknown')
    
    # ========================================================================
    # Vulnerability Assessment
    # ========================================================================
    
    def calculate_vulnerability_score(self, port: int, service: str) -> float:
        """
        Calculate vulnerability score based on port and service
        
        Args:
            port: Port number
            service: Service name
            
        Returns:
            Vulnerability score (0-10)
        """
        # High-risk ports
        high_risk = [21, 23, 445, 3389, 5900, 5800]
        medium_risk = [80, 443, 22, 25, 110, 143, 3306, 5432]
        low_risk = [53, 123, 161]
        
        if port in high_risk:
            base_score = 7.0
        elif port in medium_risk:
            base_score = 4.0
        elif port in low_risk:
            base_score = 1.0
        else:
            base_score = 0.5
        
        # Adjust based on service
        vulnerable_services = ['ftp', 'telnet', 'smb', 'rdp']
        if service.lower() in vulnerable_services:
            base_score += 2.0
        
        return min(base_score, 10.0)
    
    # ========================================================================
    # Main Scanning Method
    # ========================================================================
    
    def scan(self, target: str, ports: str = "1-1024", 
             scan_type: str = "tcp_connect", 
             output_format: str = "table",
             output_file: str = None,
             service_detection: bool = True,
             os_detection: bool = True) -> ScanResult:
        """
        Main scanning method
        
        Args:
            target: Target IP, range, or hostname
            ports: Port range or list (e.g., "1-1024" or "22,80,443")
            scan_type: Type of scan to perform
            output_format: Output format (table, json, csv)
            output_file: Output file path
            service_detection: Enable service detection
            os_detection: Enable OS detection
            
        Returns:
            ScanResult object
        """
        start_time = datetime.now()
        
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Professional Port Scanner v2.0.0{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"Target: {target}")
        print(f"Ports: {ports}")
        print(f"Scan Type: {scan_type}")
        print(f"Service Detection: {service_detection}")
        print(f"OS Detection: {os_detection}")
        print(f"{Fore.CYAN}{'-'*70}{Style.RESET_ALL}")
        
        # Parse ports
        port_list = self.parse_ports(ports)
        print(f"Scanning {len(port_list)} ports")
        
        # Discover live hosts
        live_hosts = self.discover_hosts(target)
        
        if not live_hosts:
            print(f"{Fore.RED}[-] No live hosts found{Style.RESET_ALL}")
            return None
        
        # Scan each host
        hosts_info = []
        scan_type_enum = ScanType[scan_type.upper()]
        
        for host in live_hosts:
            if self.stop_scan:
                break
                
            host_info = self.scan_host(host, port_list, scan_type_enum)
            hosts_info.append(host_info)
        
        # Create scan result
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        result = ScanResult(
            target=target,
            scan_type=scan_type_enum,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            hosts=hosts_info,
            command_line=" ".join(sys.argv),
            scan_params={
                "ports": ports,
                "service_detection": service_detection,
                "os_detection": os_detection,
                "threads": self.max_threads,
                "timeout": self.timeout
            }
        )
        
        # Generate summary
        result.summary = self.generate_summary(result)
        
        # Output results
        self.output_results(result, output_format, output_file)
        
        return result
    
    def parse_ports(self, ports: str) -> List[int]:
        """
        Parse port string into list of ports
        
        Args:
            ports: Port range or list
            
        Returns:
            List of ports
        """
        port_list = []
        
        try:
            if '-' in ports:
                # Range format
                start, end = map(int, ports.split('-'))
                port_list = list(range(start, end + 1))
            elif ',' in ports:
                # Comma-separated list
                port_list = [int(p.strip()) for p in ports.split(',')]
            else:
                # Single port
                port_list = [int(ports)]
        except:
            # Default to common ports
            port_list = list(self.SERVICE_SIGNATURES.keys())
        
        return sorted(port_list)
    
    def generate_summary(self, result: ScanResult) -> Dict:
        """
        Generate scan summary
        
        Args:
            result: ScanResult object
            
        Returns:
            Summary dictionary
        """
        summary = {
            "total_hosts": len(result.hosts),
            "total_open_ports": sum(len(h.open_ports) for h in result.hosts),
            "total_filtered_ports": sum(len(h.filtered_ports) for h in result.hosts),
            "hosts_by_os": {},
            "services_found": {},
            "vulnerability_stats": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }
        
        for host in result.hosts:
            # Count OS
            if host.os_guess:
                summary["hosts_by_os"][host.os_guess] = summary["hosts_by_os"].get(host.os_guess, 0) + 1
            
            # Count services
            for port in host.ports:
                if port.state == ServiceState.OPEN:
                    summary["services_found"][port.service] = summary["services_found"].get(port.service, 0) + 1
                
                # Vulnerability stats
                if port.vulnerability_score >= 8.0:
                    summary["vulnerability_stats"]["critical"] += 1
                elif port.vulnerability_score >= 6.0:
                    summary["vulnerability_stats"]["high"] += 1
                elif port.vulnerability_score >= 4.0:
                    summary["vulnerability_stats"]["medium"] += 1
                elif port.vulnerability_score > 0:
                    summary["vulnerability_stats"]["low"] += 1
        
        return summary
    
    # ========================================================================
    # Output Methods
    # ========================================================================
    
    def output_results(self, result: ScanResult, format: str, output_file: str = None):
        """
        Output scan results in specified format
        
        Args:
            result: ScanResult object
            format: Output format
            output_file: Output file path
        """
        if format == "json":
            self.output_json(result, output_file)
        elif format == "csv":
            self.output_csv(result, output_file)
        elif format == "html":
            self.output_html(result, output_file)
        else:
            self.output_table(result)
    
    def output_table(self, result: ScanResult):
        """
        Output results as formatted table
        
        Args:
            result: ScanResult object
        """
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SCAN RESULTS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        
        print(f"\nScan Information:")
        print(f"  Target: {result.target}")
        print(f"  Scan Type: {result.scan_type.value}")
        print(f"  Start Time: {result.start_time}")
        print(f"  End Time: {result.end_time}")
        print(f"  Duration: {result.duration:.2f} seconds")
        
        print(f"\nSummary:")
        print(f"  Total Hosts: {result.summary['total_hosts']}")
        print(f"  Open Ports: {result.summary['total_open_ports']}")
        print(f"  Filtered Ports: {result.summary['total_filtered_ports']}")
        
        if result.summary['services_found']:
            print(f"\nServices Found:")
            for service, count in sorted(result.summary['services_found'].items()):
                print(f"  {service}: {count}")
        
        if result.summary['vulnerability_stats']['critical'] > 0:
            print(f"\n{Fore.RED}Vulnerability Assessment:{Style.RESET_ALL}")
            print(f"  {Fore.RED}Critical: {result.summary['vulnerability_stats']['critical']}{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}High: {result.summary['vulnerability_stats']['high']}{Style.RESET_ALL}")
            print(f"  {Fore.CYAN}Medium: {result.summary['vulnerability_stats']['medium']}{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}Low: {result.summary['vulnerability_stats']['low']}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Host Details:{Style.RESET_ALL}")
        for host in result.hosts:
            print(f"\n{Fore.YELLOW}Host: {host.ip_address} ({host.hostname}){Style.RESET_ALL}")
            if host.mac_address:
                print(f"  MAC: {host.mac_address} ({host.vendor})")
            if host.os_guess:
                print(f"  OS: {host.os_guess} (Accuracy: {host.os_accuracy:.1f}%)")
            print(f"  Open Ports: {len(host.open_ports)}")
            
            if host.open_ports:
                print(f"\n  {'PORT':<8} {'STATE':<10} {'SERVICE':<15} {'VERSION':<20} {'VULN':<6}")
                print(f"  {'-'*70}")
                
                for port in sorted(host.ports, key=lambda x: x.port):
                    if port.state == ServiceState.OPEN:
                        vuln_color = Fore.RED if port.vulnerability_score >= 6.0 else Fore.YELLOW
                        print(f"  {port.port:<8} {port.state.value:<10} {port.service:<15} {port.version:<20} {vuln_color}{port.vulnerability_score:<6.1f}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    
    def output_json(self, result: ScanResult, output_file: str = None):
        """
        Output results as JSON
        
        Args:
            result: ScanResult object
            output_file: Output file path
        """
        import json
        
        # Convert to dictionary
        data = {
            "scan_info": {
                "target": result.target,
                "scan_type": result.scan_type.value,
                "start_time": result.start_time.isoformat(),
                "end_time": result.end_time.isoformat(),
                "duration": result.duration,
                "command_line": result.command_line,
                "parameters": result.scan_params
            },
            "summary": result.summary,
            "hosts": []
        }
        
        for host in result.hosts:
            host_dict = {
                "ip_address": host.ip_address,
                "hostname": host.hostname,
                "mac_address": host.mac_address,
                "vendor": host.vendor,
                "os_guess": host.os_guess,
                "os_accuracy": host.os_accuracy,
                "scan_time": host.scan_time,
                "ports": []
            }
            
            for port in host.ports:
                port_dict = asdict(port)
                port_dict['state'] = port.state.value
                host_dict['ports'].append(port_dict)
            
            data['hosts'].append(host_dict)
        
        # Output
        json_data = json.dumps(data, indent=2)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_data)
            print(f"{Fore.GREEN}[+] Results saved to {output_file}{Style.RESET_ALL}")
        else:
            print(json_data)
    
    def output_csv(self, result: ScanResult, output_file: str = None):
        """
        Output results as CSV
        
        Args:
            result: ScanResult object
            output_file: Output file path
        """
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Host', 'Hostname', 'Port', 'Protocol', 'State', 
                        'Service', 'Version', 'Banner', 'Vulnerability Score'])
        
        # Write data
        for host in result.hosts:
            for port in host.ports:
                writer.writerow([
                    host.ip_address,
                    host.hostname,
                    port.port,
                    port.protocol,
                    port.state.value,
                    port.service,
                    port.version,
                    port.banner[:100] if port.banner else '',
                    port.vulnerability_score
                ])
        
        csv_data = output.getvalue()
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(csv_data)
            print(f"{Fore.GREEN}[+] Results saved to {output_file}{Style.RESET_ALL}")
        else:
            print(csv_data)
    
    def output_html(self, result: ScanResult, output_file: str = None):
        """
        Output results as HTML report
        
        Args:
            result: ScanResult object
            output_file: Output file path
        """
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Port Scan Results - {target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                h2 {{ color: #666; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #4CAF50; color: white; }}
                tr:nth-child(even) {{ background-color: #f2f2f2; }}
                .open {{ color: green; }}
                .filtered {{ color: orange; }}
                .closed {{ color: red; }}
                .summary {{ background-color: #f9f9f9; padding: 15px; margin-bottom: 20px; }}
                .vuln-critical {{ color: red; font-weight: bold; }}
                .vuln-high {{ color: orange; font-weight: bold; }}
                .vuln-medium {{ color: blue; }}
                .vuln-low {{ color: green; }}
            </style>
        </head>
        <body>
            <h1>Port Scan Results</h1>
            
            <div class="summary">
                <h2>Scan Information</h2>
                <p><strong>Target:</strong> {target}</p>
                <p><strong>Scan Type:</strong> {scan_type}</p>
                <p><strong>Start Time:</strong> {start_time}</p>
                <p><strong>End Time:</strong> {end_time}</p>
                <p><strong>Duration:</strong> {duration:.2f} seconds</p>
            </div>
            
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Total Hosts:</strong> {total_hosts}</p>
                <p><strong>Open Ports:</strong> {open_ports}</p>
                <p><strong>Filtered Ports:</strong> {filtered_ports}</p>
                <p><strong>Services Found:</strong> {services}</p>
            </div>
            
            <h2>Host Details</h2>
            {host_tables}
            
            <script>
                // Add any JavaScript functionality here
            </script>
        </body>
        </html>
        """
        
        # Generate host tables
        host_tables = ""
        for host in result.hosts:
            host_tables += f"""
            <h3>Host: {host.ip_address} ({host.hostname})</h3>
            <p>OS: {host.os_guess} (Accuracy: {host.os_accuracy:.1f}%)</p>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>Vulnerability</th>
                </tr>
            """
            
            for port in sorted(host.ports, key=lambda x: x.port):
                vuln_class = ""
                if port.vulnerability_score >= 8.0:
                    vuln_class = "vuln-critical"
                elif port.vulnerability_score >= 6.0:
                    vuln_class = "vuln-high"
                elif port.vulnerability_score >= 4.0:
                    vuln_class = "vuln-medium"
                elif port.vulnerability_score > 0:
                    vuln_class = "vuln-low"
                
                host_tables += f"""
                <tr>
                    <td>{port.port}</td>
                    <td>{port.protocol}</td>
                    <td class="{port.state.value}">{port.state.value}</td>
                    <td>{port.service}</td>
                    <td>{port.version}</td>
                    <td class="{vuln_class}">{port.vulnerability_score}</td>
                </tr>
                """
            
            host_tables += "</table>"
        
        # Prepare services string
        services = ", ".join([f"{k} ({v})" for k, v in result.summary['services_found'].items()])
        
        # Fill template
        html_content = html_template.format(
            target=result.target,
            scan_type=result.scan_type.value,
            start_time=result.start_time,
            end_time=result.end_time,
            duration=result.duration,
            total_hosts=result.summary['total_hosts'],
            open_ports=result.summary['total_open_ports'],
            filtered_ports=result.summary['total_filtered_ports'],
            services=services,
            host_tables=host_tables
        )
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(html_content)
            print(f"{Fore.GREEN}[+] HTML report saved to {output_file}{Style.RESET_ALL}")
        else:
            print(html_content)

# ============================================================================
# Command Line Interface
# ============================================================================

def main():
    """Main function for command line interface"""
    parser = argparse.ArgumentParser(
        description="Professional Enterprise-Grade Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 port_scanner.py 192.168.1.1
  python3 port_scanner.py 192.168.1.0/24 -p 1-1024 -t syn -o json -f results.json
  python3 port_scanner.py example.com -p 80,443,8080 -T 200 -v
  python3 port_scanner.py 10.0.0.1-10.0.0.255 -t udp --stealth
        """
    )
    
    # Target specification
    parser.add_argument('target', help='Target IP, range (e.g., 192.168.1.1-100), or CIDR (e.g., 192.168.1.0/24)')
    
    # Port specification
    parser.add_argument('-p', '--ports', default='1-1024', 
                       help='Port range or list (default: 1-1024)')
    
    # Scan type
    parser.add_argument('-t', '--type', default='tcp_connect',
                       choices=['tcp_connect', 'tcp_syn', 'udp'],
                       help='Scan type (default: tcp_connect)')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-f', '--format', default='table',
                       choices=['table', 'json', 'csv', 'html'],
                       help='Output format (default: table)')
    
    # Performance options
    parser.add_argument('-T', '--threads', type=int, default=100,
                       help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=2.0,
                       help='Connection timeout in seconds (default: 2.0)')
    
    # Features
    parser.add_argument('--stealth', action='store_true',
                       help='Enable stealth scanning techniques')
    parser.add_argument('--no-service', action='store_true',
                       help='Disable service detection')
    parser.add_argument('--no-os', action='store_true',
                       help='Disable OS detection')
    
    # Miscellaneous
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--version', action='version',
                       version='Professional Port Scanner v2.0.0')
    
    args = parser.parse_args()
    
    # Check for root privileges if using SYN or UDP scan
    if args.type in ['tcp_syn', 'udp'] and os.geteuid() != 0:
        print(f"{Fore.RED}Error: {args.type} scan requires root privileges{Style.RESET_ALL}")
        print("Please run with sudo or use tcp_connect scan")
        sys.exit(1)
    
    # Create scanner instance
    scanner = ProfessionalPortScanner(
        timeout=args.timeout,
        threads=args.threads,
        stealth=args.stealth,
        verbose=args.verbose
    )
    
    # Perform scan
    try:
        result = scanner.scan(
            target=args.target,
            ports=args.ports,
            scan_type=args.type,
            output_format=args.format,
            output_file=args.output,
            service_detection=not args.no_service,
            os_detection=not args.no_os
        )
        
        if result:
            print(f"\n{Fore.GREEN}[+] Scan completed successfully{Style.RESET_ALL}")
            sys.exit(0)
        else:
            print(f"\n{Fore.RED}[-] Scan failed{Style.RESET_ALL}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        logger.error(f"Scan error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
