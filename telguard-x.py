#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════╗
║  TELGUARD-X v4.0 - Mobile Network Penetration Testing Framework║
║  GTP (GPRS Tunneling Protocol) Host Discovery & Analysis       ║
║  VERBOSE MODE - Shows ALL Activities A-Z                       ║
╚═══════════════════════════════════════════════════════════════════╝
"""

import socket
import struct
import random
import time
import threading
import queue
import json
import csv
import os
import sys
import signal
import hashlib
import base64
import subprocess
from datetime import datetime
from ipaddress import ip_network, ip_address
from collections import defaultdict
from typing import List, Dict, Optional, Tuple, Union, Any
import requests
import re
import ssl
import urllib.parse
from http.client import HTTPConnection
import warnings
warnings.filterwarnings('ignore')

# ============ CONSTANTS ============
GTP_C_PORT = 2123
GTP_U_PORT = 2152
PFCP_PORT = 8805
S1AP_PORT = 36412
NGAP_PORT = 38412
DIAMETER_PORT = 3868

NF_ENDPOINTS = {
    'nrf': '/nrf/v1/nf-instances',
    'smf': '/nsmf/v1/sessions',
    'amf': '/namf/v1/ue-contexts',
    'udm': '/nudm/v1/ue-contexts',
    'ausf': '/nausf/v1/auth',
    'pcf': '/npcf/v1/policies',
    'nssf': '/nnssf/v1/nsi',
    'nef': '/nnef/v1/exposure',
    'nwdaf': '/nnwdaf/v1/analytics'
}

CONTAINER_INDICATORS = {
    '/.dockerenv': 'Docker',
    '/var/run/secrets/kubernetes.io': 'Kubernetes',
    '/.container': 'Podman',
    '/var/run/docker.sock': 'Docker-Socket',
    '/run/containerd': 'Containerd',
    'ecs-container': 'AWS-ECS',
    'container-id': 'Generic-Container'
}

JWT_PAYLOADS = [
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.timestamp"
]

API_SECURITY_PAYLOADS = {
    'SQL Injection': ["' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT NULL--"],
    'XSS': ["<script>alert('XSS')</script>", "javascript:alert('XSS')"],
    'Path Traversal': ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini"],
    'Command Injection': ["; ls -la", "| whoami", "&& cat /etc/passwd"],
    'NoSQL Injection': ["{ $ne: null }", "{ $or: [ { 'username': 'admin' }, { 'password': { $regex: '.*' } } ] }"],
    'XXE': ["<?xml version='1.0'?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>"],
    'SSRF': ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8080/admin"],
    'LDAP Injection': ["*)(&", "admin*)((|userPassword=*"]
}

# ============ BANNER ============
BANNER = """
\033[95m
⣿⣿⣿⡟⢻⣿⣿⠟⢻⣿⣿⠟⣻⣿⣿⣿⣿⣟⠻⣿⣿⡟⠻⣿⣿⡟⢻⣿⣿⣿
⣿⣿⣿⡇⣿⣿⣿⠀⣿⣿⣿⢠⣿⡟⠉⠉⢻⣿⡄⣿⣿⣿⠀⣿⣿⣿⢸⣿⣿⣿
⣿⣿⣿⡇⢿⣿⣿⠀⢿⣿⣿⠈⣿⣷⣤⣤⣾⣿⠁⣿⣿⡿⠀⣿⣿⡿⢸⣿⣿⣿
⣿⣿⣿⣧⠸⣿⣿⣧⠈⢿⣿⣷⣼⠇⢸⡇⠸⣧⣾⣿⡿⠁⣼⣿⣿⠇⣼⣿⣿⣿
⣿⣿⣿⣿⣆⠹⣿⣿⣧⡀⢻⣿⡟⢀⣿⣿⡀⢻⣿⡟⢀⣼⣿⣿⠏⣰⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣦⡘⠻⣿⣿⣿⣿⠁⣼⣿⣿⣧⠈⣿⣿⣿⣿⠟⢃⣴⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣦⣈⢿⣿⡇⢰⣿⣿⣿⣿⡆⢸⣿⡿⣁⣴⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⣿⣿⣿⣿⣿⣿⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⢠⠤⠈⠉⠉⠁⠤⡄⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⡀⠐⠲⠿⠿⠖⠂⢀⠀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠸⠛⠋⣀⣤⣤⣀⠙⠛⠇⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⡏⢠⣀⣈⠙⠛⠛⠛⠛⠋⣁⣀⡄⢹⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⡿⠀⢈⣉⣠⣤⣴⣶⣶⣦⣤⣄⣉⡁⠀⢿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⠃⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠘⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
\033[0m
\033[93m
╔═══════════════════════════════════════════════════════════════╗
║  TELGUARD-X v4.0 - Mobile Network Penetration Testing       ║
║  GTP Host Discovery & Analysis Framework (Modern Edition)   ║
║  VERBOSE MODE - Full Activity Logging                       ║
╚═══════════════════════════════════════════════════════════════╝
AUTHOR: SYLHETYHACKVENGER (THE-ERROR808)
\033[0m
"""

# ============ COLORS ============
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

# ============ VERBOSE LOGGER ============
class VerboseLogger:
    """Detailed logging system for all activities"""
    
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.log_file = f"logs/telguard_verbose_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        os.makedirs('logs', exist_ok=True)
        self.activity_counter = 0
        self.start_time = datetime.now()
        
    def log(self, activity: str, detail: str = "", level: str = "INFO", color: str = Colors.WHITE):
        """Log activity with timestamp and details"""
        if not self.enabled:
            return
            
        self.activity_counter += 1
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        # Prepare log message
        log_msg = f"[{timestamp}] [{elapsed:6.2f}s] [{self.activity_counter:04d}] [{level}] {activity}"
        if detail:
            log_msg += f"\n{' ' * 35}└─ {detail}"
        
        # Print to console with color
        print(f"{color}{log_msg}{Colors.RESET}")
        
        # Write to log file
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(log_msg + "\n")
            
    def step(self, activity: str, detail: str = ""):
        """Log a step activity"""
        self.log(f"📌 {activity}", detail, "STEP", Colors.CYAN)
        
    def info(self, activity: str, detail: str = ""):
        """Log info activity"""
        self.log(f"ℹ️ {activity}", detail, "INFO", Colors.GREEN)
        
    def warning(self, activity: str, detail: str = ""):
        """Log warning activity"""
        self.log(f"⚠️ {activity}", detail, "WARN", Colors.YELLOW)
        
    def error(self, activity: str, detail: str = ""):
        """Log error activity"""
        self.log(f"❌ {activity}", detail, "ERROR", Colors.RED)
        
    def success(self, activity: str, detail: str = ""):
        """Log success activity"""
        self.log(f"✅ {activity}", detail, "SUCCESS", Colors.GREEN)
        
    def debug(self, activity: str, detail: str = ""):
        """Log debug activity (detailed)"""
        self.log(f"🔍 {activity}", detail, "DEBUG", Colors.DIM)
        
    def packet(self, direction: str, src: str, dst: str, proto: str, size: int):
        """Log packet activity"""
        self.log(f"📦 {direction} Packet", 
                 f"{proto} {src} -> {dst} ({size} bytes)", 
                 "PACKET", Colors.MAGENTA)
        
    def result(self, activity: str, detail: str = ""):
        """Log result activity"""
        self.log(f"📊 {activity}", detail, "RESULT", Colors.BLUE)

# ============ MAIN SCANNER ============
class TELGUARDX:
    """Enhanced TELGUARD-X Scanner Engine with Full Verbose"""
    
    def __init__(self):
        self.verbose = True  # Enable verbose by default
        self.logger = VerboseLogger(self.verbose)
        
        self.targets = []
        self.options = {
            'workers': 10,
            'stealth': False,
            'verbose': True,
            'ports': [22, 80, 443, 8080, 2123, 5060, 3389, 8443, 2152, 8805, 36412, 38412, 3868],
            'timeout': 3,
            'raw_sockets': False,
            'threat_intel': True,
            'report_format': 'html',
            'api_testing': True,
            'container_detection': True,
            'auth_testing': True,
            'anomaly_detection': True
        }
        self.results = {
            'vulnerable': [],
            'suspicious': [],
            'scanned': [],
            'errors': [],
            'stats': {
                'packets_sent': 0,
                'packets_received': 0,
                'beacons_detected': 0,
                'start_time': datetime.now(),
                'duration': 0,
                'anomalies_detected': 0,
                'containers_detected': 0,
                'api_vulnerabilities': 0,
                'targets_generated': 0,
                'ports_scanned': 0,
                'services_identified': 0
            }
        }
        self.running = True
        self.lock = threading.Lock()
        self.baseline_stats = {}
        
        self.logger.info("TELGUARD-X v4.0 Initialized", "Scanner engine ready")
        
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        os.makedirs('reports', exist_ok=True)
        os.makedirs('logs', exist_ok=True)
        os.makedirs('targets', exist_ok=True)
        os.makedirs('reports/html', exist_ok=True)
        
        self.logger.info("Directories Created", "reports/, logs/, targets/, reports/html/")
        self.load_config()
    
    def load_config(self):
        """Load configuration from file"""
        self.logger.step("Loading Configuration", "Checking for telguard_config.json")
        
        config_file = 'telguard_config.json'
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    self.options.update(config)
                self.logger.success("Configuration Loaded", f"From {config_file}")
            except Exception as e:
                self.logger.error("Config Load Failed", str(e))
        else:
            default_config = {
                'workers': 10,
                'stealth': False,
                'timeout': 3,
                'ports': [22, 80, 443, 8080, 2123, 5060, 3389, 8443, 2152, 8805, 36412, 38412, 3868],
                'api_testing': True,
                'container_detection': True,
                'auth_testing': True,
                'anomaly_detection': True
            }
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            self.logger.info("Default Config Created", "telguard_config.json")
    
    def signal_handler(self, sig, frame):
        """Handle termination signals"""
        self.logger.warning("Interrupt Signal Received", "User terminated scan")
        print(f"\n{Colors.YELLOW}[!] Interrupted by user{Colors.RESET}")
        self.running = False
        self.save_results()
        sys.exit(0)
    
    def print_banner(self):
        """Display the banner"""
        print(BANNER)
        self.logger.info("Banner Displayed", f"TELGUARD-X v4.0 at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    def generate_targets(self, target_input: str) -> List[str]:
        """Generate target list from various input formats"""
        self.logger.step("Generating Targets", f"Input: {target_input}")
        targets = []
        
        if os.path.exists(target_input):
            self.logger.info("File Input Detected", target_input)
            try:
                with open(target_input, 'r') as f:
                    lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    self.logger.debug(f"Read {len(lines)} lines from file")
                    for line in lines:
                        targets.extend(self.parse_target(line))
            except Exception as e:
                self.logger.error("File Read Error", str(e))
                return []
        else:
            self.logger.debug("Single Target Input", target_input)
            targets.extend(self.parse_target(target_input))
            
        targets = sorted(list(set(targets)))
        self.results['stats']['targets_generated'] = len(targets)
        
        self.logger.success(f"Generated {len(targets)} Targets", 
                           f"First 5: {targets[:5] if len(targets) > 5 else targets}")
        return targets
    
    def parse_target(self, target: str) -> List[str]:
        """Parse individual target (IP, CIDR, domain, range)"""
        self.logger.debug(f"Parsing Target: {target}")
        targets = []
        
        try:
            if '/' in target:
                # CIDR notation
                self.logger.debug(f"CIDR Notation Detected: {target}")
                network = ip_network(target, strict=False)
                hosts = list(network.hosts())
                self.logger.debug(f"CIDR Range: {len(hosts)} hosts")
                for ip in hosts:
                    targets.append(str(ip))
                    
            elif '-' in target:
                # IP range
                self.logger.debug(f"IP Range Detected: {target}")
                parts = target.split('-')
                if len(parts) == 2:
                    base_ip = parts[0].rsplit('.', 1)[0]
                    start = int(parts[0].rsplit('.', 1)[1])
                    end = int(parts[1])
                    self.logger.debug(f"Range: {base_ip}.{start}-{end}")
                    for i in range(start, end + 1):
                        targets.append(f"{base_ip}.{i}")
                        
            elif target.replace('.', '').isdigit():
                # Single IP
                self.logger.debug(f"Single IP: {target}")
                targets.append(target)
                
            else:
                # Domain
                self.logger.debug(f"Domain Resolution: {target}")
                try:
                    ip = socket.gethostbyname(target)
                    self.logger.success(f"Domain Resolved", f"{target} -> {ip}")
                    targets.append(ip)
                except Exception as e:
                    self.logger.error(f"Domain Resolution Failed: {target}", str(e))
                    
        except Exception as e:
            self.logger.error(f"Parse Error: {target}", str(e))
            
        return targets
    
    def create_raw_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, 
                          flags: int, payload: bytes = b'') -> Optional[bytes]:
        """Create raw TCP packet"""
        self.logger.debug(f"Creating Raw Packet", f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} flags:{flags}")
        
        try:
            total_length = 20 + 20 + len(payload)
            
            # IP Header
            ip_header = struct.pack('!BBHHHBBH4s4s',
                0x45, 0x00, total_length, 0, 0, 64, 6, 0,
                socket.inet_aton(src_ip),
                socket.inet_aton(dst_ip)
            )
            
            # TCP Header
            seq_num = random.randint(0, 0xFFFFFFFF)
            tcp_header = struct.pack('!HHLLBBHHH',
                src_port, dst_port,
                seq_num,
                0,
                5 << 4,
                flags,
                1024,
                0, 0
            )
            
            # Pseudo header for checksum
            psh = struct.pack('!4s4sBBH',
                socket.inet_aton(src_ip),
                socket.inet_aton(dst_ip),
                0, 6,
                len(tcp_header) + len(payload)
            )
            
            tcp_checksum = self.checksum(psh + tcp_header + payload)
            ip_checksum = self.checksum(ip_header)
            
            ip_header = ip_header[:10] + struct.pack('!H', ip_checksum) + ip_header[12:]
            tcp_header = tcp_header[:16] + struct.pack('!H', tcp_checksum) + tcp_header[18:]
            
            packet = ip_header + tcp_header + payload
            self.logger.packet("SENT", src_ip, dst_ip, f"TCP-{flags}", len(packet))
            
            return packet
            
        except Exception as e:
            self.logger.error("Raw Packet Creation Failed", str(e))
            return None
    
    def checksum(self, data: bytes) -> int:
        """Calculate checksum"""
        if len(data) % 2 != 0:
            data += b'\x00'
        s = sum(struct.unpack('!%dH' % (len(data)//2), data))
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return ~s & 0xFFFF
    
    def tcp_connect_scan(self, target_ip: str, port: int) -> bool:
        """TCP connect scan with verbose logging"""
        self.logger.debug(f"TCP Connect Scan", f"{target_ip}:{port}")
        
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.options['timeout'])
            
            result = sock.connect_ex((target_ip, port))
            elapsed = (time.time() - start_time) * 1000
            
            sock.close()
            self.results['stats']['packets_sent'] += 1
            
            if result == 0:
                self.logger.packet("RECEIVED", f"{target_ip}:{port}", "LOCAL", "TCP-OPEN", 0)
                self.logger.success(f"Port {port} Open", f"Response time: {elapsed:.1f}ms")
                return True
            else:
                self.logger.debug(f"Port {port} Closed", f"Result: {result}")
                return False
                
        except Exception as e:
            self.logger.error(f"TCP Scan Error {target_ip}:{port}", str(e))
            return False
    
    def gtp_probe(self, target_ip: str, port: int = 2123) -> bool:
        """GTP-C probe with enhanced detection"""
        self.logger.step(f"GTP-C Probe", f"{target_ip}:{port}")
        
        try:
            # Build GTP-C header
            gtp_header = bytearray(24)
            gtp_header[0] = 0x1E  # Version 1, flags
            gtp_header[1] = 0x06  # Message type (GTPDOOR ACL query)
            gtp_header[2] = 0x00
            gtp_header[3] = 0x0A  # Length
            gtp_header[4:8] = struct.pack('!I', random.randint(0, 0xFFFFFFFF))
            gtp_header[8:12] = struct.pack('!I', random.randint(0, 0xFFFFFFFF))
            gtp_header[12:16] = struct.pack('!H', random.randint(0, 65535))
            gtp_header[16:24] = os.urandom(8)
            
            self.logger.debug("GTP-C Packet Built", f"Header: {gtp_header[:8].hex()}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.options['timeout'])
            
            sock.sendto(bytes(gtp_header), (target_ip, port))
            self.results['stats']['packets_sent'] += 1
            self.logger.packet("SENT", "LOCAL", target_ip, "GTP-C", len(gtp_header))
            
            try:
                response, addr = sock.recvfrom(1024)
                self.results['stats']['packets_received'] += 1
                self.logger.packet("RECEIVED", target_ip, "LOCAL", "GTP-C", len(response))
                
                if len(response) > 1 and response[1] == 0x02:
                    self.logger.success("GTP-C Response", "GTP_ECHO_RESPONSE detected")
                    return True
                else:
                    self.logger.debug("GTP-C Response", f"Unknown response type: {response[1] if len(response) > 1 else 'None'}")
                    
            except socket.timeout:
                self.logger.debug("GTP-C Timeout", "No response received")
                
            sock.close()
            
        except Exception as e:
            self.logger.error("GTP-C Probe Failed", str(e))
            
        return False
    
    def icmp_echo(self, target_ip: str) -> bool:
        """ICMP echo (ping) for host discovery"""
        self.logger.debug(f"ICMP Echo", target_ip)
        
        try:
            icmp_header = struct.pack('!BBHHH', 8, 0, 0, 0, 1)
            data = os.urandom(16)
            checksum = self.checksum(icmp_header + data)
            icmp_header = struct.pack('!BBHHH', 8, 0, checksum, 0, 1)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(2)
            
            start_time = time.time()
            sock.sendto(icmp_header + data, (target_ip, 0))
            self.results['stats']['packets_sent'] += 1
            self.logger.packet("SENT", "LOCAL", target_ip, "ICMP", len(icmp_header) + len(data))
            
            try:
                response, _ = sock.recvfrom(1024)
                self.results['stats']['packets_received'] += 1
                elapsed = (time.time() - start_time) * 1000
                self.logger.packet("RECEIVED", target_ip, "LOCAL", "ICMP", len(response))
                self.logger.success("ICMP Response", f"Time: {elapsed:.1f}ms")
                return True
            except socket.timeout:
                self.logger.debug("ICMP Timeout", "No response")
                return False
                
            sock.close()
            
        except Exception as e:
            self.logger.error("ICMP Echo Failed", str(e))
            return False
    
    def detect_5g_nf(self, target_ip: str) -> Dict[str, bool]:
        """Detect 5G Network Functions"""
        self.logger.step("5G Network Function Detection", target_ip)
        detected = {}
        
        for nf_name, endpoint in NF_ENDPOINTS.items():
            self.logger.debug(f"Checking 5G NF: {nf_name}", endpoint)
            
            for port in [443, 8443, 8080, 9090]:
                try:
                    url = f"https://{target_ip}:{port}{endpoint}"
                    self.logger.debug(f"HTTPS Request", url)
                    
                    response = requests.get(
                        url,
                        timeout=3,
                        verify=False,
                        headers={'Accept': 'application/json'}
                    )
                    
                    if response.status_code in [200, 401, 403, 404]:
                        detected[nf_name] = True
                        self.logger.success(f"5G NF Detected: {nf_name}", f"Port {port}, Status {response.status_code}")
                        break
                        
                except:
                    try:
                        url = f"http://{target_ip}:{port}{endpoint}"
                        self.logger.debug(f"HTTP Request", url)
                        
                        response = requests.get(url, timeout=3, headers={'Accept': 'application/json'})
                        
                        if response.status_code in [200, 401, 403, 404]:
                            detected[nf_name] = True
                            self.logger.success(f"5G NF Detected: {nf_name}", f"Port {port}, Status {response.status_code}")
                            break
                    except:
                        continue
        
        if detected:
            self.logger.success("5G Network Functions Found", f"{len(detected)}: {', '.join(detected.keys())}")
        else:
            self.logger.debug("No 5G Network Functions Found")
            
        return detected
    
    def detect_container_environment(self, target_ip: str) -> Optional[str]:
        """Detect containerized environment"""
        self.logger.step("Container Environment Detection", target_ip)
        
        if not self.options['container_detection']:
            self.logger.debug("Container Detection Disabled")
            return None
            
        for path, container_type in CONTAINER_INDICATORS.items():
            self.logger.debug(f"Checking for {container_type}", path)
            
            for port in [80, 443, 8080, 8443, 9090]:
                try:
                    url = f"http://{target_ip}:{port}{path}"
                    response = requests.get(url, timeout=2)
                    
                    if response.status_code in [200, 403, 404]:
                        self.results['stats']['containers_detected'] += 1
                        self.logger.success(f"Container Detected: {container_type}", f"Port {port}, Path {path}")
                        return container_type
                        
                except:
                    continue
                    
        self.logger.debug("No Container Environment Found")
        return None
    
    def test_jwt_authentication(self, target_ip: str) -> Dict[str, Any]:
        """Test JWT authentication vulnerabilities"""
        self.logger.step("JWT Authentication Testing", target_ip)
        results = {
            'vulnerable': False,
            'weak_tokens': [],
            'bypass_possible': False
        }
        
        if not self.options['auth_testing']:
            self.logger.debug("Auth Testing Disabled")
            return results
            
        endpoints = ['/api/v1/admin', '/api/v1/users', '/admin', '/api/auth/verify']
        self.logger.debug(f"Testing {len(endpoints)} endpoints", f"Endpoints: {', '.join(endpoints)}")
        
        for endpoint in endpoints:
            for port in [80, 443, 8080, 8443]:
                for payload in JWT_PAYLOADS[:2]:  # Limit for speed
                    try:
                        headers = {'Authorization': f'Bearer {payload}'}
                        url = f"http://{target_ip}:{port}{endpoint}"
                        
                        if port in [443, 8443]:
                            url = f"https://{target_ip}:{port}{endpoint}"
                            
                        self.logger.debug(f"Testing JWT", f"{url} with token: {payload[:20]}...")
                        
                        response = requests.get(url, headers=headers, timeout=3, verify=False)
                        
                        if response.status_code == 200:
                            results['vulnerable'] = True
                            results['bypass_possible'] = True
                            results['weak_tokens'].append({
                                'token': payload[:30] + '...',
                                'endpoint': endpoint,
                                'status': response.status_code
                            })
                            self.logger.warning("JWT Vulnerability Found", f"Endpoint: {endpoint}, Status: {response.status_code}")
                            
                    except Exception as e:
                        continue
        
        if results['vulnerable']:
            self.logger.warning("JWT Authentication Vulnerable", f"{len(results['weak_tokens'])} issues found")
        else:
            self.logger.success("JWT Authentication Secure", "No vulnerabilities detected")
            
        return results
    
    def test_api_security(self, target_ip: str) -> Dict[str, Any]:
        """Test API security vulnerabilities"""
        self.logger.step("API Security Testing", target_ip)
        results = {
            'vulnerable': False,
            'vulnerabilities': []
        }
        
        if not self.options['api_testing']:
            self.logger.debug("API Testing Disabled")
            return results
            
        endpoints = ['/api/v1', '/api', '/v1/api', '/rest', '/graphql']
        self.logger.debug(f"Testing {len(endpoints)} endpoints", f"Attack types: {len(API_SECURITY_PAYLOADS)}")
        
        total_tests = 0
        for endpoint in endpoints:
            for attack_type, payloads in API_SECURITY_PAYLOADS.items():
                for payload in payloads[:2]:  # Limit payloads for speed
                    for port in [80, 443, 8080, 8443]:
                        total_tests += 1
                        try:
                            url = f"http://{target_ip}:{port}{endpoint}"
                            if port in [443, 8443]:
                                url = f"https://{target_ip}:{port}{endpoint}"
                            
                            # Test GET
                            params = {'q': payload, 'input': payload, 'query': payload}
                            response = requests.get(url, params=params, timeout=3, verify=False)
                            
                            if response.status_code in [200, 500] and len(response.text) < 1000:
                                if any(error in response.text.lower() for error in ['error', 'exception', 'stack trace']):
                                    results['vulnerable'] = True
                                    results['vulnerabilities'].append({
                                        'type': attack_type,
                                        'method': 'GET',
                                        'endpoint': endpoint,
                                        'payload': payload[:50] + '...',
                                        'status': response.status_code
                                    })
                                    self.logger.warning(f"API Vulnerability: {attack_type}", 
                                                      f"GET {endpoint} -> {response.status_code}")
                                    continue
                            
                            # Test POST
                            json_payload = {'data': payload, 'input': payload}
                            response = requests.post(url, json=json_payload, timeout=3, verify=False)
                            
                            if response.status_code in [200, 500] and len(response.text) < 1000:
                                if any(error in response.text.lower() for error in ['error', 'exception', 'stack trace']):
                                    results['vulnerable'] = True
                                    results['vulnerabilities'].append({
                                        'type': attack_type,
                                        'method': 'POST',
                                        'endpoint': endpoint,
                                        'payload': payload[:50] + '...',
                                        'status': response.status_code
                                    })
                                    self.logger.warning(f"API Vulnerability: {attack_type}", 
                                                      f"POST {endpoint} -> {response.status_code}")
                        except:
                            continue
        
        self.logger.debug(f"Completed {total_tests} API tests")
        
        if results['vulnerable']:
            self.results['stats']['api_vulnerabilities'] += 1
            self.logger.warning("API Security Vulnerable", f"{len(results['vulnerabilities'])} issues found")
        else:
            self.logger.success("API Security Secure", "No vulnerabilities detected")
            
        return results
    
    def detect_anomalies(self, target_ip: str, scan_results: Dict) -> Dict[str, Any]:
        """Detect anomalies using statistical methods"""
        self.logger.step("Anomaly Detection", target_ip)
        anomalies = {
            'detected': False,
            'anomalies': []
        }
        
        if not self.options['anomaly_detection']:
            self.logger.debug("Anomaly Detection Disabled")
            return anomalies
            
        # Build baseline if not exists
        if target_ip not in self.baseline_stats:
            self.baseline_stats[target_ip] = {
                'packet_sizes': [],
                'response_times': [],
                'port_patterns': []
            }
            
        # Analyze packet sizes
        if len(scan_results.get('packet_sizes', [])) > 0:
            avg_size = sum(scan_results['packet_sizes']) / len(scan_results['packet_sizes'])
            self.logger.debug(f"Average Packet Size: {avg_size:.0f} bytes")
            
            if avg_size > 1500:
                anomalies['anomalies'].append(f"Large packet size: {avg_size:.0f} bytes")
                anomalies['detected'] = True
                self.logger.warning("Anomaly Detected", "Large packet size")
            elif avg_size < 64:
                anomalies['anomalies'].append(f"Small packet size: {avg_size:.0f} bytes")
                anomalies['detected'] = True
                self.logger.warning("Anomaly Detected", "Small packet size")
        
        # Analyze response times
        if len(scan_results.get('response_times', [])) > 0:
            avg_time = sum(scan_results['response_times']) / len(scan_results['response_times'])
            self.logger.debug(f"Average Response Time: {avg_time:.2f}s")
            
            if avg_time > 5.0:
                anomalies['anomalies'].append(f"High latency: {avg_time:.2f}s")
                anomalies['detected'] = True
                self.logger.warning("Anomaly Detected", "High latency")
        
        # Check for unusual port patterns
        if len(scan_results.get('open_ports', [])) > 0:
            ports = scan_results['open_ports']
            self.logger.debug(f"Open Ports: {ports}")
            
            # Check for sequential port openings
            if len(ports) > 3 and all(ports[i] + 1 == ports[i+1] for i in range(len(ports)-1)):
                anomalies['anomalies'].append("Sequential port scan detected")
                anomalies['detected'] = True
                self.logger.warning("Anomaly Detected", "Sequential port scanning")
        
        if anomalies['detected']:
            self.results['stats']['anomalies_detected'] += 1
            self.logger.warning(f"Anomalies Detected", f"{len(anomalies['anomalies'])}: {', '.join(anomalies['anomalies'])}")
        else:
            self.logger.success("No Anomalies Detected", "System appears normal")
            
        return anomalies
    
    def identify_service(self, port: int) -> Optional[str]:
        """Identify service by port number"""
        self.logger.debug(f"Identifying Service for port {port}")
        
        common_services = {
            22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            2123: 'GTP-C', 2152: 'GTP-U', 8805: 'PFCP',
            36412: 'S1AP', 38412: 'NGAP', 3868: 'Diameter',
            5060: 'SIP', 3389: 'RDP', 3306: 'MySQL',
            5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB',
            9200: 'Elasticsearch', 5672: 'RabbitMQ', 1883: 'MQTT',
            113: 'Ident', 389: 'LDAP', 636: 'LDAPS',
            1433: 'MSSQL', 1521: 'Oracle', 8088: 'REST-API',
            9090: 'HTTP-Admin', 9092: 'Kafka', 2181: 'Zookeeper',
            5000: 'Flask/API', 5001: 'Python-API', 3000: 'Node.js',
            8000: 'Python-Dev', 8888: 'Jupyter', 7070: 'API-Gateway'
        }
        
        service = common_services.get(port, None)
        if service:
            self.logger.debug(f"Service Identified: {service}")
            self.results['stats']['services_identified'] += 1
        else:
            self.logger.debug(f"Unknown service for port {port}")
            
        return service
    
    def check_threat_intel(self, ip: str) -> Dict:
        """Check IP against threat intelligence feeds"""
        self.logger.step("Threat Intelligence Check", ip)
        results = {'malicious': False, 'reports': [], 'score': 0}
        
        if not self.options['threat_intel']:
            self.logger.debug("Threat Intel Disabled")
            return results
        
        # VirusTotal check
        vt_key = os.environ.get('VT_API_KEY')
        if vt_key:
            self.logger.debug("Checking VirusTotal", "API Key found")
            try:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
                headers = {"x-apikey": vt_key}
                response = requests.get(url, headers=headers, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    
                    results['score'] = malicious * 10 + suspicious * 5
                    results['malicious'] = malicious > 0
                    
                    if malicious > 0:
                        results['reports'].append(f"VirusTotal: {malicious} malicious detections")
                        self.logger.warning("VirusTotal Report", f"{malicious} malicious detections")
                    if suspicious > 0:
                        results['reports'].append(f"VirusTotal: {suspicious} suspicious detections")
                        self.logger.warning("VirusTotal Report", f"{suspicious} suspicious detections")
                    if malicious == 0 and suspicious == 0:
                        self.logger.success("VirusTotal Clean", "No detections")
            except Exception as e:
                self.logger.error("VirusTotal Check Failed", str(e))
        else:
            self.logger.debug("VirusTotal Skipped", "No API key found")
        
        # AbuseIPDB check
        abuse_key = os.environ.get('ABUSEIPDB_API_KEY')
        if abuse_key:
            self.logger.debug("Checking AbuseIPDB", "API Key found")
            try:
                url = "https://api.abuseipdb.com/api/v2/check"
                params = {'ipAddress': ip, 'maxAgeInDays': '90'}
                headers = {'Key': abuse_key, 'Accept': 'application/json'}
                response = requests.get(url, headers=headers, params=params, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    score = data.get('data', {}).get('abuseConfidenceScore', 0)
                    if score > 50:
                        results['malicious'] = True
                        results['score'] = max(results['score'], score)
                        results['reports'].append(f"AbuseIPDB: Score {score}%")
                        self.logger.warning("AbuseIPDB Report", f"Score: {score}%")
                    else:
                        self.logger.success("AbuseIPDB Clean", f"Score: {score}%")
            except Exception as e:
                self.logger.error("AbuseIPDB Check Failed", str(e))
        else:
            self.logger.debug("AbuseIPDB Skipped", "No API key found")
        
        return results
    
    def scan_target(self, target_ip: str):
        """Enhanced multi-method scanning for a single target"""
        if not self.running:
            return
            
        if target_ip in self.results['scanned']:
            self.logger.debug(f"Target Already Scanned: {target_ip}")
            return
            
        self.logger.step(f"Starting Scan", f"Target: {target_ip}")
        self.logger.info(f"Processing Target", target_ip)
        
        results = {
            'ip': target_ip,
            'timestamp': datetime.now().isoformat(),
            'vulnerable': False,
            'risk_score': 0,
            'detection_methods': [],
            'open_ports': [],
            'services': [],
            'fingerprint': {},
            'gtp_detected': False,
            'packet_sizes': [],
            'response_times': [],
            '5g_nf': {},
            'container_type': None,
            'jwt_vulnerabilities': {},
            'api_vulnerabilities': {},
            'anomalies': {},
            'threat_intel': {},
            'banner': {}
        }
        
        self.logger.info("ICMP Echo Check", target_ip)
        if self.icmp_echo(target_ip):
            results['fingerprint']['icmp'] = True
            self.logger.success("Host is Alive", "ICMP response received")
        else:
            self.logger.debug("Host Unreachable", "No ICMP response")
        
        # Scan ports
        self.logger.info(f"Port Scanning", f"Scanning {len(self.options['ports'])} ports on {target_ip}")
        
        for port in self.options['ports']:
            if not self.running:
                break
                
            self.logger.debug(f"Testing Port", f"{target_ip}:{port}")
            start_time = time.time()
            
            if self.tcp_connect_scan(target_ip, port):
                response_time = time.time() - start_time
                results['open_ports'].append(port)
                results['response_times'].append(response_time)
                results['packet_sizes'].append(64 + random.randint(0, 100))
                results['risk_score'] += 5
                self.results['stats']['ports_scanned'] += 1
                
                service = self.identify_service(port)
                if service:
                    results['services'].append(service)
                
                # Port-specific checks
                if port == 2123:
                    self.logger.info("GTP-C Probe", f"Checking {target_ip}")
                    if self.gtp_probe(target_ip):
                        results['gtp_detected'] = True
                        results['vulnerable'] = True
                        results['detection_methods'].append('GTP-C Probe')
                        results['risk_score'] += 30
                        self.logger.warning("GTP-C Service Detected", "Potential GTPDOOR vulnerability")
                
                if port == 2152:
                    results['detection_methods'].append('GTP-U Port Open')
                    results['risk_score'] += 10
                    self.logger.info("GTP-U Port Open", f"{target_ip}:2152")
                
                if port in [8805, 36412, 38412, 3868]:
                    results['detection_methods'].append(f'5G Core Port {port} Open')
                    results['risk_score'] += 15
                    self.logger.info("5G Core Port Open", f"{target_ip}:{port}")
            else:
                self.logger.debug(f"Port {port} Closed", target_ip)
        
        self.logger.info("5G Network Function Detection", f"Checking {target_ip}")
        if results['open_ports']:
            results['5g_nf'] = self.detect_5g_nf(target_ip)
            if results['5g_nf']:
                results['vulnerable'] = True
                results['risk_score'] += 20
        
        self.logger.info("Container Detection", f"Checking {target_ip}")
        results['container_type'] = self.detect_container_environment(target_ip)
        if results['container_type']:
            results['vulnerable'] = True
            results['risk_score'] += 15
        
        self.logger.info("JWT Authentication Testing", f"Checking {target_ip}")
        if results['open_ports']:
            results['jwt_vulnerabilities'] = self.test_jwt_authentication(target_ip)
            if results['jwt_vulnerabilities'].get('vulnerable'):
                results['vulnerable'] = True
                results['risk_score'] += 25
        
        self.logger.info("API Security Testing", f"Checking {target_ip}")
        if results['open_ports']:
            results['api_vulnerabilities'] = self.test_api_security(target_ip)
            if results['api_vulnerabilities'].get('vulnerable'):
                results['vulnerable'] = True
                results['risk_score'] += 30
        
        self.logger.info("Anomaly Detection", f"Checking {target_ip}")
        results['anomalies'] = self.detect_anomalies(target_ip, results)
        if results['anomalies'].get('detected'):
            results['vulnerable'] = True
            results['risk_score'] += 20
        
        self.logger.info("Threat Intelligence", f"Checking {target_ip}")
        results['threat_intel'] = self.check_threat_intel(target_ip)
        if results['threat_intel'].get('malicious'):
            results['vulnerable'] = True
            results['risk_score'] += 30
        
        # Final risk assessment
        if results['risk_score'] >= 20:
            results['vulnerable'] = True
        
        # Store results
        with self.lock:
            self.results['scanned'].append(target_ip)
            if results['vulnerable']:
                self.results['vulnerable'].append(results)
                self.results['stats']['beacons_detected'] += 1
                
                self.logger.warning("VULNERABLE HOST FOUND", 
                                   f"{target_ip} - Risk Score: {results['risk_score']}/100")
                
                # Display findings
                self.display_finding(results)
            else:
                self.logger.success("Target Secured", f"{target_ip} - No vulnerabilities found")
    
    def display_finding(self, results: Dict):
        """Display detailed findings"""
        print(f"\n{Colors.RED}{Colors.BOLD}╔══════════════════════════════════════════╗")
        print(f"║  [!] VULNERABLE HOST DETECTED         ║")
        print(f"╚══════════════════════════════════════════╝{Colors.RESET}")
        print(f"{Colors.RED}    Target: {results['ip']}")
        print(f"    Risk Score: {results['risk_score']}/100")
        print(f"    Open Ports: {', '.join(str(p) for p in results['open_ports'])}")
        
        if results['services']:
            print(f"    Services: {', '.join(results['services'])}")
        
        if results['detection_methods']:
            print(f"    Detection: {', '.join(results['detection_methods'])}")
        
        if results['5g_nf']:
            print(f"    5G NF: {', '.join(results['5g_nf'].keys())}")
        
        if results['container_type']:
            print(f"    Container: {results['container_type']}")
        
        if results['jwt_vulnerabilities'].get('vulnerable'):
            print(f"    JWT Auth: VULNERABLE")
        
        if results['api_vulnerabilities'].get('vulnerable'):
            print(f"    API Security: VULNERABLE ({len(results['api_vulnerabilities'].get('vulnerabilities', []))} issues)")
        
        if results['anomalies'].get('detected'):
            print(f"    Anomalies: {', '.join(results['anomalies'].get('anomalies', []))}")
        
        if results['threat_intel'].get('malicious'):
            print(f"    Threat Intel: MALICIOUS")
        
        print(f"{Colors.RESET}")
        
        # Log to file
        self.logger.result("Vulnerable Host Details", 
                          f"IP: {results['ip']}, Risk: {results['risk_score']}, "
                          f"Ports: {', '.join(str(p) for p in results['open_ports'])}")
    
    def scan_worker(self, target_queue: queue.Queue):
        """Worker thread for scanning"""
        thread_id = threading.current_thread().name
        self.logger.debug(f"Worker Thread Started", thread_id)
        
        while self.running:
            try:
                target = target_queue.get(timeout=1)
                self.logger.debug(f"Worker {thread_id} Processing", target)
                
                if self.options['stealth']:
                    delay = random.uniform(0.1, 0.5)
                    self.logger.debug(f"Stealth Delay", f"{delay:.2f}s")
                    time.sleep(delay)
                    
                self.scan_target(target)
                target_queue.task_done()
                self.logger.debug(f"Worker {thread_id} Done", target)
                
            except queue.Empty:
                self.logger.debug(f"Worker {thread_id} Idle", "Queue empty")
                break
            except Exception as e:
                self.logger.error(f"Worker {thread_id} Error", str(e))
    
    def start_scan(self):
        """Start the scanning process"""
        if not self.targets:
            self.logger.error("No Targets", "Target list is empty")
            print(f"{Colors.RED}[-] No targets to scan{Colors.RESET}")
            return
            
        self.logger.step("Starting Scan", f"{len(self.targets)} targets")
        
        print(f"{Colors.GREEN}[+] Target count: {len(self.targets)}")
        print(f"{Colors.GREEN}[+] Workers: {self.options['workers']}")
        print(f"{Colors.GREEN}[+] Stealth mode: {self.options['stealth']}")
        print(f"{Colors.GREEN}[+] Ports: {', '.join(str(p) for p in self.options['ports'])}")
        print(f"{Colors.GREEN}[+] API Testing: {self.options['api_testing']}")
        print(f"{Colors.GREEN}[+] Auth Testing: {self.options['auth_testing']}")
        print(f"{Colors.GREEN}[+] Container Detection: {self.options['container_detection']}")
        print(f"{Colors.GREEN}[+] Anomaly Detection: {self.options['anomaly_detection']}")
        print(f"{Colors.GREEN}[+] Threat Intel: {self.options['threat_intel']}")
        print(f"{Colors.GREEN}[+] Timeout: {self.options['timeout']}s{Colors.RESET}")
        print(f"\n{Colors.CYAN}[*] Starting scan...{Colors.RESET}\n")
        
        self.logger.info("Scan Configuration", 
                        f"Workers: {self.options['workers']}, Ports: {len(self.options['ports'])}, "
                        f"Timeout: {self.options['timeout']}s")
        
        target_queue = queue.Queue()
        for target in self.targets:
            target_queue.put(target)
            
        self.logger.debug(f"Target Queue Populated", f"{target_queue.qsize()} targets")
            
        threads = []
        for i in range(min(self.options['workers'], len(self.targets))):
            t = threading.Thread(target=self.scan_worker, args=(target_queue,))
            t.daemon = True
            t.start()
            threads.append(t)
            self.logger.debug(f"Thread {i+1} Started", t.name)
            
        target_queue.join()
        
        self.results['stats']['duration'] = (datetime.now() - self.results['stats']['start_time']).total_seconds()
        
        self.logger.success("Scan Complete", 
                           f"Duration: {self.results['stats']['duration']:.2f}s, "
                           f"Scanned: {len(self.results['scanned'])}, "
                           f"Vulnerable: {len(self.results['vulnerable'])}")
        
        self.print_summary()
    
    def print_summary(self):
        """Print scan summary"""
        print(f"\n{Colors.CYAN}╔══════════════════════════════════════════╗")
        print(f"║         SCAN COMPLETE                   ║")
        print(f"╚══════════════════════════════════════════╝{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Total targets: {len(self.targets)}")
        print(f"[+] Scanned: {len(self.results['scanned'])}")
        print(f"[+] Vulnerable hosts: {len(self.results['vulnerable'])}")
        print(f"[+] Packets sent: {self.results['stats']['packets_sent']}")
        print(f"[+] Packets received: {self.results['stats']['packets_received']}")
        print(f"[+] Anomalies detected: {self.results['stats']['anomalies_detected']}")
        print(f"[+] Containers detected: {self.results['stats']['containers_detected']}")
        print(f"[+] API vulnerabilities: {self.results['stats']['api_vulnerabilities']}")
        print(f"[+] Duration: {self.results['stats']['duration']:.2f}s{Colors.RESET}")
        
        self.logger.info("Scan Summary", 
                        f"Targets: {len(self.targets)}, Scanned: {len(self.results['scanned'])}, "
                        f"Vulnerable: {len(self.results['vulnerable'])}, "
                        f"Duration: {self.results['stats']['duration']:.2f}s")
        
        self.save_results()
    
    def save_results(self):
        """Save scan results to files"""
        if not self.results['vulnerable']:
            self.logger.warning("No Vulnerable Hosts", "No results to save")
            print(f"{Colors.YELLOW}[!] No vulnerable hosts found{Colors.RESET}")
            return
            
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_name = f"reports/telguard_scan_{timestamp}"
        
        self.logger.step("Saving Results", f"Base name: {base_name}")
        
        # JSON report
        try:
            with open(f"{base_name}.json", 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            self.logger.success("JSON Report Saved", f"{base_name}.json")
        except Exception as e:
            self.logger.error("JSON Report Failed", str(e))
        
        # HTML Report
        self.generate_html_report(base_name)
        
        # CSV report
        try:
            with open(f"{base_name}.csv", 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'IP', 'Risk Score', 'Open Ports', 'Services', 
                    '5G NF', 'Container', 'Detection Methods', 
                    'JWT Vulnerable', 'API Vulnerable', 'Anomalies',
                    'Threat Intel', 'Timestamp'
                ])
                for host in self.results['vulnerable']:
                    writer.writerow([
                        host['ip'],
                        host['risk_score'],
                        '; '.join(str(p) for p in host['open_ports']),
                        '; '.join(host['services']),
                        '; '.join(host.get('5g_nf', {}).keys()),
                        host.get('container_type', 'None'),
                        '; '.join(host['detection_methods']),
                        'Yes' if host.get('jwt_vulnerabilities', {}).get('vulnerable') else 'No',
                        'Yes' if host.get('api_vulnerabilities', {}).get('vulnerable') else 'No',
                        '; '.join(host.get('anomalies', {}).get('anomalies', [])),
                        'Malicious' if host.get('threat_intel', {}).get('malicious') else 'Clean',
                        host['timestamp']
                    ])
            self.logger.success("CSV Report Saved", f"{base_name}.csv")
        except Exception as e:
            self.logger.error("CSV Report Failed", str(e))
        
        print(f"{Colors.GREEN}[+] Reports saved: {base_name}.json, {base_name}.html, and {base_name}.csv{Colors.RESET}")
        self.logger.info("Reports Complete", f"3 reports generated: JSON, HTML, CSV")
    
    def generate_html_report(self, base_name: str):
        """Generate interactive HTML report with charts"""
        self.logger.debug("Generating HTML Report", base_name)
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>TELGUARD-X v4.0 Scan Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0e17;
            color: #e0e6ed;
            padding: 20px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(135deg, #1a2332, #0d1520);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            border: 1px solid #2a3a50;
        }}
        .header h1 {{
            background: linear-gradient(90deg, #00d4ff, #7b2ffc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-size: 2.5em;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: #1a2332;
            padding: 20px;
            border-radius: 10px;
            border: 1px solid #2a3a50;
            text-align: center;
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            background: linear-gradient(90deg, #00d4ff, #7b2ffc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .stat-label {{
            color: #8899aa;
            margin-top: 5px;
        }}
        .host-card {{
            background: #1a2332;
            padding: 20px;
            border-radius: 10px;
            margin: 15px 0;
            border-left: 4px solid #ff4444;
            transition: transform 0.2s;
        }}
        .host-card:hover {{ transform: translateX(5px); }}
        .host-ip {{
            font-size: 1.3em;
            font-weight: bold;
            color: #00d4ff;
        }}
        .risk-score {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            margin-left: 10px;
        }}
        .risk-high {{ background: #ff4444; color: white; }}
        .risk-medium {{ background: #ffaa00; color: black; }}
        .risk-low {{ background: #44ff44; color: black; }}
        .tag {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 15px;
            margin: 3px;
            font-size: 0.8em;
        }}
        .tag-red {{ background: #ff4444; color: white; }}
        .tag-blue {{ background: #4444ff; color: white; }}
        .tag-green {{ background: #44ff44; color: black; }}
        .tag-yellow {{ background: #ffaa00; color: black; }}
        .tag-purple {{ background: #7b2ffc; color: white; }}
        .vuln-detail {{
            margin: 10px 0;
            padding: 10px;
            background: #0d1520;
            border-radius: 5px;
            font-size: 0.9em;
        }}
        .vuln-detail strong {{ color: #00d4ff; }}
        .chart-container {{
            background: #1a2332;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            border: 1px solid #2a3a50;
        }}
        .footer {{
            text-align: center;
            color: #556677;
            margin-top: 40px;
            padding: 20px;
            border-top: 1px solid #1a2332;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ TELGUARD-X v4.0 Report</h1>
            <p style="color: #8899aa; margin-top: 10px;">
                Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                | Duration: {self.results['stats']['duration']:.2f}s
                | Total Activities: {self.logger.activity_counter}
            </p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{len(self.results['scanned'])}</div>
                <div class="stat-label">Total Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(self.results['vulnerable'])}</div>
                <div class="stat-label">Vulnerable Hosts</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.results['stats']['beacons_detected']}</div>
                <div class="stat-label">Beacons Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.results['stats']['anomalies_detected']}</div>
                <div class="stat-label">Anomalies Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.results['stats']['containers_detected']}</div>
                <div class="stat-label">Containers Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.results['stats']['api_vulnerabilities']}</div>
                <div class="stat-label">API Vulnerabilities</div>
            </div>
        </div>
        
        <div class="chart-container">
            <h3 style="margin-bottom: 20px;">📊 Risk Distribution</h3>
            <canvas id="riskChart" height="200"></canvas>
        </div>
        
        <h2 style="margin: 30px 0 20px 0;">🔴 Vulnerable Hosts</h2>
        
        <div id="hosts">
"""
        
        for host in self.results['vulnerable']:
            risk_class = 'risk-high' if host['risk_score'] > 70 else 'risk-medium' if host['risk_score'] > 40 else 'risk-low'
            
            html_content += f"""
            <div class="host-card">
                <div class="host-ip">
                    {host['ip']}
                    <span class="risk-score {risk_class}">{host['risk_score']}/100</span>
                </div>
                <div style="margin: 10px 0;">
                    <span class="tag tag-blue">Ports: {', '.join(str(p) for p in host['open_ports'])}</span>
                    {' '.join(f'<span class="tag tag-green">{s}</span>' for s in host['services'])}
                </div>
                <div style="margin: 10px 0;">
                    {' '.join(f'<span class="tag tag-red">{m}</span>' for m in host['detection_methods'])}
                </div>
"""
            
            if host.get('5g_nf'):
                html_content += f"""
                <div class="vuln-detail">
                    <strong>📶 5G Network Functions:</strong> {', '.join(host['5g_nf'].keys())}
                </div>
"""
            
            if host.get('container_type'):
                html_content += f"""
                <div class="vuln-detail">
                    <strong>🐳 Container:</strong> {host['container_type']}
                </div>
"""
            
            if host.get('jwt_vulnerabilities', {}).get('vulnerable'):
                html_content += f"""
                <div class="vuln-detail">
                    <strong>🔑 JWT Authentication:</strong> VULNERABLE
                </div>
"""
            
            if host.get('api_vulnerabilities', {}).get('vulnerable'):
                vuln_count = len(host['api_vulnerabilities'].get('vulnerabilities', []))
                html_content += f"""
                <div class="vuln-detail">
                    <strong>⚠️ API Security:</strong> {vuln_count} vulnerabilities found
                </div>
"""
            
            if host.get('anomalies', {}).get('detected'):
                html_content += f"""
                <div class="vuln-detail">
                    <strong>📊 Anomalies:</strong> {', '.join(host['anomalies'].get('anomalies', []))}
                </div>
"""
            
            if host.get('threat_intel', {}).get('malicious'):
                html_content += f"""
                <div class="vuln-detail">
                    <strong>🛑 Threat Intelligence:</strong> MALICIOUS ({host['threat_intel'].get('score', 0)} score)
                </div>
"""
            
            html_content += """
            </div>
"""
        
        html_content += """
        </div>
        
        <div class="footer">
            <p>TELGUARD-X v4.0 | Mobile Network Penetration Testing Framework</p>
            <p>Author: SYLHETYHACKVENGER (THE-ERROR808)</p>
            <p style="font-size: 0.8em; margin-top: 10px;">
                ⚠️ This report is for authorized security testing only
            </p>
        </div>
    </div>
    
    <script>
        const ctx = document.getElementById('riskChart').getContext('2d');
        const riskData = {
            labels: ['Low (0-30)', 'Medium (31-60)', 'High (61-80)', 'Critical (81-100)'],
            datasets: [{
                label: 'Hosts by Risk Level',
                data: [
                    document.querySelectorAll('.risk-low').length,
                    document.querySelectorAll('.risk-medium').length,
                    document.querySelectorAll('.risk-high').length,
                    document.querySelectorAll('.risk-score:contains("Critical")').length || 0
                ],
                backgroundColor: [
                    'rgba(68, 255, 68, 0.7)',
                    'rgba(255, 170, 0, 0.7)',
                    'rgba(255, 68, 68, 0.7)',
                    'rgba(128, 0, 0, 0.8)'
                ],
                borderColor: [
                    '#44ff44',
                    '#ffaa00',
                    '#ff4444',
                    '#800000'
                ],
                borderWidth: 2
            }]
        };
        
        new Chart(ctx, {
            type: 'bar',
            data: riskData,
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        labels: { color: '#e0e6ed' }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#e0e6ed' }
                    },
                    x: {
                        ticks: { color: '#e0e6ed' }
                    }
                }
            }
        });
    </script>
</body>
</html>
"""
        
        try:
            with open(f"{base_name}.html", 'w') as f:
                f.write(html_content)
            self.logger.success("HTML Report Saved", f"{base_name}.html")
        except Exception as e:
            self.logger.error("HTML Report Failed", str(e))
    
    def interactive_menu(self):
        """Interactive menu for TELGUARD-X"""
        while self.running:
            print(f"""
{Colors.CYAN}╔══════════════════════════════════════════╗
║         TELGUARD-X v4.0 MENU              ║
╠══════════════════════════════════════════╣
║  [1] Quick Scan (Single IP)              ║
║  [2] Network Scan (CIDR)                 ║
║  [3] Range Scan (IP Range)               ║
║  [4] File Scan (Target List)             ║
║  [5] Stealth Scan                        ║
║  [6] Modern Features Scan                ║
║  [7] View Reports                        ║
║  [8] Configuration                       ║
║  [9] About                               ║
║  [10] Exit                               ║
╚══════════════════════════════════════════╝{Colors.RESET}
            """)
            
            choice = input(f"{Colors.GREEN}[?] Select option: {Colors.RESET}")
            
            if choice == '1':
                target = input("Enter IP address: ")
                self.logger.info("Menu Selection", "Quick Scan (Single IP)")
                self.targets = self.generate_targets(target)
                self.options['stealth'] = False
                self.start_scan()
                
            elif choice == '2':
                cidr = input("Enter CIDR (e.g., 192.168.1.0/24): ")
                self.logger.info("Menu Selection", f"Network Scan (CIDR: {cidr})")
                self.targets = self.generate_targets(cidr)
                self.options['stealth'] = False
                self.start_scan()
                
            elif choice == '3':
                ip_range = input("Enter IP range (e.g., 192.168.1.1-100): ")
                self.logger.info("Menu Selection", f"Range Scan (IP: {ip_range})")
                self.targets = self.generate_targets(ip_range)
                self.options['stealth'] = False
                self.start_scan()
                
            elif choice == '4':
                filepath = input("Enter target file path: ")
                self.logger.info("Menu Selection", f"File Scan ({filepath})")
                if os.path.exists(filepath):
                    self.targets = self.generate_targets(filepath)
                    self.options['stealth'] = False
                    self.start_scan()
                else:
                    self.logger.error("File Not Found", filepath)
                    print(f"{Colors.RED}[-] File not found{Colors.RESET}")
                    
            elif choice == '5':
                target = input("Enter target IP/CIDR: ")
                self.logger.info("Menu Selection", f"Stealth Scan ({target})")
                self.targets = self.generate_targets(target)
                self.options['stealth'] = True
                self.start_scan()
                
            elif choice == '6':
                self.modern_scan_menu()
                
            elif choice == '7':
                self.view_reports()
                
            elif choice == '8':
                self.configure()
                
            elif choice == '9':
                self.about()
                
            elif choice == '10':
                self.logger.info("Menu Selection", "Exit")
                print(f"{Colors.GREEN}[+] Exiting TELGUARD-X...{Colors.RESET}")
                self.running = False
                break
                
            else:
                self.logger.warning("Invalid Menu Selection", choice)
                print(f"{Colors.RED}[-] Invalid option{Colors.RESET}")
    
    def modern_scan_menu(self):
        """Modern features scan menu"""
        print(f"""
{Colors.CYAN}╔══════════════════════════════════════════╗
║      MODERN FEATURES SCAN                ║
╠══════════════════════════════════════════╣
║  [1] 5G Core Network Detection           ║
║  [2] Container/Cloud Detection           ║
║  [3] JWT/OAuth2 Testing                  ║
║  [4] API Security Testing                ║
║  [5] Full Modern Scan (All Features)     ║
║  [6] Back to Main Menu                   ║
╚══════════════════════════════════════════╝{Colors.RESET}
        """)
        
        choice = input(f"{Colors.GREEN}[?] Select option: {Colors.RESET}")
        
        if choice in ['1', '2', '3', '4', '5']:
            target = input("Enter target IP: ")
            self.logger.info("Modern Scan", f"Type: {choice}, Target: {target}")
            self.targets = self.generate_targets(target)
            
            self.options['api_testing'] = choice in ['3', '4', '5']
            self.options['auth_testing'] = choice in ['3', '5']
            self.options['container_detection'] = choice in ['2', '5']
            
            self.start_scan()
        else:
            return
    
    def view_reports(self):
        """View saved reports"""
        self.logger.step("View Reports", "Checking reports directory")
        
        reports_dir = 'reports'
        if not os.path.exists(reports_dir):
            self.logger.warning("No Reports", "Directory doesn't exist")
            print(f"{Colors.YELLOW}[!] No reports found{Colors.RESET}")
            return
            
        reports = [f for f in os.listdir(reports_dir) if f.endswith('.html') or f.endswith('.json')]
        if not reports:
            self.logger.warning("No Reports", "Directory is empty")
            print(f"{Colors.YELLOW}[!] No reports found{Colors.RESET}")
            return
            
        self.logger.info(f"Found Reports", f"{len(reports)} files")
        print(f"\n{Colors.CYAN}Recent Reports:{Colors.RESET}")
        for i, report in enumerate(sorted(reports, reverse=True)[:10], 1):
            print(f"  {i}. {report}")
            
        choice = input(f"\n{Colors.GREEN}[?] View report (number) or 'q' to quit: {Colors.RESET}")
        if choice.lower() == 'q':
            return
            
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(reports):
                report_file = os.path.join(reports_dir, reports[idx])
                self.logger.info("Opening Report", report_file)
                
                if report_file.endswith('.html'):
                    import webbrowser
                    webbrowser.open(f"file://{os.path.abspath(report_file)}")
                    print(f"{Colors.GREEN}[+] Opening HTML report in browser{Colors.RESET}")
                    self.logger.success("HTML Report Opened", "In browser")
                else:
                    with open(report_file, 'r') as f:
                        data = json.load(f)
                    print(f"\n{Colors.CYAN}Report: {reports[idx]}{Colors.RESET}")
                    print(json.dumps(data, indent=2, default=str)[:1000] + "...")
                    input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        except Exception as e:
            self.logger.error("View Report Failed", str(e))
    
    def configure(self):
        """Configure TELGUARD-X settings"""
        self.logger.step("Configuration Menu", "Current settings display")
        
        print(f"\n{Colors.CYAN}Configuration:{Colors.RESET}")
        print(f"1. Workers: {self.options['workers']}")
        print(f"2. Stealth: {self.options['stealth']}")
        print(f"3. Timeout: {self.options['timeout']}s")
        print(f"4. Ports: {', '.join(str(p) for p in self.options['ports'])}")
        print(f"5. API Testing: {self.options['api_testing']}")
        print(f"6. Auth Testing: {self.options['auth_testing']}")
        print(f"7. Container Detection: {self.options['container_detection']}")
        print(f"8. Anomaly Detection: {self.options['anomaly_detection']}")
        print(f"9. Threat Intelligence: {self.options['threat_intel']}")
        print(f"10. Save and exit")
        
        choice = input(f"{Colors.GREEN}[?] Select setting to change: {Colors.RESET}")
        
        if choice == '1':
            value = int(input("Enter worker count: "))
            self.options['workers'] = value
            self.logger.info("Config Change", f"Workers: {value}")
        elif choice == '2':
            value = input("Enable stealth? (y/n): ").lower() == 'y'
            self.options['stealth'] = value
            self.logger.info("Config Change", f"Stealth: {value}")
        elif choice == '3':
            value = int(input("Enter timeout (seconds): "))
            self.options['timeout'] = value
            self.logger.info("Config Change", f"Timeout: {value}s")
        elif choice == '4':
            ports = input("Enter ports (comma-separated): ")
            self.options['ports'] = [int(p.strip()) for p in ports.split(',')]
            self.logger.info("Config Change", f"Ports: {self.options['ports']}")
        elif choice in ['5', '6', '7', '8', '9']:
            key_map = {'5': 'api_testing', '6': 'auth_testing', 
                      '7': 'container_detection', '8': 'anomaly_detection', 
                      '9': 'threat_intel'}
            value = input(f"Enable? (y/n): ").lower() == 'y'
            self.options[key_map[choice]] = value
            self.logger.info("Config Change", f"{key_map[choice]}: {value}")
        elif choice == '10':
            with open('telguard_config.json', 'w') as f:
                json.dump(self.options, f, indent=2)
            self.logger.success("Configuration Saved", "telguard_config.json")
            print(f"{Colors.GREEN}[+] Configuration saved{Colors.RESET}")
    
    def about(self):
        """Display about information"""
        self.logger.step("About", "Displaying tool information")
        
        print(f"""
{Colors.CYAN}╔══════════════════════════════════════════╗
║         TELGUARD-X v4.0                   ║
╠══════════════════════════════════════════╣
║  Mobile Network Penetration Testing Tool ║
║  GTP (GPRS Tunneling Protocol) Host      ║
║  Discovery & Analysis Framework          ║
║                                          ║
║  Author: SYLHETYHACKVENGER               ║
║  Handle: THE-ERROR808                    ║
║  GitHub: THE-ERROR808/TELGUARD-X         ║
║  Telegram: @SYLHETY_HACKVENGER           ║
║                                          ║
║  Modern Features:                        ║
║  • 5G Core Network Detection             ║
║  • Container/Kubernetes Detection        ║
║  • JWT/OAuth2 Testing                    ║
║  • API Security Testing                  ║
║  • Anomaly Detection                     ║
║  • Threat Intelligence Integration       ║
║  • Interactive HTML Reports              ║
║  • Multi-threaded Scanning               ║
║  • JSON/CSV/HTML Reporting               ║
║  • FULL VERBOSE ACTIVITY LOGGING         ║
║                                          ║
║  Legacy Features:                        ║
║  • ACK Scan Detection                    ║
║  • TCP Connect Scanning                  ║
║  • GTP-C Protocol Probe                  ║
║  • ICMP Host Discovery                   ║
║  • Stealth Mode                          ║
╚══════════════════════════════════════════╝{Colors.RESET}
        """)
        
        self.logger.info("About Displayed", "Tool information shown")
        input(f"{Colors.DIM}Press Enter to continue...{Colors.RESET}")

# ============ MAIN ============
def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='TELGUARD-X v4.0 - Modern GTP Host Discovery Tool')
    parser.add_argument('-t', '--target', help='Target IP, CIDR, IP range, or file')
    parser.add_argument('-p', '--ports', help='Ports to scan (comma-separated)')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of worker threads')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth scanning')
    parser.add_argument('--timeout', type=int, default=3, help='Timeout in seconds')
    parser.add_argument('--threat-intel', action='store_true', help='Enable threat intelligence')
    parser.add_argument('--api-test', action='store_true', help='Enable API security testing')
    parser.add_argument('--auth-test', action='store_true', help='Enable authentication testing')
    parser.add_argument('--container-detect', action='store_true', help='Enable container detection')
    parser.add_argument('--no-banner', action='store_true', help='Hide banner')
    parser.add_argument('--interactive', action='store_true', help='Interactive menu mode')
    parser.add_argument('-v', '--verbose', action='store_true', default=True, help='Verbose output')
    
    args = parser.parse_args()
    
    telguard = TELGUARDX()
    telguard.verbose = args.verbose
    telguard.logger.enabled = args.verbose
    
    if not args.no_banner:
        telguard.print_banner()
    
    # Set options from args
    if args.ports:
        telguard.options['ports'] = [int(p.strip()) for p in args.ports.split(',')]
    if args.workers:
        telguard.options['workers'] = args.workers
    if args.stealth:
        telguard.options['stealth'] = args.stealth
    if args.timeout:
        telguard.options['timeout'] = args.timeout
    if args.threat_intel:
        telguard.options['threat_intel'] = args.threat_intel
    if args.api_test:
        telguard.options['api_testing'] = args.api_test
    if args.auth_test:
        telguard.options['auth_testing'] = args.auth_test
    if args.container_detect:
        telguard.options['container_detection'] = args.container_detect
    
    # Check for raw socket support
    try:
        socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        telguard.options['raw_sockets'] = True
        if args.verbose:
            print(f"{Colors.GREEN}[+] Raw socket support available{Colors.RESET}")
            telguard.logger.success("Raw Socket Support", "Available")
    except PermissionError:
        print(f"{Colors.YELLOW}[!] Raw sockets require root - using TCP connect fallback{Colors.RESET}")
        telguard.options['raw_sockets'] = False
        telguard.logger.warning("Raw Socket Support", "Requires root - using fallback")
    except:
        telguard.logger.warning("Raw Socket Support", "Unavailable - using fallback")
    
    if args.interactive or (not args.target):
        telguard.interactive_menu()
    elif args.target:
        telguard.logger.info("Command Line Mode", f"Target: {args.target}")
        telguard.targets = telguard.generate_targets(args.target)
        telguard.start_scan()
    else:
        telguard.interactive_menu()

if __name__ == "__main__":
    if sys.version_info < (3, 6):
        print("Python 3.6+ required")
        sys.exit(1)
    
    try:
        import requests
    except ImportError:
        print(f"{Colors.YELLOW}[!] Installing requests...{Colors.RESET}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    
    main()
