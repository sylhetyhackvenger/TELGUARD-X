TELGUARD-X v4.0


TELGUARD-X v4.0 is an advanced mobile network penetration testing framework designed for GTP (GPRS Tunneling Protocol) host discovery, 5G core network analysis, and comprehensive security assessment of telecommunications infrastructure.

🔥 Features

🚀 Modern Capabilities

· 5G Core Network Detection - Automatically identifies 5G Network Functions (NRF, SMF, AMF, UDM, AUSF, PCF, NSSF, NEF, NWDAF)
· Container & Cloud Environment Detection - Identifies Docker, Kubernetes, Podman, AWS-ECS, and Containerd environments
· JWT/OAuth2 Security Testing - Tests for weak tokens, algorithm confusion, and authentication bypasses
· API Security Testing - Comprehensive testing for SQL Injection, XSS, Path Traversal, Command Injection, NoSQL Injection, XXE, SSRF, and LDAP Injection
· Anomaly Detection - Statistical analysis for unusual packet sizes, response times, and port patterns
· Threat Intelligence Integration - VirusTotal and AbuseIPDB checks for malicious IPs
· Interactive HTML Reports - Beautiful, interactive reports with Chart.js visualizations

📡 Legacy Features

· GTP-C Protocol Probing - Advanced GTP-C probe with GTPDOOR ACL query detection
· Multi-Method Host Discovery - ICMP echo, TCP connect scanning, and raw packet crafting
· Stealth Scanning - Configurable delays to avoid detection
· Multi-Threaded Scanning - High-performance concurrent scanning with worker threads
· Comprehensive Reporting - JSON, CSV, and interactive HTML report generation
· Verbose Activity Logging - Complete A-Z activity logging with timestamps and colors

📋 Prerequisites

· Python 3.6 or higher
· Root/Administrator privileges (for raw socket operations)
· Required Python packages (automatically installed if missing)

🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/sylhetyhackvenger/TELGUARD-X
cd TELGUARD-X

# Install required packages
pip install -r requirements.txt
```

Requirements.txt

```txt
requests>=2.25.0
# Other dependencies are built-in (socket, struct, threading, json, csv, etc.)
```

🚀 Quick Start

Interactive Mode

```bash
sudo python telguard-x.py --interactive
```

Command Line Mode

```bash
# Single IP scan
sudo python telguard-x.py -t 192.168.1.1

# CIDR network scan
sudo python telguard-x.py -t 192.168.1.0/24

# IP range scan
sudo python telguard-x.py -t 192.168.1.1-100

# File with target list
sudo python telguard-x.py -t targets.txt

# Full modern features scan
sudo python telguard-x.py -t 10.0.0.1 --api-test --auth-test --container-detect --threat-intel

# Stealth scan with custom ports
sudo python telguard-x.py -t 192.168.1.0/24 --stealth -p 80,443,2123,2152,8805,36412,38412,3868
```

📊 Example Commands

```bash
# 5G Core Network Detection
sudo python telguard-x.py -t 10.0.0.1 --api-test --container-detect

# Comprehensive API Security Testing
sudo python telguard-x.py -t api-gateway.company.com --api-test --auth-test

# Threat Intelligence Enhanced Scan
sudo python telguard-x.py -t suspicious-ip.com --threat-intel

# Full Modern Feature Scan
sudo python telguard-x.py -t 10.0.0.0/24 --api-test --auth-test --container-detect --threat-intel --stealth -w 20
```

🎯 Scan Output Example

```
╔══════════════════════════════════════════╗
║  [!] VULNERABLE HOST DETECTED         ║
╚══════════════════════════════════════════╝
    Target: 10.0.0.1
    Risk Score: 85/100
    Open Ports: 22, 80, 443, 2123, 2152, 8805, 36412, 38412, 3868
    Services: SSH, HTTP, HTTPS, GTP-C, GTP-U, PFCP, S1AP, NGAP, Diameter
    Detection: GTP-C Probe, 5G Core Port Open
    5G NF: nrf, smf, amf, udm, ausf, pcf, nssf, nef, nwdaf
    Container: Kubernetes
    JWT Auth: VULNERABLE
    API Security: VULNERABLE (12 issues)
    Anomalies: Large packet size, High latency, Sequential port scan
    Threat Intel: MALICIOUS
```

📈 Reports

TELGUARD-X generates three types of reports in the reports/ directory:

1. HTML Report (Interactive)

· Interactive charts with risk distribution
· Color-coded vulnerability display
· Detailed host information
· Mobile-friendly responsive design

2. JSON Report (Machine-Readable)

· Complete scan results in structured format
· Perfect for automation and integration
· Includes all details about vulnerabilities

3. CSV Report (Spreadsheet)

· Tabular data for analysis
· Compatible with Excel, Google Sheets
· Summary of all vulnerable hosts

🎨 Verbose Logging

TELGUARD-X features comprehensive verbose logging with color-coded output:

· 📌 STEP - Current operation steps
· ℹ️ INFO - General information
· ⚠️ WARN - Warnings and potential issues
· ❌ ERROR - Errors and failures
· ✅ SUCCESS - Successful operations
· 🔍 DEBUG - Detailed debug information
· 📦 PACKET - Network packet activity
· 📊 RESULT - Scan results and findings

All logs are saved in the logs/ directory with timestamps.

🔐 Security Notice

⚠️ IMPORTANT DISCLAIMER
This tool is intended for authorized security testing and educational purposes only. Use it only on networks and systems you own or have explicit permission to test. Unauthorized scanning may be illegal in your jurisdiction.

🤝 Contributing

We welcome contributions! Here's how you can help:

1. Fork the repository
2. Create your feature branch (git checkout -b feature/AmazingFeature)
3. Commit your changes (git commit -m 'Add some AmazingFeature')
4. Push to the branch (git push origin feature/AmazingFeature)
5. Open a Pull Request

📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

👨‍💻 Author

SYLHETYHACKVENGER (THE-ERROR808)

· GitHub: @sylhetyhackvenger 

🌟 Support

· ⭐ Star this repository if you find it useful!
· 🐛 Report issues on GitHub Issues
· 💬 Join discussions on GitHub Discussions

📚 Documentation

For detailed documentation, visit the Wiki

🎯 Features Matrix

Feature Status Description
5G Core Detection ✅ NRF, SMF, AMF, UDM, AUSF, PCF, NSSF, NEF, NWDAF
Container Detection ✅ Docker, Kubernetes, Podman, ECS, Containerd
JWT Testing ✅ Token validation, algorithm confusion, bypass testing
API Security ✅ SQLi, XSS, Path Traversal, Command Injection, NoSQL, XXE, SSRF, LDAP
Anomaly Detection ✅ Statistical analysis of network behavior
Threat Intelligence ✅ VirusTotal, AbuseIPDB integration
GTP-C Probing ✅ Advanced GTP-C protocol discovery
Interactive Reports ✅ Beautiful HTML reports with charts
Verbose Logging ✅ Complete A-Z activity logging
Stealth Mode ✅ Configurable delays to avoid detection
Multi-Threading ✅ High-performance concurrent scanning
Raw Sockets ✅ Low-level packet crafting (root required)

🚦 Performance

· Target Scanning: ~10 targets per minute (configurable)
· Port Scanning: ~50 ports per second per worker
· Memory Usage: ~100 MB for 1000 targets
· Thread Support: Up to 50 concurrent workers

🔧 Configuration

TELGUARD-X creates a telguard_config.json file for persistent configuration:

```json
{
  "workers": 10,
  "stealth": false,
  "timeout": 3,
  "ports": [22, 80, 443, 8080, 2123, 5060, 3389, 8443, 2152, 8805, 36412, 38412, 3868],
  "api_testing": true,
  "container_detection": true,
  "auth_testing": true,
  "anomaly_detection": true
}
```

🎯 Use Cases

1. Telecom Security Assessment - Identify exposed GTP services in mobile networks
2. 5G Core Security - Detect and analyze 5G Network Functions
3. Container Security - Identify containerized applications in cloud environments
4. API Security Testing - Comprehensive API vulnerability assessment
5. Threat Hunting - Identify malicious IPs and suspicious network activity

---

Made with ❤️ by SYLHETYHACKVENGER (THE-ERROR808)
