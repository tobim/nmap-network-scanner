# Network Scanner API v3.1.0 - Feature Summary

## 🎉 What's New: Port Scanning & Vulnerability Assessment

This feature branch adds comprehensive **security scanning capabilities** to detect open ports, identify services, and discover vulnerabilities on network devices.

---

## ✨ New Features

### 1. Port & Service Scanning
**Endpoint**: `GET /scan/ports/{ip}`

Scans all 65,535 ports on a target host and identifies running services with version detection.

**Example**:
```bash
curl http://localhost:8001/scan/ports/192.168.1.10
```

**Returns**:
- Open ports (number, protocol, state)
- Service names (ssh, http, https, etc.)
- Service versions (OpenSSH 8.2p1, nginx 1.18.0, etc.)
- OS detection hints

---

### 2. Vulnerability Detection
**Endpoint**: `GET /scan/vulnerabilities/{ip}?ports=22,80,443`

Scans for known vulnerabilities (CVEs) using nmap NSE scripts (vulners, vulscan, vuln).

**Example**:
```bash
curl "http://localhost:8001/scan/vulnerabilities/192.168.1.10?ports=22,80,443"
```

**Returns**:
- CVE identifiers
- CVSS scores
- Severity levels (Critical/High/Medium/Low)
- Vulnerability descriptions
- Count by severity

---

### 3. Comprehensive Security Assessment
**Endpoint**: `GET /scan/comprehensive/{ip}`

Complete security profile combining device info, ports, services, and vulnerabilities.

**Example**:
```bash
curl http://localhost:8001/scan/comprehensive/192.168.1.10
```

**Returns**:
- All port scan data
- All vulnerability data
- Combined security report
- Complete timestamp

---

## 🔧 Technical Implementation

### nmap Commands Used

**Port Scanning**:
```bash
# Full scan (all 65,535 ports)
nmap -sV -sC --version-all -p- --max-retries 2 --host-timeout 5m <ip>

# Fallback (top 1000 ports if timeout)
nmap -sV -sC --top-ports 1000 <ip>
```

**Vulnerability Scanning**:
```bash
# With vulners, vulscan, and vuln NSE scripts
nmap -sV --script=vulners,vulscan,vuln --script-args mincvss=5.0 -p <ports> <ip>
```

### NSE Scripts Integrated

1. **vulners** - CVE database with CVSS scoring
2. **vulscan** - Multiple vulnerability databases (OSVDB, SecurityFocus, etc.)
3. **vuln** - General vulnerability detection scripts

---

## 📊 Example Outputs

### Port Scan Example
```json
{
  "ip": "192.168.1.10",
  "open_ports": 5,
  "ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "state": "open",
      "service": "ssh",
      "version": "OpenSSH 8.2p1 Ubuntu"
    },
    {
      "port": 80,
      "protocol": "tcp",
      "state": "open",
      "service": "http",
      "version": "nginx 1.18.0"
    },
    {
      "port": 443,
      "protocol": "tcp",
      "state": "open",
      "service": "https",
      "version": "nginx 1.18.0"
    }
  ],
  "services": [
    {
      "name": "ssh",
      "version": "OpenSSH 8.2p1 Ubuntu",
      "port": 22,
      "protocol": "tcp"
    },
    {
      "name": "http",
      "version": "nginx 1.18.0",
      "port": 80,
      "protocol": "tcp"
    }
  ],
  "os_detection": "Linux 4.15 - 5.6"
}
```

### Vulnerability Scan Example
```json
{
  "ip": "192.168.1.10",
  "vulnerability_count": 3,
  "vulnerabilities": [
    {
      "cve": "CVE-2023-38408",
      "cvss_score": 9.8,
      "severity": "Critical",
      "description": "The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2..."
    },
    {
      "cve": "CVE-2023-28531",
      "cvss_score": 7.5,
      "severity": "High",
      "description": "CSRF vulnerability in nginx admin interface..."
    },
    {
      "cve": "CVE-2023-12345",
      "cvss_score": 5.3,
      "severity": "Medium",
      "description": "Information disclosure in nginx error pages..."
    }
  ],
  "critical": 1,
  "high": 1,
  "medium": 1,
  "low": 0,
  "timestamp": "2025-10-03T14:30:00.123456"
}
```

---

## 🚀 Quick Start

### 1. Install Vulners Script
```bash
mkdir -p ~/.nmap/scripts
cd ~/.nmap/scripts
curl -o vulners.nse https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse
```

### 2. Start API Server
```bash
cd "/Users/pranavreddy/Desktop/nmap api 2.0"
source api_env/bin/activate
sudo ./api_env/bin/python3 api.py
```

### 3. Test New Endpoints
```bash
# Check API documentation
curl http://localhost:8001/

# Scan network (existing feature)
curl http://localhost:8001/scan/clean

# NEW: Scan ports on specific device
curl http://localhost:8001/scan/ports/192.168.1.10

# NEW: Check vulnerabilities
curl "http://localhost:8001/scan/vulnerabilities/192.168.1.10?ports=22,80,443"

# NEW: Full security assessment
curl http://localhost:8001/scan/comprehensive/192.168.1.10
```

---

## 📈 Use Cases

### 1. Network Security Audit
```bash
# Step 1: Discover all devices
curl http://localhost:8001/scan/clean

# Step 2: Deep scan interesting devices
curl http://localhost:8001/scan/comprehensive/192.168.1.50
```

### 2. Service Inventory
```bash
# Find all services running on web server
curl http://localhost:8001/scan/ports/192.168.1.100
```

### 3. Vulnerability Management
```bash
# Check specific critical services
curl "http://localhost:8001/scan/vulnerabilities/192.168.1.10?ports=22,3306,5432"
```

### 4. Compliance Checking
```bash
# Regular automated scans
curl http://localhost:8001/scan/comprehensive/192.168.1.10 > security_report_$(date +%Y%m%d).json
```

---

## ⚡ Performance Notes

- **Port scan (all ports)**: 5-10 minutes per host
- **Port scan (top 1000)**: 30-60 seconds per host
- **Vulnerability scan**: 2-5 minutes per host
- **Comprehensive scan**: 7-15 minutes per host

💡 **Tip**: Specify exact ports for faster vulnerability scans

---

## 🔒 Security & Permissions

- Requires **sudo** for accurate scanning
- Only scan networks/devices you own or have permission to test
- Comply with local laws and regulations
- Disable in production unless authorized for security testing

---

## 📚 Resources

- **Full Documentation**: [PORT_SCANNING_GUIDE.md](./PORT_SCANNING_GUIDE.md)
- **Black Hills InfoSec Guide**: https://www.blackhillsinfosec.com/vulnerability-scanning-with-nmap/
- **nmap Vulners Script**: https://nmap.org/nsedoc/scripts/vulners.html
- **CVE Database**: https://cve.mitre.org/

---

## 🌿 Git Workflow

```bash
# Current branch
git branch --show-current
# feature/open-ports-services

# View changes
git log --oneline -5

# Push to GitHub
git push -u origin feature/open-ports-services

# Create pull request on GitHub to merge into main
```

---

## ✅ Testing Checklist

- [x] Install vulners NSE script
- [x] Add port scanning functionality
- [x] Add service detection
- [x] Add vulnerability scanning
- [x] Parse CVE and CVSS data
- [x] Create new API endpoints
- [x] Update API documentation
- [x] Write comprehensive guide
- [x] Commit changes
- [x] Push to GitHub
- [ ] Test with live devices
- [ ] Merge to main branch

---

**Version**: 3.1.0  
**Branch**: feature/open-ports-services  
**Status**: Ready for testing  
**GitHub**: https://github.com/sunkenship2025/nmap-network-scanner/tree/feature/open-ports-services
