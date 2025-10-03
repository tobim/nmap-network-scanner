# Port Scanning & Vulnerability Assessment Guide

## 🚀 New Features in v3.1.0

This branch adds comprehensive **port scanning**, **service detection**, and **vulnerability assessment** capabilities to the Network Scanner API.

## 📋 Features

### 1. **Port & Service Scanning**
- Scan all 65,535 ports on any host
- Automatic service version detection
- Protocol identification (TCP/UDP)
- Service fingerprinting

### 2. **Vulnerability Detection**
- CVE detection using nmap NSE scripts
- CVSS score analysis
- Severity classification (Critical/High/Medium/Low)
- Multiple vulnerability databases (vulners, vulscan, vuln)

### 3. **Comprehensive Host Assessment**
- Device identification (from existing rules)
- Open ports and services
- Known vulnerabilities
- Security posture report

## 🔧 Setup

### Install nmap Vulners Script
```bash
mkdir -p ~/.nmap/scripts
cd ~/.nmap/scripts
curl -o vulners.nse https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse
nmap --script-updatedb
```

### Start the API Server
```bash
cd "/Users/pranavreddy/Desktop/nmap api 2.0"
source api_env/bin/activate
sudo ./api_env/bin/python3 api.py
```

Server runs on: **http://localhost:8001**

## 📡 API Endpoints

### Network Scanning (Existing)
```bash
# Discover all devices
GET http://localhost:8001/scan

# Clean format
GET http://localhost:8001/scan/clean
```

### Port & Service Scanning (NEW)
```bash
# Scan all ports on a specific host
GET http://localhost:8001/scan/ports/192.168.1.10

# Example Response:
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
    }
  ],
  "services": [
    {
      "name": "ssh",
      "version": "OpenSSH 8.2p1 Ubuntu",
      "port": 22,
      "protocol": "tcp"
    }
  ],
  "os_detection": "Linux 4.15 - 5.6"
}
```

### Vulnerability Scanning (NEW)
```bash
# Scan all ports for vulnerabilities
GET http://localhost:8001/scan/vulnerabilities/192.168.1.10

# Scan specific ports only
GET http://localhost:8001/scan/vulnerabilities/192.168.1.10?ports=22,80,443

# Example Response:
{
  "ip": "192.168.1.10",
  "vulnerability_count": 3,
  "vulnerabilities": [
    {
      "cve": "CVE-2023-38408",
      "cvss_score": 9.8,
      "severity": "Critical",
      "description": "The PKCS#11 feature in ssh-agent in OpenSSH..."
    },
    {
      "cve": "CVE-2023-28531",
      "cvss_score": 7.5,
      "severity": "High",
      "description": "CSRF vulnerability in nginx..."
    }
  ],
  "critical": 1,
  "high": 1,
  "medium": 1,
  "low": 0
}
```

### Comprehensive Scan (NEW)
```bash
# Full security assessment (device + ports + vulnerabilities)
GET http://localhost:8001/scan/comprehensive/192.168.1.10

# Example Response:
{
  "ip": "192.168.1.10",
  "timestamp": "2025-10-03T14:30:00",
  "scan_type": "comprehensive",
  "ports": {
    "open_ports": 5,
    "ports": [...],
    "services": [...]
  },
  "vulnerabilities": {
    "vulnerability_count": 3,
    "vulnerabilities": [...],
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0
  }
}
```

## 🧪 Testing Examples

### Using curl
```bash
# Check API status
curl http://localhost:8001/

# Scan network
curl http://localhost:8001/scan/clean | python3 -m json.tool

# Scan specific host ports
curl http://localhost:8001/scan/ports/192.168.1.10 | python3 -m json.tool

# Check vulnerabilities
curl "http://localhost:8001/scan/vulnerabilities/192.168.1.10?ports=22,80,443" | python3 -m json.tool

# Full assessment
curl http://localhost:8001/scan/comprehensive/192.168.1.10 | python3 -m json.tool
```

### Using Python
```python
import requests

# Port scan
response = requests.get("http://localhost:8001/scan/ports/192.168.1.10")
data = response.json()

print(f"Open ports: {data['open_ports']}")
for port in data['ports']:
    print(f"  Port {port['port']}: {port['service']} {port['version']}")

# Vulnerability scan
response = requests.get("http://localhost:8001/scan/vulnerabilities/192.168.1.10")
data = response.json()

print(f"Vulnerabilities found: {data['vulnerability_count']}")
print(f"  Critical: {data['critical']}")
print(f"  High: {data['high']}")
print(f"  Medium: {data['medium']}")
```

## 🛡️ Security Considerations

### Permissions
- Requires **sudo** for accurate port scanning
- Uses `sudo -n` (non-interactive) to avoid password prompts
- Configure sudoers for production use:
  ```bash
  echo "username ALL=(ALL) NOPASSWD: /usr/local/bin/nmap" | sudo tee /etc/sudoers.d/nmap
  ```

### Rate Limiting
- Scans can be intensive - consider rate limiting in production
- Use `--max-retries 2` and `--host-timeout 5m` to prevent hangs
- Port scanning all 65,535 ports can take 5-10 minutes per host

### Legal Compliance
- Only scan networks and devices you own or have permission to test
- Comply with local laws and regulations
- Disable vulnerability scanning in production environments if not authorized

## 📊 nmap NSE Scripts Used

### Vulners
- Database of known CVEs
- CVSS scoring
- Exploit availability info
- Source: https://github.com/vulnersCom/nmap-vulners

### Vulscan
- Multiple vulnerability databases
- OSVDB, SecurityFocus, CVE, etc.
- Comprehensive coverage

### Vuln Category Scripts
- HTTP vulnerabilities
- SMB vulnerabilities
- SSL/TLS issues
- Database exploits

## 🔍 Implementation Details

### Port Scanning Strategy
1. **Primary**: Full port scan with service detection
   ```bash
   nmap -sV -sC --version-all -p- --max-retries 2 --host-timeout 5m <ip>
   ```

2. **Fallback**: Top 1000 ports if full scan times out
   ```bash
   nmap -sV -sC --top-ports 1000 <ip>
   ```

### Vulnerability Scanning Strategy
1. Run vulners, vulscan, and vuln scripts
2. Filter by CVSS score >= 5.0 (medium severity)
3. Parse CVE IDs and scores
4. Classify by severity
5. Return deduplicated results

## 📈 Performance

### Scan Times (Approximate)
- **Port scan** (all ports): 5-10 minutes per host
- **Port scan** (top 1000): 30-60 seconds per host
- **Vulnerability scan**: 2-5 minutes per host
- **Comprehensive scan**: 7-15 minutes per host

### Optimization Tips
- Scan specific ports when possible
- Use parallel scanning for multiple hosts
- Cache results for frequently scanned hosts
- Schedule deep scans during off-hours

## 🚧 Roadmap

- [ ] Parallel host scanning
- [ ] Scan result caching
- [ ] Historical scan comparison
- [ ] Email alerts for critical vulnerabilities
- [ ] Export to PDF/CSV
- [ ] Integration with vulnerability databases
- [ ] Custom scan profiles
- [ ] Scheduled scanning

## 📚 References

- [Black Hills InfoSec - Vulnerability Scanning with nmap](https://www.blackhillsinfosec.com/vulnerability-scanning-with-nmap/)
- [nmap Vulners Script Documentation](https://nmap.org/nsedoc/scripts/vulners.html)
- [nmap NSE Scripts Library](https://nmap.org/nsedoc/)
- [CVE Database](https://cve.mitre.org/)
- [CVSS Scoring Guide](https://www.first.org/cvss/)

## 💡 Usage Tips

1. **Start with network discovery**: Use `/scan` to find all devices
2. **Identify targets**: Pick specific IPs for detailed scanning
3. **Port scan first**: Check open ports with `/scan/ports/{ip}`
4. **Vulnerability assessment**: Use `/scan/vulnerabilities/{ip}` on interesting hosts
5. **Full report**: Get comprehensive data with `/scan/comprehensive/{ip}`

## 🐛 Troubleshooting

### "Permission denied" errors
- Make sure to run API with `sudo`
- Check nmap is installed: `nmap --version`

### Scans timing out
- Reduce port range or use `--top-ports`
- Increase timeout limits
- Check network connectivity

### No vulnerabilities found
- Some systems may not have detectable CVEs
- Update nmap scripts: `nmap --script-updatedb`
- Check if vulners script is installed

## 👨‍💻 Development

```bash
# Create feature branch
git checkout -b feature/open-ports-services

# Make changes
# ...

# Test
curl http://localhost:8001/scan/ports/192.168.1.1

# Commit
git add .
git commit -m "feat: Add port scanning"

# Push
git push -u origin feature/open-ports-services
```

---

**Version**: 3.1.0  
**Branch**: feature/open-ports-services  
**Author**: Pranav Reddy  
**Date**: October 3, 2025
