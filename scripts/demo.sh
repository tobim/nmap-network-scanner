#!/bin/bash

# Network Scanner API - Port Scanning & Vulnerability Detection Demo
# Feature Branch: feature/open-ports-services
# Version: 3.1.0

API_URL="http://localhost:8001"
TEST_IP="${1:-192.168.1.1}" # Default to gateway if no IP provided

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Network Scanner API - Port & Vulnerability Demo          ║${NC}"
echo -e "${BLUE}║  Version 3.1.0 - Feature Branch Demo                      ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if API is running
echo -e "${YELLOW}→ Checking API status...${NC}"
if curl -s "${API_URL}/health" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ API is running on ${API_URL}${NC}"
else
    echo -e "${RED}✗ API is not running!${NC}"
    echo -e "${YELLOW}  Start it with: sudo ./api_env/bin/python3 api.py${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Demo 1: API Information${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"

echo -e "${YELLOW}→ Fetching API info...${NC}"
curl -s "${API_URL}/" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f\"API Version: {data['version']}\")
print(f\"Description: {data['description']}\")
print(f\"\\nNew Endpoints:\")
for category, endpoints in data['endpoints'].items():
    print(f\"\\n{category}:\")
    if isinstance(endpoints, dict):
        for endpoint, desc in endpoints.items():
            print(f\"  {endpoint}\")
            print(f\"    {desc}\")
print(f\"\\nSecurity Scripts:\")
for script, desc in data['security_scripts'].items():
    print(f\"  • {script}: {desc}\")
"

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Demo 2: Network Discovery${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"

echo -e "${YELLOW}→ Discovering devices on network...${NC}"
echo -e "${YELLOW}  (This may take 30-60 seconds)${NC}"
echo ""

curl -s "${API_URL}/scan/clean" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f\"Devices found: {data['devices_found']}\")
print(f\"\\nDevice List:\")
for i, device in enumerate(data['devices'][:10], 1):  # Show first 10
    print(f\"\\n{i}. {device['name']}\")
    print(f\"   IP: {device['ipv4']}\")
    print(f\"   MAC: {device['mac']}\")
    print(f\"   Type: {device['type']}\")
    print(f\"   Manufacturer: {device['manufacturer']}\")

if data['devices_found'] > 10:
    print(f\"\\n... and {data['devices_found'] - 10} more devices\")
"

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Demo 3: Port Scanning (NEW)${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"

echo -e "${YELLOW}→ Scanning ports on ${TEST_IP}...${NC}"
echo -e "${YELLOW}  (This may take 5-10 minutes for full scan)${NC}"
echo ""

curl -s "${API_URL}/scan/ports/${TEST_IP}" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(f\"Target: {data['ip']}\")
    print(f\"Open Ports: {data.get('open_ports', 0)}\")
    
    if data.get('os_detection'):
        print(f\"OS Detection: {data['os_detection']}\")
    
    if data.get('ports'):
        print(f\"\\nPort Details:\")
        for port in data['ports'][:10]:  # Show first 10 ports
            print(f\"  • Port {port['port']}/{port['protocol']}: {port['service']}\")
            if port.get('version'):
                print(f\"    Version: {port['version']}\")
    
    if data.get('services'):
        print(f\"\\nServices Detected:\")
        for service in data['services'][:5]:  # Show first 5 services
            print(f\"  • {service['name']} on port {service['port']}\")
            if service.get('version'):
                print(f\"    {service['version']}\")
    
    if data.get('error'):
        print(f\"\\n⚠️  Error: {data['error']}\")
except json.JSONDecodeError:
    print('⚠️  Invalid JSON response or scan still in progress')
except Exception as e:
    print(f'⚠️  Error: {e}')
"

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Demo 4: Vulnerability Scanning (NEW)${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"

echo -e "${YELLOW}→ Scanning vulnerabilities on ${TEST_IP}...${NC}"
echo -e "${YELLOW}  (This may take 2-5 minutes)${NC}"
echo ""

curl -s "${API_URL}/scan/vulnerabilities/${TEST_IP}?ports=22,80,443" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(f\"Target: {data['ip']}\")
    print(f\"Vulnerabilities Found: {data.get('vulnerability_count', 0)}\")
    
    if data.get('vulnerability_count', 0) > 0:
        print(f\"\\nSeverity Breakdown:\")
        print(f\"  🔴 Critical: {data.get('critical', 0)}\")
        print(f\"  🟠 High: {data.get('high', 0)}\")
        print(f\"  🟡 Medium: {data.get('medium', 0)}\")
        print(f\"  🟢 Low: {data.get('low', 0)}\")
        
        if data.get('vulnerabilities'):
            print(f\"\\nTop Vulnerabilities:\")
            for vuln in data['vulnerabilities'][:5]:  # Show first 5
                severity_emoji = {
                    'Critical': '🔴',
                    'High': '🟠',
                    'Medium': '🟡',
                    'Low': '🟢'
                }.get(vuln.get('severity', 'Unknown'), '⚪')
                
                print(f\"\\n  {severity_emoji} {vuln.get('cve', 'N/A')}\")
                print(f\"     CVSS Score: {vuln.get('cvss_score', 'N/A')}\")
                print(f\"     Severity: {vuln.get('severity', 'Unknown')}\")
                desc = vuln.get('description', 'No description')
                if len(desc) > 80:
                    desc = desc[:77] + '...'
                print(f\"     {desc}\")
    else:
        print(f\"\\n✅ No vulnerabilities detected (CVSS >= 5.0)\")
    
    if data.get('error'):
        print(f\"\\n⚠️  Error: {data['error']}\")
except json.JSONDecodeError:
    print('⚠️  Invalid JSON response or scan still in progress')
except Exception as e:
    print(f'⚠️  Error: {e}')
"

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Demo 5: Comprehensive Scan (NEW)${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"

echo -e "${YELLOW}→ Running comprehensive scan on ${TEST_IP}...${NC}"
echo -e "${YELLOW}  (Combines port scan + vulnerability scan)${NC}"
echo -e "${YELLOW}  (This may take 7-15 minutes)${NC}"
echo ""

curl -s "${API_URL}/scan/comprehensive/${TEST_IP}" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(f\"Target: {data['ip']}\")
    print(f\"Scan Type: {data['scan_type']}\")
    print(f\"Timestamp: {data['timestamp']}\")
    
    # Port info
    if data.get('ports'):
        ports_data = data['ports']
        print(f\"\\n📊 Port Scan Results:\")
        print(f\"   Open Ports: {ports_data.get('open_ports', 0)}\")
        if ports_data.get('services'):
            print(f\"   Services: {len(ports_data['services'])}\")
    
    # Vulnerability info
    if data.get('vulnerabilities'):
        vuln_data = data['vulnerabilities']
        print(f\"\\n🔒 Vulnerability Scan Results:\")
        print(f\"   Total: {vuln_data.get('vulnerability_count', 0)}\")
        print(f\"   Critical: {vuln_data.get('critical', 0)}\")
        print(f\"   High: {vuln_data.get('high', 0)}\")
        print(f\"   Medium: {vuln_data.get('medium', 0)}\")
    
    print(f\"\\n✅ Comprehensive scan complete!\")
    print(f\"   View full results in JSON format for detailed analysis.\")
    
except json.JSONDecodeError:
    print('⚠️  Invalid JSON response or scan still in progress')
except Exception as e:
    print(f'⚠️  Error: {e}')
"

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Demo Complete!                                           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}✓ All new features demonstrated successfully!${NC}"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "  1. Review full documentation: PORT_SCANNING_GUIDE.md"
echo "  2. Test with your own devices"
echo "  3. Integrate into your security workflow"
echo "  4. Merge feature branch to main when ready"
echo ""
echo -e "${YELLOW}Useful Commands:${NC}"
echo "  • Get API docs: curl ${API_URL}/"
echo "  • Port scan: curl ${API_URL}/scan/ports/<ip>"
echo "  • Vuln scan: curl \"${API_URL}/scan/vulnerabilities/<ip>?ports=22,80,443\""
echo "  • Full scan: curl ${API_URL}/scan/comprehensive/<ip>"
echo ""
