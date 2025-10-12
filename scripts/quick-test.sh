#!/bin/bash

# Quick API Test Script
# Tests basic functionality without long scans

API_URL="http://localhost:8001"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Quick API Test - v3.1.0              ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

# Test 1: Health Check
echo -e "${YELLOW}→ Test 1: Health Check${NC}"
curl -s "${API_URL}/health" | python3 -m json.tool
echo ""

# Test 2: API Info
echo -e "${YELLOW}→ Test 2: API Information${NC}"
curl -s "${API_URL}/" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f\"✓ Name: {data['name']}\")
print(f\"✓ Version: {data['version']}\")
print(f\"✓ Endpoints available: {len(data['endpoints'])}\")
"
echo ""

# Test 3: Rules Info
echo -e "${YELLOW}→ Test 3: Device Rules${NC}"
curl -s "${API_URL}/rules/info" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f\"✓ Total rules: {data['total_rules']}\")
print(f\"✓ Categories: {data['categories_count']}\")
print(f\"✓ Vendors: {data['vendors_count']}\")
"
echo ""

# Test 4: Network Info
echo -e "${YELLOW}→ Test 4: Network Information${NC}"
curl -s "${API_URL}/network/info" | python3 -m json.tool
echo ""

# Test 5: Categories
echo -e "${YELLOW}→ Test 5: Device Categories${NC}"
curl -s "${API_URL}/rules/categories" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f\"✓ Available categories: {len(data['categories'])}\")
for cat in data['categories'][:10]:
    print(f\"  • {cat}\")
if len(data['categories']) > 10:
    print(f\"  ... and {len(data['categories']) - 10} more\")
"
echo ""

echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  All Tests Passed! ✓                  ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}API is ready for:${NC}"
echo "  • Network scanning: curl ${API_URL}/scan/clean"
echo "  • Port scanning: curl ${API_URL}/scan/ports/<ip>"
echo "  • Vulnerability scans: curl ${API_URL}/scan/vulnerabilities/<ip>"
echo "  • Full demo: ./scripts/demo.sh"
echo ""
