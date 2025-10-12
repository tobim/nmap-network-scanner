# Network Scanner API v3.1.0

Fast and accurate network device discovery with intelligent device identification, port scanning, service detection, and vulnerability assessment.

[![Python](https://img.shields.io/badge/Python-3.13-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.116.1-green.svg)](https://fastapi.tiangolo.com/)
[![nmap](https://img.shields.io/badge/nmap-7.x+-red.svg)](https://nmap.org/)

---

## 🚀 Quick Start

```bash
# 1. Activate virtual environment
source api_env/bin/activate

# 2. Start the API server (requires sudo for accurate scanning)
sudo ./api_env/bin/python3 run.py

# 3. Run the demo
./scripts/demo.sh

# 4. Access API documentation
open http://localhost:8001
```

---

## 📁 Project Structure

```
nmap-network-scanner/
├── run.py                          # API launcher script (NEW)
├── package.json                    # Node.js dependencies (legacy)
│
├── src/                            # Python source code (NEW)
│   ├── __init__.py
│   ├── api.py                     # Main FastAPI application (v3.1.0)
│   └── device_rule_engine.py      # Device detection engine
│
├── config/                         # Configuration files
│   ├── device_rules.json          # Main device detection rules (10,000+)
│   └── extended_device_rules.json # Extended IoT rules
│
├── docs/                           # Documentation
│   ├── README.md                  # Main documentation
│   ├── PORT_SCANNING_GUIDE.md     # Technical guide (336 lines)
│   ├── FEATURE_SUMMARY.md         # Executive summary (310 lines)
│   └── TEST_RESULTS.md            # Live test results (283 lines)
│
├── scripts/                        # Utility scripts
│   └── demo.sh                    # Interactive demo script (235 lines)
│
├── lib/                            # JavaScript libraries (legacy)
│   ├── deviceAnalyzer.js
│   └── networkScanner.js
│
├── legacy/                         # Old/deprecated files
│   ├── *-scanner.js               # Previous scanner implementations
│   └── *-server.js                # Old server files
│
├── public/                         # Web interface (if needed)
│   └── index.html
│
└── api_env/                        # Python virtual environment
    └── (venv files)
```

---

## ✨ Features

### 🔍 Network Scanning
- **Fast device discovery** - Scan entire network in under 60 seconds
- **10,000+ device patterns** - Comprehensive device identification
- **28 device categories** - From smartphones to industrial equipment
- **97+ vendors supported** - Apple, Samsung, Xiaomi, Google, Amazon, etc.

### 🔒 Security Features (NEW in v3.1.0)
- **Port scanning** - Detect open ports with `-p-` full scan
- **Service detection** - Identify software versions running on ports
- **Vulnerability assessment** - CVE detection with CVSS scoring
- **NSE scripts** - vulners, vulscan, vuln for deep analysis

### 📊 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API information and available endpoints |
| `/health` | GET | Health check with status |
| `/scan` | GET | Full network scan with device info |
| `/scan/clean` | GET | Clean JSON format scan |
| `/scan/ports/{ip}` | GET | Port scan for specific host |
| `/scan/vulnerabilities/{ip}` | GET | Vulnerability scan (optional: ?ports=) |
| `/scan/comprehensive/{ip}` | GET | Complete scan: device + ports + vulns |
| `/rules/info` | GET | Device rules statistics |
| `/rules/reload` | POST | Reload rules from JSON files |

---

## 📖 Documentation

- **[PORT_SCANNING_GUIDE.md](docs/PORT_SCANNING_GUIDE.md)** - Comprehensive technical guide with nmap commands, API examples, and troubleshooting
- **[FEATURE_SUMMARY.md](docs/FEATURE_SUMMARY.md)** - Executive summary with use cases and quick start
- **[TEST_RESULTS.md](docs/TEST_RESULTS.md)** - Real-world test results on live network with 11 devices

---

## 🎬 Demo

Run the interactive demo to see all features in action:

```bash
# Default demo (scans gateway 192.168.1.1)
./scripts/demo.sh

# Test specific device
./scripts/demo.sh 192.168.1.10
```

The demo showcases:
- ✅ API health check
- ✅ Network discovery (all devices)
- ✅ Port scanning with service detection
- ✅ Vulnerability assessment with CVE detection
- ✅ Comprehensive scan combining all features

---

## 🔧 Requirements

- **Python 3.13+** with FastAPI
- **nmap 7.x+** installed on system
- **sudo privileges** for accurate MAC address and port scanning
- **nmap NSE scripts** (vulners, vulscan, vuln)

### Install Dependencies

```bash
# Python dependencies (already in api_env)
pip install fastapi uvicorn pydantic

# nmap (macOS)
brew install nmap

# Install vulners NSE script
mkdir -p ~/.nmap/scripts
curl -o ~/.nmap/scripts/vulners.nse https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse
```

---

## 🎯 Usage Examples

### Basic Network Scan
```bash
curl http://localhost:8001/scan/clean
```

### Port Scan
```bash
curl http://localhost:8001/scan/ports/192.168.1.1
```

### Vulnerability Scan
```bash
curl "http://localhost:8001/scan/vulnerabilities/192.168.1.1?ports=22,80,443"
```

### Comprehensive Scan
```bash
curl http://localhost:8001/scan/comprehensive/192.168.1.1
```

---

## 🛠️ Development

### File Organization

- **Core files**: `api.py`, `device_rule_engine.py` (root directory)
- **Configuration**: All JSON rules in `config/` directory
- **Documentation**: All markdown files in `docs/` directory
- **Scripts**: Utility scripts in `scripts/` directory
- **Legacy code**: Old files in `legacy/` directory

### Running Tests

```bash
# Start API server (new method)
sudo ./api_env/bin/python3 run.py

# Run full demo
./scripts/demo.sh

# Test specific endpoint
curl http://localhost:8001/health
```

---

## 📈 Performance

- **Network scan**: ~45-60 seconds for typical home network
- **Port scan**: ~5-10 minutes (full -p- scan with version detection)
- **Vulnerability scan**: ~2-5 minutes per host
- **Comprehensive scan**: ~7-15 minutes per host

---

## 🔐 Security Notes

- **Requires sudo** for accurate scanning (MAC addresses, port scanning)
- **NSE scripts** access external CVE databases
- **Rate limiting** recommended for production use
- **Firewall rules** may affect scan accuracy

---

## 🌟 Device Detection Examples

### Supported Categories
- Smartphones, Tablets, Laptops, Desktops
- Routers, Switches, Access Points
- Smart Speakers, Smart TVs, Streaming Devices
- Security Cameras, Smart Displays
- Gaming Consoles, Wearables
- Smart Home Devices (lights, thermostats, locks)
- Industrial Automation, Laboratory Equipment
- Medical Devices, Retail POS Systems

### Vendor Coverage
Apple, Samsung, Xiaomi, Google, Amazon, Microsoft, Dell, HP, Lenovo, Asus, Sony, LG, Philips, Ring, Nest, Sonos, Roku, and 80+ more manufacturers.

---

## 📝 Version History

### v3.1.0 (October 2025) - Current
- ✅ Added port scanning with full `-p-` support
- ✅ Service detection with version identification
- ✅ Vulnerability assessment with CVE detection
- ✅ NSE script integration (vulners, vulscan, vuln)
- ✅ Comprehensive scan endpoint
- ✅ Enhanced documentation (336+ lines)
- ✅ Interactive demo script

### v3.0.0
- ✅ Expanded device rules to 10,000+ patterns
- ✅ 28 device categories
- ✅ 97+ vendor support
- ✅ Clean JSON output format

---

## 🤝 Contributing

This is a private project, but suggestions are welcome!

1. Create feature branch: `git checkout -b feature/your-feature`
2. Make changes and test thoroughly
3. Commit with clear messages: `git commit -m "feat: add new feature"`
4. Push to GitHub: `git push origin feature/your-feature`
5. Create pull request for review

---

## 📄 License

Private project - All rights reserved

---

## 👤 Author

**sunkenship2025**

- GitHub: [@sunkenship2025](https://github.com/sunkenship2025)
- Repository: [nmap-network-scanner](https://github.com/sunkenship2025/nmap-network-scanner)

---

## 🙏 Acknowledgments

- **nmap** - Network scanning capabilities
- **FastAPI** - Modern Python web framework
- **vulners** - CVE detection NSE script
- **vulscan** - Vulnerability database scanning

---

**Built with ❤️ for network security and device discovery**
