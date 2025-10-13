# Project Structure

```
nmap-network-scanner/
│
├── 📄 Core Application Files
│   ├── api.py                         # Main FastAPI server (v3.1.0) - 464 lines
│   ├── device_rule_engine.py          # Device detection engine - 362 lines
│   ├── package.json                   # Node.js dependencies
│   └── README.md                      # Main documentation (THIS FILE)
│
├── ⚙️ config/                          # Configuration Files
│   ├── device_rules.json              # Main rules: 10,000+ patterns
│   ├── extended_device_rules.json     # Extended IoT rules
│   └── comprehensive_device_rules.json # Comprehensive ruleset
│
├── 📚 docs/                            # Documentation
│   ├── PORT_SCANNING_GUIDE.md         # Technical guide - 336 lines
│   ├── FEATURE_SUMMARY.md             # Executive summary - 310 lines
│   └── TEST_RESULTS.md                # Live test results - 283 lines
│
├── 🔧 scripts/                         # Utility Scripts
│   └── demo.sh                        # Interactive demo - 235 lines
│
├── 📦 lib/                             # JavaScript Libraries (Legacy)
│   ├── deviceAnalyzer.js              # Device analysis module
│   └── networkScanner.js              # Network scanning module
│
├── 🗃️ legacy/                          # Deprecated Files
│   ├── api-server.js                  # Old API implementation
│   ├── api-test.js                    # API tests
│   ├── clean-api.js                   # Clean API version
│   ├── clean-scanner.js               # Clean scanner
│   ├── cli-scanner.js                 # CLI scanner
│   ├── enhanced-scanner.js            # Enhanced version
│   ├── fast-scanner.js                # Fast scanner
│   ├── final-scanner.js               # Final version
│   ├── formatScanResults.js           # Formatting utility
│   ├── import-test.js                 # Import tests
│   ├── production-scanner.js          # Production scanner
│   ├── require-test.js                # Require tests
│   ├── server-clean.js                # Clean server
│   ├── server.js                      # Original server
│   ├── simple-scanner.js              # Simple scanner
│   ├── test-scanner.js                # Test scanner
│   ├── test-server.js                 # Test server
│   └── ultimate-scanner.js            # Ultimate scanner
│
├── 🌐 public/                          # Web Interface
│   ├── index.html                     # Main web interface
│   └── index.html.bak                 # Backup
│
├── 🐍 api_env/                         # Python Virtual Environment
│   ├── bin/                           # Executables
│   ├── lib/                           # Python packages
│   └── pyvenv.cfg                     # Environment config
│
├── 📝 Git & Config Files
│   ├── .git/                          # Git repository
│   ├── .gitignore                     # Git ignore rules
│   └── node_modules/                  # Node dependencies (ignored)
│
└── 🧪 tests/                           # Test Files (empty)
    └── (future test files)

```

## 📊 Statistics

- **Total Lines of Code**: ~2,500+ lines (excluding JSON rules)
- **JSON Rules**: 10,000+ device detection patterns
- **Device Categories**: 28
- **Supported Vendors**: 97+
- **Documentation**: 929 lines across 3 files
- **Legacy Files**: 18 deprecated scanner implementations

## 🎯 Key Files

### Production Files (Active)
- ✅ `api.py` - Main application (use this!)
- ✅ `device_rule_engine.py` - Device detection
- ✅ `config/*.json` - Detection rules
- ✅ `scripts/demo.sh` - Testing & demos

### Documentation Files
- 📖 `README.md` - Start here
- 📖 `docs/PORT_SCANNING_GUIDE.md` - Technical reference
- 📖 `docs/FEATURE_SUMMARY.md` - Executive summary
- 📖 `docs/TEST_RESULTS.md` - Test validation

### Legacy Files (Do Not Use)
- ❌ `legacy/*.js` - Old implementations
- ❌ Use `api.py` instead

## 🚀 Quick Start

```bash
# 1. Start API
sudo ./api_env/bin/python3 api.py

# 2. Run demo
./scripts/demo.sh

# 3. Access docs
open http://localhost:8001
```

## 📁 Directory Purposes

| Directory | Purpose | Files |
|-----------|---------|-------|
| **Root** | Core application files | 2 Python files |
| **config/** | JSON device detection rules | 3 JSON files |
| **docs/** | Comprehensive documentation | 3 MD files |
| **scripts/** | Utility and demo scripts | 1 shell script |
| **legacy/** | Deprecated old code | 18 JS files |
| **lib/** | JavaScript library modules | 2 JS files |
| **public/** | Web interface files | 2 HTML files |
| **api_env/** | Python virtual environment | (many files) |
| **tests/** | Future test suite | (empty) |

## 🔄 File Organization Logic

- **Core files** stay in root for easy access
- **Configuration** separated into `config/` for clarity
- **Documentation** organized in `docs/` for reference
- **Utility scripts** in `scripts/` for tooling
- **Legacy code** isolated in `legacy/` to avoid confusion
- **Tests** prepared in `tests/` for future expansion

---

**Last Updated**: October 3, 2025  
**Version**: 3.1.0  
**Branch**: feature/open-ports-services
