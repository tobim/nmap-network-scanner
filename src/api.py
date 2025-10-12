#!/usr/bin/env python3
"""
FastAPI Network Scanner
Based on the working cli-scanner.js logic with external JSON rule integration
"""

import subprocess
import re
import asyncio
import time
import json
import logging
import ipaddress
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from collections import defaultdict
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from device_rule_engine import DeviceRuleEngine

# Configure logging for live logs
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),  # Console output
    ]
)
logger = logging.getLogger("NetworkScanner")


class Device(BaseModel):
    name: str
    ipv4: str
    ipv6: str = "N/A"
    mac: str
    hostname: str = "N/A"
    manufacturer: str
    type: str


class ScanResponse(BaseModel):
    scan_type: str
    timestamp: str
    devices_found: int
    devices: List[Dict[str, Any]]


class NetworkInfo(BaseModel):
    gateway: str
    network: str
    timestamp: str


app = FastAPI(
    title="Network Scanner API",
    description="Fast and accurate network device discovery with intelligent device identification",
    version="3.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class PrettyJSONResponse(JSONResponse):
    """Custom JSON response that formats output nicely"""
    def render(self, content: any) -> bytes:
        return json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            separators=(",", ": "),
        ).encode("utf-8")


# Set default response class for all endpoints
app.router.default_response_class = PrettyJSONResponse


class NetworkScanner:
    """Enhanced Network Scanner with rule-based device detection"""
    
    def __init__(self):
        """Initialize scanner with device rule engine"""
        self.gateway = None
        self.network_range = None
        self.device_rule_engine = DeviceRuleEngine()
        
        # Rate limiting: track requests per IP
        self.rate_limit_store = defaultdict(list)
        self.rate_limit_window = 60  # seconds
        self.rate_limit_max = 3  # max requests per window
        
        # Scan state tracking
        self.active_scans = set()
        
        # Result caching
        self.cache = {}
        self.cache_ttl = 300  # 5 minutes
        
        # Check sudo and nmap availability
        self._check_system_requirements()
        
        logger.info("🚀 Network Scanner initialized with external device rules")
    
    def _check_system_requirements(self):
        """Check if sudo and nmap are available"""
        try:
            # Check if sudo works with -n (non-interactive)
            result = subprocess.run(
                ["sudo", "-n", "true"], 
                capture_output=True, 
                timeout=5
            )
            if result.returncode != 0:
                logger.warning("⚠️ sudo not configured for passwordless access. Port scanning may fail.")
                logger.warning("   Configure with: sudo visudo (add 'username ALL=(ALL) NOPASSWD: /usr/bin/nmap')")
            else:
                logger.info("✅ sudo configured correctly")
            
            # Check if nmap is installed
            result = subprocess.run(
                ["which", "nmap"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                logger.error("❌ nmap not found! Install with: brew install nmap")
            else:
                nmap_path = result.stdout.strip()
                logger.info(f"✅ nmap found at {nmap_path}")
            
            # Check for NSE scripts
            self._check_nse_scripts()
            
        except Exception as e:
            logger.warning(f"⚠️ System requirements check failed: {str(e)}")
    
    def _check_nse_scripts(self):
        """Check if vulnerability scanning NSE scripts are available"""
        try:
            result = subprocess.run(
                ["nmap", "--script-help", "vulners"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if "vulners" in result.stdout.lower():
                logger.info("✅ NSE script 'vulners' available")
            else:
                logger.warning("⚠️ NSE script 'vulners' not found. Vulnerability scanning may be limited.")
                logger.warning("   Install: curl -o ~/.nmap/scripts/vulners.nse https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse")
        except Exception as e:
            logger.warning(f"⚠️ Could not check NSE scripts: {str(e)}")
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address format and range"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _validate_ports(self, ports: List[int]) -> bool:
        """Validate port numbers are in valid range"""
        return all(1 <= port <= 65535 for port in ports)
    
    def _check_rate_limit(self, client_ip: str) -> bool:
        """Check if client has exceeded rate limit"""
        now = time.time()
        
        # Clean old entries
        self.rate_limit_store[client_ip] = [
            timestamp for timestamp in self.rate_limit_store[client_ip]
            if now - timestamp < self.rate_limit_window
        ]
        
        # Check if limit exceeded
        if len(self.rate_limit_store[client_ip]) >= self.rate_limit_max:
            return False
        
        # Add new request
        self.rate_limit_store[client_ip].append(now)
        return True
    
    def _get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached scan result if still valid"""
        if cache_key in self.cache:
            result, timestamp = self.cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                logger.info(f"📦 Returning cached result for {cache_key}")
                return result
            else:
                del self.cache[cache_key]
        return None
    
    def _cache_result(self, cache_key: str, result: Dict[str, Any]):
        """Cache scan result"""
        self.cache[cache_key] = (result, time.time())
    
    def _sanitize_error(self, error: str) -> str:
        """Sanitize error messages to prevent information disclosure"""
        # Remove system paths
        error = re.sub(r'/[\w/.-]+', '[path]', error)
        # Remove version numbers
        error = re.sub(r'\d+\.\d+\.\d+', '[version]', error)
        return error
    
    def reload_rules(self) -> bool:
        """Reload device detection rules"""
        return self.device_rule_engine.reload_rules()
    
    def get_rules_info(self) -> Dict[str, Any]:
        """Get information about loaded rules"""
        return self.device_rule_engine.get_rules_info()
        
    async def get_network_info(self) -> Dict[str, str]:
        """Get network gateway and range"""
        try:
            logger.info("🌐 Getting network information...")
            # Get default gateway
            result = subprocess.run(['route', 'get', 'default'], 
                                  capture_output=True, text=True, timeout=10)
            
            gateway_match = re.search(r'gateway: ([\d.]+)', result.stdout)
            gateway = gateway_match.group(1) if gateway_match else '192.168.1.1'
            
            # Calculate network range
            parts = gateway.split('.')
            network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            
            self.gateway = gateway
            self.network_range = network
            
            logger.info(f"📡 Network: {network}, Gateway: {gateway}")
            
            return {
                "gateway": gateway,
                "network": network,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"❌ Failed to get network info: {str(e)}")
            raise Exception(f"Failed to get network info: {str(e)}")
    
    async def perform_host_discovery(self, scan_range: str) -> List[Dict[str, Any]]:
        """Perform host discovery using nmap"""
        logger.info(f"🔍 Starting host discovery on {scan_range}")
        
        # Try different nmap approaches with DNS resolution enabled
        # -R: Always do DNS resolution to get hostnames
        commands = [
            f"sudo -n nmap -sn -R -PE -PP -PM --script broadcast-dns-service-discovery,broadcast-dhcp-discover --script-timeout 10s {scan_range}",
            f"sudo -n nmap -sn -R {scan_range}",
            f"nmap -sn -R {scan_range}"
        ]
        
        for i, cmd in enumerate(commands):
            try:
                logger.info(f"⚡ Trying scan method {i+1}: {'Enhanced' if i==0 else 'Sudo' if i==1 else 'Basic'}")
                result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0 and result.stdout:
                    hosts = self.parse_host_discovery(result.stdout)
                    if hosts:
                        logger.info(f"✅ Found {len(hosts)} hosts with {['Enhanced', 'Sudo', 'Basic'][i]} method")
                        return hosts
                        
            except subprocess.TimeoutExpired:
                logger.warning(f"⚠️  Method {i+1} timed out")
                continue
            except Exception as e:
                logger.warning(f"⚠️  Method {i+1} failed: {str(e)}")
                continue
        
        logger.warning("⚠️  All discovery methods failed")
        return []
    
    def parse_host_discovery(self, output: str) -> List[Dict[str, Any]]:
        """Parse nmap host discovery output"""
        hosts = []
        lines = output.split('\n')
        current = None
        
        for line in lines:
            # Look for host entries
            ip_match = re.search(r'Nmap scan report for (.+)', line)
            if ip_match:
                if current:
                    hosts.append(current)
                
                target = ip_match.group(1)
                hostname_match = re.search(r'(.+) \((.+)\)', target)
                
                if hostname_match:
                    current = {
                        'ip': hostname_match.group(2),
                        'hostname': hostname_match.group(1)
                    }
                else:
                    current = {
                        'ip': target,
                        'hostname': None
                    }
            
            # Look for MAC addresses
            mac_match = re.search(r'MAC Address: ([0-9A-Fa-f:]{17}) \((.+)\)', line)
            if mac_match and current:
                current['mac'] = mac_match.group(1).upper()
                current['manufacturer'] = mac_match.group(2)
        
        if current:
            hosts.append(current)
        
        return hosts
    
    async def scan_ports_and_services(self, ip: str) -> Dict[str, Any]:
        """Scan ports and identify services on a specific host"""
        logger.info(f"🔍 Scanning ports and services on {ip}")
        
        # Check cache first
        cache_key = f"ports_{ip}"
        cached = self._get_cached_result(cache_key)
        if cached:
            return cached
        
        # Check if scan already in progress
        if ip in self.active_scans:
            logger.warning(f"⚠️ Port scan already in progress for {ip}")
            return {"ip": ip, "open_ports": 0, "ports": [], "services": [], "error": "Scan already in progress"}
        
        try:
            self.active_scans.add(ip)
            
            # Comprehensive port scan with service version detection
            # Use list format to prevent command injection
            cmd = ["sudo", "-n", "nmap", "-sV", "-sC", "--version-all", "-p-", 
                   "--max-retries", "2", "--host-timeout", "3m", ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
            
            if result.returncode != 0:
                logger.warning(f"⚠️ Full port scan failed for {ip}, trying top ports")
                # Fallback to top 1000 ports
                cmd = ["sudo", "-n", "nmap", "-sV", "-sC", "--top-ports", "1000", ip]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            scan_result = self.parse_port_scan(result.stdout, ip)
            self._cache_result(cache_key, scan_result)
            return scan_result
            
        except subprocess.TimeoutExpired:
            logger.warning(f"⏱️ Port scan timed out for {ip}")
            return {"ip": ip, "open_ports": 0, "ports": [], "services": [], "error": "Scan timeout"}
        except Exception as e:
            logger.error(f"❌ Port scan failed for {ip}: {str(e)}")
            sanitized_error = self._sanitize_error(str(e))
            return {"ip": ip, "open_ports": 0, "ports": [], "services": [], "error": sanitized_error}
        finally:
            self.active_scans.discard(ip)
    
    async def scan_vulnerabilities(self, ip: str, ports: List[int] = None) -> Dict[str, Any]:
        """Scan for vulnerabilities using nmap NSE scripts"""
        logger.info(f"🔎 Scanning vulnerabilities on {ip}")
        
        # Validate ports if provided
        if ports and not self._validate_ports(ports):
            logger.error(f"❌ Invalid port numbers provided for {ip}")
            return {"ip": ip, "vulnerability_count": 0, "vulnerabilities": [], "error": "Invalid port numbers (must be 1-65535)"}
        
        # Check cache first
        cache_key = f"vulns_{ip}_{'all' if not ports else ','.join(map(str, ports))}"
        cached = self._get_cached_result(cache_key)
        if cached:
            return cached
        
        # Check if scan already in progress
        scan_id = f"{ip}_vuln"
        if scan_id in self.active_scans:
            logger.warning(f"⚠️ Vulnerability scan already in progress for {ip}")
            return {"ip": ip, "vulnerability_count": 0, "vulnerabilities": [], "error": "Scan already in progress"}
        
        try:
            self.active_scans.add(scan_id)
            
            port_spec = ",".join(map(str, ports)) if ports else "-"
            
            # Use vulners and other vulnerability detection scripts
            scripts = "vulners,vulscan,vuln"
            # Use list format to prevent command injection
            cmd = ["sudo", "-n", "nmap", "-sV", f"--script={scripts}", 
                   "--script-args", "mincvss=5.0", "-p", port_spec, ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            scan_result = self.parse_vulnerability_scan(result.stdout, ip)
            self._cache_result(cache_key, scan_result)
            return scan_result
            
        except subprocess.TimeoutExpired:
            logger.warning(f"⏱️ Vulnerability scan timed out for {ip}")
            return {"ip": ip, "vulnerability_count": 0, "vulnerabilities": [], "error": "Scan timeout"}
        except Exception as e:
            logger.error(f"❌ Vulnerability scan failed for {ip}: {str(e)}")
            sanitized_error = self._sanitize_error(str(e))
            return {"ip": ip, "vulnerability_count": 0, "vulnerabilities": [], "error": sanitized_error}
        finally:
            self.active_scans.discard(scan_id)
    
    def parse_port_scan(self, output: str, ip: str) -> Dict[str, Any]:
        """Parse nmap port scan output with improved pattern matching"""
        ports = []
        services = []
        os_info = None
        
        lines = output.split('\n')
        for line in lines:
            # Improved regex to handle all port states and service names
            # Matches: open, closed, filtered, open|filtered, closed|filtered, tcpwrapped
            port_match = re.search(
                r'(\d+)/(tcp|udp)\s+(open|closed|filtered|open\|filtered|closed\|filtered)\s+(\S+)(?:\s+(.+))?',
                line
            )
            if port_match:
                port_num = int(port_match.group(1))
                protocol = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4)
                version = port_match.group(5).strip() if port_match.group(5) else ""
                
                # Handle tcpwrapped service
                if service == "tcpwrapped":
                    version = "Service wrapped"
                
                port_info = {
                    "port": port_num,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "version": version
                }
                
                ports.append(port_info)
                
                # Only add to services if open
                if "open" in state and service not in [s["name"] for s in services]:
                    services.append({
                        "name": service,
                        "version": version,
                        "port": port_num,
                        "protocol": protocol
                    })
            
            # Parse OS detection
            os_match = re.search(r'Running: (.+)', line)
            if os_match:
                os_info = os_match.group(1)
        
        # Count only open ports
        open_count = len([p for p in ports if "open" in p["state"]])
        
        return {
            "ip": ip,
            "open_ports": open_count,
            "total_ports_scanned": len(ports),
            "ports": ports,
            "services": services,
            "os_detection": os_info
        }
    
    def parse_vulnerability_scan(self, output: str, ip: str) -> Dict[str, Any]:
        """Parse nmap vulnerability scan output with improved pattern matching"""
        vulnerabilities = []
        current_port = None
        
        lines = output.split('\n')
        
        for i, line in enumerate(lines):
            # Track current port being scanned
            port_match = re.search(r'(\d+)/(tcp|udp)\s+open', line)
            if port_match:
                current_port = int(port_match.group(1))
            
            # Look for CVE references with better context
            cve_match = re.search(r'(CVE-\d{4}-\d{4,})', line)
            if cve_match:
                cve_id = cve_match.group(1)
                
                # Extract CVSS score more carefully (look for patterns like "7.5" or "CVSS: 7.5")
                score = None
                score_match = re.search(r'(?:CVSS|cvss|score)[:\s]*(\d+\.\d+)', line, re.IGNORECASE)
                if score_match:
                    score = float(score_match.group(1))
                else:
                    # Try to find any decimal number between 0-10
                    score_match = re.search(r'\b([0-9]\.\d+|10\.0)\b', line)
                    if score_match:
                        potential_score = float(score_match.group(1))
                        if 0 <= potential_score <= 10:
                            score = potential_score
                
                # Determine severity
                severity = "Unknown"
                if score:
                    if score >= 9.0:
                        severity = "Critical"
                    elif score >= 7.0:
                        severity = "High"
                    elif score >= 4.0:
                        severity = "Medium"
                    else:
                        severity = "Low"
                
                # Try to extract title/description from next few lines
                description = line.strip()
                title = ""
                
                # Look for title in next line
                if i + 1 < len(lines):
                    next_line = lines[i + 1].strip()
                    if next_line and not next_line.startswith('|') and len(next_line) > 10:
                        title = next_line[:100]  # Limit title length
                
                # Check for exploit availability
                exploit_available = bool(re.search(r'exploit|metasploit|public', line, re.IGNORECASE))
                
                vuln = {
                    "cve": cve_id,
                    "cvss_score": score,
                    "severity": severity,
                    "title": title,
                    "description": description[:200],  # Limit description length
                    "port": current_port,
                    "exploit_available": exploit_available
                }
                
                # Avoid duplicates
                if not any(v["cve"] == cve_id for v in vulnerabilities):
                    vulnerabilities.append(vuln)
        
        return {
            "ip": ip,
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "critical": len([v for v in vulnerabilities if v["severity"] == "Critical"]),
            "high": len([v for v in vulnerabilities if v["severity"] == "High"]),
            "medium": len([v for v in vulnerabilities if v["severity"] == "Medium"]),
            "low": len([v for v in vulnerabilities if v["severity"] == "Low"]),
            "with_exploits": len([v for v in vulnerabilities if v.get("exploit_available")])
        }
    
    async def perform_comprehensive_analysis(self, host: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze device characteristics using external rule engine"""
        device_data = {
            'name': host.get('hostname') or host['ip'],
            'ipv4': host['ip'],
            'ipv6': 'N/A',
            'mac': host.get('mac', 'N/A'),
            'manufacturer': host.get('manufacturer', 'Unknown'),
            'hostname': host.get('hostname'),
            'type': 'Unknown Device',
            'category': 'Unknown',
            'confidence': 0,
            'capabilities': [],
            'osGuess': 'Unknown',
            'vendor': 'Unknown'
        }
        
        # Use rule engine for analysis
        analysis_result = self.device_rule_engine.analyze_device(device_data)
        
        # Update device data with analysis results
        device_data.update(analysis_result)
        
        return device_data
    
    async def scan_network(self) -> List[Dict[str, Any]]:
        """Main network scanning function"""
        try:
            # Get network info if not cached
            if not self.network_range:
                await self.get_network_info()
            
            logger.info(f"🚀 Starting network scan on {self.network_range}")
            
            # Stage 1: Host Discovery
            logger.info("📡 Stage 1: Host Discovery")
            hosts = await self.perform_host_discovery(self.network_range)
            logger.info(f"✅ Discovery complete: {len(hosts)} live hosts found")
            
            if not hosts:
                logger.warning("❌ No hosts found on network")
                return []
            
            # Stage 2: Comprehensive Analysis
            logger.info("🔬 Stage 2: Device Analysis")
            devices = []
            for i, host in enumerate(hosts, 1):
                logger.info(f"🔍 Analyzing device {i}/{len(hosts)}: {host['ip']}")
                device_data = await self.perform_comprehensive_analysis(host)
                devices.append(device_data)
                logger.info(f"✅ Device {i}: {device_data['name']} ({device_data['type']})")
            
            logger.info(f"🎉 Scan complete! Analyzed {len(devices)} devices")
            return devices
            
        except Exception as e:
            logger.error(f"❌ Network scan failed: {str(e)}")
            raise Exception(f"Network scan failed: {str(e)}")


# Initialize scanner
scanner = NetworkScanner()


@app.get("/")
async def root():
    """API documentation and endpoints"""
    return {
        "name": "Network Scanner API",
        "version": "3.1.0",
        "description": "Fast and accurate network device discovery with intelligent device identification, port scanning, service detection, and vulnerability assessment",
        "endpoints": {
            "network_scanning": {
                "/scan": "GET - Comprehensive network scan with device identification",
                "/scan/clean": "GET - Clean format scan with simple JSON output",
                "/network/info": "GET - Get current network information"
            },
            "port_and_service_scanning": {
                "/scan/ports/{ip}": "GET - Scan open ports and services on specific host",
                "/scan/vulnerabilities/{ip}": "GET - Scan for vulnerabilities (optional: ?ports=22,80,443)"
            },
            "rules_management": {
                "/rules/info": "GET - Get information about loaded device detection rules",
                "/rules/reload": "POST - Reload device detection rules from JSON files",
                "/rules/categories": "GET - Get list of available device categories",
                "/rules/vendors/{category}": "GET - Get vendors for a specific category"
            },
            "health": {
                "/health": "GET - API health check"
            }
        },
        "features": {
            "device_detection": "10,000+ device patterns from external JSON rules",
            "port_scanning": "Comprehensive port scanning with service version detection",
            "vulnerability_scanning": "CVE detection using nmap NSE scripts (vulners, vulscan, vuln)",
            "service_identification": "Automatic service fingerprinting and version detection",
            "dynamic_loading": "Rules can be updated without server restart",
            "comprehensive_categories": "Smartphones, tablets, routers, smart home, IoT, computers, gaming, printers, NAS, industrial devices"
        },
        "usage_examples": {
            "network_scan": "GET /scan - Discover all devices on network",
            "port_scan": "GET /scan/ports/192.168.1.10 - Check open ports on specific device",
            "vuln_scan": "GET /scan/vulnerabilities/192.168.1.10?ports=22,80,443 - Check vulnerabilities"
        },
        "security_scripts": {
            "vulners": "CVE detection and CVSS scoring",
            "vulscan": "Vulnerability database scanning",
            "vuln": "General vulnerability detection scripts"
        },
        "timestamp": datetime.now().isoformat()
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "rules_loaded": scanner.device_rule_engine.loaded_at is not None
    }


@app.get("/rules/info")
async def get_rules_info():
    """Get information about loaded device detection rules"""
    try:
        return scanner.get_rules_info()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/rules/reload")
async def reload_rules():
    """Reload device detection rules from JSON files"""
    try:
        success = scanner.reload_rules()
        if success:
            return {
                "status": "success",
                "message": "Device detection rules reloaded successfully",
                "timestamp": datetime.now().isoformat(),
                "rules_info": scanner.get_rules_info()
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to reload rules")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/rules/categories")
async def get_categories():
    """Get list of available device categories"""
    try:
        categories = scanner.device_rule_engine.get_categories()
        return {
            "categories": categories,
            "count": len(categories),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/rules/vendors/{category}")
async def get_vendors_by_category(category: str):
    """Get vendors for a specific category"""
    try:
        vendors = scanner.device_rule_engine.get_vendors_by_category(category)
        if not vendors:
            raise HTTPException(status_code=404, detail=f"Category '{category}' not found")
        
        return {
            "category": category,
            "vendors": vendors,
            "count": len(vendors),
            "timestamp": datetime.now().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/network/info", response_model=NetworkInfo)
async def get_network_info():
    """Get current network information"""
    try:
        info = await scanner.get_network_info()
        return NetworkInfo(**info)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scan", response_model=ScanResponse)
async def scan_network():
    """Comprehensive network scan with device identification"""
    try:
        logger.info("🌟 API: Comprehensive scan requested")
        devices = await scanner.scan_network()
        
        result = ScanResponse(
            scan_type="comprehensive",
            timestamp=datetime.now().isoformat(),
            devices_found=len(devices),
            devices=devices
        )
        
        logger.info(f"✅ API: Comprehensive scan completed - {len(devices)} devices found")
        return result
        
    except Exception as e:
        logger.error(f"❌ API comprehensive scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scan/clean", response_model=ScanResponse)
async def scan_network_clean():
    """Clean format scan with simple JSON output"""
    try:
        logger.info("🧹 API: Clean scan requested")
        devices = await scanner.scan_network()
        
        # Convert to clean format
        clean_devices = [
            {
                "name": device["name"],
                "ipv4": device["ipv4"],
                "ipv6": device.get("ipv6", "N/A"),
                "mac": device["mac"],
                "hostname": device.get("hostname", "N/A"),
                "manufacturer": device["manufacturer"],
                "type": device["type"]
            }
            for device in devices
        ]
        
        result = ScanResponse(
            scan_type="clean",
            timestamp=datetime.now().isoformat(),
            devices_found=len(clean_devices),
            devices=clean_devices
        )
        
        logger.info(f"✅ API: Clean scan completed - {len(clean_devices)} devices found")
        return result
        
    except Exception as e:
        logger.error(f"❌ API clean scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scan/ports/{ip}")
async def scan_host_ports(ip: str, request: Request):
    """Scan open ports and services on a specific host"""
    try:
        logger.info(f"🔍 API: Port scan requested for {ip}")
        
        # Validate IP format using proper validation
        if not scanner._validate_ip(ip):
            raise HTTPException(status_code=400, detail="Invalid IP address format")
        
        # Check rate limiting
        client_ip = request.client.host
        if not scanner._check_rate_limit(client_ip):
            raise HTTPException(
                status_code=429, 
                detail=f"Rate limit exceeded. Maximum {scanner.rate_limit_max} requests per {scanner.rate_limit_window} seconds"
            )
        
        result = await scanner.scan_ports_and_services(ip)
        result["timestamp"] = datetime.now().isoformat()
        result["scan_type"] = "ports_and_services"
        
        logger.info(f"✅ API: Port scan completed for {ip} - {result.get('open_ports', 0)} ports found")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ API port scan error for {ip}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scan/vulnerabilities/{ip}")
async def scan_host_vulnerabilities(ip: str, request: Request, ports: Optional[str] = None):
    """Scan for vulnerabilities on a specific host
    
    Args:
        ip: Target IP address
        ports: Optional comma-separated list of ports (e.g., "22,80,443")
    """
    try:
        logger.info(f"🔎 API: Vulnerability scan requested for {ip}")
        
        # Validate IP format using proper validation
        if not scanner._validate_ip(ip):
            raise HTTPException(status_code=400, detail="Invalid IP address format")
        
        # Check rate limiting
        client_ip = request.client.host
        if not scanner._check_rate_limit(client_ip):
            raise HTTPException(
                status_code=429, 
                detail=f"Rate limit exceeded. Maximum {scanner.rate_limit_max} requests per {scanner.rate_limit_window} seconds"
            )
        
        # Parse and validate ports if provided
        port_list = None
        if ports:
            try:
                port_list = [int(p.strip()) for p in ports.split(',')]
                # Validate port range
                if not scanner._validate_ports(port_list):
                    raise HTTPException(status_code=400, detail="Port numbers must be between 1 and 65535")
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid port format. Use comma-separated numbers (e.g., 22,80,443)")
        
        result = await scanner.scan_vulnerabilities(ip, port_list)
        result["timestamp"] = datetime.now().isoformat()
        result["scan_type"] = "vulnerability"
        
        logger.info(f"✅ API: Vulnerability scan completed for {ip} - {result.get('vulnerability_count', 0)} vulnerabilities found")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ API vulnerability scan error for {ip}: {str(e)}")
        sanitized_error = scanner._sanitize_error(str(e))
        raise HTTPException(status_code=500, detail=sanitized_error)


if __name__ == "__main__":
    import uvicorn
    
    # Configure uvicorn logging
    log_config = uvicorn.config.LOGGING_CONFIG
    log_config["formatters"]["default"]["fmt"] = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    log_config["formatters"]["access"]["fmt"] = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    logger.info("🚀 Starting Network Scanner API v3.0 with External Rule Engine...")
    logger.info("📚 Loading device detection rules from JSON files...")
    logger.info("🎯 10,000+ device patterns loaded for comprehensive identification")
    logger.info("📡 Ready to scan network devices with advanced detection")
    logger.info("🔍 API Documentation: http://localhost:8001")
    logger.info("🎯 Test scanning: http://localhost:8001/scan")
    logger.info("✨ Clean format: http://localhost:8001/scan/clean")
    logger.info("⚙️  Rules management: http://localhost:8001/rules/info")
    logger.info("🔄 Reload rules: POST http://localhost:8001/rules/reload")
    logger.info("📊 Live logs enabled for real-time monitoring")
    logger.info("🎨 Pretty JSON formatting enabled (no need for json.tool)")
    
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8001,
        log_config=log_config,
        access_log=True
    )
