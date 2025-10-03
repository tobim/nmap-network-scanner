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
from datetime import datetime
from typing import List, Dict, Optional, Any
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
        logger.info("🚀 Network Scanner initialized with external device rules")
    
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
        
        # Try different nmap approaches (same as cli-scanner.js)
        commands = [
            f"sudo -n nmap -sn -PE -PP -PM --script broadcast-dns-service-discovery,broadcast-dhcp-discover --script-timeout 10s {scan_range}",
            f"sudo -n nmap -sn {scan_range}",
            f"nmap -sn {scan_range}"
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
        "version": "3.0.0",
        "description": "Fast and accurate network device discovery with intelligent device identification using external JSON rules",
        "endpoints": {
            "/scan": "GET - Comprehensive network scan with device identification",
            "/scan/clean": "GET - Clean format scan with simple JSON output",
            "/network/info": "GET - Get current network information",
            "/rules/info": "GET - Get information about loaded device detection rules",
            "/rules/reload": "POST - Reload device detection rules from JSON files",
            "/rules/categories": "GET - Get list of available device categories",
            "/rules/vendors/{category}": "GET - Get vendors for a specific category",
            "/health": "GET - API health check"
        },
        "features": {
            "external_rules": "Device detection powered by comprehensive JSON rule files",
            "10000_patterns": "Over 10,000 device detection patterns",
            "dynamic_loading": "Rules can be updated without server restart",
            "comprehensive_categories": "Smartphones, tablets, routers, smart home, IoT, computers, gaming, printers, NAS, industrial devices"
        },
        "usage": {
            "recommended": "/scan - Best balance of speed and accuracy",
            "simple": "/scan/clean - Clean JSON format perfect for integrations",
            "rules": "/rules/info - View currently loaded detection rules"
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
