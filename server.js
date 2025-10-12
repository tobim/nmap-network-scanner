#!/usr/bin/env node

/**
 * Network Scanner API Server
 * Based on the working cli-scanner.js logic
 */

const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ===== CORE SCANNER FUNCTIONS (from working cli-scanner.js) =====

async function performHostDiscovery(scanRange) {
  console.log('🔍 Performing host discovery...');
  
  try {
    // Enhanced host discovery with broadcast enumeration
    const hostDiscoveryCmd = `sudo -n nmap -sn -PE -PP -PM ` +
                            `--script broadcast-dns-service-discovery,broadcast-dhcp-discover ` +
                            `--script-timeout 10s ${scanRange}`;
    
    const { stdout } = await execAsync(hostDiscoveryCmd, { timeout: 60000 });
    return parseHostDiscovery(stdout);
  } catch (error) {
    console.warn('⚠️  Enhanced host discovery failed, using basic discovery...');
    try {
      const { stdout } = await execAsync(`sudo -n nmap -sn ${scanRange}`, { timeout: 45000 });
      return parseHostDiscovery(stdout);
    } catch (sudoError) {
      console.warn('⚠️  Sudo scan failed, using non-sudo scan...');
      try {
        const { stdout } = await execAsync(`nmap -sn ${scanRange}`, { timeout: 30000 });
        return parseHostDiscovery(stdout);
      } catch (basicError) {
        throw new Error(`Host discovery failed: ${basicError.message}`);
      }
    }
  }
}

function parseHostDiscovery(output) {
  const hosts = [];
  const lines = output.split('\n');
  let current = null;
  
  for (const line of lines) {
    const ipMatch = line.match(/Nmap scan report for (.+)/);
    if (ipMatch) {
      if (current) hosts.push(current);
      
      const target = ipMatch[1];
      const hostnameMatch = target.match(/(.+) \((.+)\)/);
      
      current = {
        ip: hostnameMatch ? hostnameMatch[2] : target,
        hostname: hostnameMatch ? hostnameMatch[1] : null
      };
    }
    
    const macMatch = line.match(/MAC Address: ([0-9A-Fa-f:]{17}) \((.+)\)/);
    if (macMatch && current) {
      current.mac = macMatch[1].toUpperCase();
      current.manufacturer = macMatch[2];
    }
  }
  
  if (current) hosts.push(current);
  return hosts;
}

async function performComprehensiveAnalysis(host) {
  const deviceData = {
    name: host.hostname || host.ip,
    ipv4: host.ip,
    ipv6: "N/A",
    mac: host.mac || "N/A",
    manufacturer: host.manufacturer || "Unknown",
    hostname: host.hostname,
    type: "Unknown Device",
    category: "Unknown",
    confidence: 0,
    capabilities: [],
    osGuess: "Unknown",
    vendor: "Unknown"
  };

  const ip = host.ip;
  const mfg = (host.manufacturer || '').toLowerCase();
  const hostname = (host.hostname || '').toLowerCase();

  // Enhanced device analysis
  let confidence = 0;
  let type = 'Unknown Device';
  let name = host.hostname || host.ip;
  let vendor = host.manufacturer || 'Unknown';
  let capabilities = ['Network Connected'];

  // === PRIORITIZED MOBILE DEVICE DETECTION ===
  
  // Apple devices
  if (mfg.includes('apple') || hostname.includes('iphone') || hostname.includes('ipad')) {
    vendor = 'Apple'; confidence = 90;
    capabilities.push('iOS/iPadOS', 'WiFi', 'Bluetooth', 'Camera');
    
    if (hostname.includes('iphone')) {
      type = 'Smartphone'; name = 'iPhone';
    } else if (hostname.includes('ipad')) {
      type = 'Tablet'; name = 'iPad';
    } else {
      type = 'Apple Device'; name = 'Apple Device';
    }
  }
  
  // Samsung devices
  else if (mfg.includes('samsung') || hostname.includes('galaxy') || hostname.includes('samsung') || 
           hostname.includes('s20') || hostname.includes('s21') || hostname.includes('s22') || 
           hostname.includes('s23') || hostname.includes('s24')) {
    vendor = 'Samsung'; confidence = 90;
    capabilities.push('Android', 'WiFi', 'Bluetooth', 'Camera');
    
    if (hostname.includes('s20-fe') || hostname.includes('s20_fe')) {
      type = 'Smartphone'; name = 'Samsung Galaxy S20 FE';
    } else if (hostname.includes('s20')) {
      type = 'Smartphone'; name = 'Samsung Galaxy S20';
    } else if (hostname.includes('s21')) {
      type = 'Smartphone'; name = 'Samsung Galaxy S21';
    } else if (hostname.includes('s22')) {
      type = 'Smartphone'; name = 'Samsung Galaxy S22';
    } else if (hostname.includes('s23')) {
      type = 'Smartphone'; name = 'Samsung Galaxy S23';
    } else if (hostname.includes('s24')) {
      type = 'Smartphone'; name = 'Samsung Galaxy S24';
    } else if (hostname.includes('tab')) {
      type = 'Tablet'; name = 'Samsung Galaxy Tab';
    } else {
      type = 'Smartphone'; name = 'Samsung Galaxy';
    }
  }
  
  // Google Pixel devices
  else if (hostname.includes('pixel') || mfg.includes('google')) {
    vendor = 'Google'; confidence = 90;
    capabilities.push('Android', 'WiFi', 'Bluetooth', 'Camera');
    
    if (hostname.includes('pixel-8')) {
      name = 'Google Pixel 8';
    } else if (hostname.includes('pixel-7')) {
      name = 'Google Pixel 7';
    } else if (hostname.includes('pixel-6')) {
      name = 'Google Pixel 6';
    } else {
      name = 'Google Pixel';
    }
    type = 'Smartphone';
  }

  // Router detection
  else if (ip.endsWith('.1') || ip.endsWith('.254')) {
    type = 'Router'; confidence = 80;
    capabilities.push('Routing', 'WiFi', 'DHCP', 'NAT');
    
    if (mfg.includes('zyxel')) {
      vendor = 'Zyxel'; name = 'Zyxel Router'; confidence = 95;
    } else if (mfg.includes('netgear')) {
      vendor = 'Netgear'; name = 'Netgear Router'; confidence = 95;
    } else if (mfg.includes('cisco')) {
      vendor = 'Cisco'; name = 'Cisco Router'; confidence = 95;
    } else if (mfg.includes('linksys')) {
      vendor = 'Linksys'; name = 'Linksys Router'; confidence = 95;
    } else {
      name = 'Network Router';
    }
  }

  // Computer detection
  else if (hostname.includes('mac') || hostname.includes('imac') || hostname.includes('macbook')) {
    vendor = 'Apple'; type = 'Computer'; confidence = 90;
    capabilities.push('macOS', 'WiFi', 'Bluetooth');
    
    if (hostname.includes('macbook')) { name = 'MacBook'; }
    else if (hostname.includes('imac')) { name = 'iMac'; }
    else { name = 'Mac Computer'; }
  }
  else if (hostname.includes('desktop') || hostname.includes('pc') || hostname.includes('laptop')) {
    type = 'Computer'; confidence = 80;
    name = 'Windows PC';
    capabilities.push('Windows', 'WiFi');
  }

  // IoT device detection
  else if (mfg.includes('murata') || mfg.includes('sichuan') || mfg.includes('ai-link')) {
    type = 'IoT Device'; confidence = 75;
    name = 'Smart Device';
    capabilities.push('WiFi', 'IoT');
  }

  // Media device detection
  else if (hostname.includes('appletv') || hostname.includes('apple-tv')) {
    vendor = 'Apple'; type = 'Media Device'; name = 'Apple TV'; confidence = 95;
    capabilities.push('tvOS', 'AirPlay', '4K Streaming');
  }
  else if (hostname.includes('chromecast')) {
    vendor = 'Google'; type = 'Media Device'; name = 'Google Chromecast'; confidence = 95;
    capabilities.push('Cast', 'Streaming');
  }

  // Generic manufacturer-based detection
  else if (mfg.includes('apple')) { 
    vendor = 'Apple'; type = 'Apple Device'; confidence = 70;
  }
  else if (mfg.includes('samsung')) { 
    vendor = 'Samsung'; type = 'Samsung Device'; confidence = 70;
  }
  else if (mfg.includes('google')) { 
    vendor = 'Google'; type = 'Google Device'; confidence = 70;
  }

  // Update device data
  deviceData.type = type;
  deviceData.name = name;
  deviceData.vendor = vendor;
  deviceData.manufacturer = vendor !== 'Unknown' ? vendor : deviceData.manufacturer;
  deviceData.confidence = confidence;
  deviceData.capabilities = capabilities;

  return deviceData;
}

async function scanNetwork() {
  try {
    // Get network info
    const { stdout: routeOutput } = await execAsync('route get default');
    const gatewayMatch = routeOutput.match(/gateway: ([\d.]+)/);
    const gateway = gatewayMatch ? gatewayMatch[1] : '192.168.1.1';
    const parts = gateway.split('.');
    const scanRange = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    
    console.log(`📡 Scanning network: ${scanRange}`);

    // Stage 1: Host Discovery
    const hosts = await performHostDiscovery(scanRange);
    console.log(`✅ Found ${hosts.length} live hosts`);
    
    if (hosts.length === 0) {
      return [];
    }
    
    // Stage 2: Comprehensive Analysis
    const devices = [];
    for (const host of hosts) {
      console.log(`🔍 Analyzing ${host.ip}...`);
      const deviceData = await performComprehensiveAnalysis(host);
      devices.push(deviceData);
    }
    
    return devices;
    
  } catch (error) {
    console.error('❌ Network scan failed:', error.message);
    throw error;
  }
}

// ===== API ENDPOINTS =====

// Root endpoint - API documentation
app.get('/', (req, res) => {
  res.json({
    name: 'Network Scanner API',
    version: '3.0',
    description: 'Fast and accurate network device discovery with intelligent device identification',
    endpoints: {
      '/scan': 'GET - Comprehensive network scan with device identification',
      '/scan/clean': 'GET - Clean format scan with simple JSON output',
      '/network/info': 'GET - Get current network information',
      '/health': 'GET - API health check'
    },
    usage: {
      recommended: '/scan - Best balance of speed and accuracy',
      simple: '/scan/clean - Clean JSON format perfect for integrations'
    },
    timestamp: new Date().toISOString()
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Network info endpoint
app.get('/network/info', async (req, res) => {
  try {
    const { stdout: routeOutput } = await execAsync('route get default');
    const gatewayMatch = routeOutput.match(/gateway: ([\d.]+)/);
    const gateway = gatewayMatch ? gatewayMatch[1] : '192.168.1.1';
    const parts = gateway.split('.');
    const network = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    
    res.json({
      gateway: gateway,
      network: network,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Failed to get network info',
      message: error.message 
    });
  }
});

// Comprehensive scan endpoint
app.get('/scan', async (req, res) => {
  try {
    console.log('🔍 API: Starting comprehensive network scan...');
    const devices = await scanNetwork();
    
    res.json({
      scan_type: 'comprehensive',
      timestamp: new Date().toISOString(),
      devices_found: devices.length,
      devices: devices
    });
    
  } catch (error) {
    console.error('API scan error:', error);
    res.status(500).json({ 
      error: 'Scan failed',
      message: error.message 
    });
  }
});

// Clean format scan endpoint
app.get('/scan/clean', async (req, res) => {
  try {
    console.log('🔍 API: Starting clean network scan...');
    const devices = await scanNetwork();
    
    // Convert to clean format
    const cleanDevices = devices.map(device => ({
      name: device.name,
      ipv4: device.ipv4,
      ipv6: device.ipv6 || 'N/A',
      mac: device.mac,
      manufacturer: device.manufacturer,
      type: device.type
    }));
    
    res.json({
      scan_type: 'clean',
      timestamp: new Date().toISOString(),
      devices_found: cleanDevices.length,
      devices: cleanDevices
    });
    
  } catch (error) {
    console.error('API clean scan error:', error);
    res.status(500).json({ 
      error: 'Clean scan failed',
      message: error.message 
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: err.message 
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Endpoint not found',
    available_endpoints: ['/', '/scan', '/scan/clean', '/network/info', '/health']
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Network Scanner API v3.0 running on port ${PORT}`);
  console.log(`📡 Ready to scan network devices`);
  console.log(`🔍 API Documentation: http://localhost:${PORT}`);
  console.log(`🎯 Test scanning: http://localhost:${PORT}/scan`);
  console.log(`✨ Clean format: http://localhost:${PORT}/scan/clean`);
});

module.exports = app;