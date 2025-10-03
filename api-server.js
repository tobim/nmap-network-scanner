#!/usr/bin/env node

/**
 * Clean Nmap Network Scanner API
 * Incorporates the working simple-scanner logic directly
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// ===== SCANNER LOGIC (from working simple-scanner.js) =====

async function performHostDiscovery(scanRange) {
  console.log('🔍 Performing host discovery...');
  
  try {
    // Try enhanced discovery first
    const hostDiscoveryCmd = `sudo -n nmap -sn -PE -PP -PM --script-timeout 10s ${scanRange}`;
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

  // Advanced device analysis
  let confidence = 0;
  let type = 'Unknown Device';
  let name = host.hostname || host.ip;
  let vendor = host.manufacturer || 'Unknown';
  let capabilities = ['Network Connected'];

  // === SMARTPHONE DETECTION ===
  if (mfg.includes('apple') || hostname.includes('iphone')) {
    vendor = 'Apple'; type = 'Smartphone'; confidence = 90;
    if (hostname.includes('iphone')) { name = 'iPhone'; }
    else { name = 'Apple Device'; }
    capabilities.push('iOS', 'WiFi', 'Bluetooth', 'Camera');
  }
  else if (mfg.includes('samsung') || hostname.includes('galaxy') || hostname.includes('samsung') || 
           hostname.includes('s20') || hostname.includes('s21') || hostname.includes('s22') || 
           hostname.includes('s23') || hostname.includes('s24')) {
    vendor = 'Samsung'; type = 'Smartphone'; confidence = 90;
    if (hostname.includes('s20')) { name = 'Samsung Galaxy S20'; }
    else if (hostname.includes('s21')) { name = 'Samsung Galaxy S21'; }
    else if (hostname.includes('s22')) { name = 'Samsung Galaxy S22'; }
    else if (hostname.includes('s23')) { name = 'Samsung Galaxy S23'; }
    else if (hostname.includes('s24')) { name = 'Samsung Galaxy S24'; }
    else if (hostname.includes('tab')) { name = 'Samsung Galaxy Tab'; type = 'Tablet'; }
    else { name = 'Samsung Galaxy'; }
    capabilities.push('Android', 'WiFi', 'Bluetooth', 'Camera');
  }
  else if (hostname.includes('pixel') || mfg.includes('google')) {
    vendor = 'Google'; type = 'Smartphone'; confidence = 90;
    if (hostname.includes('pixel-8')) { name = 'Google Pixel 8'; }
    else if (hostname.includes('pixel-7')) { name = 'Google Pixel 7'; }
    else if (hostname.includes('pixel-6')) { name = 'Google Pixel 6'; }
    else { name = 'Google Pixel'; }
    capabilities.push('Android', 'WiFi', 'Bluetooth', 'Camera');
  }

  // === TABLET DETECTION ===
  else if (hostname.includes('ipad') || (mfg.includes('apple') && hostname.includes('pad'))) {
    vendor = 'Apple'; type = 'Tablet'; name = 'iPad'; confidence = 95;
    capabilities.push('iPadOS', 'WiFi', 'Bluetooth', 'Camera', 'Touch Screen');
  }
  else if (hostname.includes('tab') && (hostname.includes('samsung') || mfg.includes('samsung'))) {
    vendor = 'Samsung'; type = 'Tablet'; name = 'Samsung Galaxy Tab'; confidence = 95;
    capabilities.push('Android', 'WiFi', 'Bluetooth', 'S Pen');
  }

  // === ROUTER DETECTION ===
  else if (ip.endsWith('.1') || ip.endsWith('.254')) {
    type = 'Router'; confidence = 80;
    if (mfg.includes('zyxel')) { vendor = 'Zyxel'; name = 'Zyxel Router'; confidence = 95; }
    else if (mfg.includes('netgear')) { vendor = 'Netgear'; name = 'Netgear Router'; confidence = 95; }
    else if (mfg.includes('cisco')) { vendor = 'Cisco'; name = 'Cisco Router'; confidence = 95; }
    else if (mfg.includes('linksys')) { vendor = 'Linksys'; name = 'Linksys Router'; confidence = 95; }
    else { name = 'Network Router'; }
    capabilities.push('Routing', 'WiFi', 'DHCP', 'NAT');
  }

  // === COMPUTER DETECTION ===
  else if (hostname.includes('mac') || hostname.includes('imac') || hostname.includes('macbook')) {
    vendor = 'Apple'; type = 'Computer'; confidence = 90;
    if (hostname.includes('macbook')) { name = 'MacBook'; }
    else if (hostname.includes('imac')) { name = 'iMac'; }
    else { name = 'Mac Computer'; }
    capabilities.push('macOS', 'WiFi', 'Bluetooth');
  }
  else if (hostname.includes('desktop') || hostname.includes('pc') || hostname.includes('laptop')) {
    type = 'Computer'; confidence = 80;
    name = 'Windows PC';
    capabilities.push('Windows', 'WiFi');
  }

  // === IOT DEVICE DETECTION ===
  else if (mfg.includes('murata') || mfg.includes('sichuan') || mfg.includes('ai-link')) {
    type = 'IoT Device'; confidence = 75;
    name = 'Smart Device';
    capabilities.push('WiFi', 'IoT');
  }

  // === MEDIA DEVICE DETECTION ===
  else if (hostname.includes('appletv') || hostname.includes('apple-tv')) {
    vendor = 'Apple'; type = 'Media Device'; name = 'Apple TV'; confidence = 95;
    capabilities.push('tvOS', 'AirPlay', '4K Streaming');
  }
  else if (hostname.includes('chromecast')) {
    vendor = 'Google'; type = 'Media Device'; name = 'Google Chromecast'; confidence = 95;
    capabilities.push('Cast', 'Streaming');
  }

  // === ENHANCE BASED ON MANUFACTURER ===
  else if (mfg.includes('apple')) { 
    vendor = 'Apple'; type = 'Apple Device'; confidence = 70;
    capabilities.push('Apple Ecosystem');
  }
  else if (mfg.includes('samsung')) { 
    vendor = 'Samsung'; type = 'Samsung Device'; confidence = 70;
    capabilities.push('Samsung Ecosystem');
  }
  else if (mfg.includes('google')) { 
    vendor = 'Google'; type = 'Google Device'; confidence = 70;
    capabilities.push('Google Services');
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

    // Host Discovery
    const hosts = await performHostDiscovery(scanRange);
    console.log(`✅ Found ${hosts.length} live hosts`);
    
    if (hosts.length === 0) {
      return [];
    }
    
    // Comprehensive Analysis
    const devices = [];
    for (const host of hosts) {
      console.log(`🔍 Analyzing ${host.ip}...`);
      const deviceData = await performComprehensiveAnalysis(host);
      devices.push(deviceData);
    }
    
    return devices;
    
  } catch (error) {
    console.error('❌ Network scan failed:', error.message);
    return [];
  }
}

// ===== API ENDPOINTS =====

// Root endpoint - API documentation
app.get('/', (req, res) => {
  res.json({
    message: 'Clean Nmap Network Scanner API v3.0',
    description: 'Fast and accurate network device discovery with intelligent device identification',
    endpoints: {
      '/scan': 'GET - Comprehensive network scan with device identification',
      '/scan/clean': 'GET - Clean format scan with simple JSON output',
      '/network/info': 'GET - Get current network information'
    },
    usage: {
      recommended: '/scan - Best balance of speed and accuracy',
      simple: '/scan/clean - Clean JSON format perfect for integrations'
    }
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
    res.status(500).json({ error: error.message });
  }
});

// Comprehensive scan endpoint
app.get('/scan', async (req, res) => {
  try {
    console.log('🔍 Starting comprehensive network scan...');
    const devices = await scanNetwork();
    
    res.json({
      scan_type: 'comprehensive',
      timestamp: new Date().toISOString(),
      devices_found: devices.length,
      devices: devices
    });
    
  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Clean format scan endpoint
app.get('/scan/clean', async (req, res) => {
  try {
    console.log('🔍 Starting clean network scan...');
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
    console.error('Clean scan error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Clean Nmap Network Scanner API v3.0 running on port ${PORT}`);
  console.log(`📡 Ready to scan network devices`);
  console.log(`🔍 Access API documentation at http://localhost:${PORT}`);
  console.log(`🎯 Test scanning: http://localhost:${PORT}/scan`);
});

module.exports = app;
