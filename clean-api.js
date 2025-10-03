const express = require('express');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);
const app = express();
const PORT = 3000;

app.use(express.json());

app.get('/', (req, res) => {
  res.json({
    message: 'Simple Network Scanner API',
    endpoints: {
      '/scan': 'GET - Scan network for devices'
    }
  });
});

app.get('/scan', async (req, res) => {
  try {
    console.log('Starting network scan...');
    
    // Get gateway
    const { stdout: routeOutput } = await execAsync('route get default');
    const gatewayMatch = routeOutput.match(/gateway: ([\d.]+)/);
    const gateway = gatewayMatch ? gatewayMatch[1] : '192.168.1.1';
    const parts = gateway.split('.');
    const scanRange = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    
    // Run nmap scan
    const { stdout } = await execAsync(`nmap -sn ${scanRange}`, { timeout: 30000 });
    
    // Parse results
    const devices = [];
    const lines = stdout.split('\n');
    let current = null;
    
    for (const line of lines) {
      const ipMatch = line.match(/Nmap scan report for (.+)/);
      if (ipMatch) {
        if (current) devices.push(current);
        
        const target = ipMatch[1];
        const hostnameMatch = target.match(/(.+) \((.+)\)/);
        
        current = {
          name: hostnameMatch ? hostnameMatch[1] : target,
          ipv4: hostnameMatch ? hostnameMatch[2] : target,
          ipv6: 'N/A',
          mac: 'N/A',
          manufacturer: 'Unknown',
          type: 'Unknown Device'
        };
      }
      
      const macMatch = line.match(/MAC Address: ([0-9A-Fa-f:]{17}) \((.+)\)/);
      if (macMatch && current) {
        current.mac = macMatch[1].toUpperCase();
        current.manufacturer = macMatch[2];
        
        // Enhanced device identification
        const mfg = current.manufacturer.toLowerCase();
        const hostname = current.name.toLowerCase();
        
        if (mfg.includes('apple') || hostname.includes('iphone')) {
          current.type = hostname.includes('iphone') ? 'Smartphone' : 'Apple Device';
        } else if (mfg.includes('samsung') || hostname.includes('galaxy')) {
          current.type = hostname.includes('tab') ? 'Tablet' : 'Smartphone';
        } else if (hostname.includes('pixel')) {
          current.type = 'Smartphone';
        } else if (current.ipv4.endsWith('.1')) {
          current.type = 'Router';
        } else if (mfg.includes('zyxel')) {
          current.type = 'Router';
        }
      }
    }
    
    if (current) devices.push(current);
    
    console.log(`Found ${devices.length} devices`);
    
    res.json({
      scan_type: 'network',
      timestamp: new Date().toISOString(),
      devices_found: devices.length,
      devices: devices
    });
    
  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({ error: error.message });
  }
});

console.log('Starting server...');

app.listen(PORT, () => {
  console.log(`🚀 Network Scanner API running on port ${PORT}`);
  console.log(`🔍 Test: http://localhost:${PORT}/scan`);
});
