#!/usr/bin/env node

/**
 * Simple Reliable Network Scanner
 * Fast and effective device discovery with enhanced manufacturer detection
 */

const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

async function simpleNetworkScan(verbose = false) {
  console.log('🔍 Simple Network Scanner');
  console.log('=========================\n');

  try {
    // Get network info
    const { stdout: routeOutput } = await execAsync('route get default');
    const gatewayMatch = routeOutput.match(/gateway: ([\d.]+)/);
    const gateway = gatewayMatch ? gatewayMatch[1] : '192.168.1.1';
    const parts = gateway.split('.');
    const scanRange = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    
    console.log(`📡 Network: ${scanRange}`);
    console.log(`🚪 Gateway: ${gateway}\n`);

    // Multi-stage comprehensive scanning
    console.log('🔍 Starting comprehensive network analysis...');
    
    // Stage 1: Host Discovery
    console.log('📡 Stage 1: Host Discovery...');
    const hosts = await performHostDiscovery(scanRange);
    console.log(`✅ Found ${hosts.length} live hosts`);
    
    if (hosts.length === 0) {
      console.log('❌ No hosts found');
      return [];
    }
    
    // Stage 2: Comprehensive Analysis
    console.log('🔬 Stage 2: Deep Device Analysis...');
    const enhancedDevices = [];
    
    for (const host of hosts) {
      console.log(`🔍 Analyzing ${host.ip}...`);
      const deviceData = await performComprehensiveAnalysis(host);
      enhancedDevices.push(deviceData);
    }
    
    console.log(`\n✅ Analysis complete! Found ${enhancedDevices.length} devices:\n`);
    
    if (verbose) {
      // Output detailed verbose data
      enhancedDevices.forEach((device, index) => {
        console.log(`\n--- Device ${index + 1} ---`);
        console.log(JSON.stringify(device, null, 2));
      });
    } else {
      // Output clean, refined results using all the rich data
      enhancedDevices.forEach((device, index) => {
        const cleanDevice = {
          name: device.name,
          ipv4: device.ipv4,
          ipv6: "N/A",
          mac: device.mac || "N/A",
          manufacturer: device.manufacturer || "Unknown",
          type: device.type
        };
        
        console.log(`${JSON.stringify(cleanDevice, null, 2)}${index < enhancedDevices.length - 1 ? ',' : ''}`);
      });
    }

    return enhancedDevices;

  } catch (error) {
    console.error('❌ Error:', error.message);
    return [];
  }
}

function parseDevices(output) {
  const devices = [];
  const lines = output.split('\n');
  let current = null;
  
  for (const line of lines) {
    const ipMatch = line.match(/Nmap scan report for (.+)/);
    if (ipMatch) {
      if (current) devices.push(enhanceDevice(current));
      
      const target = ipMatch[1];
      const hostnameMatch = target.match(/(.+) \((.+)\)/);
      
      current = {
        ipv4: hostnameMatch ? hostnameMatch[2] : target,
        hostname: hostnameMatch ? hostnameMatch[1] : null
      };
    }
    
    const macMatch = line.match(/MAC Address: ([0-9A-Fa-f:]{17}) \((.+)\)/);
    if (macMatch && current) {
      current.mac = macMatch[1].toUpperCase();
      current.manufacturer = macMatch[2];
    }
  }
  
  if (current) devices.push(enhanceDevice(current));
  return devices;
}

function enhanceDevice(device) {
  const mfg = (device.manufacturer || '').toLowerCase();
  const host = (device.hostname || '').toLowerCase();
  const mac = (device.mac || '').toLowerCase();
  const ip = device.ipv4 || '';
  
  let type = 'Unknown Device';
  let name = device.hostname || 'Unknown';
  let confidence = 0;
  let category = 'Unknown';
  let osGuess = 'Unknown';
  let capabilities = [];
  let deviceAge = 'Unknown';
  let securityRisk = 'Low';
  
  // Advanced device analysis with confidence scoring
  const analysis = performAdvancedDeviceAnalysis(device, mfg, host, mac, ip);
  
  return {
    ...device,
    name: analysis.name,
    type: analysis.type,
    category: analysis.category,
    confidence: analysis.confidence,
    osGuess: analysis.osGuess,
    capabilities: analysis.capabilities,
    deviceAge: analysis.deviceAge,
    securityRisk: analysis.securityRisk,
    vendor: analysis.vendor,
    model: analysis.model,
    generation: analysis.generation
  };
}

function performAdvancedDeviceAnalysis(device, mfg, host, mac, ip) {
  let confidence = device.confidence || 0;
  let type = device.type || 'Unknown Device';
  let name = device.name || device.hostname || 'Unknown';
  let category = device.category || 'Unknown';
  let osGuess = device.osGuess || 'Unknown';
  let capabilities = device.capabilities || [];
  let deviceAge = device.deviceAge || 'Unknown';
  let securityRisk = device.securityRisk || 'Low';
  let vendor = device.vendor || 'Unknown';
  let model = device.model || 'Unknown';
  let generation = device.generation || 'Unknown';

  // === ENHANCED ANALYSIS USING NMAP DATA ===
  
  // First pass: Hostname and Manufacturer Analysis (HIGHEST PRIORITY)
  const hostnameAnalysis = analyzeDeviceByHostnameAndManufacturer(device, mfg, host, mac);
  if (hostnameAnalysis.confidence > 70) {
    // High confidence identification - use this as base
    confidence = hostnameAnalysis.confidence;
    type = hostnameAnalysis.type;
    name = hostnameAnalysis.name;
    category = hostnameAnalysis.category;
    vendor = hostnameAnalysis.vendor;
    model = hostnameAnalysis.model;
    capabilities = [...capabilities, ...hostnameAnalysis.capabilities];
  }
  
  // OS Detection Confidence Boost
  if (device.osDetails && device.osDetails.length > 0) {
    const bestOS = device.osDetails.reduce((best, current) => 
      current.accuracy > best.accuracy ? current : best
    );
    confidence = Math.max(confidence, bestOS.accuracy);
    osGuess = `${bestOS.vendor} ${bestOS.name} ${bestOS.generation}`.trim();
    
    // Only override device type if we don't have high confidence already
    if (confidence < 70) {
      vendor = bestOS.vendor;
      
      // Determine device type from OS
      if (bestOS.family.toLowerCase().includes('windows')) {
        type = 'Windows Computer'; category = 'Computer';
        capabilities.push('Windows OS', 'SMB', 'RDP');
      } else if (bestOS.family.toLowerCase().includes('linux')) {
        type = 'Linux Computer'; category = 'Computer';
        capabilities.push('Linux OS', 'SSH', 'Terminal');
      } else if (bestOS.name.toLowerCase().includes('ios')) {
        type = 'iPhone'; category = 'Mobile Device';
        capabilities.push('iOS', 'Touch ID/Face ID', 'Siri');
      } else if (bestOS.name.toLowerCase().includes('android')) {
        type = 'Android Device'; category = 'Mobile Device';
        capabilities.push('Android OS', 'Google Services');
      }
    }
  }

  // === PRIORITIZED MOBILE DEVICE DETECTION FIRST ===
  
  // Smartphone Detection (HIGH PRIORITY)
  const smartphoneResult = analyzeSmartphone(mfg, host, mac);
  if (smartphoneResult.confidence > 60) {
    confidence = smartphoneResult.confidence;
    type = smartphoneResult.type;
    name = smartphoneResult.name;
    category = 'Mobile Device';
    osGuess = smartphoneResult.osGuess;
    capabilities = [...capabilities, ...smartphoneResult.capabilities];
    vendor = smartphoneResult.vendor;
    model = smartphoneResult.model;
    generation = smartphoneResult.generation;
    deviceAge = smartphoneResult.deviceAge;
  }

  // Tablet Detection (HIGH PRIORITY)
  const tabletResult = analyzeTablet(mfg, host, mac);
  if (tabletResult.confidence > 60 && category !== 'Mobile Device') {
    confidence = tabletResult.confidence;
    type = tabletResult.type;
    name = tabletResult.name;
    category = 'Mobile Device';
    osGuess = tabletResult.osGuess;
    capabilities = [...capabilities, ...tabletResult.capabilities];
    vendor = tabletResult.vendor;
    model = tabletResult.model;
  }

  // Service-Based Analysis (LOWER PRIORITY - don't override mobile devices)
  if (device.services && device.services.length > 0 && category !== 'Mobile Device') {
    device.services.forEach(service => {
      // SSH services - be careful not to override mobile devices
      if (service.name === 'ssh') {
        // Only set as Linux/Unix Server if we don't know what it is AND it's not a mobile device
        if (type === 'Unknown Device' && !['Mobile Device', 'Smartphone', 'Tablet'].includes(category)) {
          type = 'Linux/Unix Server'; category = 'Computer';
        }
        capabilities.push('SSH Server');
        if (service.product) capabilities.push(`SSH: ${service.product}`);
      }
      
      // HTTP services indicate web servers/devices
      if (service.name === 'http' || service.name === 'https') {
        capabilities.push('Web Server');
        if (service.product) {
          capabilities.push(`Web: ${service.product}`);
          // Identify specific devices by web server
          if (service.product.toLowerCase().includes('nginx')) {
            capabilities.push('Nginx');
          } else if (service.product.toLowerCase().includes('apache')) {
            capabilities.push('Apache');
          } else if (service.product.toLowerCase().includes('iis')) {
            capabilities.push('IIS');
            if (type === 'Unknown Device') {
              type = 'Windows Server'; category = 'Computer';
            }
          }
        }
      }
      
      // SMB services indicate Windows systems
      if (service.name === 'microsoft-ds' || service.name === 'netbios-ssn') {
        if (type === 'Unknown Device') {
          type = 'Windows Computer'; category = 'Computer';
        }
        capabilities.push('SMB/CIFS', 'File Sharing');
      }
      
      // Printer services
      if (service.name === 'ipp' || service.name === 'printer') {
        type = 'Network Printer'; category = 'Office Equipment';
        capabilities.push('Network Printing', 'IPP');
      }
      
      // SNMP indicates network equipment
      if (service.name === 'snmp') {
        if (type === 'Unknown Device') {
          type = 'Network Equipment'; category = 'Network Infrastructure';
        }
        capabilities.push('SNMP Management');
      }
    });
    
    confidence += Math.min(device.services.length * 5, 25); // Boost confidence based on services found
  }

  // Script Results Analysis
  if (device.scripts) {
    // SMB OS Discovery
    if (device.scripts['smb-os-discovery']) {
      const smbInfo = device.scripts['smb-os-discovery'];
      if (smbInfo.includes('Windows')) {
        type = 'Windows Computer'; category = 'Computer';
        confidence += 30;
        
        // Extract Windows version
        const versionMatch = smbInfo.match(/Windows ([^\\n]*)/);
        if (versionMatch) {
          osGuess = `Microsoft Windows ${versionMatch[1]}`;
          capabilities.push(`Windows ${versionMatch[1]}`);
        }
      }
    }
    
    // NetBIOS information
    if (device.scripts['nbstat']) {
      const nbInfo = device.scripts['nbstat'];
      capabilities.push('NetBIOS');
      
      // Extract computer name
      const nameMatch = nbInfo.match(/Computer name: ([^\\n]*)/);
      if (nameMatch && name === 'Unknown') {
        name = nameMatch[1];
        confidence += 20;
      }
    }
    
    // HTTP title for web interfaces
    if (device.scripts['http-title']) {
      const title = device.scripts['http-title'];
      capabilities.push(`Web Interface: ${title}`);
      
      // Identify specific devices by web interface
      if (title.toLowerCase().includes('router')) {
        type = 'Router'; category = 'Network Infrastructure';
        confidence += 25;
      } else if (title.toLowerCase().includes('printer')) {
        type = 'Network Printer'; category = 'Office Equipment';
        confidence += 25;
      } else if (title.toLowerCase().includes('camera')) {
        type = 'IP Camera'; category = 'Security Device';
        capabilities.push('Video Surveillance');
        confidence += 25;
      }
    }
    
    // SSL certificate information
    if (device.scripts['ssl-cert']) {
      capabilities.push('SSL/TLS');
      const certInfo = device.scripts['ssl-cert'];
      
      // Extract organization from certificate
      const orgMatch = certInfo.match(/Organization: ([^\\n]*)/);
      if (orgMatch && vendor === 'Unknown') {
        vendor = orgMatch[1];
        confidence += 15;
      }
    }
  }

  // SNMP Information Analysis
  if (device.snmpInfo) {
    capabilities.push('SNMP Enabled');
    confidence += 20;
    
    // SNMP often reveals detailed device information
    if (device.snmpInfo.sysDescr) {
      const sysDescr = device.snmpInfo.sysDescr.toLowerCase();
      
      if (sysDescr.includes('cisco')) {
        vendor = 'Cisco'; type = 'Cisco Network Device'; 
        category = 'Network Infrastructure'; confidence += 30;
      } else if (sysDescr.includes('hp') || sysDescr.includes('hewlett')) {
        vendor = 'HP'; 
        if (sysDescr.includes('printer')) {
          type = 'HP Printer'; category = 'Office Equipment';
        } else {
          type = 'HP Network Device';
        }
        confidence += 30;
      }
    }
  }

  // mDNS/DNS-SD Analysis
  if (device.mdnsServices && device.mdnsServices.length > 0) {
    capabilities.push('mDNS/Bonjour');
    
    device.mdnsServices.forEach(service => {
      if (service.includes('_airplay')) {
        type = 'Apple TV'; category = 'Media Device';
        vendor = 'Apple'; capabilities.push('AirPlay');
        confidence += 35;
      } else if (service.includes('_googlecast')) {
        type = 'Google Chromecast'; category = 'Media Device';
        vendor = 'Google'; capabilities.push('Google Cast');
        confidence += 35;
      } else if (service.includes('_ipp')) {
        if (type === 'Unknown Device') {
          type = 'Network Printer'; category = 'Office Equipment';
        }
        capabilities.push('AirPrint');
        confidence += 25;
      }
    });
  }

  // === EXISTING ANALYSIS METHODS ===
  
  // Network Infrastructure Detection
  if (isNetworkInfrastructure(ip, mfg, host)) {
    const infraResult = analyzeNetworkInfrastructure(mfg, host, mac, ip);
    if (infraResult.confidence > confidence) {
      return { ...infraResult, confidence: Math.min(infraResult.confidence + 20, 100) };
    }
  }

  // Computer Detection
  const computerResult = analyzeComputer(mfg, host, mac);
  if (computerResult.confidence > confidence && category !== 'Mobile Device') {
    confidence = computerResult.confidence;
    type = computerResult.type;
    name = computerResult.name;
    category = 'Computer';
    osGuess = computerResult.osGuess;
    capabilities = [...capabilities, ...computerResult.capabilities];
    vendor = computerResult.vendor;
    model = computerResult.model;
    deviceAge = computerResult.deviceAge;
  }

  // IoT Device Detection
  const iotResult = analyzeIoTDevice(mfg, host, mac);
  if (iotResult.confidence > confidence && !['Mobile Device', 'Computer'].includes(category)) {
    confidence = iotResult.confidence;
    type = iotResult.type;
    name = iotResult.name;
    category = 'IoT Device';
    capabilities = [...capabilities, ...iotResult.capabilities];
    vendor = iotResult.vendor;
    securityRisk = iotResult.securityRisk;
  }

  // Additional device type analysis...
  const gamingResult = analyzeGamingDevice(mfg, host, mac);
  const mediaResult = analyzeMediaDevice(mfg, host, mac);
  const printerResult = analyzePrinterDevice(mfg, host, mac);
  const securityResult = analyzeSecurityDevice(mfg, host, mac);
  const vehicleResult = analyzeVehicleDevice(mfg, host, mac);

  // Apply the best match
  const allResults = [gamingResult, mediaResult, printerResult, securityResult, vehicleResult];
  const bestResult = allResults.reduce((best, current) => 
    current.confidence > best.confidence ? current : best, 
    { confidence: confidence }
  );

  if (bestResult.confidence > confidence) {
    Object.assign({ type, name, category, vendor, capabilities }, bestResult);
    confidence = bestResult.confidence;
  }

  // Security Risk Assessment
  if (device.ports && device.ports.length > 10) securityRisk = 'High';
  else if (device.ports && device.ports.length > 5) securityRisk = 'Medium';
  if (capabilities.includes('SSH Server') || capabilities.includes('Web Server')) {
    securityRisk = securityRisk === 'Low' ? 'Medium' : securityRisk;
  }

  // Final confidence adjustments
  if (device.mac && device.manufacturer !== 'Unknown') confidence += 15;
  if (device.hostname && device.hostname !== device.ipv4) confidence += 10;
  if (device.services && device.services.length > 0) confidence += 10;
  
  // Remove duplicate capabilities
  capabilities = [...new Set(capabilities)];
  
  // Ensure confidence doesn't exceed 100
  confidence = Math.min(confidence, 100);

  return {
    name, type, category, confidence, osGuess, capabilities, 
    deviceAge, securityRisk, vendor, model, generation
  };
}

// === ADVANCED DEVICE ANALYSIS FUNCTIONS ===

function analyzeDeviceByHostnameAndManufacturer(device, mfg, host, mac) {
  let confidence = 0;
  let type = 'Unknown Device';
  let name = device.name || device.hostname || 'Unknown';
  let category = 'Unknown';
  let vendor = 'Unknown';
  let model = 'Unknown';
  let capabilities = [];

  // === SMARTPHONE DETECTION (HIGHEST PRIORITY) ===
  
  // iPhone Detection
  if (host.includes('iphone') || (mfg.includes('apple') && (host.includes('phone') || host.match(/\biphone\b/i)))) {
    vendor = 'Apple'; type = 'Smartphone'; category = 'Mobile Device';
    confidence = 95; capabilities.push('iOS', 'Face ID/Touch ID', 'Siri', 'AirDrop');
    if (name === 'Unknown' || name === device.ipv4) name = 'iPhone';
  }
  
  // Samsung Galaxy Detection
  else if (host.includes('galaxy') || (mfg.includes('samsung') && host.includes('s20'))) {
    vendor = 'Samsung'; type = 'Smartphone'; category = 'Mobile Device';
    confidence = 95; capabilities.push('Android', 'Samsung Pay', 'Bixby', 'Knox Security');
    if (host.includes('s20')) { name = 'Samsung Galaxy S20'; model = 'Galaxy S20'; }
    else if (host.includes('s21')) { name = 'Samsung Galaxy S21'; model = 'Galaxy S21'; }
    else if (host.includes('s22')) { name = 'Samsung Galaxy S22'; model = 'Galaxy S22'; }
    else if (host.includes('s23')) { name = 'Samsung Galaxy S23'; model = 'Galaxy S23'; }
    else if (host.includes('s24')) { name = 'Samsung Galaxy S24'; model = 'Galaxy S24'; }
    else { name = 'Samsung Galaxy'; model = 'Galaxy Series'; }
  }
  
  // Google Pixel Detection
  else if (host.includes('pixel')) {
    vendor = 'Google'; type = 'Smartphone'; category = 'Mobile Device';
    confidence = 95; capabilities.push('Android (Pure)', 'Google Assistant', 'Pixel Camera');
    if (host.includes('pixel-7')) { name = 'Google Pixel 7'; model = 'Pixel 7'; }
    else if (host.includes('pixel-8')) { name = 'Google Pixel 8'; model = 'Pixel 8'; }
    else { name = 'Google Pixel'; model = 'Pixel Series'; }
  }
  
  // === TABLET DETECTION ===
  
  // iPad Detection
  else if (host.includes('ipad') || (mfg.includes('apple') && host.includes('pad'))) {
    vendor = 'Apple'; type = 'Tablet'; category = 'Mobile Device';
    confidence = 95; capabilities.push('iPadOS', 'Apple Pencil', 'Split View');
    if (name === 'Unknown' || name === device.ipv4) name = 'iPad';
  }
  
  // Samsung Tab Detection  
  else if (host.includes('tab') && (mfg.includes('samsung') || host.includes('samsung'))) {
    vendor = 'Samsung'; type = 'Tablet'; category = 'Mobile Device';
    confidence = 90; capabilities.push('Android', 'S Pen', 'Samsung DeX');
    if (host.includes('tab-a')) { name = 'Samsung Galaxy Tab A'; model = 'Galaxy Tab A'; }
    else if (host.includes('tab-s')) { name = 'Samsung Galaxy Tab S'; model = 'Galaxy Tab S'; }
    else { name = 'Samsung Galaxy Tab'; model = 'Galaxy Tab'; }
  }
  
  // Generic tablet detection by name
  else if (host.includes('tab') || host.includes('tablet')) {
    type = 'Tablet'; category = 'Mobile Device'; confidence = 75;
    capabilities.push('Touch Screen', 'Portable');
    if (mfg.includes('samsung')) { vendor = 'Samsung'; name = 'Samsung Tablet'; confidence = 85; }
    else if (mfg.includes('apple')) { vendor = 'Apple'; name = 'iPad'; confidence = 85; }
    else { name = 'Tablet Device'; }
  }
  
  // === COMPUTER DETECTION ===
  
  // Mac Detection
  else if (host.includes('mac') || host.includes('imac') || host.includes('macbook')) {
    vendor = 'Apple'; type = 'Computer'; category = 'Computer';
    confidence = 95; capabilities.push('macOS', 'AirDrop', 'Handoff', 'Universal Clipboard');
    if (host.includes('macbook')) { name = 'MacBook'; model = 'MacBook'; }
    else if (host.includes('imac')) { name = 'iMac'; model = 'iMac'; }
    else { name = 'Mac Computer'; model = 'Mac'; }
  }
  
  // === ANDROID DEVICE DETECTION ===
  
  // Android device name patterns
  else if (host.includes('android') || host.includes('droid')) {
    type = 'Android Device'; category = 'Mobile Device';
    confidence = 80; capabilities.push('Android OS', 'Google Play');
    if (mfg.includes('samsung')) { 
      vendor = 'Samsung'; name = 'Samsung Android Device'; confidence = 90; 
    }
    else if (mfg.includes('google')) { 
      vendor = 'Google'; name = 'Google Android Device'; confidence = 90; 
    }
    else { name = 'Android Device'; }
  }
  
  // === MANUFACTURER-BASED DETECTION ===
  
  // Apple devices (when hostname doesn't give specific type)
  else if (mfg.includes('apple')) {
    vendor = 'Apple'; confidence = 85;
    // Default Apple devices to likely mobile unless proven otherwise
    type = 'Apple Device'; category = 'Mobile Device';
    capabilities.push('Apple Ecosystem', 'iCloud');
    if (name === 'Unknown' || name === device.ipv4) name = 'Apple Device';
  }
  
  // Samsung devices
  else if (mfg.includes('samsung')) {
    vendor = 'Samsung'; confidence = 85;
    type = 'Samsung Device'; category = 'Mobile Device';
    capabilities.push('Samsung Ecosystem');
    if (name === 'Unknown' || name === device.ipv4) name = 'Samsung Device';
  }
  
  // Google devices
  else if (mfg.includes('google')) {
    vendor = 'Google'; confidence = 85;
    type = 'Google Device'; category = 'Mobile Device';
    capabilities.push('Google Services');
    if (name === 'Unknown' || name === device.ipv4) name = 'Google Device';
  }
  
  // === NETWORK EQUIPMENT ===
  
  // Router detection by IP pattern
  else if (device.ipv4.endsWith('.1') || device.ipv4.endsWith('.254')) {
    type = 'Router'; category = 'Network Infrastructure';
    confidence = 80; capabilities.push('Routing', 'DHCP', 'Gateway');
    if (mfg.includes('zyxel')) { 
      vendor = 'Zyxel'; name = 'Zyxel Router'; confidence = 95; 
    }
    else { name = 'Network Router'; }
  }
  
  return { confidence, type, name, category, vendor, model, capabilities };
}

function isNetworkInfrastructure(ip, mfg, host) {
  return ip.endsWith('.1') || ip.endsWith('.254') || ip.endsWith('.0') || 
         mfg.includes('router') || mfg.includes('gateway') || mfg.includes('switch') ||
         host.includes('router') || host.includes('gateway') || host.includes('modem');
}

function analyzeNetworkInfrastructure(mfg, host, mac, ip) {
  let confidence = 75;
  let type = 'Router';
  let name = 'Network Router';
  let vendor = 'Unknown';
  let model = 'Unknown';
  let capabilities = ['Routing', 'DHCP', 'NAT'];
  let securityRisk = 'Critical';
  let osGuess = 'Embedded Linux';

  // Router Manufacturers
  if (mfg.includes('zyxel')) {
    vendor = 'Zyxel'; name = 'Zyxel Router'; confidence = 95;
    capabilities.push('VPN', 'Firewall', 'QoS');
  } else if (mfg.includes('netgear')) {
    vendor = 'Netgear'; name = 'Netgear Router'; confidence = 95;
    capabilities.push('WiFi 6', 'MU-MIMO', 'Beamforming');
  } else if (mfg.includes('linksys')) {
    vendor = 'Linksys'; name = 'Linksys Router'; confidence = 95;
    capabilities.push('Smart WiFi', 'Guest Network');
  } else if (mfg.includes('cisco')) {
    vendor = 'Cisco'; name = 'Cisco Router'; confidence = 98;
    type = 'Enterprise Router';
    capabilities.push('Advanced Security', 'VPN', 'VLAN', 'Enterprise Management');
    osGuess = 'Cisco IOS';
  } else if (mfg.includes('d-link') || mfg.includes('dlink')) {
    vendor = 'D-Link'; name = 'D-Link Router'; confidence = 95;
  } else if (mfg.includes('tp-link') || mfg.includes('tplink')) {
    vendor = 'TP-Link'; name = 'TP-Link Router'; confidence = 95;
  } else if (mfg.includes('asus')) {
    vendor = 'ASUS'; name = 'ASUS Router'; confidence = 95;
    capabilities.push('Gaming Mode', 'AiMesh', 'Adaptive QoS');
  }

  return { confidence, type, name, vendor, model, capabilities, securityRisk, osGuess };
}

function analyzeSmartphone(mfg, host, mac) {
  let confidence = 0;
  let type = 'Smartphone';
  let name = 'Unknown Smartphone';
  let vendor = 'Unknown';
  let model = 'Unknown';
  let generation = 'Unknown';
  let osGuess = 'Unknown';
  let capabilities = ['WiFi', 'Bluetooth', 'Camera', 'GPS'];
  let deviceAge = 'Unknown';

  // Apple iPhones
  if (mfg.includes('apple') || host.includes('iphone')) {
    vendor = 'Apple'; osGuess = 'iOS'; confidence = 90;
    capabilities.push('Face ID', 'Siri', 'iCloud', 'AirDrop', 'CarPlay');
    
    if (host.includes('iphone-15')) { name = 'iPhone 15'; model = 'iPhone 15'; generation = '2023'; deviceAge = 'New'; confidence = 98; }
    else if (host.includes('iphone-14')) { name = 'iPhone 14'; model = 'iPhone 14'; generation = '2022'; deviceAge = 'Recent'; confidence = 98; }
    else if (host.includes('iphone-13')) { name = 'iPhone 13'; model = 'iPhone 13'; generation = '2021'; deviceAge = 'Recent'; confidence = 98; }
    else if (host.includes('iphone-12')) { name = 'iPhone 12'; model = 'iPhone 12'; generation = '2020'; deviceAge = 'Moderate'; confidence = 98; }
    else if (host.includes('iphone-11')) { name = 'iPhone 11'; model = 'iPhone 11'; generation = '2019'; deviceAge = 'Moderate'; confidence = 98; }
    else if (host.includes('iphone-x')) { name = 'iPhone X'; model = 'iPhone X'; generation = '2017'; deviceAge = 'Old'; confidence = 98; }
    else { name = 'iPhone'; model = 'iPhone'; }
  }

  // Samsung Galaxy Series
  else if (mfg.includes('samsung') || host.includes('galaxy') || host.includes('samsung') || 
           host.includes('s20-fe') || host.includes('s21-fe') || host.includes('s22-fe') || 
           host.includes('s23-fe') || host.includes('s24-fe') || host.includes('note') ||
           host.match(/s\d+/i) || host.match(/galaxy/i) || host.match(/samsung/i)) {
    vendor = 'Samsung'; osGuess = 'Android'; confidence = 90;
    capabilities.push('Samsung Pay', 'Bixby', 'DeX', 'S Pen', 'Knox Security');
    
    if (host.includes('s24') || host.includes('s-24')) { name = 'Samsung Galaxy S24'; model = 'Galaxy S24'; generation = '2024'; deviceAge = 'New'; confidence = 98; }
    else if (host.includes('s23') || host.includes('s-23')) { name = 'Samsung Galaxy S23'; model = 'Galaxy S23'; generation = '2023'; deviceAge = 'New'; confidence = 98; }
    else if (host.includes('s22') || host.includes('s-22')) { name = 'Samsung Galaxy S22'; model = 'Galaxy S22'; generation = '2022'; deviceAge = 'Recent'; confidence = 98; }
    else if (host.includes('s21') || host.includes('s-21')) { name = 'Samsung Galaxy S21'; model = 'Galaxy S21'; generation = '2021'; deviceAge = 'Recent'; confidence = 98; }
    else if (host.includes('s20-fe') || host.includes('s20_fe')) { name = 'Samsung Galaxy S20 FE'; model = 'Galaxy S20 FE'; generation = '2020'; deviceAge = 'Moderate'; confidence = 98; }
    else if (host.includes('s20') || host.includes('s-20')) { name = 'Samsung Galaxy S20'; model = 'Galaxy S20'; generation = '2020'; deviceAge = 'Moderate'; confidence = 98; }
    else if (host.includes('note')) { name = 'Samsung Galaxy Note'; model = 'Galaxy Note'; capabilities.push('S Pen Advanced'); confidence = 95; }
    else if (host.includes('fold')) { name = 'Samsung Galaxy Fold'; model = 'Galaxy Fold'; capabilities.push('Foldable Display'); confidence = 95; }
    else if (host.includes('tab') || host.includes('tablet')) { 
      name = 'Samsung Galaxy Tab'; model = 'Galaxy Tab'; type = 'Tablet'; 
      capabilities.push('S Pen', 'DeX Mode'); confidence = 95; 
    }
    else { name = 'Samsung Galaxy'; model = 'Galaxy Series'; }
  }

  // Google Pixel Series
  else if (host.includes('pixel') || mfg.includes('google')) {
    vendor = 'Google'; osGuess = 'Android (Pure)'; confidence = 95;
    capabilities.push('Google Assistant', 'Pixel Camera', 'Google Photos', 'Call Screen');
    
    if (host.includes('pixel-8')) { name = 'Google Pixel 8'; model = 'Pixel 8'; generation = '2023'; deviceAge = 'New'; confidence = 98; }
    else if (host.includes('pixel-7')) { name = 'Google Pixel 7'; model = 'Pixel 7'; generation = '2022'; deviceAge = 'Recent'; confidence = 98; }
    else if (host.includes('pixel-6')) { name = 'Google Pixel 6'; model = 'Pixel 6'; generation = '2021'; deviceAge = 'Recent'; confidence = 98; }
    else if (host.includes('pixel-5')) { name = 'Google Pixel 5'; model = 'Pixel 5'; generation = '2020'; deviceAge = 'Moderate'; confidence = 98; }
    else { name = 'Google Pixel'; model = 'Pixel Series'; }
  }

  // OnePlus Devices
  else if (host.includes('oneplus') || mfg.includes('oneplus')) {
    vendor = 'OnePlus'; osGuess = 'OxygenOS (Android)'; confidence = 95;
    capabilities.push('Warp Charge', 'OxygenOS', 'Alert Slider');
    name = 'OnePlus Smartphone'; model = 'OnePlus';
  }

  // Xiaomi/Redmi
  else if (host.includes('xiaomi') || host.includes('redmi') || mfg.includes('xiaomi')) {
    vendor = 'Xiaomi'; osGuess = 'MIUI (Android)'; confidence = 90;
    capabilities.push('MIUI', 'Mi ecosystem');
    if (host.includes('redmi')) { name = 'Redmi Smartphone'; model = 'Redmi'; }
    else { name = 'Xiaomi Smartphone'; model = 'Mi Series'; }
  }

  // Huawei
  else if (host.includes('huawei') || mfg.includes('huawei')) {
    vendor = 'Huawei'; osGuess = 'HarmonyOS/EMUI'; confidence = 90;
    capabilities.push('HarmonyOS', 'Leica Camera');
    name = 'Huawei Smartphone'; model = 'Huawei';
  }

  return { confidence, type, name, vendor, model, generation, osGuess, capabilities, deviceAge };
}

function analyzeTablet(mfg, host, mac) {
  let confidence = 0;
  let type = 'Tablet';
  let name = 'Unknown Tablet';
  let vendor = 'Unknown';
  let model = 'Unknown';
  let osGuess = 'Unknown';
  let capabilities = ['WiFi', 'Bluetooth', 'Touchscreen', 'Camera', 'GPS'];

  // Apple iPads
  if (mfg.includes('apple') || host.includes('ipad')) {
    vendor = 'Apple'; osGuess = 'iPadOS'; confidence = 95;
    capabilities.push('Apple Pencil', 'Face ID', 'Touch ID', 'AirDrop', 'Sidecar');
    
    if (host.includes('ipad-pro')) { name = 'iPad Pro'; model = 'iPad Pro'; capabilities.push('M1/M2 Chip', 'Thunderbolt'); confidence = 98; }
    else if (host.includes('ipad-air')) { name = 'iPad Air'; model = 'iPad Air'; confidence = 98; }
    else if (host.includes('ipad-mini')) { name = 'iPad mini'; model = 'iPad mini'; confidence = 98; }
    else { name = 'iPad'; model = 'iPad'; }
  }

  // Samsung Galaxy Tabs
  else if ((mfg.includes('samsung') || host.includes('samsung') || host.includes('galaxy')) && 
           (host.includes('tab') || host.includes('tablet'))) {
    vendor = 'Samsung'; osGuess = 'Android'; confidence = 95;
    capabilities.push('S Pen', 'DeX Mode', 'Samsung Pay', 'Knox Security');
    
    if (host.includes('tab-s')) { name = 'Samsung Galaxy Tab S'; model = 'Galaxy Tab S'; confidence = 98; }
    else if (host.includes('tab-a')) { name = 'Samsung Galaxy Tab A'; model = 'Galaxy Tab A'; confidence = 98; }
    else { name = 'Samsung Galaxy Tab'; model = 'Galaxy Tab'; }
  }

  // Microsoft Surface Tablets
  else if (host.includes('surface') || mfg.includes('microsoft')) {
    vendor = 'Microsoft'; osGuess = 'Windows 11'; confidence = 95;
    capabilities.push('Surface Pen', 'Windows Hello', 'Type Cover');
    
    if (host.includes('surface-pro')) { name = 'Microsoft Surface Pro'; model = 'Surface Pro'; confidence = 98; }
    else if (host.includes('surface-go')) { name = 'Microsoft Surface Go'; model = 'Surface Go'; confidence = 98; }
    else { name = 'Microsoft Surface'; model = 'Surface'; }
  }

  // Amazon Fire Tablets
  else if (host.includes('fire') || mfg.includes('amazon') || host.includes('kindle')) {
    vendor = 'Amazon'; osGuess = 'Fire OS'; confidence = 90;
    capabilities.push('Alexa', 'Prime Video', 'Kindle');
    name = 'Amazon Fire Tablet'; model = 'Fire';
  }

  // Generic Android Tablets
  else if (host.includes('tablet') || host.includes('tab')) {
    osGuess = 'Android'; confidence = 70;
    name = 'Android Tablet'; model = 'Tablet';
    
    if (host.includes('lenovo')) { vendor = 'Lenovo'; name = 'Lenovo Tablet'; confidence = 85; }
    else if (host.includes('huawei')) { vendor = 'Huawei'; name = 'Huawei Tablet'; confidence = 85; }
    else if (host.includes('asus')) { vendor = 'ASUS'; name = 'ASUS Tablet'; confidence = 85; }
  }

  // Check for tablet indicators in hostname patterns
  else if (host.match(/.*-tab$/i) || host.match(/.*tablet$/i) || host.match(/tab-.*$/i)) {
    confidence = 80;
    name = 'Tablet Device'; model = 'Tablet';
    osGuess = 'Android';
  }

  return { confidence, type, name, vendor, model, osGuess, capabilities };
}

function analyzeComputer(mfg, host, mac) {
  let confidence = 0;
  let type = 'Computer';
  let name = 'Unknown Computer';
  let vendor = 'Unknown';
  let model = 'Unknown';
  let osGuess = 'Unknown';
  let capabilities = ['WiFi', 'Bluetooth', 'USB', 'Display Output'];
  let deviceAge = 'Unknown';

  // Apple Mac Systems
  if (mfg.includes('apple') || host.includes('mac') || host.includes('imac') || host.includes('macbook')) {
    vendor = 'Apple'; osGuess = 'macOS'; confidence = 95;
    capabilities.push('AirDrop', 'Handoff', 'Universal Clipboard', 'Sidecar', 'iCloud');
    
    if (host.includes('macbook-pro')) { name = 'MacBook Pro'; model = 'MacBook Pro'; type = 'Laptop'; }
    else if (host.includes('macbook-air')) { name = 'MacBook Air'; model = 'MacBook Air'; type = 'Laptop'; }
    else if (host.includes('imac')) { name = 'iMac'; model = 'iMac'; type = 'Desktop'; }
    else if (host.includes('mac-pro')) { name = 'Mac Pro'; model = 'Mac Pro'; type = 'Workstation'; }
    else if (host.includes('mac-mini')) { name = 'Mac mini'; model = 'Mac mini'; type = 'Mini PC'; }
    else if (host.includes('mac-studio')) { name = 'Mac Studio'; model = 'Mac Studio'; type = 'Desktop'; }
    else { name = 'Mac Computer'; model = 'Mac'; }
  }

  // Windows PCs
  else if (host.includes('desktop') || host.includes('pc') || host.includes('windows') || host.includes('laptop')) {
    osGuess = 'Windows'; confidence = 70;
    capabilities.push('DirectX', 'Windows Hello', 'Cortana');
    
    if (host.includes('dell')) { vendor = 'Dell'; name = 'Dell Computer'; confidence = 90; }
    else if (host.includes('hp')) { vendor = 'HP'; name = 'HP Computer'; confidence = 90; }
    else if (host.includes('lenovo')) { vendor = 'Lenovo'; name = 'Lenovo Computer'; confidence = 90; }
    else if (host.includes('asus')) { vendor = 'ASUS'; name = 'ASUS Computer'; confidence = 90; }
    else if (host.includes('acer')) { vendor = 'Acer'; name = 'Acer Computer'; confidence = 90; }
    else { name = 'Windows PC'; }
  }

  // Linux Systems
  else if (host.includes('ubuntu') || host.includes('linux') || host.includes('debian')) {
    osGuess = 'Linux'; confidence = 85;
    capabilities.push('Open Source', 'Terminal', 'Package Manager');
    name = 'Linux Computer';
  }

  return { confidence, type, name, vendor, model, osGuess, capabilities, deviceAge };
}

function analyzeIoTDevice(mfg, host, mac) {
  let confidence = 0;
  let type = 'IoT Device';
  let name = 'Unknown IoT Device';
  let vendor = 'Unknown';
  let capabilities = ['WiFi', 'Low Power'];
  let securityRisk = 'Medium';

  // Smart Home Devices
  if (mfg.includes('murata')) {
    vendor = 'Murata'; name = 'Smart IoT Module'; confidence = 80;
    capabilities.push('Sensor Data', 'Wireless Communication');
  } else if (mfg.includes('sichuan') || mfg.includes('ai-link')) {
    vendor = 'Sichuan AI-Link'; name = 'Smart IoT Device'; confidence = 85;
    capabilities.push('AI Processing', 'Edge Computing');
  } else if (mfg.includes('espressif')) {
    vendor = 'Espressif'; name = 'ESP32/ESP8266 Device'; confidence = 90;
    capabilities.push('Microcontroller', 'WiFi Module', 'Bluetooth');
  } else if (mfg.includes('amazon')) {
    vendor = 'Amazon'; confidence = 95;
    if (host.includes('echo')) { name = 'Amazon Echo'; type = 'Smart Speaker'; capabilities.push('Alexa', 'Voice Control'); }
    else if (host.includes('ring')) { name = 'Ring Security Device'; type = 'Security Camera'; capabilities.push('Video Recording', 'Motion Detection'); }
    else { name = 'Amazon Smart Device'; }
  } else if (mfg.includes('google') && (host.includes('nest') || host.includes('home'))) {
    vendor = 'Google'; name = 'Google Nest Device'; confidence = 95;
    capabilities.push('Google Assistant', 'Smart Home Control');
  }

  return { confidence, type, name, vendor, capabilities, securityRisk };
}

function analyzeGamingDevice(mfg, host, mac) {
  let confidence = 0;
  let type = 'Gaming Console';
  let name = 'Unknown Gaming Device';
  let vendor = 'Unknown';
  let generation = 'Unknown';
  let osGuess = 'Gaming OS';
  let capabilities = ['Gaming', 'Media Streaming', 'Online Multiplayer'];

  if (host.includes('playstation') || host.includes('ps5') || host.includes('ps4')) {
    vendor = 'Sony'; osGuess = 'PlayStation OS'; confidence = 95;
    capabilities.push('PlayStation Network', 'Blu-ray', 'VR Support');
    if (host.includes('ps5')) { name = 'PlayStation 5'; generation = '9th Gen'; }
    else if (host.includes('ps4')) { name = 'PlayStation 4'; generation = '8th Gen'; }
    else { name = 'PlayStation Console'; }
  } else if (host.includes('xbox')) {
    vendor = 'Microsoft'; osGuess = 'Xbox OS'; confidence = 95;
    capabilities.push('Xbox Live', 'Game Pass', 'Quick Resume');
    if (host.includes('series')) { name = 'Xbox Series X/S'; generation = '9th Gen'; }
    else { name = 'Xbox Console'; }
  } else if (host.includes('nintendo') || host.includes('switch')) {
    vendor = 'Nintendo'; osGuess = 'Nintendo OS'; confidence = 95;
    capabilities.push('Portable Gaming', 'Nintendo eShop');
    name = 'Nintendo Switch';
  }

  return { confidence, type, name, vendor, generation, osGuess, capabilities };
}

function analyzeMediaDevice(mfg, host, mac) {
  let confidence = 0;
  let type = 'Media Device';
  let name = 'Unknown Media Device';
  let vendor = 'Unknown';
  let capabilities = ['Media Streaming', 'WiFi'];

  if (host.includes('appletv') || host.includes('apple-tv')) {
    vendor = 'Apple'; name = 'Apple TV'; confidence = 95;
    capabilities.push('AirPlay', 'tvOS', '4K Streaming', 'HomeKit Hub');
  } else if (host.includes('roku')) {
    vendor = 'Roku'; name = 'Roku Streaming Device'; confidence = 95;
    capabilities.push('Roku OS', '4K Streaming', 'Voice Remote');
  } else if (host.includes('chromecast')) {
    vendor = 'Google'; name = 'Google Chromecast'; confidence = 95;
    capabilities.push('Cast', 'Google TV', '4K Streaming');
  } else if (host.includes('firetv') || host.includes('fire-tv')) {
    vendor = 'Amazon'; name = 'Amazon Fire TV'; confidence = 95;
    capabilities.push('Fire OS', 'Alexa Voice Remote', '4K Streaming');
  }

  return { confidence, type, name, vendor, capabilities };
}

function analyzePrinterDevice(mfg, host, mac) {
  let confidence = 0;
  let type = 'Printer';
  let name = 'Unknown Printer';
  let vendor = 'Unknown';
  let capabilities = ['Printing', 'WiFi'];

  if (mfg.includes('hp') || host.includes('hp')) {
    vendor = 'HP'; name = 'HP Printer'; confidence = 90;
    capabilities.push('HP Smart', 'Mobile Printing', 'Cloud Printing');
  } else if (mfg.includes('canon') || host.includes('canon')) {
    vendor = 'Canon'; name = 'Canon Printer'; confidence = 90;
    capabilities.push('PIXMA', 'Mobile Printing');
  } else if (mfg.includes('epson') || host.includes('epson')) {
    vendor = 'Epson'; name = 'Epson Printer'; confidence = 90;
    capabilities.push('EcoTank', 'Mobile Printing');
  } else if (mfg.includes('brother') || host.includes('brother')) {
    vendor = 'Brother'; name = 'Brother Printer'; confidence = 90;
    capabilities.push('Mobile Connect', 'Laser Printing');
  }

  return { confidence, type, name, vendor, capabilities };
}

function analyzeSecurityDevice(mfg, host, mac) {
  let confidence = 0;
  let type = 'Security Device';
  let name = 'Unknown Security Device';
  let vendor = 'Unknown';
  let capabilities = ['Security Monitoring', 'WiFi'];

  if (host.includes('ring') || mfg.includes('ring')) {
    vendor = 'Ring (Amazon)'; name = 'Ring Security Device'; confidence = 95;
    capabilities.push('Video Recording', 'Motion Detection', 'Cloud Storage');
  } else if (host.includes('nest') && (host.includes('cam') || host.includes('doorbell'))) {
    vendor = 'Google Nest'; name = 'Nest Security Camera'; confidence = 95;
    capabilities.push('AI Detection', 'Cloud Recording', 'Smart Alerts');
  } else if (host.includes('arlo') || mfg.includes('arlo')) {
    vendor = 'Arlo'; name = 'Arlo Security Camera'; confidence = 95;
    capabilities.push('Wireless', 'Weather Resistant', 'Night Vision');
  }

  return { confidence, type, name, vendor, capabilities };
}

function analyzeVehicleDevice(mfg, host, mac) {
  let confidence = 0;
  let type = 'Vehicle System';
  let name = 'Unknown Vehicle Device';
  let vendor = 'Unknown';
  let capabilities = ['Vehicle Integration', 'WiFi Hotspot'];

  if (host.includes('tesla') || mfg.includes('tesla')) {
    vendor = 'Tesla'; name = 'Tesla Vehicle System'; confidence = 95;
    capabilities.push('Autopilot', 'Over-the-Air Updates', 'Supercharging');
  } else if (host.includes('bmw') || mfg.includes('bmw')) {
    vendor = 'BMW'; name = 'BMW ConnectedDrive'; confidence = 90;
    capabilities.push('iDrive', 'Remote Services', 'Digital Key');
  } else if (host.includes('audi') || mfg.includes('audi')) {
    vendor = 'Audi'; name = 'Audi Connect'; confidence = 90;
    capabilities.push('MMI', 'Virtual Cockpit', 'Connect Services');
  }

  return { confidence, type, name, vendor, capabilities };
}

function analyzeMacAddress(mac, mfg) {
  let confidence = 0;
  let vendor = 'Unknown';
  let deviceType = 'Unknown';

  // Enhanced MAC OUI database (first 3 octets)
  const macOUI = mac.substring(0, 8).toUpperCase();
  const ouiDatabase = {
    '00:00:0C': { vendor: 'Cisco', type: 'Network Equipment', confidence: 95 },
    '00:1B:63': { vendor: 'Apple', type: 'Apple Device', confidence: 95 },
    '00:23:DF': { vendor: 'Apple', type: 'Apple Device', confidence: 95 },
    '00:25:00': { vendor: 'Apple', type: 'Apple Device', confidence: 95 },
    '00:26:08': { vendor: 'Apple', type: 'Apple Device', confidence: 95 },
    '3C:07:54': { vendor: 'Apple', type: 'Apple Device', confidence: 95 },
    '9C:58:84': { vendor: 'Apple', type: 'Apple Device', confidence: 95 },
    '04:B4:29': { vendor: 'Samsung', type: 'Samsung Device', confidence: 95 },
    '00:16:6C': { vendor: 'Samsung', type: 'Samsung Device', confidence: 95 },
    'C0:E7:BF': { vendor: 'Sichuan AI-Link', type: 'IoT Device', confidence: 85 },
    'B0:72:BF': { vendor: 'Murata', type: 'IoT Module', confidence: 85 }
  };

  if (ouiDatabase[macOUI]) {
    const ouiInfo = ouiDatabase[macOUI];
    vendor = ouiInfo.vendor;
    deviceType = ouiInfo.type;
    confidence = ouiInfo.confidence;
  }

  return { confidence, vendor, deviceType };
}

function analyzeHostnamePatterns(hostname) {
  let confidence = 0;
  let insights = [];

  const patterns = {
    'android-': { insight: 'Android Device', confidence: 80 },
    'iphone': { insight: 'iPhone', confidence: 90 },
    'ipad': { insight: 'iPad', confidence: 90 },
    'macbook': { insight: 'MacBook', confidence: 90 },
    'pixel-': { insight: 'Google Pixel', confidence: 85 },
    'galaxy-': { insight: 'Samsung Galaxy', confidence: 85 },
    'echo-': { insight: 'Amazon Echo', confidence: 85 },
    'nest-': { insight: 'Google Nest', confidence: 85 },
    'ring-': { insight: 'Ring Device', confidence: 85 },
    'ps4-': { insight: 'PlayStation 4', confidence: 90 },
    'ps5-': { insight: 'PlayStation 5', confidence: 90 },
    'xbox-': { insight: 'Xbox Console', confidence: 90 }
  };

  for (const [pattern, info] of Object.entries(patterns)) {
    if (hostname.toLowerCase().includes(pattern)) {
      insights.push(info.insight);
      confidence = Math.max(confidence, info.confidence);
    }
  }

  return { confidence, insights };
}

function generateIntelligentFallback(device, mfg, host, mac, ip) {
  let confidence = 25;
  let type = 'Unknown Device';
  let name = device.hostname || 'Unknown Device';
  let category = 'Unknown';
  let vendor = 'Unknown';

  // IP-based analysis
  if (ip.endsWith('.1')) {
    type = 'Gateway/Router'; category = 'Network Infrastructure'; confidence = 60;
  } else if (ip.endsWith('.254')) {
    type = 'Network Device'; category = 'Network Infrastructure'; confidence = 50;
  }

  // Manufacturer-based fallback
  if (device.manufacturer && device.manufacturer !== 'Unknown') {
    vendor = device.manufacturer.split(',')[0].trim();
    name = vendor + ' Device';
    type = vendor + ' Device';
    confidence += 20;
  }

  // MAC address pattern analysis
  if (device.mac) {
    confidence += 15;
    if (device.mac.startsWith('02:') || device.mac.startsWith('06:') || 
        device.mac.startsWith('0A:') || device.mac.startsWith('0E:')) {
      name += ' (Virtual Interface)';
      confidence -= 10;
    }
  }

  return {
    name, type, category, confidence: Math.min(confidence, 100),
    osGuess: 'Unknown', capabilities: ['Network Connected'],
    deviceAge: 'Unknown', securityRisk: 'Low', vendor,
    model: 'Unknown', generation: 'Unknown'
  };
}

// === COMPREHENSIVE NMAP SCANNING FUNCTIONS ===

async function performHostDiscovery(scanRange) {
  console.log('🔍 Performing host discovery with broadcast enumeration...');
  
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
    osGuess: "Unknown",
    osDetails: {},
    services: [],
    capabilities: [],
    deviceAge: "Unknown",
    securityRisk: "Low",
    vendor: "Unknown",
    model: "Unknown",
    generation: "Unknown",
    ports: [],
    scripts: {},
    reverseDns: [],
    broadcasts: []
  };

  try {
    // Stage 1: OS and Service Detection
    console.log(`  🖥️  OS & Service fingerprinting...`);
    const osServiceData = await performOSServiceDetection(host.ip);
    Object.assign(deviceData, osServiceData);

    // Stage 2: Enhanced Script Scanning
    console.log(`  📜 Enhanced script enumeration...`);
    const scriptData = await performEnhancedScriptScan(host.ip);
    Object.assign(deviceData, scriptData);

    // Stage 3: SNMP Discovery (if applicable)
    console.log(`  📊 SNMP enumeration...`);
    const snmpData = await performSNMPDiscovery(host.ip);
    Object.assign(deviceData, snmpData);

    // Stage 4: mDNS/DNS-SD Discovery
    console.log(`  🎯 mDNS/DNS-SD discovery...`);
    const mdnsData = await performMDNSDiscovery(host.ip);
    Object.assign(deviceData, mdnsData);

    // Stage 5: Enhanced Device Analysis
    console.log(`  🔬 Advanced device analysis...`);
    const enhancedAnalysis = performAdvancedDeviceAnalysis(deviceData, 
      (deviceData.manufacturer || '').toLowerCase(),
      (deviceData.hostname || '').toLowerCase(),
      (deviceData.mac || '').toLowerCase(),
      deviceData.ipv4
    );
    
    Object.assign(deviceData, enhancedAnalysis);

    return deviceData;

  } catch (error) {
    console.warn(`  ⚠️  Analysis failed for ${host.ip}: ${error.message}`);
    // Return basic enhanced device data
    const basicAnalysis = performAdvancedDeviceAnalysis(deviceData, 
      (deviceData.manufacturer || '').toLowerCase(),
      (deviceData.hostname || '').toLowerCase(),
      (deviceData.mac || '').toLowerCase(),
      deviceData.ipv4
    );
    return Object.assign(deviceData, basicAnalysis);
  }
}

async function performOSServiceDetection(ip) {
  try {
    // Focused OS and service detection with reasonable timeout
    const osCmd = `sudo -n nmap -O -sS -sV --version-light ` +
                  `--osscan-guess --max-retries 1 ` +
                  `--host-timeout 60s --script-timeout 15s ` +
                  `-p22,23,25,53,80,135,137,138,139,443,445,993,995,3389,5900,8080 ` +
                  `-oX - ${ip}`;
    
    const { stdout } = await execAsync(osCmd, { timeout: 120000 }); // 2 minute timeout
    return parseNmapXML(stdout, 'os-service');
  } catch (error) {
    console.warn(`    ⚠️  OS/Service detection failed: ${error.message}`);
    return { osGuess: "Unknown", services: [], ports: [] };
  }
}

async function performEnhancedScriptScan(ip) {
  try {
    // Focused script scanning for key enumeration
    const scriptCmd = `sudo -n nmap -sS --script "smb-os-discovery,nbstat,http-title,ssl-cert" ` +
                     `--script-timeout 20s -p22,80,135,139,443,445 ` +
                     `-oX - ${ip}`;
    
    const { stdout } = await execAsync(scriptCmd, { timeout: 90000 }); // 1.5 minute timeout
    return parseNmapXML(stdout, 'scripts');
  } catch (error) {
    console.warn(`    ⚠️  Script scanning failed: ${error.message}`);
    return { scripts: {} };
  }
}

async function performSNMPDiscovery(ip) {
  try {
    // SNMP enumeration for network devices
    const snmpCmd = `nmap --script "snmp-info,snmp-interfaces,snmp-sysdescr,snmp-processes" ` +
                   `--script-args snmp.version=all -sU -p161 --script-timeout 20s ` +
                   `-oX - ${ip}`;
    
    const { stdout } = await execAsync(snmpCmd, { timeout: 60000 });
    return parseNmapXML(stdout, 'snmp');
  } catch (error) {
    console.warn(`    ⚠️  SNMP discovery failed: ${error.message}`);
    return { snmpInfo: {} };
  }
}

async function performMDNSDiscovery(ip) {
  try {
    // mDNS/DNS-SD discovery for modern devices
    const mdnsCmd = `nmap --script "dns-service-discovery,broadcast-dns-service-discovery" ` +
                   `--script-timeout 15s -p5353 ` +
                   `-oX - ${ip}`;
    
    const { stdout } = await execAsync(mdnsCmd, { timeout: 45000 });
    return parseNmapXML(stdout, 'mdns');
  } catch (error) {
    console.warn(`    ⚠️  mDNS discovery failed: ${error.message}`);
    return { mdnsServices: [] };
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

function parseNmapXML(xmlOutput, type) {
  const result = {};
  
  try {
    // Parse key information from nmap XML output
    if (type === 'os-service') {
      // Extract OS information
      const osMatches = xmlOutput.match(/<osclass[^>]*name="([^"]*)"[^>]*accuracy="([^"]*)"[^>]*vendor="([^"]*)"[^>]*osfamily="([^"]*)"[^>]*osgen="([^"]*)"/g);
      if (osMatches) {
        result.osDetails = osMatches.map(match => {
          const nameMatch = match.match(/name="([^"]*)"/);
          const accuracyMatch = match.match(/accuracy="([^"]*)"/);
          const vendorMatch = match.match(/vendor="([^"]*)"/);
          const familyMatch = match.match(/osfamily="([^"]*)"/);
          const genMatch = match.match(/osgen="([^"]*)"/);
          
          return {
            name: nameMatch ? nameMatch[1] : 'Unknown',
            accuracy: accuracyMatch ? parseInt(accuracyMatch[1]) : 0,
            vendor: vendorMatch ? vendorMatch[1] : 'Unknown',
            family: familyMatch ? familyMatch[1] : 'Unknown',
            generation: genMatch ? genMatch[1] : 'Unknown'
          };
        });
        
        // Set best OS guess
        if (result.osDetails.length > 0) {
          const bestOS = result.osDetails.reduce((best, current) => 
            current.accuracy > best.accuracy ? current : best
          );
          result.osGuess = `${bestOS.vendor} ${bestOS.name} ${bestOS.generation}`.trim();
          result.confidence = Math.max(result.confidence || 0, bestOS.accuracy);
        }
      }
      
      // Extract service information
      const serviceMatches = xmlOutput.match(/<service[^>]*>/g);
      if (serviceMatches) {
        result.services = serviceMatches.map(service => {
          const nameMatch = service.match(/name="([^"]*)"/);
          const productMatch = service.match(/product="([^"]*)"/);
          const versionMatch = service.match(/version="([^"]*)"/);
          const extrainfoMatch = service.match(/extrainfo="([^"]*)"/);
          
          return {
            name: nameMatch ? nameMatch[1] : 'Unknown',
            product: productMatch ? productMatch[1] : '',
            version: versionMatch ? versionMatch[1] : '',
            extraInfo: extrainfoMatch ? extrainfoMatch[1] : ''
          };
        });
      }
      
      // Extract port information
      const portMatches = xmlOutput.match(/<port[^>]*protocol="([^"]*)"[^>]*portid="([^"]*)"[^>]*>/g);
      if (portMatches) {
        result.ports = portMatches.map(port => {
          const protocolMatch = port.match(/protocol="([^"]*)"/);
          const portidMatch = port.match(/portid="([^"]*)"/);
          return {
            protocol: protocolMatch ? protocolMatch[1] : 'tcp',
            port: portidMatch ? parseInt(portidMatch[1]) : 0
          };
        });
      }
    }
    
    if (type === 'scripts') {
      // Extract script results
      const scriptMatches = xmlOutput.match(/<script[^>]*id="([^"]*)"[^>]*output="([^"]*)"/g);
      if (scriptMatches) {
        result.scripts = {};
        scriptMatches.forEach(script => {
          const idMatch = script.match(/id="([^"]*)"/);
          const outputMatch = script.match(/output="([^"]*)"/);
          if (idMatch && outputMatch) {
            result.scripts[idMatch[1]] = outputMatch[1];
          }
        });
      }
    }
    
    // Extract hostname information
    const hostnameMatches = xmlOutput.match(/<hostname[^>]*name="([^"]*)"[^>]*type="([^"]*)"/g);
    if (hostnameMatches) {
      result.reverseDns = hostnameMatches.map(hostname => {
        const nameMatch = hostname.match(/name="([^"]*)"/);
        const typeMatch = hostname.match(/type="([^"]*)"/);
        return {
          name: nameMatch ? nameMatch[1] : '',
          type: typeMatch ? typeMatch[1] : 'PTR'
        };
      });
    }
    
  } catch (parseError) {
    console.warn(`    ⚠️  XML parsing failed: ${parseError.message}`);
  }
  
  return result;
}

// Run the scanner
if (require.main === module) {
  // Check if user wants verbose format
  const args = process.argv.slice(2);
  const useVerboseFormat = args.includes('--verbose') || args.includes('-v');
  
  simpleNetworkScan(useVerboseFormat);
}

module.exports = { 
  parseDevices, 
  enhanceDevice, 
  simpleNetworkScan
};