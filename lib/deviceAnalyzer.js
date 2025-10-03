class DeviceAnalyzer {
  constructor() {
    this.devicePatterns = this.initializeDevicePatterns();
  }

  initializeDevicePatterns() {
    return {
      // Apple devices
      apple: {
        patterns: ['iphone', 'ipad', 'mac', 'apple', 'airpods', 'watch'],
        types: {
          'iphone': 'Smartphone',
          'ipad': 'Tablet', 
          'mac': 'Computer',
          'airpods': 'Audio Device',
          'watch': 'Wearable'
        }
      },
      // Google devices
      google: {
        patterns: ['pixel', 'nest', 'chromecast', 'google'],
        types: {
          'pixel': 'Smartphone',
          'nest': 'Smart Home',
          'chromecast': 'Media Device'
        }
      },
      // Samsung devices
      samsung: {
        patterns: ['galaxy', 'samsung', 'tab'],
        types: {
          'galaxy': 'Smartphone',
          'tab': 'Tablet'
        }
      },
      // Network equipment
      network: {
        patterns: ['router', 'switch', 'access-point', 'modem'],
        types: {
          'router': 'Router',
          'switch': 'Network Switch',
          'access-point': 'Access Point',
          'modem': 'Modem'
        }
      }
    };
  }

  async enrichDevices(devices) {
    return devices.map(device => this.enrichDevice(device));
  }

  enrichDevice(device) {
    if (!device) return null;

    const enriched = { ...device };
    
    // Enhance device type based on hostname and manufacturer
    const hostname = (device.name || '').toLowerCase();
    const manufacturer = (device.manufacturer || '').toLowerCase();
    
    // Check for specific device patterns
    for (const [brand, config] of Object.entries(this.devicePatterns)) {
      for (const pattern of config.patterns) {
        if (hostname.includes(pattern) || manufacturer.includes(pattern)) {
          if (config.types[pattern]) {
            enriched.type = config.types[pattern];
          } else {
            enriched.type = this.capitalizeFirst(brand) + ' Device';
          }
          
          if (enriched.manufacturer === 'Unknown') {
            enriched.manufacturer = this.capitalizeFirst(brand);
          }
          break;
        }
      }
    }

    // Enhance based on IP patterns (routers typically use .1 or .254)
    if (device.ipv4 && (device.ipv4.endsWith('.1') || device.ipv4.endsWith('.254'))) {
      enriched.type = 'Router';
    }

    // Calculate confidence score
    enriched.confidence = this.calculateConfidence(enriched);

    return enriched;
  }

  calculateConfidence(device) {
    let confidence = 0;
    
    // MAC address gives manufacturer info
    if (device.mac && device.mac !== 'N/A') confidence += 40;
    
    // Hostname provides device clues
    if (device.name && device.name !== 'Unknown' && device.name.length > 3) confidence += 30;
    
    // Manufacturer identified
    if (device.manufacturer && device.manufacturer !== 'Unknown') confidence += 30;
    
    return Math.min(100, confidence);
  }

  capitalizeFirst(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
  }
}

module.exports = DeviceAnalyzer;