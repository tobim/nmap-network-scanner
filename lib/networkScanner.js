const { exec } = require('child_process');
const { promisify } = require('util');

class NetworkScanner {
  constructor() {
    this.execAsync = promisify(exec);
  }

  async getNetworkInfo() {
    try {
      const { stdout } = await this.execAsync('route get default');
      const gatewayMatch = stdout.match(/gateway: ([\d.]+)/);
      const interfaceMatch = stdout.match(/interface: (\w+)/);
      
      return {
        gateway: gatewayMatch ? gatewayMatch[1] : 'Unknown',
        interface: interfaceMatch ? interfaceMatch[1] : 'Unknown',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to get network info: ${error.message}`);
    }
  }

  async quickScan() {
    try {
      const networkInfo = await this.getNetworkInfo();
      const gateway = networkInfo.gateway;
      const parts = gateway.split('.');
      const scanRange = `${parts[0]}.${parts[1]}.${parts[2]}.1-254`;
      
      const { stdout } = await this.execAsync(`nmap -sn -T4 ${scanRange}`);
      return this.parseNmapOutput(stdout);
    } catch (error) {
      throw new Error(`Quick scan failed: ${error.message}`);
    }
  }

  async standardScan() {
    try {
      const networkInfo = await this.getNetworkInfo();
      const gateway = networkInfo.gateway;
      const parts = gateway.split('.');
      const scanRange = `${parts[0]}.${parts[1]}.${parts[2]}.1-254`;
      
      const { stdout } = await this.execAsync(`nmap -sn ${scanRange}`);
      return this.parseNmapOutput(stdout);
    } catch (error) {
      throw new Error(`Standard scan failed: ${error.message}`);
    }
  }

  async detailedScan() {
    try {
      const networkInfo = await this.getNetworkInfo();
      const gateway = networkInfo.gateway;
      const parts = gateway.split('.');
      const scanRange = `${parts[0]}.${parts[1]}.${parts[2]}.1-254`;
      
      const { stdout } = await this.execAsync(`nmap -sn -O ${scanRange}`);
      return this.parseNmapOutput(stdout);
    } catch (error) {
      throw new Error(`Detailed scan failed: ${error.message}`);
    }
  }

  async scanSpecificDevice(ip) {
    try {
      const { stdout } = await this.execAsync(`nmap -sn -O ${ip}`);
      const devices = this.parseNmapOutput(stdout);
      return devices.length > 0 ? devices[0] : null;
    } catch (error) {
      throw new Error(`Device scan failed: ${error.message}`);
    }
  }

  parseNmapOutput(output) {
    const devices = [];
    const lines = output.split('\n');
    let current = null;
    
    for (const line of lines) {
      const ipMatch = line.match(/Nmap scan report for (.+)/);
      if (ipMatch) {
        if (current) devices.push(current);
        
        const target = ipMatch[1];
        const hostnameMatch = target.match(/(.+) \((.+)\)/);
        
        current = {
          ipv4: hostnameMatch ? hostnameMatch[2] : target,
          name: hostnameMatch ? hostnameMatch[1] : target,
          ipv6: 'N/A',
          mac: 'N/A',
          manufacturer: 'Unknown',
          type: 'Unknown Device',
          status: 'up'
        };
      }
      
      const macMatch = line.match(/MAC Address: ([0-9A-Fa-f:]{17}) \((.+)\)/);
      if (macMatch && current) {
        current.mac = macMatch[1].toUpperCase();
        current.manufacturer = macMatch[2];
      }
    }
    
    if (current) devices.push(current);
    
    return devices;
  }
}

module.exports = NetworkScanner;