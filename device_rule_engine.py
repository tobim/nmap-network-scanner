#!/usr/bin/env python3
"""
Device Rule Engine for Network Scanner
Loads and processes device detection rules from JSON files
"""

import json
import os
import re
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

logger = logging.getLogger("DeviceRuleEngine")

class DeviceRuleEngine:
    """Manages device detection rules from external JSON files"""
    
    def __init__(self, rules_dir: str = None):
        self.rules_dir = rules_dir or os.path.dirname(os.path.abspath(__file__))
        self.rules = {}
        self.extended_rules = {}
        self.loaded_at = None
        self.load_rules()
    
    def load_rules(self) -> bool:
        """Load device rules from JSON files"""
        try:
            # Try config directory first, then fall back to root directory
            config_dir = os.path.join(self.rules_dir, 'config')
            
            # Load main device rules
            main_rules_path = os.path.join(config_dir, 'device_rules.json')
            if not os.path.exists(main_rules_path):
                main_rules_path = os.path.join(self.rules_dir, 'device_rules.json')
            
            if os.path.exists(main_rules_path):
                with open(main_rules_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Remove JSON comments (lines starting with //)
                    content = '\n'.join(line for line in content.splitlines() 
                                      if not line.strip().startswith('//'))
                    self.rules = json.loads(content)
                logger.info(f"✅ Loaded main device rules from {main_rules_path}")
            
            # Load extended IoT rules
            extended_rules_path = os.path.join(config_dir, 'extended_device_rules.json')
            if not os.path.exists(extended_rules_path):
                extended_rules_path = os.path.join(self.rules_dir, 'extended_device_rules.json')
            
            if os.path.exists(extended_rules_path):
                with open(extended_rules_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Remove JSON comments
                    content = '\n'.join(line for line in content.splitlines() 
                                      if not line.strip().startswith('//'))
                    self.extended_rules = json.loads(content)
                logger.info(f"✅ Loaded extended device rules from {extended_rules_path}")
            
            self.loaded_at = datetime.now()
            logger.info(f"🎉 Device rules loaded successfully at {self.loaded_at}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to load device rules: {str(e)}")
            return False
    
    def reload_rules(self) -> bool:
        """Reload rules from files"""
        logger.info("🔄 Reloading device rules...")
        return self.load_rules()
    
    def get_rules_info(self) -> Dict[str, Any]:
        """Get information about loaded rules"""
        info = {
            'main_rules_version': self.rules.get('version', 'Unknown'),
            'main_rules_updated': self.rules.get('last_updated', 'Unknown'),
            'extended_rules_version': self.extended_rules.get('version', 'Unknown'),
            'extended_rules_updated': self.extended_rules.get('last_updated', 'Unknown'),
            'loaded_at': self.loaded_at.isoformat() if self.loaded_at else None,
            'total_categories': 0,
            'total_vendors': 0
        }
        
        # Count categories and vendors
        if 'rules' in self.rules:
            info['total_categories'] = len(self.rules['rules'])
            total_vendors = 0
            for category in self.rules['rules'].values():
                if isinstance(category, dict):
                    total_vendors += len(category)
            info['total_vendors'] = total_vendors
        
        return info
    
    def analyze_device(self, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze device using rule-based system
        
        Args:
            device_info: Dictionary containing device data (hostname, manufacturer, mac, ip, etc.)
            
        Returns:
            Dictionary with analysis results (type, name, vendor, confidence, capabilities, etc.)
        """
        ip = device_info.get('ipv4', device_info.get('ip', ''))
        mfg = (device_info.get('manufacturer', '') or '').lower()
        hostname = (device_info.get('hostname', '') or '').lower()
        mac = (device_info.get('mac', '') or '').lower()
        
        # CRITICAL FIX 3: Handle missing MAC addresses early
        if not mac or mac in ['n/a', 'unknown', '']:
            logger.info(f"Device {ip} has no MAC address - likely offline or firewalled")
            return {
                'name': f'Unresponsive Device ({ip})',
                'type': 'Offline or Firewalled Device',
                'category': 'Network Issue',
                'vendor': 'Unknown',
                'confidence': 50,
                'capabilities': ['Not Responding to MAC Requests'],
                'osGuess': 'Unknown',
                'model': 'Unknown',
                'generation': 'Unknown',
                'deviceAge': 'Unknown',
                'securityRisk': 'Low',
                'note': 'Device not responding to ARP/MAC requests - may be offline or behind firewall'
            }
        
        # CRITICAL FIX 2: Detect randomized MAC addresses (privacy feature)
        if self.is_randomized_mac(mac):
            logger.info(f"Device {ip} using randomized MAC address: {mac}")
            return {
                'name': 'Privacy-Protected Device',
                'type': 'Device with MAC Randomization',
                'category': 'Privacy Device',
                'vendor': 'Unknown (Privacy Enabled)',
                'confidence': 80,
                'capabilities': ['MAC Randomization', 'Privacy Features', 'Network Connected'],
                'osGuess': 'iOS/Android/Modern OS',
                'model': 'Unknown',
                'generation': 'Modern (2018+)',
                'deviceAge': 'Recent',
                'securityRisk': 'Low',
                'note': 'Device using MAC address randomization for privacy. Disable in system settings to identify device.'
            }
        
        # CRITICAL FIX 2: Check hostname patterns FIRST (highest priority)
        hostname_match = self._check_hostname_patterns(hostname, mfg, device_info)
        if hostname_match:
            logger.info(f"Device {ip} matched by hostname pattern: {hostname}")
            return hostname_match
        
        # Initialize result
        result = {
            'name': device_info.get('hostname') or ip or 'Unknown Device',
            'type': 'Unknown Device',
            'category': 'Unknown',
            'vendor': device_info.get('manufacturer', 'Unknown'),
            'confidence': 0,
            'capabilities': ['Network Connected'],
            'osGuess': 'Unknown',
            'model': 'Unknown',
            'generation': 'Unknown',
            'deviceAge': 'Unknown',
            'securityRisk': 'Low'
        }
        
        # Try to match against rules
        best_match = self._find_best_match(hostname, mfg, mac, ip)
        
        if best_match:
            result.update(best_match)
        else:
            # Fallback analysis
            result.update(self._fallback_analysis(hostname, mfg, mac, ip))
        
        return result
    
    def _check_hostname_patterns(self, hostname: str, mfg: str, device_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check hostname for device type patterns (highest priority detection).
        This fixes misidentification issues like MacBook Air being detected as iPhone.
        
        Args:
            hostname: Device hostname (e.g., "Anuradhas-Air", "Johns-iPhone")
            mfg: Manufacturer name
            device_info: Full device information dictionary
            
        Returns:
            Device classification dict if pattern matched, None otherwise
        """
        if not hostname:
            return None
        
        hostname_lower = hostname.lower()
        vendor = device_info.get('manufacturer', 'Unknown')
        
        # Apple device patterns (most common misidentification)
        if 'apple' in mfg.lower() or vendor.lower().startswith('apple'):
            
            # MacBook detection (includes Air, Pro, etc.)
            if 'macbook' in hostname_lower or '-air' in hostname_lower or '-pro' in hostname_lower:
                model = 'MacBook'
                if 'air' in hostname_lower:
                    model = 'MacBook Air'
                elif 'pro' in hostname_lower:
                    model = 'MacBook Pro'
                
                return {
                    'name': f'Apple {model}',
                    'type': 'Laptop',
                    'category': 'Computer',
                    'vendor': 'Apple Inc.',
                    'confidence': 95,
                    'capabilities': ['WiFi', 'Bluetooth', 'Computing', 'macOS'],
                    'osGuess': 'macOS',
                    'model': model,
                    'generation': 'Modern',
                    'deviceAge': 'Recent',
                    'securityRisk': 'Low'
                }
            
            # iMac detection
            elif 'imac' in hostname_lower:
                return {
                    'name': 'Apple iMac',
                    'type': 'Desktop',
                    'category': 'Computer',
                    'vendor': 'Apple Inc.',
                    'confidence': 95,
                    'capabilities': ['WiFi', 'Bluetooth', 'Computing', 'macOS'],
                    'osGuess': 'macOS',
                    'model': 'iMac',
                    'generation': 'Modern',
                    'deviceAge': 'Recent',
                    'securityRisk': 'Low'
                }
            
            # Mac Mini/Studio detection
            elif 'mac-mini' in hostname_lower or 'mini' in hostname_lower or 'mac-studio' in hostname_lower:
                model = 'Mac Mini' if 'mini' in hostname_lower else 'Mac Studio'
                return {
                    'name': f'Apple {model}',
                    'type': 'Desktop',
                    'category': 'Computer',
                    'vendor': 'Apple Inc.',
                    'confidence': 95,
                    'capabilities': ['WiFi', 'Bluetooth', 'Computing', 'macOS'],
                    'osGuess': 'macOS',
                    'model': model,
                    'generation': 'Modern',
                    'deviceAge': 'Recent',
                    'securityRisk': 'Low'
                }
            
            # iPad detection
            elif 'ipad' in hostname_lower:
                model = 'iPad'
                if 'pro' in hostname_lower:
                    model = 'iPad Pro'
                elif 'air' in hostname_lower:
                    model = 'iPad Air'
                elif 'mini' in hostname_lower:
                    model = 'iPad Mini'
                
                return {
                    'name': f'Apple {model}',
                    'type': 'Tablet',
                    'category': 'Mobile Device',
                    'vendor': 'Apple Inc.',
                    'confidence': 95,
                    'capabilities': ['WiFi', 'Touchscreen', 'iPadOS', 'App Store'],
                    'osGuess': 'iPadOS',
                    'model': model,
                    'generation': 'Modern',
                    'deviceAge': 'Recent',
                    'securityRisk': 'Low'
                }
            
            # iPhone detection
            elif 'iphone' in hostname_lower:
                return {
                    'name': 'Apple iPhone',
                    'type': 'Smartphone',
                    'category': 'Mobile Device',
                    'vendor': 'Apple Inc.',
                    'confidence': 95,
                    'capabilities': ['WiFi', 'Cellular', 'Touchscreen', 'iOS', 'App Store'],
                    'osGuess': 'iOS',
                    'model': 'iPhone',
                    'generation': 'Modern',
                    'deviceAge': 'Recent',
                    'securityRisk': 'Low'
                }
            
            # Apple Watch detection
            elif 'watch' in hostname_lower or 'apple-watch' in hostname_lower:
                return {
                    'name': 'Apple Watch',
                    'type': 'Smartwatch',
                    'category': 'Wearable',
                    'vendor': 'Apple Inc.',
                    'confidence': 95,
                    'capabilities': ['WiFi', 'Bluetooth', 'watchOS', 'Health Tracking'],
                    'osGuess': 'watchOS',
                    'model': 'Apple Watch',
                    'generation': 'Modern',
                    'deviceAge': 'Recent',
                    'securityRisk': 'Low'
                }
        
        # Samsung device patterns
        elif 'samsung' in mfg.lower() or 'samsung' in hostname_lower:
            if 'galaxy-tab' in hostname_lower or 'tab-' in hostname_lower:
                return {
                    'name': 'Samsung Galaxy Tab',
                    'type': 'Tablet',
                    'category': 'Mobile Device',
                    'vendor': 'Samsung Electronics',
                    'confidence': 90,
                    'capabilities': ['WiFi', 'Touchscreen', 'Android'],
                    'osGuess': 'Android',
                    'model': 'Galaxy Tab',
                    'generation': 'Modern',
                    'deviceAge': 'Recent',
                    'securityRisk': 'Low'
                }
            elif 'galaxy' in hostname_lower or 'samsung' in hostname_lower:
                return {
                    'name': 'Samsung Galaxy Smartphone',
                    'type': 'Smartphone',
                    'category': 'Mobile Device',
                    'vendor': 'Samsung Electronics',
                    'confidence': 90,
                    'capabilities': ['WiFi', 'Cellular', 'Touchscreen', 'Android'],
                    'osGuess': 'Android',
                    'model': 'Galaxy',
                    'generation': 'Modern',
                    'deviceAge': 'Recent',
                    'securityRisk': 'Low'
                }
        
        # Generic laptop/desktop patterns
        elif any(pattern in hostname_lower for pattern in ['laptop', 'notebook', 'thinkpad', 'latitude', 'pavilion']):
            return {
                'name': f'{vendor} Laptop',
                'type': 'Laptop',
                'category': 'Computer',
                'vendor': vendor,
                'confidence': 85,
                'capabilities': ['WiFi', 'Computing'],
                'osGuess': 'Windows/Linux',
                'model': 'Laptop',
                'generation': 'Modern',
                'deviceAge': 'Unknown',
                'securityRisk': 'Low'
            }
        
        elif any(pattern in hostname_lower for pattern in ['desktop', 'pc-', 'workstation']):
            return {
                'name': f'{vendor} Desktop',
                'type': 'Desktop',
                'category': 'Computer',
                'vendor': vendor,
                'confidence': 85,
                'capabilities': ['WiFi/Ethernet', 'Computing'],
                'osGuess': 'Windows/Linux',
                'model': 'Desktop',
                'generation': 'Modern',
                'deviceAge': 'Unknown',
                'securityRisk': 'Low'
            }
        
        # No hostname pattern matched
        return None
    
    def _find_best_match(self, hostname: str, mfg: str, mac: str, ip: str) -> Optional[Dict[str, Any]]:
        """Find the best matching rule for the device"""
        best_match = None
        highest_confidence = 0
        
        # Check main device rules
        if 'rules' in self.rules:
            match = self._check_main_rules(hostname, mfg, mac, ip, self.rules['rules'])
            if match and match['confidence'] > highest_confidence:
                best_match = match
                highest_confidence = match['confidence']
        
        # Check extended IoT rules
        if 'extended_iot_rules' in self.extended_rules:
            match = self._check_extended_rules(hostname, mfg, mac, ip, self.extended_rules['extended_iot_rules'])
            if match and match['confidence'] > highest_confidence:
                best_match = match
                highest_confidence = match['confidence']
        
        return best_match
    
    def _check_main_rules(self, hostname: str, mfg: str, mac: str, ip: str, rules: Dict) -> Optional[Dict[str, Any]]:
        """Check against main device rules"""
        for category_name, category_rules in rules.items():
            if not isinstance(category_rules, dict):
                continue
                
            for vendor_name, vendor_rules in category_rules.items():
                if not isinstance(vendor_rules, dict):
                    continue
                
                match = self._match_vendor_rule(hostname, mfg, mac, ip, vendor_rules, category_name, vendor_name)
                if match:
                    return match
        
        return None
    
    def _check_extended_rules(self, hostname: str, mfg: str, mac: str, ip: str, rules: Dict) -> Optional[Dict[str, Any]]:
        """Check against extended IoT rules"""
        for category_name, category_rules in rules.items():
            if not isinstance(category_rules, dict):
                continue
                
            for subcategory_name, subcategory_rules in category_rules.items():
                if not isinstance(subcategory_rules, dict):
                    continue
                
                # Check general patterns
                if self._matches_patterns(hostname, mfg, subcategory_rules.get('patterns', [])):
                    base_confidence = 60
                    
                    # Check vendor-specific patterns
                    vendors = subcategory_rules.get('vendors', {})
                    for vendor_name, vendor_info in vendors.items():
                        if self._matches_patterns(hostname, mfg, vendor_info.get('patterns', [])):
                            return {
                                'name': vendor_info.get('type', subcategory_name.replace('_', ' ').title()),
                                'type': vendor_info.get('type', subcategory_name.replace('_', ' ').title()),
                                'category': 'IoT Device',
                                'vendor': vendor_name.replace('_', ' ').title(),
                                'confidence': base_confidence + 25,
                                'capabilities': vendor_info.get('capabilities', []),
                                'model': vendor_info.get('type', 'Unknown'),
                                'generation': 'IoT',
                                'deviceAge': 'Modern',
                                'securityRisk': 'Medium'
                            }
                    
                    # General category match
                    return {
                        'name': subcategory_name.replace('_', ' ').title(),
                        'type': subcategory_name.replace('_', ' ').title(),
                        'category': 'IoT Device',
                        'vendor': 'Unknown',
                        'confidence': base_confidence,
                        'capabilities': ['IoT', 'WiFi'],
                        'model': 'Unknown',
                        'generation': 'IoT',
                        'deviceAge': 'Modern',
                        'securityRisk': 'Medium'
                    }
        
        return None
    
    def _match_vendor_rule(self, hostname: str, mfg: str, mac: str, ip: str, 
                          vendor_rules: Dict, category_name: str, vendor_name: str) -> Optional[Dict[str, Any]]:
        """Match against a specific vendor rule"""
        patterns = vendor_rules.get('patterns', [])
        hostnames = vendor_rules.get('hostnames', [])
        
        # FIX #4: Use word boundary matching to prevent false positives
        vendor_match = any(self._matches_with_word_boundary(mfg.lower(), pattern.lower()) for pattern in patterns)
        hostname_match = any(self._matches_with_word_boundary(hostname.lower(), hostname_pattern.lower()) for hostname_pattern in hostnames)
        
        if not (vendor_match or hostname_match):
            return None
        
        # Calculate confidence
        confidence = vendor_rules.get('confidence', 70)
        if vendor_match:
            confidence += 10
        if hostname_match:
            confidence += 15
        
        # Check for specific model matches
        model_info = self._get_model_info(hostname, vendor_rules.get('models', {}))
        
        result = {
            'name': model_info.get('name', vendor_rules.get('vendor', vendor_name.title()) + ' ' + vendor_rules.get('type', 'Device')),
            'type': vendor_rules.get('type', category_name.rstrip('s').title()),
            'category': self._get_category_name(category_name),
            'vendor': vendor_rules.get('vendor', vendor_name.title()),
            'confidence': min(confidence, 100),
            'capabilities': vendor_rules.get('capabilities', []),
            'model': model_info.get('name', 'Unknown'),
            'generation': model_info.get('generation', 'Unknown'),
            'deviceAge': model_info.get('age', 'Unknown'),
            'securityRisk': 'Low'
        }
        
        # Special handling for network infrastructure
        if ip.endswith('.1') or ip.endswith('.254'):
            if category_name in ['routers', 'network_equipment']:
                result['confidence'] = min(result['confidence'] + 20, 100)
                result['securityRisk'] = 'Medium'
        
        return result
    
    def _get_model_info(self, hostname: str, models: Dict) -> Dict[str, str]:
        """Get specific model information from hostname"""
        for model_key, model_info in models.items():
            if model_key in hostname:
                return model_info
        return {}
    
    def _matches_patterns(self, hostname: str, mfg: str, patterns: List[str]) -> bool:
        """
        Check if hostname or manufacturer matches any pattern with word boundaries.
        
        FIX #4: Prevents false positives like 'ring' matching 'Murata'
        Uses word boundary matching instead of simple substring search.
        """
        hostname_lower = hostname.lower()
        mfg_lower = mfg.lower()
        
        for pattern in patterns:
            pattern_lower = pattern.lower()
            
            # Check hostname with word boundaries
            if self._matches_with_word_boundary(hostname_lower, pattern_lower):
                logger.debug(f"Pattern '{pattern}' matched hostname '{hostname}'")
                return True
            
            # Check manufacturer with word boundaries  
            if self._matches_with_word_boundary(mfg_lower, pattern_lower):
                logger.debug(f"Pattern '{pattern}' matched manufacturer '{mfg}'")
                return True
        
        return False
    
    def _matches_with_word_boundary(self, text: str, pattern: str) -> bool:
        """
        Check if pattern matches text with word boundaries.
        
        This prevents false matches like:
        - 'ring' matching 'Murata' (contains 'rat' but not 'ring' as whole word)
        - 'art' matching 'Samsung' (contains 'amsung' but not 'art' as whole word)
        
        Valid matches:
        - 'ring' in 'ring-doorbell' ✓
        - 'ring' in 'ring camera' ✓
        - 'ring' in 'My Ring Device' ✓
        - 'samsung' in 'samsung-galaxy' ✓
        
        Invalid matches:
        - 'ring' in 'murata' ✗ (no word boundary)
        - 'art' in 'smart' ✗ (no word boundary)
        
        Args:
            text: Text to search in (hostname or manufacturer)
            pattern: Pattern to search for
            
        Returns:
            True if pattern found as whole word, False otherwise
        """
        if not text or not pattern:
            return False
        
        # Match pattern as whole word or with non-letter boundaries
        # (^|[^a-z]) means: start of string OR non-letter character
        # ($|[^a-z]) means: end of string OR non-letter character
        regex = r'(^|[^a-z])' + re.escape(pattern) + r'($|[^a-z])'
        
        try:
            return bool(re.search(regex, text))
        except Exception as e:
            logger.debug(f"Regex error matching '{pattern}' in '{text}': {e}")
            # Fallback to simple substring match if regex fails
            return pattern in text
    
    def _get_category_name(self, category_key: str) -> str:
        """Convert category key to display name"""
        category_map = {
            'smartphones': 'Mobile Device',
            'tablets': 'Mobile Device', 
            'routers': 'Network Infrastructure',
            'smart_home': 'Smart Home',
            'iot_devices': 'IoT Device',
            'computers': 'Computer',
            'gaming': 'Gaming Device',
            'printers': 'Office Equipment',
            'nas': 'Storage Device',
            'industrial': 'Industrial Equipment'
        }
        return category_map.get(category_key, category_key.replace('_', ' ').title())
    
    def _fallback_analysis(self, hostname: str, mfg: str, mac: str, ip: str) -> Dict[str, Any]:
        """Fallback analysis when no rules match"""
        result = {
            'confidence': 25,
            'type': 'Unknown Device',
            'name': hostname or 'Unknown Device',
            'category': 'Unknown',
            'vendor': 'Unknown',
            'capabilities': ['Network Connected'],
            'model': 'Unknown',
            'generation': 'Unknown',
            'deviceAge': 'Unknown',
            'securityRisk': 'Low'
        }
        
        # FIX #5: Detect OEM chipmakers (make components, not end devices)
        oem_chipmakers = {
            'murata': {'type': 'WiFi/Bluetooth Module', 'note': 'OEM WiFi module inside another device'},
            'broadcom': {'type': 'Network Chip', 'note': 'OEM network chip inside another device'},
            'realtek': {'type': 'Network Chip', 'note': 'OEM Ethernet/WiFi chip inside another device'},
            'qualcomm': {'type': 'Mobile Chipset', 'note': 'OEM mobile chipset inside another device'},
            'mediatek': {'type': 'WiFi/SOC Chip', 'note': 'OEM WiFi/processor chip inside another device'},
            'texas instruments': {'type': 'Electronics Module', 'note': 'OEM electronic components inside another device'},
            'espressif': {'type': 'ESP32/ESP8266 Module', 'note': 'OEM WiFi module (ESP32/ESP8266)'},
            'atheros': {'type': 'WiFi Chip', 'note': 'OEM WiFi chip inside another device'},
            'marvell': {'type': 'Network Chip', 'note': 'OEM network chip inside another device'},
            'intel corporate': {'type': 'Network Adapter', 'note': 'Intel network adapter inside computer'},
            'raspberry pi': {'type': 'Raspberry Pi', 'note': 'Single-board computer'}  # Exception: actual device
        }
        
        mfg_lower = mfg.lower()
        for chipmaker, info in oem_chipmakers.items():
            if chipmaker in mfg_lower:
                # Special case: Raspberry Pi IS the actual device
                if chipmaker == 'raspberry pi':
                    result.update({
                        'type': 'Single-Board Computer',
                        'name': 'Raspberry Pi',
                        'category': 'Computer',
                        'vendor': 'Raspberry Pi Foundation',
                        'confidence': 85,
                        'capabilities': ['Linux', 'GPIO', 'Computing', 'WiFi', 'Bluetooth'],
                        'model': 'Raspberry Pi',
                        'generation': 'Various',
                        'deviceAge': 'Modern',
                        'securityRisk': 'Medium',
                        'note': 'Single-board computer (check hostname for model)'
                    })
                else:
                    # OEM component - not the actual device
                    result.update({
                        'type': f'Unknown Device ({info["type"]})',
                        'name': f'Device with {mfg.split()[0]} Module',
                        'category': 'Unknown',
                        'vendor': mfg.split()[0].title(),
                        'confidence': 40,
                        'capabilities': ['Network Connected', 'Contains OEM Components'],
                        'model': 'Unknown',
                        'generation': 'Unknown',
                        'deviceAge': 'Unknown',
                        'securityRisk': 'Low',
                        'note': info['note']
                    })
                return result
        
        # IP-based analysis
        if ip.endswith('.1'):
            result.update({
                'type': 'Gateway/Router',
                'category': 'Network Infrastructure',
                'confidence': 60,
                'capabilities': ['Gateway', 'Routing', 'DHCP'],
                'securityRisk': 'Medium'
            })
        elif ip.endswith('.254'):
            result.update({
                'type': 'Network Device',
                'category': 'Network Infrastructure', 
                'confidence': 50,
                'capabilities': ['Network Equipment'],
                'securityRisk': 'Medium'
            })
        
        # Manufacturer-based fallback
        if mfg and mfg != 'unknown':
            vendor = mfg.split(',')[0].strip().title()
            result.update({
                'vendor': vendor,
                'name': f"{vendor} Device",
                'type': f"{vendor} Device",
                'confidence': result['confidence'] + 20
            })
        
        # MAC address analysis
        if mac:
            result['confidence'] += 15
            
            # Check for virtual interfaces
            if mac.startswith(('02:', '06:', '0a:', '0e:')):
                result['name'] += ' (Virtual Interface)'
                result['confidence'] -= 10
        
        return result
    
    def get_categories(self) -> List[str]:
        """Get list of available device categories"""
        categories = []
        if 'rules' in self.rules:
            categories.extend(self.rules['rules'].keys())
        if 'extended_iot_rules' in self.extended_rules:
            categories.extend(self.extended_rules['extended_iot_rules'].keys())
        return sorted(list(set(categories)))
    
    def get_vendors_by_category(self, category: str) -> List[str]:
        """Get list of vendors for a specific category"""
        vendors = []
        
        # Check main rules
        if 'rules' in self.rules and category in self.rules['rules']:
            vendors.extend(self.rules['rules'][category].keys())
        
        # Check extended rules
        if 'extended_iot_rules' in self.extended_rules and category in self.extended_rules['extended_iot_rules']:
            for subcategory in self.extended_rules['extended_iot_rules'][category].values():
                if isinstance(subcategory, dict) and 'vendors' in subcategory:
                    vendors.extend(subcategory['vendors'].keys())
        
        return sorted(list(set(vendors)))
    
    def is_randomized_mac(self, mac: str) -> bool:
        """
        Detect locally administered (randomized) MAC addresses.
        
        iOS, Android, and modern operating systems use MAC randomization for privacy.
        These MACs have bit 1 of the first byte set to 1 (locally administered bit).
        
        Args:
            mac: MAC address string (e.g., "DA:4C:A2:2E:5C:DB")
            
        Returns:
            True if MAC is randomized/locally administered, False otherwise
        """
        if not mac or mac.upper() in ['N/A', 'UNKNOWN', '']:
            return False
        
        try:
            # Get first byte of MAC address
            first_byte_hex = mac.split(':')[0]
            first_byte = int(first_byte_hex, 16)
            
            # Check if bit 1 is set (0x02 = 00000010)
            # Locally administered MACs have this bit set to 1
            is_local = (first_byte & 0x02) != 0
            
            if is_local:
                logger.debug(f"Detected randomized MAC: {mac} (first byte: {first_byte_hex})")
            
            return is_local
        except (ValueError, IndexError, AttributeError) as e:
            logger.debug(f"Error checking MAC {mac}: {e}")
            return False
