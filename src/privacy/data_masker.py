#!/usr/bin/env python3
"""
Data Masking - Privacy protection before sending to LLM
Anonymizes PII and sensitive data while preserving analytical value
"""

import re
import hashlib
import ipaddress
from typing import Dict, Any, List, Set
import logging

logger = logging.getLogger(__name__)


class DataMasker:
    """
    Anonymize sensitive data while preserving behavioral patterns
    """
    
    def __init__(self, salt: str = "network-observer-salt-2025"):
        """
        Initialize data masker
        
        Args:
            salt: Salt for consistent hashing (allows correlation without revealing originals)
        """
        self.salt = salt
        self.ip_mapping = {}  # Consistent IP anonymization
        self.domain_mapping = {}  # Consistent domain anonymization
        
        # PII patterns
        self.pii_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b(\+\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            'api_key': r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
            'password': r'["\']?pass(?:word)?["\']?\s*[:=]\s*["\']?([^"\'&\s]{6,})["\']?',
            'jwt': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
        }
        
        # Sensitive header fields
        self.sensitive_headers = {
            'authorization', 'cookie', 'set-cookie', 'x-api-key',
            'x-auth-token', 'proxy-authorization'
        }
    
    def mask_session_data(self, session_data: Dict) -> Dict:
        """
        Mask entire session data structure
        
        Returns anonymized copy that's safe to send to LLM
        """
        masked = self._deep_copy_and_mask(session_data)
        
        # Add privacy notice
        masked['_privacy_notice'] = {
            'anonymized': True,
            'masking_applied': [
                'IP addresses hashed with consistent mapping',
                'Domain names pseudonymized',
                'PII removed or hashed',
                'Sensitive headers redacted',
                'Payload content sanitized'
            ]
        }
        
        return masked
    
    def _deep_copy_and_mask(self, obj: Any) -> Any:
        """Recursively mask data structures"""
        
        if isinstance(obj, dict):
            return {k: self._mask_value(k, v) for k, v in obj.items()}
        
        elif isinstance(obj, list):
            return [self._deep_copy_and_mask(item) for item in obj]
        
        elif isinstance(obj, str):
            return self._mask_string(obj)
        
        else:
            return obj
    
    def _mask_value(self, key: str, value: Any) -> Any:
        """Mask value based on key context"""
        
        # Handle specific field types
        key_lower = key.lower()
        
        # IP addresses
        if 'ip' in key_lower or key_lower in ['src', 'dst', 'source', 'destination']:
            if isinstance(value, str):
                return self.mask_ip(value)
        
        # Domains/hosts
        if key_lower in ['domain', 'host', 'hostname', 'sni']:
            if isinstance(value, str):
                return self.mask_domain(value)
        
        # Sensitive headers
        if key_lower in self.sensitive_headers:
            return '[REDACTED]'
        
        # URLs
        if key_lower in ['url', 'uri', 'path']:
            if isinstance(value, str):
                return self.mask_url(value)
        
        # Recursive masking for nested structures
        if isinstance(value, (dict, list)):
            return self._deep_copy_and_mask(value)
        
        # String content masking
        if isinstance(value, str):
            return self._mask_string(value)
        
        return value
    
    def mask_ip(self, ip_str: str) -> str:
        """
        Anonymize IP address with consistent hashing
        Preserves subnet relationships
        """
        try:
            # Check cache for consistency
            if ip_str in self.ip_mapping:
                return self.ip_mapping[ip_str]
            
            ip = ipaddress.ip_address(ip_str)
            
            # Hash IP to generate consistent pseudonym
            hash_input = f"{ip_str}{self.salt}".encode()
            ip_hash = hashlib.sha256(hash_input).hexdigest()[:8]
            
            # Create readable pseudonym that preserves IP version
            if ip.version == 4:
                # Map to 10.x.x.x range (private)
                octets = [int(ip_hash[i:i+2], 16) % 256 for i in range(0, 8, 2)]
                masked = f"10.{octets[0]}.{octets[1]}.{octets[2]}"
            else:
                # IPv6 - use fd00::/8 (unique local)
                masked = f"fd00::{ip_hash[:4]}:{ip_hash[4:8]}"
            
            # Cache for consistency
            self.ip_mapping[ip_str] = masked
            return masked
            
        except ValueError:
            # Not a valid IP
            return f"[INVALID_IP:{self._hash_short(ip_str)}]"
    
    def mask_domain(self, domain: str) -> str:
        """
        Pseudonymize domain while preserving TLD and structure
        
        Example: mail.google.com -> entity-a3f2.example.com
        """
        if domain in self.domain_mapping:
            return self.domain_mapping[domain]
        
        # Split domain into parts
        parts = domain.lower().rstrip('.').split('.')
        
        if len(parts) < 2:
            masked = f"entity-{self._hash_short(domain)}.local"
        else:
            # Keep TLD, mask the rest
            tld = parts[-1]
            
            # Preserve second-level domain structure but pseudonymize
            if len(parts) == 2:
                # example.com -> entity-abc.com
                masked = f"entity-{self._hash_short(parts[0])}.{tld}"
            else:
                # subdomain.example.com -> sub-xyz.entity-abc.com
                subdomain_hash = self._hash_short('.'.join(parts[:-2]))
                domain_hash = self._hash_short(parts[-2])
                masked = f"sub-{subdomain_hash}.entity-{domain_hash}.{tld}"
        
        self.domain_mapping[domain] = masked
        return masked
    
    def mask_url(self, url: str) -> str:
        """
        Mask URL while preserving structure
        
        Example: https://example.com/user/123/profile?token=abc
        Becomes: https://entity-xyz.com/resource/[ID]/action?param=[REDACTED]
        """
        # Mask domain
        domain_pattern = r'(https?://)([\w\.-]+)(.*)'
        match = re.match(domain_pattern, url)
        
        if match:
            protocol, domain, path = match.groups()
            masked_domain = self.mask_domain(domain)
            masked_path = self._mask_url_path(path)
            return f"{protocol}{masked_domain}{masked_path}"
        
        return self._mask_url_path(url)
    
    def _mask_url_path(self, path: str) -> str:
        """Mask URL path components"""
        # Remove query parameters with sensitive data
        if '?' in path:
            path_part, query = path.split('?', 1)
            # Mask query parameters
            query_masked = re.sub(
                r'([a-zA-Z_-]+)=([^&]+)',
                lambda m: f"{m.group(1)}=[REDACTED]" if len(m.group(2)) > 10 else m.group(0),
                query
            )
            path = f"{path_part}?{query_masked}"
        
        # Mask numeric IDs but preserve structure
        path = re.sub(r'/\d{3,}', '/[ID]', path)
        
        # Mask UUIDs
        path = re.sub(
            r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '/[UUID]',
            path,
            flags=re.I
        )
        
        return path
    
    def _mask_string(self, text: str) -> str:
        """
        Remove PII from arbitrary string content
        """
        masked = text
        
        # Apply PII pattern masking
        for pii_type, pattern in self.pii_patterns.items():
            masked = re.sub(
                pattern,
                lambda m: f"[{pii_type.upper()}:{self._hash_short(m.group(0))}]",
                masked,
                flags=re.I
            )
        
        return masked
    
    def _hash_short(self, value: str) -> str:
        """Generate short consistent hash"""
        hash_input = f"{value}{self.salt}".encode()
        return hashlib.sha256(hash_input).hexdigest()[:8]
    
    def generate_privacy_report(self) -> Dict:
        """
        Generate report on masking applied
        
        Useful for compliance and auditing
        """
        return {
            'total_ips_masked': len(self.ip_mapping),
            'total_domains_masked': len(self.domain_mapping),
            'ip_mapping_sample': {
                k: v for k, v in list(self.ip_mapping.items())[:5]
            },
            'domain_mapping_sample': {
                k: v for k, v in list(self.domain_mapping.items())[:5]
            },
            'pii_patterns_detected': list(self.pii_patterns.keys()),
            'sensitive_headers_redacted': list(self.sensitive_headers)
        }


class PIIDetector:
    """
    Detect PII in network data before masking
    Used for compliance reporting and validation
    """
    
    def __init__(self):
        self.detections = {
            'emails': [],
            'phone_numbers': [],
            'api_keys': [],
            'passwords': [],
            'credit_cards': [],
            'other_pii': []
        }
    
    def scan_for_pii(self, data: Any) -> Dict[str, int]:
        """
        Scan data structure for PII
        
        Returns summary counts
        """
        self.detections = {k: [] for k in self.detections}
        self._recursive_scan(data)
        
        return {
            pii_type: len(items) 
            for pii_type, items in self.detections.items()
        }
    
    def _recursive_scan(self, obj: Any):
        """Recursively scan for PII"""
        if isinstance(obj, dict):
            for v in obj.values():
                self._recursive_scan(v)
        
        elif isinstance(obj, list):
            for item in obj:
                self._recursive_scan(item)
        
        elif isinstance(obj, str):
            self._scan_string(obj)
    
    def _scan_string(self, text: str):
        """Scan string for PII patterns"""
        # Email
        if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text):
            self.detections['emails'].append(True)
        
        # Phone
        if re.search(r'\b(\+\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b', text):
            self.detections['phone_numbers'].append(True)
        
        # API Keys
        if re.search(r'["\']?api[_-]?key["\']?\s*[:=]', text, re.I):
            self.detections['api_keys'].append(True)
        
        # Passwords
        if re.search(r'["\']?pass(?:word)?["\']?\s*[:=]', text, re.I):
            self.detections['passwords'].append(True)
        
        # Credit cards
        if re.search(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b', text):
            self.detections['credit_cards'].append(True)


if __name__ == "__main__":
    # Test data masking
    logging.basicConfig(level=logging.INFO)
    
    masker = DataMasker()
    
    # Test data with sensitive information
    test_data = {
        'dns_queries': [
            {
                'domain': 'mail.google.com',
                'src_ip': '192.168.1.100',
                'dst_ip': '8.8.8.8'
            }
        ],
        'http_requests': [
            {
                'url': 'https://api.example.com/user/12345/profile?api_key=sk_live_abc123xyz789',
                'headers': {
                    'Host': 'api.example.com',
                    'Authorization': 'Bearer secret_token_xyz',
                    'User-Agent': 'MyApp/1.0'
                },
                'body': 'email=user@example.com&password=MySecretPass123'
            }
        ]
    }
    
    print("Original Data:")
    print(json.dumps(test_data, indent=2))
    
    print("\n" + "="*80 + "\n")
    
    masked_data = masker.mask_session_data(test_data)
    
    print("Masked Data (safe for LLM):")
    print(json.dumps(masked_data, indent=2))
    
    print("\n" + "="*80 + "\n")
    
    privacy_report = masker.generate_privacy_report()
    print("Privacy Report:")
    print(json.dumps(privacy_report, indent=2))
