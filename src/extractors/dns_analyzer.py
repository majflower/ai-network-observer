#!/usr/bin/env python3
"""
DNS Analyzer - Advanced DNS analysis with tunneling detection
Detects DNS exfiltration, DGA, and C2 beaconing
"""

import re
import math
from typing import Dict, List, Optional
from collections import defaultdict, deque
from datetime import datetime, timedelta
from scapy.all import DNS, DNSQR, DNSRR
import logging

logger = logging.getLogger(__name__)


class DNSAnalyzer:
    """Advanced DNS analysis and anomaly detection"""
    
    def __init__(self, window_size: int = 100):
        self.query_history = defaultdict(deque)  # Domain -> timestamps
        self.subdomain_counts = defaultdict(int)
        self.window_size = window_size
        
        # Baseline for legitimate domains
        self.known_domains = set([
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'netflix.com', 'cloudflare.com', 'akamai.net'
        ])
        
        # DGA detection thresholds
        self.entropy_threshold = 3.5
        self.subdomain_threshold = 10
    
    def analyze_packet(self, packet) -> Optional[Dict]:
        """
        Analyze DNS packet and extract features
        
        Returns metadata dictionary with anomaly scores
        """
        if not packet.haslayer(DNS):
            return None
        
        dns_layer = packet[DNS]
        
        # Process query
        if dns_layer.qd and isinstance(dns_layer.qd, DNSQR):
            return self._analyze_query(dns_layer, packet)
        
        # Process response
        if dns_layer.an:
            return self._analyze_response(dns_layer, packet)
        
        return None
    
    def _analyze_query(self, dns_layer, packet) -> Dict:
        """Analyze DNS query"""
        query = dns_layer.qd
        domain = query.qname.decode('utf-8', errors='ignore').rstrip('.')
        
        timestamp = datetime.now()
        
        # Store query history
        self.query_history[domain].append(timestamp)
        if len(self.query_history[domain]) > self.window_size:
            self.query_history[domain].popleft()
        
        # Extract features
        features = {
            'timestamp': timestamp,
            'domain': domain,
            'query_type': query.qtype,
            'query_class': query.qclass,
            'length': len(domain),
            'entropy': self._calculate_entropy(domain),
            'subdomain_count': domain.count('.'),
            'has_numbers': bool(re.search(r'\d', domain)),
            'has_hyphens': '-' in domain,
            'consonant_ratio': self._consonant_ratio(domain),
        }
        
        # Anomaly detection
        anomalies = self._detect_anomalies(domain, features)
        
        return {
            'type': 'DNS_QUERY',
            'domain': domain,
            'features': features,
            'anomalies': anomalies,
            'risk_score': self._calculate_risk_score(anomalies)
        }
    
    def _analyze_response(self, dns_layer, packet) -> Dict:
        """Analyze DNS response"""
        answers = []
        
        for i in range(dns_layer.ancount):
            if dns_layer.an:
                rr = dns_layer.an[i] if isinstance(dns_layer.an, list) else dns_layer.an
                
                if isinstance(rr, DNSRR):
                    answers.append({
                        'name': rr.rrname.decode('utf-8', errors='ignore') if hasattr(rr, 'rrname') else '',
                        'type': rr.type if hasattr(rr, 'type') else 0,
                        'ttl': rr.ttl if hasattr(rr, 'ttl') else 0,
                        'rdata': str(rr.rdata) if hasattr(rr, 'rdata') else ''
                    })
        
        return {
            'type': 'DNS_RESPONSE',
            'answer_count': dns_layer.ancount,
            'answers': answers
        }
    
    def _calculate_entropy(self, domain: str) -> float:
        """
        Calculate Shannon entropy of domain name
        High entropy = potentially DGA-generated
        """
        if not domain:
            return 0.0
        
        # Remove common TLD
        domain = re.sub(r'\.(com|net|org|io|co)$', '', domain)
        
        # Calculate character frequency
        freq = {}
        for char in domain:
            freq[char] = freq.get(char, 0) + 1
        
        # Shannon entropy
        entropy = 0.0
        length = len(domain)
        
        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return round(entropy, 3)
    
    def _consonant_ratio(self, domain: str) -> float:
        """
        Calculate consonant to vowel ratio
        DGA domains often have unusual ratios
        """
        vowels = set('aeiou')
        consonants = set('bcdfghjklmnpqrstvwxyz')
        
        domain_lower = domain.lower()
        vowel_count = sum(1 for c in domain_lower if c in vowels)
        consonant_count = sum(1 for c in domain_lower if c in consonants)
        
        if vowel_count == 0:
            return 10.0  # Suspicious
        
        return round(consonant_count / vowel_count, 2)
    
    def _detect_anomalies(self, domain: str, features: Dict) -> List[str]:
        """
        Detect various DNS anomalies
        
        Returns list of detected anomalies
        """
        anomalies = []
        
        # 1. High Entropy (DGA Detection)
        if features['entropy'] > self.entropy_threshold:
            anomalies.append(f"HIGH_ENTROPY:{features['entropy']}")
        
        # 2. Excessive Subdomain Levels (DNS Tunneling)
        if features['subdomain_count'] > self.subdomain_threshold:
            anomalies.append(f"EXCESSIVE_SUBDOMAINS:{features['subdomain_count']}")
        
        # 3. Very Long Domain (Potential Exfiltration)
        if features['length'] > 100:
            anomalies.append(f"LONG_DOMAIN:{features['length']}")
        
        # 4. Unusual Consonant Ratio
        if features['consonant_ratio'] > 5:
            anomalies.append(f"UNUSUAL_CONSONANT_RATIO:{features['consonant_ratio']}")
        
        # 5. Beaconing Detection (Regular Intervals)
        if self._is_beaconing(domain):
            anomalies.append("BEACONING_PATTERN")
        
        # 6. DNS Tunneling Pattern Detection
        if self._is_dns_tunneling(domain, features):
            anomalies.append("DNS_TUNNELING_SUSPECTED")
        
        # 7. Unknown/New Domain
        base_domain = self._get_base_domain(domain)
        if base_domain not in self.known_domains:
            anomalies.append("UNKNOWN_DOMAIN")
        
        return anomalies
    
    def _is_beaconing(self, domain: str) -> bool:
        """
        Detect C2 beaconing based on regular query intervals
        """
        queries = list(self.query_history[domain])
        
        if len(queries) < 5:
            return False
        
        # Calculate intervals between queries
        intervals = []
        for i in range(1, len(queries)):
            delta = (queries[i] - queries[i-1]).total_seconds()
            intervals.append(delta)
        
        if not intervals:
            return False
        
        # Calculate variance
        mean_interval = sum(intervals) / len(intervals)
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        
        # Low variance = regular beaconing
        coefficient_of_variation = std_dev / mean_interval if mean_interval > 0 else 0
        
        # If CV < 0.3 and interval is consistent (5-3600 seconds), likely beaconing
        if coefficient_of_variation < 0.3 and 5 < mean_interval < 3600:
            return True
        
        return False
    
    def _is_dns_tunneling(self, domain: str, features: Dict) -> bool:
        """
        Detect DNS tunneling based on multiple indicators
        """
        indicators = 0
        
        # Long subdomain names (data encoding)
        parts = domain.split('.')
        if any(len(part) > 40 for part in parts[:-2]):  # Exclude TLD
            indicators += 1
        
        # High entropy subdomains
        for part in parts[:-2]:
            if self._calculate_entropy(part) > 4.0:
                indicators += 1
                break
        
        # Hexadecimal pattern in subdomains
        if any(re.match(r'^[0-9a-f]{20,}$', part, re.I) for part in parts[:-2]):
            indicators += 1
        
        # Base64-like patterns
        if any(re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', part) for part in parts[:-2]):
            indicators += 1
        
        # Multiple indicators = likely tunneling
        return indicators >= 2
    
    def _get_base_domain(self, domain: str) -> str:
        """Extract base domain (e.g., google.com from mail.google.com)"""
        parts = domain.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain
    
    def _calculate_risk_score(self, anomalies: List[str]) -> int:
        """
        Calculate risk score (0-100) based on anomalies
        """
        if not anomalies:
            return 0
        
        score = 0
        
        for anomaly in anomalies:
            if 'HIGH_ENTROPY' in anomaly:
                score += 30
            elif 'BEACONING' in anomaly:
                score += 40
            elif 'DNS_TUNNELING' in anomaly:
                score += 50
            elif 'EXCESSIVE_SUBDOMAINS' in anomaly:
                score += 25
            elif 'LONG_DOMAIN' in anomaly:
                score += 20
            elif 'UNKNOWN_DOMAIN' in anomaly:
                score += 10
        
        return min(score, 100)
    
    def generate_summary(self) -> Dict:
        """Generate summary statistics for LLM analysis"""
        
        # Find top suspicious domains
        suspicious_domains = []
        
        for domain, timestamps in self.query_history.items():
            if len(timestamps) > 0:
                features = {
                    'domain': domain,
                    'query_count': len(timestamps),
                    'entropy': self._calculate_entropy(domain),
                    'is_beaconing': self._is_beaconing(domain)
                }
                
                anomalies = self._detect_anomalies(domain, features)
                risk = self._calculate_risk_score(anomalies)
                
                if risk > 30:
                    suspicious_domains.append({
                        'domain': domain,
                        'risk_score': risk,
                        'anomalies': anomalies,
                        'query_count': len(timestamps)
                    })
        
        # Sort by risk score
        suspicious_domains.sort(key=lambda x: x['risk_score'], reverse=True)
        
        return {
            'total_domains_queried': len(self.query_history),
            'suspicious_domains': suspicious_domains[:20],  # Top 20
            'summary': {
                'high_risk_count': sum(1 for d in suspicious_domains if d['risk_score'] > 70),
                'medium_risk_count': sum(1 for d in suspicious_domains if 30 < d['risk_score'] <= 70)
            }
        }


if __name__ == "__main__":
    # Test DNS analyzer
    logging.basicConfig(level=logging.INFO)
    
    analyzer = DNSAnalyzer()
    
    # Test domains
    test_domains = [
        "google.com",  # Legitimate
        "afjk3jl4k2jfal3jf.malware.com",  # High entropy
        "data.exfiltration.very.long.subdomain.levels.tunneling.example.com",  # Tunneling
        "regularC2beacon.net"  # Simulate multiple queries for beaconing test
    ]
    
    for domain in test_domains:
        # Simulate packet structure
        class FakeDNS:
            def __init__(self, domain):
                self.qd = type('obj', (object,), {
                    'qname': domain.encode(),
                    'qtype': 1,
                    'qclass': 1
                })
        
        class FakePacket:
            def __init__(self, domain):
                self.dns = FakeDNS(domain)
            
            def haslayer(self, layer):
                return layer == DNS
            
            def __getitem__(self, key):
                if key == DNS:
                    return self.dns
        
        result = analyzer.analyze_packet(FakePacket(domain))
        if result and result['anomalies']:
            print(f"\n{domain}:")
            print(f"  Risk Score: {result['risk_score']}")
            print(f"  Anomalies: {result['anomalies']}")
