#!/usr/bin/env python3
"""ML Feature Extraction for Network Sessions"""

import numpy as np
from datetime import datetime

class NetworkFeatureExtractor:
    """Extract 30+ ML features from network sessions"""
    
    def extract_features(self, session_summary):
        """Extract features for ML model"""
        features = {}
        
        # Temporal
        features['duration_min'] = session_summary.get('duration_minutes', 0)
        features['hour'] = self._get_hour(session_summary.get('start_time', ''))
        
        # Volume
        features['dns_count'] = session_summary.get('total_dns_queries', 0)
        features['http_count'] = session_summary.get('total_http_requests', 0)
        features['tls_count'] = session_summary.get('total_tls_sessions', 0)
        
        # DNS features
        dns_data = session_summary.get('dns_analysis', {})
        dns_summary = dns_data.get('summary', {})
        features['dns_unique'] = dns_summary.get('unique_domains', 0)
        features['dns_high_risk'] = dns_summary.get('high_risk_count', 0)
        features['dns_dga'] = dns_summary.get('dga_detected', 0)
        features['dns_tunneling'] = dns_summary.get('tunneling_detected', 0)
        features['dns_beaconing'] = dns_summary.get('beaconing_detected', 0)
        
        # Ratios
        features['dns_risk_ratio'] = self._ratio(features['dns_high_risk'], features['dns_count'])
        features['dns_unique_ratio'] = self._ratio(features['dns_unique'], features['dns_count'])
        
        # Graph features
        graph = session_summary.get('graph_analysis', {})
        features['graph_nodes'] = graph.get('total_nodes', 0)
        features['graph_edges'] = graph.get('total_edges', 0)
        features['isolated_nodes'] = len(graph.get('isolated_nodes', []))
        features['isolated_ratio'] = self._ratio(features['isolated_nodes'], features['graph_nodes'])
        
        # HTTP features
        http_data = session_summary.get('http_analysis', {})
        features['http_hosts'] = len(http_data.get('hosts', []))
        features['http_high_risk'] = len(http_data.get('high_risk_requests', []))
        
        # TLS features
        tls_data = session_summary.get('tls_analysis', {})
        features['tls_unknown'] = tls_data.get('unknown_clients', 0)
        
        # Rates (per minute)
        duration = max(features['duration_min'], 0.1)
        features['dns_per_min'] = features['dns_count'] / duration
        features['http_per_min'] = features['http_count'] / duration
        
        # Entropy (domain randomness)
        features['domain_entropy'] = self._calc_entropy(dns_data.get('queries', []))
        
        return features
    
    def _ratio(self, a, b):
        return a / max(b, 1)
    
    def _get_hour(self, timestamp):
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return dt.hour
        except:
            return 0
    
    def _calc_entropy(self, queries):
        """Calculate Shannon entropy of domains"""
        if not queries:
            return 0
        
        domains = ''.join([q.get('domain', '') for q in queries])
        if not domains:
            return 0
        
        freq = {}
        for char in domains:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0
        for count in freq.values():
            p = count / len(domains)
            if p > 0:
                entropy -= p * np.log2(p)
        
        return entropy
