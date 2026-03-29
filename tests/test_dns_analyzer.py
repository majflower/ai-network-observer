#!/usr/bin/env python3
"""
Unit tests for DNS Analyzer
"""

import pytest
from datetime import datetime
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.extractors.dns_analyzer import DNSAnalyzer


class TestDNSAnalyzer:
    """Test suite for DNS Analyzer"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance"""
        return DNSAnalyzer(window_size=10)
    
    def test_entropy_calculation(self, analyzer):
        """Test entropy calculation for domain names"""
        # Low entropy (normal domain)
        low_entropy = analyzer._calculate_entropy("google.com")
        assert low_entropy < 3.5
        
        # High entropy (DGA-like)
        high_entropy = analyzer._calculate_entropy("afjk3jl4k2jfal3jf9lk2j")
        assert high_entropy > 3.5
    
    def test_consonant_ratio(self, analyzer):
        """Test consonant to vowel ratio calculation"""
        # Normal domain
        normal_ratio = analyzer._consonant_ratio("example")
        assert 1.0 <= normal_ratio <= 3.0
        
        # Suspicious (many consonants)
        suspicious_ratio = analyzer._consonant_ratio("zkxqwrtypsd")
        assert suspicious_ratio > 5.0
    
    def test_dga_detection(self, analyzer):
        """Test DGA domain detection"""
        # Normal domain
        normal_domain = "google.com"
        normal_features = {
            'entropy': analyzer._calculate_entropy(normal_domain),
            'subdomain_count': normal_domain.count('.'),
            'length': len(normal_domain),
            'consonant_ratio': analyzer._consonant_ratio(normal_domain)
        }
        normal_anomalies = analyzer._detect_anomalies(normal_domain, normal_features)
        
        # Should have minimal anomalies
        assert len(normal_anomalies) <= 1
        
        # DGA domain
        dga_domain = "afjk3jl4k2jfal3jf9lk2j.malware.com"
        dga_features = {
            'entropy': analyzer._calculate_entropy(dga_domain),
            'subdomain_count': dga_domain.count('.'),
            'length': len(dga_domain),
            'consonant_ratio': analyzer._consonant_ratio(dga_domain)
        }
        dga_anomalies = analyzer._detect_anomalies(dga_domain, dga_features)
        
        # Should detect high entropy
        assert any('HIGH_ENTROPY' in a for a in dga_anomalies)
    
    def test_dns_tunneling_detection(self, analyzer):
        """Test DNS tunneling detection"""
        # Normal domain
        normal = "mail.google.com"
        normal_features = {
            'subdomain_count': normal.count('.'),
            'length': len(normal)
        }
        assert not analyzer._is_dns_tunneling(normal, normal_features)
        
        # Tunneling domain
        tunneling = "VGhpcyBpcyBiYXNlNjQgZW5jb2RlZCBkYXRh.verylongsubdomainname.withhexdata.0123456789abcdef.tunnel.com"
        tunneling_features = {
            'subdomain_count': tunneling.count('.'),
            'length': len(tunneling)
        }
        assert analyzer._is_dns_tunneling(tunneling, tunneling_features)
    
    def test_beaconing_detection(self, analyzer):
        """Test C2 beaconing detection"""
        domain = "c2server.com"
        
        # Add queries at regular intervals
        base_time = datetime.now()
        for i in range(10):
            # Regular 60-second intervals
            timestamp = base_time.replace(second=i*60 % 60, minute=i)
            analyzer.query_history[domain].append(timestamp)
        
        # Should detect beaconing pattern
        assert analyzer._is_beaconing(domain)
    
    def test_risk_score_calculation(self, analyzer):
        """Test risk score calculation"""
        # No anomalies
        assert analyzer._calculate_risk_score([]) == 0
        
        # High risk anomalies
        high_risk = [
            'HIGH_ENTROPY:4.8',
            'BEACONING_PATTERN',
            'DNS_TUNNELING_SUSPECTED'
        ]
        score = analyzer._calculate_risk_score(high_risk)
        assert score > 70
    
    def test_summary_generation(self, analyzer):
        """Test summary generation"""
        # Add some test data
        analyzer.query_history['google.com'] = [datetime.now()] * 5
        analyzer.query_history['malware.com'] = [datetime.now()] * 20
        
        summary = analyzer.generate_summary()
        
        assert 'total_domains_queried' in summary
        assert 'suspicious_domains' in summary
        assert isinstance(summary['suspicious_domains'], list)


@pytest.mark.integration
class TestDNSAnalyzerIntegration:
    """Integration tests for DNS Analyzer"""
    
    def test_full_analysis_pipeline(self):
        """Test complete analysis pipeline"""
        analyzer = DNSAnalyzer()
        
        test_domains = [
            "google.com",
            "facebook.com",
            "afjk3jl4k2jfal3jf.malware.com",  # DGA
            "very.long.subdomain.with.many.levels.tunnel.com",  # Tunneling
        ]
        
        for domain in test_domains:
            # Simulate packet
            class FakeDNS:
                def __init__(self, d):
                    self.qd = type('obj', (object,), {
                        'qname': d.encode(),
                        'qtype': 1,
                        'qclass': 1
                    })
            
            class FakePacket:
                def __init__(self, d):
                    from scapy.all import DNS
                    self.DNS = DNS
                    self.dns = FakeDNS(d)
                
                def haslayer(self, layer):
                    return layer == self.DNS
                
                def __getitem__(self, key):
                    return self.dns
            
            result = analyzer.analyze_packet(FakePacket(domain))
            assert result is not None
        
        # Check summary
        summary = analyzer.generate_summary()
        assert summary['total_domains_queried'] == len(test_domains)
        assert len(summary['suspicious_domains']) >= 2  # At least DGA and tunneling


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
