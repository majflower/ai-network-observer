#!/usr/bin/env python3
"""
Unit tests for Data Masker (Privacy Protection)
"""

import pytest
import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.privacy.data_masker import DataMasker, PIIDetector


class TestDataMasker:
    """Test suite for Data Masker"""
    
    @pytest.fixture
    def masker(self):
        """Create masker instance"""
        return DataMasker(salt="test-salt-123")
    
    def test_ip_masking_consistency(self, masker):
        """Test that IP masking is consistent"""
        ip = "192.168.1.100"
        
        masked1 = masker.mask_ip(ip)
        masked2 = masker.mask_ip(ip)
        
        # Should be consistent
        assert masked1 == masked2
        
        # Should be different from original
        assert masked1 != ip
        
        # Should preserve private range
        assert masked1.startswith("10.")
    
    def test_domain_masking(self, masker):
        """Test domain name masking"""
        domain = "mail.google.com"
        masked = masker.mask_domain(domain)
        
        # Should be masked
        assert masked != domain
        
        # Should preserve TLD
        assert masked.endswith(".com")
        
        # Should be consistent
        assert masker.mask_domain(domain) == masked
    
    def test_url_masking(self, masker):
        """Test URL masking"""
        url = "https://api.example.com/user/12345/profile?api_key=secret123"
        masked = masker.mask_url(url)
        
        # Domain should be masked
        assert "example.com" not in masked
        
        # ID should be masked
        assert "12345" not in masked
        assert "[ID]" in masked
        
        # Parameter should be redacted
        assert "secret123" not in masked
        assert "[REDACTED]" in masked
    
    def test_pii_detection_email(self, masker):
        """Test email detection and masking"""
        text = "Contact john.doe@example.com for details"
        masked = masker._mask_string(text)
        
        # Email should be masked
        assert "john.doe@example.com" not in masked
        assert "[EMAIL:" in masked
    
    def test_pii_detection_phone(self, masker):
        """Test phone number detection"""
        text = "Call +1-555-123-4567"
        masked = masker._mask_string(text)
        
        # Phone should be masked
        assert "555-123-4567" not in masked
        assert "[PHONE:" in masked
    
    def test_pii_detection_api_key(self, masker):
        """Test API key detection"""
        text = 'api_key="sk_live_abc123xyz789secrettoken"'
        masked = masker._mask_string(text)
        
        # API key should be masked
        assert "sk_live_abc123xyz789secrettoken" not in masked
        assert "[API_KEY:" in masked
    
    def test_sensitive_headers_redaction(self, masker):
        """Test sensitive header redaction"""
        data = {
            'headers': {
                'Authorization': 'Bearer secret_token',
                'Cookie': 'session=12345',
                'User-Agent': 'Mozilla/5.0',
                'Content-Type': 'application/json'
            }
        }
        
        masked = masker.mask_session_data(data)
        
        # Sensitive headers should be redacted
        assert masked['headers']['Authorization'] == '[REDACTED]'
        assert masked['headers']['Cookie'] == '[REDACTED]'
        
        # Non-sensitive headers should be preserved
        assert masked['headers']['User-Agent'] == 'Mozilla/5.0'
        assert masked['headers']['Content-Type'] == 'application/json'
    
    def test_full_session_masking(self, masker):
        """Test complete session data masking"""
        session_data = {
            'dns_queries': [
                {
                    'src_ip': '192.168.1.100',
                    'domain': 'mail.google.com',
                    'timestamp': '2025-02-15T10:30:00'
                }
            ],
            'http_requests': [
                {
                    'src_ip': '192.168.1.100',
                    'dst_ip': '8.8.8.8',
                    'url': 'https://api.example.com/users/profile',
                    'headers': {
                        'Authorization': 'Bearer secret',
                        'Host': 'api.example.com'
                    },
                    'body': 'email=test@example.com&password=secret123'
                }
            ]
        }
        
        masked = masker.mask_session_data(session_data)
        
        # IPs should be masked
        assert masked['dns_queries'][0]['src_ip'].startswith('10.')
        assert masked['http_requests'][0]['src_ip'].startswith('10.')
        
        # Domains should be masked
        assert 'google.com' not in str(masked)
        assert 'example.com' not in str(masked)
        
        # PII should be masked
        assert 'test@example.com' not in str(masked)
        assert 'secret123' not in str(masked)
        
        # Privacy notice should be added
        assert '_privacy_notice' in masked
    
    def test_privacy_report_generation(self, masker):
        """Test privacy report generation"""
        # Mask some data
        masker.mask_ip("192.168.1.100")
        masker.mask_ip("10.0.0.1")
        masker.mask_domain("example.com")
        
        report = masker.generate_privacy_report()
        
        assert 'total_ips_masked' in report
        assert report['total_ips_masked'] == 2
        assert 'total_domains_masked' in report
        assert report['total_domains_masked'] == 1


class TestPIIDetector:
    """Test suite for PII Detector"""
    
    @pytest.fixture
    def detector(self):
        """Create detector instance"""
        return PIIDetector()
    
    def test_email_detection(self, detector):
        """Test email detection"""
        data = {
            'body': 'Contact john@example.com or jane.doe@company.org'
        }
        
        results = detector.scan_for_pii(data)
        assert results['emails'] > 0
    
    def test_phone_detection(self, detector):
        """Test phone number detection"""
        data = {
            'text': 'Call 555-123-4567 or +1 (555) 987-6543'
        }
        
        results = detector.scan_for_pii(data)
        assert results['phone_numbers'] > 0
    
    def test_api_key_detection(self, detector):
        """Test API key detection"""
        data = {
            'config': 'api_key=sk_test_abc123xyz789'
        }
        
        results = detector.scan_for_pii(data)
        assert results['api_keys'] > 0
    
    def test_no_pii(self, detector):
        """Test with data containing no PII"""
        data = {
            'message': 'This is a clean message with no sensitive data'
        }
        
        results = detector.scan_for_pii(data)
        assert all(count == 0 for count in results.values())


@pytest.mark.integration
class TestDataMaskerIntegration:
    """Integration tests for Data Masker"""
    
    def test_end_to_end_privacy_pipeline(self):
        """Test complete privacy protection pipeline"""
        masker = DataMasker()
        detector = PIIDetector()
        
        # Raw session data with PII
        raw_data = {
            'network_flows': [
                {
                    'src_ip': '192.168.1.100',
                    'dst_ip': '8.8.8.8',
                    'domain': 'api.example.com',
                    'url': 'https://api.example.com/user/12345?token=secret',
                    'headers': {
                        'Authorization': 'Bearer my-secret-token',
                        'User-Agent': 'MyApp/1.0'
                    },
                    'payload': 'username=john.doe@example.com&password=MyPassword123&phone=555-1234'
                }
            ]
        }
        
        # Detect PII first
        pii_counts = detector.scan_for_pii(raw_data)
        assert pii_counts['emails'] > 0
        assert pii_counts['passwords'] > 0
        
        # Mask data
        masked_data = masker.mask_session_data(raw_data)
        
        # Verify masking
        masked_str = json.dumps(masked_data)
        
        # Original values should not appear
        assert '192.168.1.100' not in masked_str
        assert 'example.com' not in masked_str
        assert 'john.doe@example.com' not in masked_str
        assert 'MyPassword123' not in masked_str
        assert 'my-secret-token' not in masked_str
        
        # Masked values should appear
        assert '10.' in masked_str  # Masked IP
        assert 'entity-' in masked_str  # Masked domain
        assert '[REDACTED]' in masked_str  # Redacted header
        
        # Re-scan masked data - should find no PII
        masked_pii = detector.scan_for_pii(masked_data)
        # Note: Some patterns might still match hashes, but should be much less
        assert masked_pii['emails'] == 0
        assert masked_pii['passwords'] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
