#!/usr/bin/env python3
"""
HTTP Metadata Extractor - Extract headers and features from HTTP traffic
"""

import re
from typing import Dict, Optional, List
from scapy.all import TCP, Raw
from urllib.parse import urlparse, parse_qs
import logging

logger = logging.getLogger(__name__)


class HTTPMetadataExtractor:
    """Extract metadata from HTTP requests and responses"""
    
    def __init__(self):
        # Suspicious user agents
        self.suspicious_ua_patterns = [
            r'curl',
            r'wget',
            r'python-requests',
            r'Go-http-client',
            r'nmap',
            r'sqlmap',
            r'nikto'
        ]
        
        # Sensitive data patterns
        self.sensitive_patterns = {
            'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            'password': r'pass(?:word)?["\']?\s*[:=]\s*["\']?([^"\'&\s]{6,})',
            'token': r'token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'
        }
    
    def extract(self, packet) -> Optional[Dict]:
        """Extract HTTP metadata from packet"""
        
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return None
        
        tcp_layer = packet[TCP]
        
        # Check if likely HTTP (port 80 or common proxies)
        if tcp_layer.dport not in [80, 8080, 8000, 3128] and \
           tcp_layer.sport not in [80, 8080, 8000, 3128]:
            return None
        
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Check if HTTP request
            if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ')):
                return self._extract_request(payload, packet)
            
            # Check if HTTP response
            elif payload.startswith('HTTP/'):
                return self._extract_response(payload, packet)
            
        except Exception as e:
            logger.debug(f"HTTP extraction error: {e}")
        
        return None
    
    def _extract_request(self, payload: str, packet) -> Dict:
        """Extract metadata from HTTP request"""
        
        lines = payload.split('\r\n')
        if not lines:
            return None
        
        # Parse request line
        request_line = lines[0].split(' ')
        if len(request_line) < 3:
            return None
        
        method = request_line[0]
        url = request_line[1]
        http_version = request_line[2]
        
        # Parse headers
        headers = {}
        body_start = 0
        
        for i, line in enumerate(lines[1:], 1):
            if line == '':
                body_start = i + 1
                break
            
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        
        # Extract body
        body = '\r\n'.join(lines[body_start:]) if body_start > 0 else ''
        
        # Parse URL
        parsed_url = urlparse(url)
        
        # Extract features
        metadata = {
            'type': 'HTTP_REQUEST',
            'timestamp': packet.time if hasattr(packet, 'time') else None,
            'method': method,
            'url': url,
            'path': parsed_url.path,
            'query_params': parse_qs(parsed_url.query),
            'http_version': http_version,
            'headers': headers,
            'body_length': len(body),
            'host': headers.get('host', ''),
            'user_agent': headers.get('user-agent', ''),
            'referer': headers.get('referer', ''),
            'content_type': headers.get('content-type', ''),
            'src_ip': packet[TCP].sport,
            'dst_ip': packet[TCP].dport
        }
        
        # Anomaly detection
        metadata['anomalies'] = self._detect_request_anomalies(metadata, body)
        metadata['risk_score'] = self._calculate_request_risk(metadata)
        
        # Detect sensitive data in request
        metadata['sensitive_data_detected'] = self._detect_sensitive_data(payload)
        
        return metadata
    
    def _extract_response(self, payload: str, packet) -> Dict:
        """Extract metadata from HTTP response"""
        
        lines = payload.split('\r\n')
        if not lines:
            return None
        
        # Parse status line
        status_line = lines[0].split(' ', 2)
        if len(status_line) < 3:
            return None
        
        http_version = status_line[0]
        status_code = status_line[1]
        status_message = status_line[2]
        
        # Parse headers
        headers = {}
        body_start = 0
        
        for i, line in enumerate(lines[1:], 1):
            if line == '':
                body_start = i + 1
                break
            
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        
        body = '\r\n'.join(lines[body_start:]) if body_start > 0 else ''
        
        return {
            'type': 'HTTP_RESPONSE',
            'timestamp': packet.time if hasattr(packet, 'time') else None,
            'http_version': http_version,
            'status_code': int(status_code),
            'status_message': status_message,
            'headers': headers,
            'body_length': len(body),
            'content_type': headers.get('content-type', ''),
            'server': headers.get('server', ''),
            'src_ip': packet[TCP].sport,
            'dst_ip': packet[TCP].dport
        }
    
    def _detect_request_anomalies(self, metadata: Dict, body: str) -> List[str]:
        """Detect anomalies in HTTP request"""
        anomalies = []
        
        # 1. Suspicious User-Agent
        user_agent = metadata['user_agent'].lower()
        for pattern in self.suspicious_ua_patterns:
            if re.search(pattern, user_agent, re.I):
                anomalies.append(f"SUSPICIOUS_USER_AGENT:{pattern}")
        
        # 2. SQL Injection patterns
        sql_patterns = [
            r"(\bunion\b.*\bselect\b)",
            r"(\bor\b\s+\d+\s*=\s*\d+)",
            r"(';|'--|\bexec\b|\bdrop\b)",
            r"(\band\b\s+\d+\s*=\s*\d+)"
        ]
        
        check_content = metadata['url'] + ' ' + body
        for pattern in sql_patterns:
            if re.search(pattern, check_content, re.I):
                anomalies.append("SQL_INJECTION_PATTERN")
                break
        
        # 3. XSS patterns
        xss_patterns = [
            r"<script[^>]*>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*="
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, check_content, re.I):
                anomalies.append("XSS_PATTERN")
                break
        
        # 4. Directory traversal
        if re.search(r'\.\.[/\\]', metadata['url']):
            anomalies.append("DIRECTORY_TRAVERSAL")
        
        # 5. Command injection
        cmd_patterns = [r'[;&|]', r'\$\(', r'`']
        for pattern in cmd_patterns:
            if re.search(pattern, metadata.get('query_params', {}).__str__()):
                anomalies.append("COMMAND_INJECTION_PATTERN")
                break
        
        # 6. Excessive URL length
        if len(metadata['url']) > 2000:
            anomalies.append(f"EXCESSIVE_URL_LENGTH:{len(metadata['url'])}")
        
        # 7. Missing common headers (potential scanner/bot)
        expected_headers = ['user-agent', 'accept']
        missing = [h for h in expected_headers if h not in metadata['headers']]
        if missing:
            anomalies.append(f"MISSING_HEADERS:{','.join(missing)}")
        
        return anomalies
    
    def _calculate_request_risk(self, metadata: Dict) -> int:
        """Calculate risk score for HTTP request"""
        score = 0
        
        for anomaly in metadata.get('anomalies', []):
            if 'SQL_INJECTION' in anomaly:
                score += 50
            elif 'XSS' in anomaly:
                score += 40
            elif 'COMMAND_INJECTION' in anomaly:
                score += 50
            elif 'DIRECTORY_TRAVERSAL' in anomaly:
                score += 35
            elif 'SUSPICIOUS_USER_AGENT' in anomaly:
                score += 20
            elif 'EXCESSIVE_URL_LENGTH' in anomaly:
                score += 15
            elif 'MISSING_HEADERS' in anomaly:
                score += 10
        
        return min(score, 100)
    
    def _detect_sensitive_data(self, payload: str) -> Dict[str, List[str]]:
        """Detect sensitive data in HTTP traffic (for privacy protection)"""
        detected = {}
        
        for data_type, pattern in self.sensitive_patterns.items():
            matches = re.findall(pattern, payload, re.I)
            if matches:
                # Mask the actual values for privacy
                detected[data_type] = [self._mask_sensitive(m) for m in matches]
        
        return detected
    
    def _mask_sensitive(self, value: str) -> str:
        """Mask sensitive data for logging"""
        if len(value) <= 4:
            return '***'
        
        return value[:2] + '*' * (len(value) - 4) + value[-2:]
    
    def generate_summary(self, requests: List[Dict]) -> Dict:
        """Generate summary for LLM analysis"""
        
        if not requests:
            return {'total_requests': 0}
        
        summary = {
            'total_requests': len(requests),
            'methods': {},
            'hosts': {},
            'high_risk_requests': [],
            'anomaly_types': {}
        }
        
        for req in requests:
            # Count methods
            method = req.get('method', 'UNKNOWN')
            summary['methods'][method] = summary['methods'].get(method, 0) + 1
            
            # Count hosts
            host = req.get('host', 'UNKNOWN')
            summary['hosts'][host] = summary['hosts'].get(host, 0) + 1
            
            # Collect high risk
            if req.get('risk_score', 0) > 50:
                summary['high_risk_requests'].append({
                    'method': req.get('method'),
                    'url': req.get('url'),
                    'risk_score': req.get('risk_score'),
                    'anomalies': req.get('anomalies', [])
                })
            
            # Count anomaly types
            for anomaly in req.get('anomalies', []):
                anomaly_type = anomaly.split(':')[0]
                summary['anomaly_types'][anomaly_type] = \
                    summary['anomaly_types'].get(anomaly_type, 0) + 1
        
        return summary


if __name__ == "__main__":
    # Test HTTP metadata extractor
    logging.basicConfig(level=logging.INFO)
    
    extractor = HTTPMetadataExtractor()
    
    # Test payloads
    test_request = """GET /api/user?id=1' OR '1'='1 HTTP/1.1\r
Host: example.com\r
User-Agent: sqlmap/1.0\r
Accept: */*\r
\r
"""
    
    print("Testing HTTP metadata extraction...")
    # In real usage, this would be called with actual packets
