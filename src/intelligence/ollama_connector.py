#!/usr/bin/env python3
"""
Ollama Connector for AI Network Observer
Connects to Ollama instance for network security analysis
"""

import requests
import json
import logging
import time
from typing import Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class OllamaWSLConnector:
    """
    Ollama connector with auto-detection and retry logic
    """
    
    def __init__(self, base_url: str = None, model: str = "llama3.2", 
                 timeout: int = 180, retry_attempts: int = 3):
        """Initialize Ollama connector"""
        self.model = model
        self.timeout = timeout
        self.retry_attempts = retry_attempts
        
        # Auto-detect Ollama URL
        self.base_url = base_url or self._detect_ollama_url()
        self.api_endpoint = f"{self.base_url}/api/generate"
        
        # Connection status
        self.is_connected = False
        self.available_models = []
        
        # Test connection
        self._test_connection()
    
    def _detect_ollama_url(self) -> str:
        """Auto-detect Ollama URL"""
        possible_urls = [
            "http://localhost:11434",  # PC IP
            "http://172.21.49.168:11434",  # WSL IP
            "http://host.docker.internal:11434",
            "http://localhost:11434"
        ]
        
        for url in possible_urls:
            try:
                response = requests.get(f"{url}/api/tags", timeout=5)
                if response.status_code == 200:
                    logger.info(f"✓ Ollama detected at: {url}")
                    return url
            except:
                continue
        
        logger.warning("Could not auto-detect Ollama")
        return "http://localhost:11434"
    
    def _test_connection(self):
        """Test connection to Ollama"""
        for attempt in range(self.retry_attempts):
            try:
                response = requests.get(f"{self.base_url}/api/tags", timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    self.available_models = [m['name'] for m in data.get('models', [])]
                    self.is_connected = True
                    
                    logger.info(f"✓ Connected to Ollama at {self.base_url}")
                    logger.info(f"Available models: {self.available_models}")
                    
                    if self.model not in self.available_models:
                        logger.warning(f"Model '{self.model}' not found")
                        if self.available_models:
                            self.model = self.available_models[0]
                            logger.info(f"Using: {self.model}")
                    
                    return True
                    
            except Exception as e:
                logger.warning(f"Attempt {attempt + 1}/{self.retry_attempts} failed")
                time.sleep(2)
        
        logger.error("Failed to connect to Ollama")
        return False
    
    def analyze_network_session(self, session_summary: Dict) -> Dict:
        """
        Analyze network session with Ollama
        Compatible avec LLMConnector interface
        """
        if not self.is_connected:
            return {
                'error': 'Ollama not connected',
                'success': False,
                'timestamp': datetime.now().isoformat()
            }
        
        # Create security analysis prompt
        prompt = self._create_security_prompt(session_summary)
        
        try:
            start_time = time.time()
            
            response = requests.post(
                self.api_endpoint,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.2,
                        "top_p": 0.9,
                        "num_predict": 3000,
                        "repeat_penalty": 1.1
                    }
                },
                timeout=self.timeout
            )
            
            duration = time.time() - start_time
            
            if response.status_code == 200:
                result = response.json()
                analysis_text = result.get('response', '')
                
                # Parse response
                analysis = self._parse_security_analysis(analysis_text)
                
                # Validate coherence
                analysis = self._validate_analysis(analysis, session_summary)
                
                return {
                    'timestamp': datetime.now().isoformat(),
                    'model': self.model,
                    'duration_seconds': round(duration, 2),
                    'analysis': analysis,
                    'raw_response': analysis_text,
                    'success': True
                }
            else:
                logger.error(f"Ollama API error: {response.status_code}")
                return {'error': f'API error {response.status_code}', 'success': False}
                
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            return {'error': str(e), 'success': False}
    
    def _create_security_prompt(self, session_data: Dict) -> str:
        """Create security analysis prompt"""
        
        dns_summary = session_data.get('dns_analysis', {})
        http_summary = session_data.get('http_analysis', {})
        graph_summary = session_data.get('graph_analysis', {})
        
        suspicious_domains = dns_summary.get('suspicious_domains', [])[:5]
        
        prompt = f"""You are a network security AI analyzing traffic for threats.

**SESSION DATA:**
Duration: {session_data.get('duration_minutes', 0)} minutes
DNS Queries: {session_data.get('total_dns_queries', 0)}
HTTP Requests: {session_data.get('total_http_requests', 0)}

**SUSPICIOUS ACTIVITY:**
DNS Threats: {json.dumps(suspicious_domains, indent=2) if suspicious_domains else "None"}
HTTP Threats: {json.dumps(http_summary.get('high_risk_requests', [])[:3], indent=2)}
Network Anomalies: {json.dumps(graph_summary.get('unusual_patterns', {}), indent=2)}

**ANALYZE AND RESPOND IN THIS FORMAT:**

SEVERITY: [CRITICAL|HIGH|MEDIUM|LOW|INFO]
CONFIDENCE: [0-100]%
THREAT_TYPE: [Specific threat]

SUMMARY:
[2-3 sentences about findings]

THREATS_DETECTED:
- [Threat 1]
- [Threat 2]

RECOMMENDATIONS:
- [Action 1]
- [Action 2]

INDICATORS:
- [IOC 1]
- [IOC 2]

Begin analysis:"""
        
        return prompt
    
    def _parse_security_analysis(self, response: str) -> Dict:
        """Parse LLM response into structured format"""
        analysis = {
            'severity': 'INFO',
            'confidence': 0,
            'threat_type': 'UNKNOWN',
            'summary': '',
            'threats': [],
            'recommendations': [],
            'indicators': []
        }
        
        lines = response.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('SEVERITY:'):
                analysis['severity'] = line.split(':', 1)[1].strip()
            
            elif line.startswith('CONFIDENCE:'):
                try:
                    conf = line.split(':', 1)[1].strip().rstrip('%')
                    analysis['confidence'] = int(conf)
                except:
                    pass
            
            elif line.startswith('THREAT_TYPE:'):
                analysis['threat_type'] = line.split(':', 1)[1].strip()
            
            elif line.startswith('SUMMARY:'):
                current_section = 'summary'
                analysis['summary'] = line.split(':', 1)[1].strip() if ':' in line else ''
            
            elif line.startswith('THREATS_DETECTED:'):
                current_section = 'threats'
            
            elif line.startswith('RECOMMENDATIONS:'):
                current_section = 'recommendations'
            
            elif line.startswith('INDICATORS:'):
                current_section = 'indicators'
            
            elif current_section == 'summary' and line and not line.startswith('THREATS'):
                analysis['summary'] += ' ' + line
            
            elif current_section == 'threats' and line.startswith('-'):
                analysis['threats'].append(line.lstrip('- '))
            
            elif current_section == 'recommendations' and line.startswith('-'):
                analysis['recommendations'].append(line.lstrip('- '))
            
            elif current_section == 'indicators' and line.startswith('-'):
                analysis['indicators'].append(line.lstrip('- '))
        
        return analysis


    def _validate_analysis(self, analysis: Dict, session_data: Dict) -> Dict:
        """Validate analysis coherence with session data"""
        
        dns_total = session_data.get('total_dns_queries', 0)
        http_total = session_data.get('total_http_requests', 0)
        duration = session_data.get('duration_minutes', 0)
        
        dns_summary = session_data.get('dns_analysis', {}).get('summary', {})
        high_risk_count = dns_summary.get('high_risk_count', 0)
        
        # Validation Rule 1: Empty session = INFO severity
        if dns_total == 0 and http_total == 0:
            analysis['severity'] = 'INFO'
            analysis['threat_type'] = 'No Network Activity'
            analysis['summary'] = f"No network activity captured during {duration:.1f} minute session."
            analysis['threats'] = []
            analysis['recommendations'] = []
            analysis['confidence'] = 100
        
        # Validation Rule 2: No high-risk but high severity = reduce
        elif high_risk_count == 0 and analysis['severity'] in ['HIGH', 'CRITICAL']:
            logger.warning(f"Severity downgraded: no high-risk indicators found")
            analysis['severity'] = 'LOW' if dns_total > 0 else 'INFO'
        
        # Validation Rule 3: Threats list empty but severity HIGH = inconsistent
        elif not analysis['threats'] and analysis['severity'] in ['HIGH', 'CRITICAL']:
            logger.warning(f"Severity reduced: no specific threats identified")
            analysis['severity'] = 'MEDIUM' if high_risk_count > 0 else 'LOW'
        
        # Validation Rule 4: Confidence too high without evidence
        if analysis['confidence'] > 80 and not analysis['threats']:
            analysis['confidence'] = min(50, analysis['confidence'])
        
        return analysis

if __name__ == "__main__":
    # Test
    logging.basicConfig(level=logging.INFO)
    connector = OllamaWSLConnector()
    print("Connected:", connector.is_connected)
    print("Models:", connector.available_models)
