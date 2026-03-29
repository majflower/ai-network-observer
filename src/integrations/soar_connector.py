#!/usr/bin/env python3
"""SOAR Platform Integration"""

import requests
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class SOARConnector:
    """Integration with SOAR platforms (TheHive, Cortex, etc.)"""
    
    def __init__(self, config):
        self.thehive_url = config.get('thehive_url', 'http://localhost:9000')
        self.api_key = config.get('api_key', '')
        self.enabled = config.get('enabled', False)
    
    def create_alert(self, analysis):
        """Create alert in TheHive"""
        if not self.enabled:
            logger.info("SOAR integration disabled, skipping alert creation")
            return None
        
        alert = {
            'title': f"AI Network Observer - {analysis.get('threat_type', 'Unknown')}",
            'description': analysis.get('summary', ''),
            'severity': self._map_severity(analysis.get('severity', 'LOW')),
            'type': 'network_anomaly',
            'source': 'AI-Network-Observer',
            'sourceRef': f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'tags': self._extract_tags(analysis),
            'artifacts': self._create_artifacts(analysis)
        }
        
        try:
            # Simulation (production: vraie API call)
            logger.info(f"Would create alert: {alert['title']}")
            return {'id': 'simulated-alert-123', 'status': 'created'}
        except Exception as e:
            logger.error(f"Failed to create alert: {e}")
            return None
    
    def enrich_with_threat_intel(self, iocs):
        """Enrich IOCs with threat intelligence"""
        enriched = []
        
        for ioc in iocs:
            # VirusTotal lookup (simulation)
            vt_result = self._query_virustotal(ioc)
            
            # AbuseIPDB lookup (simulation)
            abuse_result = self._query_abuseipdb(ioc)
            
            enriched.append({
                'ioc': ioc,
                'virustotal': vt_result,
                'abuseipdb': abuse_result,
                'risk_score': self._calculate_risk(vt_result, abuse_result)
            })
        
        return enriched
    
    def _map_severity(self, severity):
        """Map to TheHive severity (1-4)"""
        mapping = {
            'LOW': 1,
            'MEDIUM': 2,
            'HIGH': 3,
            'CRITICAL': 4
        }
        return mapping.get(severity, 2)
    
    def _extract_tags(self, analysis):
        """Extract tags from analysis"""
        tags = ['ai-detection', 'automated']
        
        if analysis.get('ml_analysis', {}).get('is_anomaly'):
            tags.append('ml-anomaly')
        
        threat_type = analysis.get('threat_type', '')
        if threat_type:
            tags.append(threat_type.lower().replace(' ', '-'))
        
        return tags
    
    def _create_artifacts(self, analysis):
        """Create artifacts (IOCs) for TheHive"""
        artifacts = []
        
        # Extract IOCs from indicators
        indicators = analysis.get('indicators', [])
        for indicator in indicators:
            if 'IP:' in str(indicator):
                artifacts.append({
                    'dataType': 'ip',
                    'data': self._extract_ip(indicator)
                })
            elif 'Domain:' in str(indicator):
                artifacts.append({
                    'dataType': 'domain',
                    'data': self._extract_domain(indicator)
                })
        
        return artifacts
    
    def _extract_ip(self, text):
        """Extract IP from text"""
        import re
        match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', str(text))
        return match.group(0) if match else ''
    
    def _extract_domain(self, text):
        """Extract domain from text"""
        import re
        match = re.search(r'([a-z0-9-]+\.)+[a-z]{2,}', str(text))
        return match.group(0) if match else ''
    
    def _query_virustotal(self, ioc):
        """Query VirusTotal (simulation)"""
        return {'detections': 0, 'reputation': 'unknown'}
    
    def _query_abuseipdb(self, ioc):
        """Query AbuseIPDB (simulation)"""
        return {'abuse_score': 0, 'reports': 0}
    
    def _calculate_risk(self, vt, abuse):
        """Calculate combined risk score"""
        risk = 0
        risk += vt.get('detections', 0) * 10
        risk += abuse.get('abuse_score', 0)
        return min(risk, 100)
