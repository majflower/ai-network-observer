#!/usr/bin/env python3
"""
Example Usage Script - Demonstrates various features of the Network Observability Agent
Run this in a controlled lab environment
"""

import sys
from pathlib import Path
import time
import logging

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.capture_engine import CaptureEngine
from src.extractors.dns_analyzer import DNSAnalyzer
from src.extractors.tls_fingerprint import TLSFingerprinter
from src.graph.network_graph import NetworkGraph
from src.privacy.data_masker import DataMasker
from src.intelligence.llm_connector import PromptEngineer
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def example_1_dns_analysis():
    """
    Example 1: Analyze DNS queries for anomalies
    """
    print("\n" + "="*80)
    print("EXAMPLE 1: DNS Analysis with Anomaly Detection")
    print("="*80 + "\n")
    
    analyzer = DNSAnalyzer()
    
    # Simulate different types of DNS traffic
    test_cases = [
        # Normal domains
        ("google.com", "Legitimate query"),
        ("facebook.com", "Legitimate query"),
        
        # High entropy (potential DGA)
        ("afjk3jl4k2jfal3jf9lk2j.malware.com", "DGA-generated domain"),
        ("xk9f2laj3flk2j9fla.evil.net", "Another DGA domain"),
        
        # DNS Tunneling
        ("very.long.subdomain.with.lots.of.levels.for.data.exfiltration.tunnel.com", 
         "Excessive subdomains"),
        
        # Base64-encoded subdomain (tunneling)
        ("SGVsbG8gV29ybGQgVGhpcyBJcyBEYXRh.tunnel.example.com",
         "Base64 pattern in subdomain"),
    ]
    
    for domain, description in test_cases:
        # Create fake packet structure
        class FakeDNSQuery:
            def __init__(self, domain):
                self.qname = domain.encode()
                self.qtype = 1
                self.qclass = 1
        
        class FakePacket:
            def __init__(self, domain):
                from scapy.all import DNS
                self.DNS = DNS
                self.dns = type('obj', (object,), {'qd': FakeDNSQuery(domain)})
            
            def haslayer(self, layer):
                return layer == self.DNS
            
            def __getitem__(self, key):
                return self.dns
        
        result = analyzer.analyze_packet(FakePacket(domain))
        
        if result:
            print(f"\n{description}: {domain}")
            print(f"  Entropy: {result['features']['entropy']}")
            print(f"  Risk Score: {result['risk_score']}")
            if result['anomalies']:
                print(f"  Anomalies: {', '.join(result['anomalies'])}")
    
    # Generate summary
    summary = analyzer.generate_summary()
    print("\n\nDNS Analysis Summary:")
    print(json.dumps(summary, indent=2))


def example_2_privacy_masking():
    """
    Example 2: Demonstrate privacy-preserving data masking
    """
    print("\n" + "="*80)
    print("EXAMPLE 2: Privacy-Preserving Data Masking")
    print("="*80 + "\n")
    
    masker = DataMasker()
    
    # Sample sensitive data
    sensitive_data = {
        "network_flows": [
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "8.8.8.8",
                "domain": "mail.google.com",
                "url": "https://mail.google.com/mail/u/0/?tab=rm&ogbl#inbox",
                "headers": {
                    "Authorization": "Bearer sk_live_abc123xyz789secrettoken",
                    "Cookie": "session=user_session_id_12345",
                    "User-Agent": "Mozilla/5.0"
                }
            }
        ],
        "http_requests": [
            {
                "method": "POST",
                "url": "https://api.example.com/users/profile?api_key=sk_test_very_long_secret_key_abc123",
                "body": "email=john.doe@example.com&password=MySecretPassword123&phone=+1-555-123-4567"
            }
        ]
    }
    
    print("ORIGINAL DATA:")
    print(json.dumps(sensitive_data, indent=2))
    
    # Mask the data
    masked_data = masker.mask_session_data(sensitive_data)
    
    print("\n\nMASKED DATA (safe for LLM):")
    print(json.dumps(masked_data, indent=2))
    
    # Privacy report
    print("\n\nPRIVACY REPORT:")
    privacy_report = masker.generate_privacy_report()
    print(json.dumps(privacy_report, indent=2))


def example_3_network_graph():
    """
    Example 3: Build and analyze network relationship graph
    """
    print("\n" + "="*80)
    print("EXAMPLE 3: Network Relationship Graph Analysis")
    print("="*80 + "\n")
    
    from datetime import datetime
    
    graph = NetworkGraph()
    now = datetime.now()
    
    # Simulate normal traffic
    print("Adding normal traffic...")
    for i in range(5):
        graph.add_dns_query(f"192.168.1.{100+i}", "google.com", now)
        graph.add_dns_query(f"192.168.1.{100+i}", "facebook.com", now)
    
    # Simulate suspicious: One IP contacting many DGA domains (potential malware)
    print("Adding suspicious traffic: DGA-based C2...")
    for i in range(20):
        domain = f"afjk{i}l3k9f2.malware.com"
        graph.add_dns_query("192.168.1.150", domain, now)
    
    # Simulate suspicious: Many IPs contacting same domain (potential shared C2)
    print("Adding suspicious traffic: Shared C2 server...")
    for i in range(10):
        ip = f"192.168.1.{200+i}"
        graph.add_dns_query(ip, "c2server.evil.com", now)
    
    # Simulate HTTP traffic
    print("Adding HTTP traffic...")
    graph.add_http_request("192.168.1.100", "172.217.14.206", "google.com", now)
    
    # Analyze anomalies
    print("\n\nDETECTED ANOMALIES:")
    anomalies = graph.detect_anomalies()
    
    for anomaly in anomalies:
        print(f"\n[{anomaly['severity']}] {anomaly['type']}")
        print(f"  {anomaly['description']}")
        if 'node' in anomaly:
            print(f"  Node: {anomaly['node']}")
        if 'domain' in anomaly:
            print(f"  Domain: {anomaly['domain']}")
    
    # Centrality metrics
    print("\n\nNETWORK CENTRALITY METRICS:")
    metrics = graph.calculate_centrality_metrics()
    
    print("\nTop nodes by degree (most connected):")
    for node, score in metrics['top_by_degree'][:5]:
        print(f"  {node}: {score:.3f}")
    
    print("\nTop nodes by importance (PageRank):")
    for node, score in metrics['top_by_pagerank'][:5]:
        print(f"  {node}: {score:.3f}")
    
    # Generate summary for LLM
    summary = graph.generate_summary_for_llm()
    print("\n\nGRAPH SUMMARY FOR LLM:")
    print(json.dumps(summary, indent=2, default=str))


def example_4_prompt_engineering():
    """
    Example 4: Demonstrate AI prompt engineering for network analysis
    """
    print("\n" + "="*80)
    print("EXAMPLE 4: AI Prompt Engineering")
    print("="*80 + "\n")
    
    prompt_engineer = PromptEngineer()
    
    # Sample session data
    session_data = {
        "session_id": "demo_session_001",
        "duration_minutes": 30,
        "dns_analysis": {
            "total_domains_queried": 127,
            "suspicious_domains": [
                {
                    "domain": "ak3jf9l2kjs.example.com",
                    "risk_score": 85,
                    "anomalies": ["HIGH_ENTROPY:4.8", "BEACONING_PATTERN"],
                    "query_count": 24
                },
                {
                    "domain": "very.long.subdomain.tunnel.com",
                    "risk_score": 75,
                    "anomalies": ["EXCESSIVE_SUBDOMAINS:8", "DNS_TUNNELING_SUSPECTED"],
                    "query_count": 156
                }
            ],
            "summary": {
                "high_risk_count": 3,
                "medium_risk_count": 7
            }
        },
        "http_analysis": {
            "total_requests": 450,
            "high_risk_requests": [
                {
                    "method": "GET",
                    "url": "/admin/config.php?id=1' OR '1'='1",
                    "risk_score": 90,
                    "anomalies": ["SQL_INJECTION_PATTERN", "SUSPICIOUS_USER_AGENT:sqlmap"]
                }
            ]
        },
        "graph_analysis": {
            "graph_statistics": {
                "total_nodes": 89,
                "total_edges": 312
            },
            "anomalies": [
                {
                    "type": "HUB_NODE",
                    "node": "entity-a3f2.com",
                    "degree": 45,
                    "severity": "HIGH"
                }
            ]
        }
    }
    
    # Generate analysis prompt
    print("GENERATED AI PROMPT:")
    print("="*80)
    prompt = prompt_engineer.create_analysis_prompt(session_data)
    print(prompt)
    print("="*80)
    
    # Generate correlation prompt
    print("\n\nGENERATED CORRELATION PROMPT (Multi-Session):")
    print("="*80)
    multi_session = [session_data, session_data]  # Simulate 2 sessions
    correlation_prompt = prompt_engineer.create_correlation_prompt(multi_session)
    print(correlation_prompt)
    print("="*80)
    
    # Threat hunting prompt
    print("\n\nGENERATED THREAT HUNTING PROMPT:")
    print("="*80)
    hypothesis = "The network is being used for cryptocurrency mining via DNS tunneling to evade detection"
    hunting_prompt = prompt_engineer.create_threat_hunting_prompt(hypothesis, session_data)
    print(hunting_prompt)
    print("="*80)


def example_5_tls_fingerprinting():
    """
    Example 5: TLS Fingerprinting (conceptual - requires real TLS traffic)
    """
    print("\n" + "="*80)
    print("EXAMPLE 5: TLS Fingerprinting (JA3/JA3S)")
    print("="*80 + "\n")
    
    fingerprinter = TLSFingerprinter()
    
    print("TLS Fingerprinter initialized with known signatures:")
    print(f"  Database contains {len(fingerprinter.ja3_database)} known fingerprints\n")
    
    print("Sample known fingerprints:")
    for ja3_string, client in list(fingerprinter.ja3_database.items())[:3]:
        print(f"\n  Client: {client}")
        print(f"  JA3 String: {ja3_string[:80]}...")
    
    print("\n\nNote: To see actual fingerprinting in action, run the main agent")
    print("with TLS traffic (port 443). The agent will:")
    print("  1. Extract JA3 from ClientHello")
    print("  2. Extract JA3S from ServerHello")
    print("  3. Identify known clients/servers")
    print("  4. Detect anomalous TLS configurations")


def example_6_integration():
    """
    Example 6: Full integration example (conceptual)
    """
    print("\n" + "="*80)
    print("EXAMPLE 6: Full System Integration")
    print("="*80 + "\n")
    
    print("""
This example shows how all components work together in the main agent:

1. CAPTURE ENGINE
   └─> Packets from eth0 (Scapy or eBPF)

2. EXTRACTION LAYER
   ├─> DNS Analyzer: Detects DGA, tunneling, beaconing
   ├─> TLS Fingerprinter: Identifies clients via JA3
   ├─> HTTP Extractor: Finds attacks (SQLi, XSS)
   └─> Flow Stats: Analyzes timing patterns

3. GRAPH CONSTRUCTION
   └─> Network Graph: Maps all relationships
       ├─> Nodes: IPs, domains, services
       └─> Edges: Communication flows with metadata

4. PRIVACY MASKING
   └─> Data Masker: Anonymizes before sending to AI
       ├─> Hash IPs consistently
       ├─> Pseudonymize domains
       └─> Remove PII

5. AI ANALYSIS
   └─> LLM Connector: Sends to Claude
       ├─> Prompt Engineer: Crafts specialized prompts
       ├─> Claude Analysis: Semantic threat detection
       └─> Results: Severity, threat type, recommendations

6. OUTPUT
   ├─> Session summary JSON
   ├─> LLM analysis JSON
   ├─> Network graph visualization
   └─> High-severity alerts

To run the full system:
    sudo python src/main.py -i eth0 --enable-llm --api-key YOUR_KEY
    """)


def main():
    """Run all examples"""
    examples = [
        ("DNS Analysis", example_1_dns_analysis),
        ("Privacy Masking", example_2_privacy_masking),
        ("Network Graph", example_3_network_graph),
        ("Prompt Engineering", example_4_prompt_engineering),
        ("TLS Fingerprinting", example_5_tls_fingerprinting),
        ("Full Integration", example_6_integration),
    ]
    
    print("\n" + "="*80)
    print("AI-DRIVEN NETWORK OBSERVABILITY AGENT - EXAMPLES")
    print("="*80)
    
    for i, (name, func) in enumerate(examples, 1):
        print(f"\n[{i}] {name}")
    
    print("\n[0] Run all examples")
    print("[Q] Quit")
    
    choice = input("\nSelect example: ").strip().upper()
    
    if choice == 'Q':
        return
    elif choice == '0':
        for name, func in examples:
            func()
            input("\n\nPress Enter to continue...")
    else:
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(examples):
                examples[idx][1]()
            else:
                print("Invalid selection")
        except ValueError:
            print("Invalid selection")


if __name__ == "__main__":
    main()
