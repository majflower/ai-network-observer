#!/usr/bin/env python3
"""
AI-Driven Network Observability Agent - Main Script
Integrates all components into a cohesive monitoring system
"""

import sys
import time
import logging
import argparse
import json
from datetime import datetime, timedelta
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.capture_engine import CaptureEngine
from src.extractors.tls_fingerprint import TLSFingerprinter
from src.extractors.dns_analyzer import DNSAnalyzer
from src.extractors.http_metadata import HTTPMetadataExtractor
from src.intelligence.llm_connector import LLMConnector
from src.privacy.data_masker import DataMasker
from src.graph.network_graph import NetworkGraph

logger = logging.getLogger(__name__)


class NetworkObservabilityAgent:
    """
    Main orchestrator for AI-driven network monitoring
    """
    
    def __init__(self, config: dict):
        """
        Initialize the agent with configuration
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        
        # Initialize components
        logger.info("Initializing Network Observability Agent...")
        
        # Capture
        self.capture_engine = CaptureEngine(
            backend=config.get('capture_backend', 'scapy'),
            performance_mode=config.get('performance_mode', False)
        )
        
        # Extractors
        self.tls_fingerprinter = TLSFingerprinter()
        self.dns_analyzer = DNSAnalyzer(window_size=config.get('dns_window_size', 100))
        self.http_extractor = HTTPMetadataExtractor()
        
        # Intelligence
        self.llm_connector = None
        if config.get('enable_llm', False):
            self.llm_connector = LLMConnector(
                base_url=config.get('ollama_base_url', 'http://192.168.197.1:11434'),
                model=config.get('llm_model', 'llama3.2:latest'),
            )
        
        # Privacy
        self.data_masker = DataMasker(salt=config.get('masking_salt', 'default-salt'))
        
        # Graph
        self.network_graph = NetworkGraph()
        
        # Session management
        self.session_start = datetime.now()
        self.session_duration = timedelta(minutes=config.get('session_duration_minutes', 30))
        
        # Collected data
        self.dns_queries = []
        self.http_requests = []
        self.tls_fingerprints = []
        
        logger.info("Agent initialized successfully")
    
    def packet_handler(self, packet):
        """
        Main packet processing callback
        Called for each captured packet
        """
        try:
            # Process DNS
            dns_result = self.dns_analyzer.analyze_packet(packet)
            if dns_result:
                self.dns_queries.append(dns_result)
                
                # Add to graph
                if dns_result['type'] == 'DNS_QUERY':
                    # Extract src_ip from packet if available
                    src_ip = self._extract_src_ip(packet)
                    if src_ip:
                        self.network_graph.add_dns_query(
                            src_ip,
                            dns_result['domain'],
                            dns_result['features']['timestamp'],
                            {'anomalies': dns_result.get('anomalies', [])}
                        )
            
            # Process TLS
            ja3 = self.tls_fingerprinter.extract_ja3(packet)
            if ja3:
                self.tls_fingerprints.append(ja3)
                
                # Add to graph
                src_ip = self._extract_src_ip(packet)
                dst_ip = self._extract_dst_ip(packet)
                if src_ip and dst_ip:
                    self.network_graph.add_tls_connection(
                        src_ip,
                        dst_ip,
                        ja3.get('sni'),
                        datetime.now(),
                        ja3.get('fingerprint')
                    )
            
            # Process HTTP
            http_result = self.http_extractor.extract(packet)
            if http_result and http_result['type'] == 'HTTP_REQUEST':
                self.http_requests.append(http_result)
                
                # Add to graph
                src_ip = str(http_result.get('src_ip', ''))
                dst_ip = str(http_result.get('dst_ip', ''))
                host = http_result.get('host', '')
                
                if src_ip and dst_ip and host:
                    self.network_graph.add_http_request(
                        src_ip,
                        dst_ip,
                        host,
                        datetime.now(),
                        {'anomalies': http_result.get('anomalies', [])}
                    )
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}", exc_info=True)
    
    def _extract_src_ip(self, packet) -> str:
        """Extract source IP from packet"""
        try:
            from scapy.all import IP
            if packet.haslayer(IP):
                return packet[IP].src
        except:
            pass
        return None
    
    def _extract_dst_ip(self, packet) -> str:
        """Extract destination IP from packet"""
        try:
            from scapy.all import IP
            if packet.haslayer(IP):
                return packet[IP].dst
        except:
            pass
        return None
    
    def should_end_session(self) -> bool:
        """Check if current session should end"""
        elapsed = datetime.now() - self.session_start
        return elapsed >= self.session_duration
    
    def generate_session_summary(self) -> dict:
        """
        Generate comprehensive session summary
        Aggregates data from all analyzers
        """
        logger.info("Generating session summary...")
        
        summary = {
            'session_id': f"session_{self.session_start.strftime('%Y%m%d_%H%M%S')}",
            'start_time': self.session_start.isoformat(),
            'end_time': datetime.now().isoformat(),
            'duration_minutes': (datetime.now() - self.session_start).total_seconds() / 60,
            
            # DNS Analysis
            'dns_analysis': self.dns_analyzer.generate_summary(),
            
            # HTTP Analysis
            'http_analysis': self.http_extractor.generate_summary(self.http_requests),
            
            # TLS Analysis
            'tls_analysis': self._summarize_tls(),
            
            # Graph Analysis
            'graph_analysis': self.network_graph.generate_summary_for_llm(),
            
            # Raw counts
            'total_dns_queries': len(self.dns_queries),
            'total_http_requests': len(self.http_requests),
            'total_tls_sessions': len(self.tls_fingerprints)
        }
        
        return summary
    
    def _summarize_tls(self) -> dict:
        """Summarize TLS fingerprints"""
        unique_ja3 = {}
        unknown_clients = 0
        
        for fp in self.tls_fingerprints:
            ja3_hash = fp.get('fingerprint')
            if ja3_hash:
                if ja3_hash not in unique_ja3:
                    unique_ja3[ja3_hash] = {
                        'hash': ja3_hash,
                        'identified_as': fp.get('identified_as', 'Unknown'),
                        'count': 0,
                        'sni_list': []
                    }
                
                unique_ja3[ja3_hash]['count'] += 1
                
                if fp.get('sni'):
                    unique_ja3[ja3_hash]['sni_list'].append(fp['sni'])
                
                if fp.get('identified_as') == 'Unknown Client':
                    unknown_clients += 1
        
        return {
            'unique_ja3_fingerprints': len(unique_ja3),
            'unknown_clients': unknown_clients,
            'top_fingerprints': sorted(
                unique_ja3.values(),
                key=lambda x: x['count'],
                reverse=True
            )[:10]
        }
    
    def analyze_with_llm(self, session_summary: dict) -> dict:
        """
        Send session summary to LLM for analysis
        Applies privacy masking first
        """
        if not self.llm_connector:
            logger.warning("LLM analysis disabled")
            return {'status': 'disabled'}
        
        logger.info("Applying privacy masking...")
        masked_summary = self.data_masker.mask_session_data(session_summary)
        
        logger.info("Sending to LLM for analysis...")
        llm_analysis = self.llm_connector.analyze_network_session(masked_summary)
        
        return llm_analysis
    
    def save_results(self, session_summary: dict, llm_analysis: dict = None):
        """Save analysis results to files"""
        output_dir = Path(self.config.get('output_dir', './logs'))
        output_dir.mkdir(parents=True, exist_ok=True)
        
        session_id = session_summary['session_id']
        
        # Save session summary
        summary_file = output_dir / f"{session_id}_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(session_summary, f, indent=2, default=str)
        logger.info(f"Session summary saved to {summary_file}")
        
        # Save LLM analysis
        if llm_analysis:
            analysis_file = output_dir / f"{session_id}_llm_analysis.json"
            with open(analysis_file, 'w') as f:
                json.dump(llm_analysis, f, indent=2, default=str)
            logger.info(f"LLM analysis saved to {analysis_file}")
        
        # Export graph
        graph_file = output_dir / f"{session_id}_network_graph.json"
        self.network_graph.export_for_visualization(str(graph_file))
        
        # Generate alerts file if high-severity issues found
        if llm_analysis and llm_analysis.get('analysis', {}).get('severity') in ['CRITICAL', 'HIGH']:
            alert_file = output_dir / f"{session_id}_ALERT.json"
            with open(alert_file, 'w') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'severity': llm_analysis['analysis']['severity'],
                    'threat_type': llm_analysis['analysis'].get('threat_type'),
                    'summary': llm_analysis['analysis'].get('summary'),
                    'recommendations': llm_analysis['analysis'].get('recommendations', [])
                }, f, indent=2)
            logger.warning(f"HIGH-SEVERITY ALERT saved to {alert_file}")
    
    def run(self, interface: str, bpf_filter: str = ""):
        """
        Start the monitoring agent
        
        Args:
            interface: Network interface to monitor
            bpf_filter: BPF filter expression
        """
        logger.info(f"Starting capture on {interface}...")
        logger.info(f"Session duration: {self.session_duration}")
        logger.info(f"LLM analysis: {'enabled' if self.llm_connector else 'disabled'}")
        
        try:
            # Start capture in background thread
            import threading
            
            def capture_thread():
                self.capture_engine.start(interface, self.packet_handler, bpf_filter)
            
            thread = threading.Thread(target=capture_thread, daemon=True)
            thread.start()
            
            # Monitor and analyze periodically
            while True:
                time.sleep(10)  # Check every 10 seconds
                
                if self.should_end_session():
                    logger.info("Session duration reached. Analyzing...")
                    
                    # Stop capture
                    self.capture_engine.stop()
                    
                    # Generate summary
                    session_summary = self.generate_session_summary()
                    
                    # LLM Analysis
                    llm_analysis = None
                    if self.config.get('enable_llm', False):
                        llm_analysis = self.analyze_with_llm(session_summary)
                    
                    # Save results
                    self.save_results(session_summary, llm_analysis)
                    
                    # Print summary
                    self._print_summary(session_summary, llm_analysis)
                    
                    # Reset for next session
                    self._reset_session()
                    
                    # Restart capture
                    thread = threading.Thread(target=capture_thread, daemon=True)
                    thread.start()
        
        except KeyboardInterrupt:
            logger.info("\nStopping agent...")
            self.capture_engine.stop()
            
            # Final analysis
            if self.dns_queries or self.http_requests or self.tls_fingerprints:
                logger.info("Performing final analysis...")
                session_summary = self.generate_session_summary()
                llm_analysis = None
                if self.config.get('enable_llm', False):
                    llm_analysis = self.analyze_with_llm(session_summary)
                self.save_results(session_summary, llm_analysis)
                self._print_summary(session_summary, llm_analysis)
    
    def _reset_session(self):
        """Reset session data for next session"""
        self.session_start = datetime.now()
        self.dns_queries = []
        self.http_requests = []
        self.tls_fingerprints = []
        self.network_graph = NetworkGraph()
    
    def _print_summary(self, session_summary: dict, llm_analysis: dict = None):
        """Print human-readable summary to console"""
        print("\n" + "=" * 80)
        print(f"SESSION SUMMARY: {session_summary['session_id']}")
        print("=" * 80)
        
        print(f"\nDuration: {session_summary['duration_minutes']:.1f} minutes")
        print(f"DNS Queries: {session_summary['total_dns_queries']}")
        print(f"HTTP Requests: {session_summary['total_http_requests']}")
        print(f"TLS Sessions: {session_summary['total_tls_sessions']}")
        
        # DNS highlights
        dns = session_summary.get('dns_analysis', {})
        if dns.get('summary', {}).get('high_risk_count', 0) > 0:
            print(f"\n⚠️  HIGH RISK DNS: {dns['summary']['high_risk_count']} suspicious domains detected")
        
        # HTTP highlights
        http = session_summary.get('http_analysis', {})
        if http.get('high_risk_requests'):
            print(f"⚠️  HIGH RISK HTTP: {len(http['high_risk_requests'])} suspicious requests detected")
        
        # Graph anomalies
        graph = session_summary.get('graph_analysis', {})
        anomaly_count = sum(graph.get('unusual_patterns', {}).values())
        if anomaly_count > 0:
            print(f"⚠️  GRAPH ANOMALIES: {anomaly_count} unusual patterns detected")
        
        # LLM Analysis
        if llm_analysis and 'analysis' in llm_analysis:
            analysis = llm_analysis['analysis']
            print(f"\n{'=' * 80}")
            print("AI ANALYSIS")
            print("=" * 80)
            print(f"Severity: {analysis.get('severity', 'UNKNOWN')}")
            print(f"Threat Type: {analysis.get('threat_type', 'UNKNOWN')}")
            print(f"Confidence: {analysis.get('confidence', 0)}%")
            print(f"\nSummary: {analysis.get('summary', 'N/A')}")
            
            if analysis.get('recommendations'):
                print("\nRecommendations:")
                for i, rec in enumerate(analysis['recommendations'], 1):
                    print(f"  {i}. {rec}")
        
        print("\n" + "=" * 80 + "\n")


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description='AI-Driven Network Observability Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic monitoring on eth0
  sudo python main.py -i eth0
  
  # With LLM analysis (requires API key)
  sudo python main.py -i eth0 --enable-llm --api-key YOUR_KEY
  
  # Performance mode with eBPF
  sudo python main.py -i eth0 --performance-mode
  
  # Custom session duration and filter
  sudo python main.py -i eth0 --duration 60 --filter "tcp port 443"
        """
    )
    
    parser.add_argument('-i', '--interface', required=True,
                       help='Network interface to monitor (e.g., eth0, wlan0)')
    
    parser.add_argument('--duration', type=int, default=30,
                       help='Session duration in minutes (default: 30)')
    
    parser.add_argument('--filter', default='',
                       help='BPF filter expression (e.g., "tcp port 80 or tcp port 443")')
    
    parser.add_argument('--enable-llm', action='store_true',
                       help='Enable LLM-based anomaly analysis')
    
    parser.add_argument('--api-key',
                       help='Anthropic API key (or set ANTHROPIC_API_KEY env var)')
    
    parser.add_argument('--performance-mode', action='store_true',
                       help='Use eBPF for high-performance capture')
    
    parser.add_argument('--output-dir', default='./logs',
                       help='Directory for output files')
    
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Build configuration
    config = {
        'capture_backend': 'ebpf' if args.performance_mode else 'scapy',
        'performance_mode': args.performance_mode,
        'session_duration_minutes': args.duration,
        'enable_llm': args.enable_llm,
        'anthropic_api_key': args.api_key,
        'output_dir': args.output_dir
    }
    
    # Create and run agent
    try:
        agent = NetworkObservabilityAgent(config)
        agent.run(args.interface, args.filter)
    except PermissionError:
        logger.error("Permission denied. Run with sudo for packet capture.")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Shutting down gracefully...")
        sys.exit(0)


if __name__ == "__main__":
    main()
