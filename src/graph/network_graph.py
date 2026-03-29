#!/usr/bin/env python3
"""
Network Relationship Graph - Visualize and analyze communication patterns
Detects unusual relationships between network entities
"""

import networkx as nx
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict
from datetime import datetime
import logging
import json

logger = logging.getLogger(__name__)


class NetworkGraph:
    """
    Build and analyze graph of network relationships
    Nodes: IPs, domains, services
    Edges: Communication flows with metadata
    """
    
    def __init__(self):
        self.graph = nx.MultiDiGraph()  # Directed graph with multiple edges
        self.baseline_graph = None  # For anomaly detection
        
        # Track entity types
        self.entity_types = defaultdict(set)  # type -> set of entities
        
        # Communication patterns
        self.flows = []  # List of all flows for analysis
        
        # Baseline statistics
        self.baseline_stats = {}
    
    def add_dns_query(self, src_ip: str, domain: str, timestamp: datetime, metadata: Dict = None):
        """Add DNS query to graph"""
        
        # Add nodes
        self.graph.add_node(src_ip, type='ip', first_seen=timestamp)
        self.graph.add_node(domain, type='domain', first_seen=timestamp)
        
        # Track types
        self.entity_types['ip'].add(src_ip)
        self.entity_types['domain'].add(domain)
        
        # Add edge with metadata
        edge_data = {
            'timestamp': timestamp,
            'protocol': 'DNS',
            'query_count': 1,
            **(metadata or {})
        }
        
        # Check if edge exists and update
        if self.graph.has_edge(src_ip, domain):
            # Increment query count
            for key in self.graph[src_ip][domain]:
                self.graph[src_ip][domain][key]['query_count'] += 1
        else:
            self.graph.add_edge(src_ip, domain, **edge_data)
        
        # Store flow
        self.flows.append({
            'src': src_ip,
            'dst': domain,
            'timestamp': timestamp,
            'type': 'DNS',
            **edge_data
        })
    
    def add_http_request(self, src_ip: str, dst_ip: str, host: str, 
                        timestamp: datetime, metadata: Dict = None):
        """Add HTTP request to graph"""
        
        # Add nodes
        self.graph.add_node(src_ip, type='ip', first_seen=timestamp)
        self.graph.add_node(dst_ip, type='ip', first_seen=timestamp)
        self.graph.add_node(host, type='domain', first_seen=timestamp)
        
        # Track types
        self.entity_types['ip'].add(src_ip)
        self.entity_types['ip'].add(dst_ip)
        self.entity_types['domain'].add(host)
        
        # Add edges
        edge_data = {
            'timestamp': timestamp,
            'protocol': 'HTTP',
            'request_count': 1,
            **(metadata or {})
        }
        
        # src_ip -> dst_ip
        if self.graph.has_edge(src_ip, dst_ip):
            for key in self.graph[src_ip][dst_ip]:
                self.graph[src_ip][dst_ip][key]['request_count'] += 1
        else:
            self.graph.add_edge(src_ip, dst_ip, **edge_data)
        
        # Also link to domain
        if not self.graph.has_edge(src_ip, host):
            self.graph.add_edge(src_ip, host, **edge_data)
        
        self.flows.append({
            'src': src_ip,
            'dst': dst_ip,
            'host': host,
            'timestamp': timestamp,
            'type': 'HTTP',
            **edge_data
        })
    
    def add_tls_connection(self, src_ip: str, dst_ip: str, sni: str,
                          timestamp: datetime, ja3_hash: str = None):
        """Add TLS connection to graph"""
        
        # Add nodes
        self.graph.add_node(src_ip, type='ip', first_seen=timestamp)
        self.graph.add_node(dst_ip, type='ip', first_seen=timestamp)
        
        if sni:
            self.graph.add_node(sni, type='domain', first_seen=timestamp)
            self.entity_types['domain'].add(sni)
        
        self.entity_types['ip'].add(src_ip)
        self.entity_types['ip'].add(dst_ip)
        
        # Add edge
        edge_data = {
            'timestamp': timestamp,
            'protocol': 'TLS',
            'ja3_hash': ja3_hash,
            'sni': sni,
            'connection_count': 1
        }
        
        self.graph.add_edge(src_ip, dst_ip, **edge_data)
        
        if sni:
            self.graph.add_edge(src_ip, sni, **edge_data)
    
    def detect_anomalies(self) -> List[Dict]:
        """
        Detect unusual network patterns using graph analysis
        
        Returns list of anomalies with descriptions
        """
        anomalies = []
        
        # 1. Isolated or poorly connected nodes (potential command & control)
        anomalies.extend(self._detect_isolated_nodes())
        
        # 2. Hub nodes (nodes with unusually high degree)
        anomalies.extend(self._detect_hub_nodes())
        
        # 3. Unusual communication patterns
        anomalies.extend(self._detect_unusual_patterns())
        
        # 4. New or rare connections
        if self.baseline_graph:
            anomalies.extend(self._detect_new_connections())
        
        # 5. Cliques (tightly connected groups - potential coordinated activity)
        anomalies.extend(self._detect_cliques())
        
        return anomalies
    
    def _detect_isolated_nodes(self) -> List[Dict]:
        """Find nodes with very few connections (potential C2)"""
        anomalies = []
        
        for node in self.graph.nodes():
            in_degree = self.graph.in_degree(node)
            out_degree = self.graph.out_degree(node)
            total_degree = in_degree + out_degree
            
            # Low degree but persistent over time
            if total_degree <= 2 and total_degree > 0:
                edges = list(self.graph.in_edges(node)) + list(self.graph.out_edges(node))
                
                # Check if connections are persistent
                is_persistent = len(edges) > 0
                
                if is_persistent:
                    anomalies.append({
                        'type': 'ISOLATED_NODE',
                        'node': node,
                        'degree': total_degree,
                        'description': f'Low connectivity node {node} - potential C2 endpoint',
                        'severity': 'MEDIUM'
                    })
        
        return anomalies
    
    def _detect_hub_nodes(self) -> List[Dict]:
        """Find nodes with unusually high connectivity"""
        anomalies = []
        
        # Calculate degree distribution
        degrees = [self.graph.degree(n) for n in self.graph.nodes()]
        
        if not degrees:
            return anomalies
        
        mean_degree = sum(degrees) / len(degrees)
        
        # Find outliers (3+ standard deviations)
        import math
        variance = sum((d - mean_degree) ** 2 for d in degrees) / len(degrees)
        std_dev = math.sqrt(variance)
        threshold = mean_degree + (3 * std_dev)
        
        for node in self.graph.nodes():
            degree = self.graph.degree(node)
            
            if degree > threshold and degree > 10:  # Minimum threshold
                anomalies.append({
                    'type': 'HUB_NODE',
                    'node': node,
                    'degree': degree,
                    'mean_degree': round(mean_degree, 2),
                    'description': f'Unusually high connectivity for {node} - potential scanner or data exfiltration target',
                    'severity': 'HIGH' if degree > threshold * 2 else 'MEDIUM'
                })
        
        return anomalies
    
    def _detect_unusual_patterns(self) -> List[Dict]:
        """Detect unusual communication patterns"""
        anomalies = []
        
        # Pattern 1: Domain contacted by many different IPs (potential DGA/C2)
        domain_sources = defaultdict(set)
        
        for src, dst in self.graph.edges():
            if self.graph.nodes[dst].get('type') == 'domain':
                if self.graph.nodes[src].get('type') == 'ip':
                    domain_sources[dst].add(src)
        
        for domain, sources in domain_sources.items():
            if len(sources) > 5:  # Threshold
                anomalies.append({
                    'type': 'MULTIPLE_SOURCE_DOMAIN',
                    'domain': domain,
                    'source_count': len(sources),
                    'description': f'Domain {domain} contacted by {len(sources)} different IPs - potential shared C2 or compromised infrastructure',
                    'severity': 'HIGH'
                })
        
        # Pattern 2: IP communicating with many domains (potential data exfiltration)
        ip_destinations = defaultdict(set)
        
        for src, dst in self.graph.edges():
            if self.graph.nodes[src].get('type') == 'ip':
                if self.graph.nodes[dst].get('type') == 'domain':
                    ip_destinations[src].add(dst)
        
        for ip, destinations in ip_destinations.items():
            if len(destinations) > 50:  # Threshold
                anomalies.append({
                    'type': 'EXCESSIVE_DESTINATIONS',
                    'ip': ip,
                    'destination_count': len(destinations),
                    'description': f'IP {ip} contacted {len(destinations)} different domains - potential scanning or exfiltration',
                    'severity': 'MEDIUM'
                })
        
        return anomalies
    
    def _detect_new_connections(self) -> List[Dict]:
        """Compare current graph to baseline to find new connections"""
        anomalies = []
        
        if not self.baseline_graph:
            return anomalies
        
        current_edges = set(self.graph.edges())
        baseline_edges = set(self.baseline_graph.edges())
        
        new_edges = current_edges - baseline_edges
        
        for src, dst in new_edges:
            # Only flag as anomaly if both nodes existed in baseline
            if (self.baseline_graph.has_node(src) and 
                self.baseline_graph.has_node(dst)):
                
                anomalies.append({
                    'type': 'NEW_CONNECTION',
                    'src': src,
                    'dst': dst,
                    'description': f'New connection between known entities: {src} -> {dst}',
                    'severity': 'LOW'
                })
        
        return anomalies
    
    def _detect_cliques(self) -> List[Dict]:
        """Find tightly connected groups (potential coordinated activity)"""
        anomalies = []
        
        # Convert to undirected for clique detection
        undirected = self.graph.to_undirected()
        
        # Find cliques of size 4+
        cliques = list(nx.find_cliques(undirected))
        large_cliques = [c for c in cliques if len(c) >= 4]
        
        for clique in large_cliques:
            anomalies.append({
                'type': 'CLIQUE',
                'nodes': clique,
                'size': len(clique),
                'description': f'Tightly connected group of {len(clique)} entities - potential coordinated activity',
                'severity': 'MEDIUM'
            })
        
        return anomalies
    
    def calculate_centrality_metrics(self) -> Dict:
        """
        Calculate importance metrics for nodes
        Useful for identifying critical infrastructure or targets
        """
        metrics = {}
        
        # Degree centrality
        metrics['degree_centrality'] = nx.degree_centrality(self.graph)
        
        # Betweenness centrality (nodes that bridge communities)
        metrics['betweenness_centrality'] = nx.betweenness_centrality(self.graph)
        
        # PageRank (importance based on connections)
        metrics['pagerank'] = nx.pagerank(self.graph)
        
        # Find top nodes for each metric
        top_k = 10
        
        metrics['top_by_degree'] = sorted(
            metrics['degree_centrality'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:top_k]
        
        metrics['top_by_betweenness'] = sorted(
            metrics['betweenness_centrality'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:top_k]
        
        metrics['top_by_pagerank'] = sorted(
            metrics['pagerank'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:top_k]
        
        return metrics
    
    def export_for_visualization(self, filename: str = "network_graph.json"):
        """
        Export graph in format suitable for visualization (D3.js, Cytoscape, etc.)
        """
        # Convert to node-link format
        data = nx.node_link_data(self.graph)
        
        # Add additional metadata
        data['metadata'] = {
            'node_count': self.graph.number_of_nodes(),
            'edge_count': self.graph.number_of_edges(),
            'entity_types': {k: len(v) for k, v in self.entity_types.items()},
            'generated_at': datetime.now().isoformat()
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        logger.info(f"Graph exported to {filename}")
        return filename
    
    def generate_summary_for_llm(self) -> Dict[str, Any]:
        """
        Generate network graph summary for LLM analysis
        FIX: Handle empty/null graph case
        """
        # Check if graph is empty BEFORE calling NetworkX functions
        if self.graph.number_of_nodes() == 0:
            logger.warning("Network graph is empty - no connections to analyze")
            return {
                'total_nodes': 0,
                'total_edges': 0,
                'node_types': {},
                'is_connected': False,
                'num_components': 0,
                'avg_degree': 0.0,
                'max_degree': 0,
                'density': 0.0,
                'unusual_patterns': [],
                'message': 'No network activity captured in this session'
            }
        
        # Count nodes by type
        node_types = {}
        for node, data in self.graph.nodes(data=True):
            node_type = data.get('type', 'unknown')
            node_types[node_type] = node_types.get(node_type, 0) + 1
        
        # Calculate metrics
        degrees = [d for n, d in self.graph.degree()]
        avg_degree = sum(degrees) / len(degrees) if degrees else 0
        max_degree = max(degrees) if degrees else 0
        
        # Density
        density = nx.density(self.graph)
        
        # Connectivity (safe for non-empty directed graphs)
        try:
            is_connected = nx.is_weakly_connected(self.graph)
            num_components = nx.number_weakly_connected_components(self.graph)
        except:
            is_connected = False
            num_components = 1
        
        # Detect unusual patterns
        unusual_patterns = self.detect_anomalies()
        
        return {
            'total_nodes': self.graph.number_of_nodes(),
            'total_edges': self.graph.number_of_edges(),
            'node_types': node_types,
            'is_connected': is_connected,
            'num_components': num_components,
            'avg_degree': round(avg_degree, 2),
            'max_degree': max_degree,
            'density': round(density, 4),
            'unusual_patterns': unusual_patterns
        }


if __name__ == "__main__":
    # Test network graph
    logging.basicConfig(level=logging.INFO)
    
    graph = NetworkGraph()
    
    # Simulate network activity
    now = datetime.now()
    
    # Normal traffic
    graph.add_dns_query("192.168.1.100", "google.com", now)
    graph.add_dns_query("192.168.1.100", "facebook.com", now)
    graph.add_http_request("192.168.1.100", "172.217.14.206", "google.com", now)
    
    # Suspicious: One IP querying many DGA-like domains (potential C2)
    for i in range(20):
        domain = f"afjk{i}l3k.malware.com"
        graph.add_dns_query("192.168.1.101", domain, now)
    
    # Suspicious: One domain contacted by many IPs (potential shared C2)
    for i in range(10):
        ip = f"192.168.1.{200 + i}"
        graph.add_dns_query(ip, "c2server.evil.com", now)
    
    # Analyze
    anomalies = graph.detect_anomalies()
    
    print("\nDetected Anomalies:")
    print("=" * 80)
    for anomaly in anomalies:
        print(f"\n[{anomaly['severity']}] {anomaly['type']}")
        print(f"  {anomaly['description']}")
    
    # Generate summary
    summary = graph.generate_summary_for_llm()
    print("\n\nGraph Summary:")
    print("=" * 80)
    print(json.dumps(summary, indent=2, default=str))
    
    # Export
    graph.export_for_visualization("/tmp/test_network_graph.json")