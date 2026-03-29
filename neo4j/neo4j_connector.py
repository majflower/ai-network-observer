#!/usr/bin/env python3
"""
Neo4j Graph Database Connector
Stores network relationships in Neo4j for advanced graph analysis
"""

from neo4j import GraphDatabase
import logging
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class Neo4jConnector:
    """
    Connect to Neo4j for persistent network graph storage
    """
    
    def __init__(self, uri="bolt://neo4j:7687", user="neo4j", password="networksecurity"):
        """
        Initialize Neo4j connector
        
        Args:
            uri: Neo4j bolt URI
            user: Neo4j username
            password: Neo4j password
        """
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            self._test_connection()
            self._create_indexes()
            logger.info(f"✓ Connected to Neo4j at {uri}")
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            self.driver = None
    
    def _test_connection(self):
        """Test Neo4j connection"""
        with self.driver.session() as session:
            result = session.run("RETURN 1 as test")
            assert result.single()['test'] == 1
    
    def _create_indexes(self):
        """Create necessary indexes and constraints"""
        with self.driver.session() as session:
            # Constraints
            session.run("""
                CREATE CONSTRAINT ip_unique IF NOT EXISTS 
                FOR (ip:IPAddress) REQUIRE ip.address IS UNIQUE
            """)
            
            session.run("""
                CREATE CONSTRAINT domain_unique IF NOT EXISTS 
                FOR (d:Domain) REQUIRE d.name IS UNIQUE
            """)
            
            # Indexes for performance
            session.run("""
                CREATE INDEX ip_risk IF NOT EXISTS 
                FOR (ip:IPAddress) ON (ip.risk_score)
            """)
            
            session.run("""
                CREATE INDEX domain_risk IF NOT EXISTS 
                FOR (d:Domain) ON (d.risk_score)
            """)
            
            logger.info("Neo4j indexes and constraints created")
    
    def add_dns_query(self, src_ip: str, domain: str, timestamp: datetime, 
                      risk_score: int = 0, anomalies: List[str] = None):
        """Add DNS query to graph"""
        if not self.driver:
            return
        
        with self.driver.session() as session:
            session.run("""
                MERGE (ip:IPAddress {address: $src_ip})
                ON CREATE SET ip.first_seen = $timestamp, ip.type = 'internal'
                ON MATCH SET ip.last_seen = $timestamp
                SET ip.risk_score = CASE WHEN $risk_score > coalesce(ip.risk_score, 0) 
                                         THEN $risk_score ELSE ip.risk_score END
                
                MERGE (d:Domain {name: $domain})
                ON CREATE SET d.first_seen = $timestamp
                ON MATCH SET d.last_seen = $timestamp
                SET d.risk_score = $risk_score,
                    d.anomalies = $anomalies
                
                MERGE (ip)-[r:QUERIED]->(d)
                ON CREATE SET r.first_seen = $timestamp, r.count = 1
                ON MATCH SET r.last_seen = $timestamp, r.count = r.count + 1
            """, src_ip=src_ip, domain=domain, timestamp=timestamp.isoformat(),
                risk_score=risk_score, anomalies=anomalies or [])
    
    def add_http_connection(self, src_ip: str, dst_ip: str, host: str,
                           timestamp: datetime, method: str = "GET"):
        """Add HTTP connection to graph"""
        if not self.driver:
            return
        
        with self.driver.session() as session:
            session.run("""
                MERGE (src:IPAddress {address: $src_ip})
                ON CREATE SET src.first_seen = $timestamp, src.type = 'internal'
                ON MATCH SET src.last_seen = $timestamp
                
                MERGE (dst:IPAddress {address: $dst_ip})
                ON CREATE SET dst.first_seen = $timestamp, dst.type = 'external'
                ON MATCH SET dst.last_seen = $timestamp
                
                MERGE (src)-[r:HTTP_REQUEST]->(dst)
                ON CREATE SET r.first_seen = $timestamp, r.count = 1, r.method = $method
                ON MATCH SET r.last_seen = $timestamp, r.count = r.count + 1
                
                MERGE (d:Domain {name: $host})
                ON CREATE SET d.first_seen = $timestamp
                MERGE (src)-[:ACCESSED]->(d)
            """, src_ip=src_ip, dst_ip=dst_ip, host=host, 
                timestamp=timestamp.isoformat(), method=method)
    
    def add_tls_connection(self, src_ip: str, dst_ip: str, sni: str,
                          timestamp: datetime, ja3_hash: str = None):
        """Add TLS connection to graph"""
        if not self.driver:
            return
        
        with self.driver.session() as session:
            session.run("""
                MERGE (src:IPAddress {address: $src_ip})
                ON CREATE SET src.first_seen = $timestamp
                ON MATCH SET src.last_seen = $timestamp
                
                MERGE (dst:IPAddress {address: $dst_ip})
                ON CREATE SET dst.first_seen = $timestamp
                ON MATCH SET dst.last_seen = $timestamp
                
                MERGE (src)-[r:TLS_CONNECTION]->(dst)
                ON CREATE SET r.first_seen = $timestamp, r.ja3_hash = $ja3_hash
                ON MATCH SET r.last_seen = $timestamp, 
                             r.connection_count = coalesce(r.connection_count, 0) + 1
                SET r.sni = $sni
            """, src_ip=src_ip, dst_ip=dst_ip, sni=sni, 
                timestamp=timestamp.isoformat(), ja3_hash=ja3_hash)
    
    def get_network_stats(self) -> Dict:
        """Get overall network statistics"""
        if not self.driver:
            return {}
        
        with self.driver.session() as session:
            result = session.run("""
                MATCH (ip:IPAddress)
                WITH count(ip) as total_ips, avg(ip.risk_score) as avg_ip_risk
                MATCH (d:Domain)
                WITH total_ips, avg_ip_risk, count(d) as total_domains
                MATCH ()-[r]->()
                RETURN total_ips, total_domains, count(r) as total_connections, avg_ip_risk
            """)
            
            record = result.single()
            if record:
                return {
                    'total_ips': record['total_ips'],
                    'total_domains': record['total_domains'],
                    'total_connections': record['total_connections'],
                    'avg_ip_risk': float(record['avg_ip_risk'] or 0)
                }
        
        return {}
    
    def find_anomalies(self) -> Dict:
        """Find network anomalies using graph patterns"""
        if not self.driver:
            return {}
        
        anomalies = {
            'hubs': [],
            'shared_c2': [],
            'isolated_nodes': [],
            'beaconing': []
        }
        
        with self.driver.session() as session:
            # Find hub nodes
            result = session.run("""
                MATCH (ip:IPAddress)
                WITH ip, size((ip)-[:QUERIED]->()) + size((ip)-[:HTTP_REQUEST]->()) as conn_count
                WHERE conn_count > 50
                RETURN ip.address as address, conn_count, ip.risk_score as risk_score
                ORDER BY conn_count DESC
                LIMIT 10
            """)
            anomalies['hubs'] = [dict(r) for r in result]
            
            # Find potential shared C2
            result = session.run("""
                MATCH (ip:IPAddress)-[:QUERIED]->(d:Domain)
                WITH d, count(DISTINCT ip) as ip_count, collect(DISTINCT ip.address) as ips
                WHERE ip_count > 5
                RETURN d.name as domain, ip_count, d.risk_score as risk_score
                ORDER BY ip_count DESC
                LIMIT 10
            """)
            anomalies['shared_c2'] = [dict(r) for r in result]
            
            # Find isolated nodes
            result = session.run("""
                MATCH (ip:IPAddress)
                WITH ip, size((ip)-[]-()) as total_conn
                WHERE total_conn > 0 AND total_conn <= 3
                RETURN ip.address as address, total_conn as connections, 
                       ip.risk_score as risk_score
                ORDER BY risk_score DESC
                LIMIT 10
            """)
            anomalies['isolated_nodes'] = [dict(r) for r in result]
        
        return anomalies
    
    def get_high_risk_entities(self, min_risk: int = 70) -> Dict:
        """Get high-risk IPs and domains"""
        if not self.driver:
            return {}
        
        entities = {'ips': [], 'domains': []}
        
        with self.driver.session() as session:
            # High-risk IPs
            result = session.run("""
                MATCH (ip:IPAddress)
                WHERE ip.risk_score >= $min_risk
                RETURN ip.address as address, ip.risk_score as risk_score
                ORDER BY risk_score DESC
                LIMIT 20
            """, min_risk=min_risk)
            entities['ips'] = [dict(r) for r in result]
            
            # High-risk domains
            result = session.run("""
                MATCH (d:Domain)
                WHERE d.risk_score >= $min_risk
                RETURN d.name as domain, d.risk_score as risk_score, d.anomalies as anomalies
                ORDER BY risk_score DESC
                LIMIT 20
            """, min_risk=min_risk)
            entities['domains'] = [dict(r) for r in result]
        
        return entities
    
    def cleanup_old_data(self, days: int = 7):
        """Remove data older than specified days"""
        if not self.driver:
            return
        
        with self.driver.session() as session:
            result = session.run("""
                MATCH (n)
                WHERE datetime(n.last_seen) < datetime() - duration({days: $days})
                DETACH DELETE n
                RETURN count(n) as deleted_count
            """, days=days)
            
            deleted = result.single()['deleted_count']
            logger.info(f"Cleaned up {deleted} old nodes from Neo4j")
    
    def close(self):
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed")


if __name__ == "__main__":
    # Test Neo4j connector
    logging.basicConfig(level=logging.INFO)
    
    neo4j = Neo4jConnector()
    
    # Test data insertion
    print("\nAdding test data...")
    neo4j.add_dns_query("192.168.1.100", "google.com", datetime.now(), risk_score=10)
    neo4j.add_dns_query("192.168.1.100", "suspicious.malware.com", datetime.now(), 
                       risk_score=85, anomalies=["HIGH_ENTROPY", "DGA"])
    
    # Get stats
    print("\nNetwork Statistics:")
    stats = neo4j.get_network_stats()
    print(f"  IPs: {stats.get('total_ips')}")
    print(f"  Domains: {stats.get('total_domains')}")
    print(f"  Connections: {stats.get('total_connections')}")
    
    # Find anomalies
    print("\nDetected Anomalies:")
    anomalies = neo4j.find_anomalies()
    print(f"  Hubs: {len(anomalies['hubs'])}")
    print(f"  Potential C2: {len(anomalies['shared_c2'])}")
    
    neo4j.close()