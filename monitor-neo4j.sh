#!/bin/bash
# Monitoring Neo4j en CLI

echo "=== NEO4J GRAPH ANALYSIS ==="
echo ""

# Node count
echo "Graph Statistics:"
docker exec network-graph-db cypher-shell -u neo4j -p networksecurity \
  "MATCH (n) RETURN count(n) as total_nodes;" --format plain

# Edges count
docker exec network-graph-db cypher-shell -u neo4j -p networksecurity \
  "MATCH ()-[r]->() RETURN count(r) as total_edges;" --format plain

# Top domains
echo ""
echo "Top 5 Most Contacted Domains:"
docker exec network-graph-db cypher-shell -u neo4j -p networksecurity \
  "MATCH (ip:IPAddress)-[r:QUERIED]->(d:Domain) 
   RETURN d.name as domain, count(r) as queries 
   ORDER BY queries DESC LIMIT 5;" --format plain

# High risk entities
echo ""
echo "High Risk Entities:"
docker exec network-graph-db cypher-shell -u neo4j -p networksecurity \
  "MATCH (n) WHERE n.risk_score > 70 
   RETURN labels(n)[0] as type, 
          CASE WHEN n.address IS NOT NULL THEN n.address ELSE n.name END as identifier,
          n.risk_score as risk 
   ORDER BY risk DESC;" --format plain
