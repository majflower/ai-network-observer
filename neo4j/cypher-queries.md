# Neo4j Cypher Queries for Network Security Analysis

## 1. CRÉATION DU SCHEMA

# Créer les contraintes et index
CREATE CONSTRAINT ip_unique IF NOT EXISTS FOR (ip:IPAddress) REQUIRE ip.address IS UNIQUE;
CREATE CONSTRAINT domain_unique IF NOT EXISTS FOR (domain:Domain) REQUIRE domain.name IS UNIQUE;
CREATE INDEX ip_risk IF NOT EXISTS FOR (ip:IPAddress) ON (ip.risk_score);
CREATE INDEX domain_risk IF NOT EXISTS FOR (domain:Domain) ON (domain.risk_score);
CREATE INDEX connection_time IF NOT EXISTS FOR ()-[c:CONNECTED_TO]-() ON (c.timestamp);

## 2. INSERTION DES DONNÉES

# Créer un nœud IP
MERGE (ip:IPAddress {address: $ip_address})
SET ip.first_seen = $timestamp,
    ip.last_seen = $timestamp,
    ip.type = $ip_type,
    ip.risk_score = $risk_score,
    ip.country = $country

# Créer un nœud Domain
MERGE (d:Domain {name: $domain_name})
SET d.first_seen = $timestamp,
    d.last_seen = $timestamp,
    d.risk_score = $risk_score,
    d.entropy = $entropy,
    d.is_dga = $is_dga

# Créer une connexion DNS
MATCH (ip:IPAddress {address: $src_ip})
MATCH (d:Domain {name: $domain})
MERGE (ip)-[r:QUERIED]->(d)
ON CREATE SET r.first_seen = $timestamp, r.count = 1
ON MATCH SET r.last_seen = $timestamp, r.count = r.count + 1
SET r.query_type = $query_type

# Créer une connexion HTTP
MATCH (src:IPAddress {address: $src_ip})
MATCH (dst:IPAddress {address: $dst_ip})
MERGE (src)-[r:HTTP_REQUEST]->(dst)
ON CREATE SET r.first_seen = $timestamp, r.count = 1, r.method = $method
ON MATCH SET r.last_seen = $timestamp, r.count = r.count + 1

# Créer une connexion TLS
MATCH (src:IPAddress {address: $src_ip})
MATCH (dst:IPAddress {address: $dst_ip})
MERGE (src)-[r:TLS_CONNECTION]->(dst)
ON CREATE SET r.first_seen = $timestamp, r.ja3_hash = $ja3_hash
ON MATCH SET r.last_seen = $timestamp, r.connection_count = coalesce(r.connection_count, 0) + 1
SET r.sni = $sni

## 3. DÉTECTION D'ANOMALIES

# Trouver les hubs (IPs avec beaucoup de connexions)
MATCH (ip:IPAddress)
WITH ip, size((ip)-[:QUERIED]->()) + size((ip)-[:HTTP_REQUEST]->()) as connection_count
WHERE connection_count > 50
RETURN ip.address, connection_count, ip.risk_score
ORDER BY connection_count DESC
LIMIT 20

# Trouver les domaines contactés par plusieurs IPs (potentiel C2)
MATCH (ip:IPAddress)-[:QUERIED]->(d:Domain)
WITH d, collect(DISTINCT ip.address) as ips, count(DISTINCT ip) as ip_count
WHERE ip_count > 5
RETURN d.name, ip_count, ips, d.risk_score
ORDER BY ip_count DESC
LIMIT 20

# Trouver les patterns de beaconing (connexions régulières)
MATCH (ip:IPAddress)-[r:QUERIED]->(d:Domain)
WHERE r.count > 10 
  AND duration.between(datetime(r.first_seen), datetime(r.last_seen)).minutes > 5
WITH ip, d, r, 
     r.count as query_count,
     duration.between(datetime(r.first_seen), datetime(r.last_seen)).minutes as duration_minutes,
     r.count / duration.between(datetime(r.first_seen), datetime(r.last_seen)).minutes as queries_per_minute
WHERE queries_per_minute > 0.1 AND queries_per_minute < 2
RETURN ip.address, d.name, query_count, duration_minutes, queries_per_minute
ORDER BY queries_per_minute DESC

# Trouver les IPs isolées (potentiel C2 endpoint)
MATCH (ip:IPAddress)
WITH ip, 
     size((ip)-[:QUERIED]->()) + size((ip)-[:HTTP_REQUEST]->()) + size((ip)-[:TLS_CONNECTION]->()) as total_connections
WHERE total_connections > 0 AND total_connections <= 3
RETURN ip.address, total_connections, ip.risk_score
ORDER BY ip.risk_score DESC

# Détecter les clusters/communautés suspectes
CALL gds.louvain.stream('network-graph')
YIELD nodeId, communityId
WITH communityId, collect(nodeId) as nodes
WHERE size(nodes) >= 3 AND size(nodes) <= 10
RETURN communityId, size(nodes) as cluster_size, nodes
ORDER BY cluster_size DESC

## 4. ANALYSE TEMPORELLE

# Activité par heure
MATCH (ip)-[r]->(d)
WITH datetime(r.timestamp).hour as hour, count(*) as activity_count
RETURN hour, activity_count
ORDER BY hour

# Nouvelles connexions dans les dernières 24h
MATCH (ip:IPAddress)-[r]->(target)
WHERE datetime(r.first_seen) > datetime() - duration({hours: 24})
RETURN ip.address, type(r) as connection_type, 
       CASE 
         WHEN target:Domain THEN target.name
         WHEN target:IPAddress THEN target.address
       END as target,
       r.first_seen
ORDER BY r.first_seen DESC
LIMIT 100

## 5. REQUÊTES DE VISUALISATION POUR GRAFANA

# Top 10 domaines à risque
MATCH (d:Domain)
WHERE d.risk_score > 50
RETURN d.name as domain, d.risk_score as risk_score, d.entropy as entropy
ORDER BY d.risk_score DESC
LIMIT 10

# Graphe des connexions suspectes
MATCH path = (ip:IPAddress)-[r]->(target)
WHERE ip.risk_score > 50 OR (target:Domain AND target.risk_score > 50)
RETURN path
LIMIT 100

# Statistiques globales
MATCH (ip:IPAddress)
WITH count(ip) as total_ips, 
     avg(ip.risk_score) as avg_risk,
     max(ip.risk_score) as max_risk
MATCH (d:Domain)
WITH total_ips, avg_risk, max_risk,
     count(d) as total_domains,
     avg(d.risk_score) as avg_domain_risk
MATCH ()-[r]->()
RETURN total_ips, total_domains, count(r) as total_connections,
       avg_risk, max_risk, avg_domain_risk

## 6. NETTOYAGE ET MAINTENANCE

# Supprimer les anciennes données (>7 jours)
MATCH (n)
WHERE datetime(n.last_seen) < datetime() - duration({days: 7})
DETACH DELETE n

# Supprimer les nœuds à faible risque et peu d'activité
MATCH (n)
WHERE n.risk_score < 20 
  AND size((n)-[]-()) < 5
  AND datetime(n.last_seen) < datetime() - duration({days: 1})
DETACH DELETE n

## 7. EXPORT POUR GRAFANA NEO4J PLUGIN

# Format pour Grafana table
MATCH (d:Domain)
WHERE d.risk_score > 40
RETURN d.name as Domain, 
       d.risk_score as `Risk Score`, 
       d.entropy as Entropy,
       d.is_dga as `Potential DGA`,
       size((d)<-[:QUERIED]-()) as `Query Count`
ORDER BY d.risk_score DESC

# Format pour Grafana graph visualization
MATCH (ip:IPAddress)-[r:QUERIED]->(d:Domain)
WHERE d.risk_score > 60
RETURN ip.address as source, 
       d.name as target,
       'QUERIED' as relationship,
       r.count as weight

## 8. REQUÊTES AVANCÉES

# Chemins d'attaque potentiels (lateral movement)
MATCH path = (start:IPAddress)-[*1..3]->(end:IPAddress)
WHERE start.risk_score > 50 AND end.risk_score > 50
  AND start <> end
RETURN path, length(path) as path_length
ORDER BY path_length
LIMIT 20

# Détecter DNS tunneling par volume
MATCH (ip:IPAddress)-[r:QUERIED]->(d:Domain)
WHERE r.count > 100
WITH ip, d, r, 
     duration.between(datetime(r.first_seen), datetime(r.last_seen)).minutes as duration_min,
     r.count as query_count
WHERE duration_min > 0 AND (query_count / duration_min) > 5
RETURN ip.address, d.name, query_count, duration_min,
       query_count / duration_min as queries_per_minute,
       'POTENTIAL_TUNNELING' as alert
ORDER BY queries_per_minute DESC

# Corrélation entre différents types d'activité
MATCH (ip:IPAddress)
OPTIONAL MATCH (ip)-[dns:QUERIED]->(d:Domain)
OPTIONAL MATCH (ip)-[http:HTTP_REQUEST]->(target:IPAddress)
OPTIONAL MATCH (ip)-[tls:TLS_CONNECTION]->(tls_target:IPAddress)
WITH ip, 
     count(DISTINCT dns) as dns_count,
     count(DISTINCT http) as http_count,
     count(DISTINCT tls) as tls_count
WHERE dns_count > 0 OR http_count > 0 OR tls_count > 0
RETURN ip.address, dns_count, http_count, tls_count, ip.risk_score
ORDER BY ip.risk_score DESC