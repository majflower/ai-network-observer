// Top 10 domaines les plus contactés
MATCH (ip:IPAddress)-[r:QUERIED]->(domain:Domain)
RETURN domain.name as domain, count(r) as queries, avg(domain.risk_score) as avg_risk
ORDER BY queries DESC
LIMIT 10;

// Détection de hubs (IPs avec beaucoup de connexions) - FIXED
MATCH (ip:IPAddress)
WITH ip, count{(ip)--()} as connections
WHERE connections > 10
RETURN ip.address, connections, ip.risk_score
ORDER BY connections DESC;

// Nœuds isolés (potentiel C2) - FIXED
MATCH (n)
WITH n, count{(n)--()} as connections
WHERE connections <= 2 AND connections > 0
RETURN labels(n)[0] as type, 
       CASE WHEN n.address IS NOT NULL THEN n.address ELSE n.name END as identifier,
       connections
ORDER BY connections;

// Domaines à haut risque
MATCH (d:Domain)
WHERE d.risk_score > 70
WITH d, count{(d)<--()} as incoming_connections
RETURN d.name, d.risk_score, incoming_connections
ORDER BY d.risk_score DESC;
