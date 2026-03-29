// Création des contraintes
CREATE CONSTRAINT ip_unique IF NOT EXISTS FOR (ip:IPAddress) REQUIRE ip.address IS UNIQUE;
CREATE CONSTRAINT domain_unique IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE;

// Index pour performance
CREATE INDEX ip_risk IF NOT EXISTS FOR (ip:IPAddress) ON (ip.risk_score);
CREATE INDEX domain_risk IF NOT EXISTS FOR (d:Domain) ON (d.risk_score);
CREATE INDEX connection_time IF NOT EXISTS FOR ()-[r:QUERIED]->() ON (r.timestamp);

RETURN "Schema initialized" as status;
