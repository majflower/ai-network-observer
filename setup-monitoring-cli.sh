#!/bin/bash
# Script de Configuration Complète - Monitoring Stack
# Grafana + Prometheus + Neo4j - SANS interface graphique

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "=========================================="
echo "  Configuration Monitoring Stack"
echo "  Grafana + Prometheus + Neo4j"
echo "=========================================="
echo ""

cd /home/maj/ai-network-observer/ai-network

# ============================================
# PARTIE 1: PROMETHEUS - Configuration
# ============================================

echo -e "${BLUE}[1/6] Configuration Prometheus...${NC}"

mkdir -p prometheus/alerts

# Prometheus config
cat > prometheus/prometheus.yml << 'EOFPROM'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

# Alertes
rule_files:
  - "/etc/prometheus/alerts/*.yml"

# Scrape configs
scrape_configs:
  # Observer metrics
  - job_name: 'network-observer'
    static_configs:
      - targets: ['localhost:8080']
    
  # Neo4j metrics
  - job_name: 'neo4j'
    static_configs:
      - targets: ['neo4j:2004']
    
  # Elasticsearch
  - job_name: 'elasticsearch'
    static_configs:
      - targets: ['elasticsearch:9200']
    
  # Grafana
  - job_name: 'grafana'
    static_configs:
      - targets: ['grafana:3000']
    
  # Prometheus self
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
EOFPROM

echo -e "${GREEN}✓ Prometheus configuré${NC}"

# ============================================
# PARTIE 2: PROMETHEUS - Alertes
# ============================================

echo -e "${BLUE}[2/6] Configuration Alertes Prometheus...${NC}"

cat > prometheus/alerts/network_alerts.yml << 'EOFALERTS'
groups:
  - name: network_security
    interval: 30s
    rules:
      # DNS Threats
      - alert: HighDNSThreats
        expr: rate(dns_high_risk_total[5m]) > 5
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High DNS threat rate detected"
          description: "{{ $value }} DNS threats per second"
      
      # Network Risk Score
      - alert: HighRiskScore
        expr: network_risk_score > 70
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Network risk score critical"
          description: "Risk score: {{ $value }}"
      
      # Observer Down
      - alert: ObserverDown
        expr: up{job="network-observer"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Network Observer is down"
      
      # LLM Analysis Slow
      - alert: SlowLLMAnalysis
        expr: histogram_quantile(0.95, llm_analysis_duration_seconds) > 120
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "LLM analysis taking too long"
          description: "95th percentile: {{ $value }}s"
EOFALERTS

echo -e "${GREEN}✓ Alertes configurées${NC}"

# ============================================
# PARTIE 3: GRAFANA - Datasources
# ============================================

echo -e "${BLUE}[3/6] Configuration Grafana Datasources...${NC}"

mkdir -p grafana/provisioning/datasources
mkdir -p grafana/provisioning/dashboards

cat > grafana/provisioning/datasources/datasources.yml << 'EOFDS'
apiVersion: 1

datasources:
  # Prometheus
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
    jsonData:
      timeInterval: "15s"
  
  # Neo4j
  - name: Neo4j
    type: neo4j-datasource
    access: proxy
    url: bolt://neo4j:7687
    editable: false
    jsonData:
      database: "neo4j"
    secureJsonData:
      password: "networksecurity"
    basicAuth: true
    basicAuthUser: "neo4j"
  
  # Elasticsearch
  - name: Elasticsearch
    type: elasticsearch
    access: proxy
    url: http://elasticsearch:9200
    database: "network-logs-*"
    editable: false
    jsonData:
      esVersion: "8.0.0"
      timeField: "@timestamp"
      logLevelField: "level"
EOFDS

echo -e "${GREEN}✓ Datasources configurés${NC}"

# ============================================
# PARTIE 4: GRAFANA - Dashboard
# ============================================

echo -e "${BLUE}[4/6] Création Dashboard Grafana...${NC}"

# Dashboard config
cat > grafana/provisioning/dashboards/dashboards.yml << 'EOFDASHCONF'
apiVersion: 1

providers:
  - name: 'Network Security'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /etc/grafana/provisioning/dashboards
EOFDASHCONF

# Dashboard JSON
cat > grafana/provisioning/dashboards/network-security.json << 'EOFDASH'
{
  "dashboard": {
    "title": "Network Security Monitor",
    "tags": ["network", "security", "ai"],
    "timezone": "browser",
    "refresh": "10s",
    "panels": [
      {
        "id": 1,
        "title": "Network Risk Score",
        "type": "gauge",
        "gridPos": {"x": 0, "y": 0, "w": 6, "h": 6},
        "targets": [{
          "expr": "network_risk_score",
          "refId": "A"
        }],
        "options": {
          "showThresholdLabels": false,
          "showThresholdMarkers": true
        },
        "fieldConfig": {
          "defaults": {
            "min": 0,
            "max": 100,
            "thresholds": {
              "mode": "absolute",
              "steps": [
                {"value": 0, "color": "green"},
                {"value": 40, "color": "yellow"},
                {"value": 70, "color": "red"}
              ]
            }
          }
        }
      },
      {
        "id": 2,
        "title": "DNS Queries Rate",
        "type": "graph",
        "gridPos": {"x": 6, "y": 0, "w": 9, "h": 6},
        "targets": [{
          "expr": "rate(dns_queries_total[5m])",
          "legendFormat": "{{protocol}}",
          "refId": "A"
        }]
      },
      {
        "id": 3,
        "title": "DNS Threats",
        "type": "graph",
        "gridPos": {"x": 15, "y": 0, "w": 9, "h": 6},
        "targets": [
          {
            "expr": "rate(dns_dga_detected_total[5m])",
            "legendFormat": "DGA Detected",
            "refId": "A"
          },
          {
            "expr": "rate(dns_tunneling_detected_total[5m])",
            "legendFormat": "DNS Tunneling",
            "refId": "B"
          },
          {
            "expr": "rate(dns_beaconing_detected_total[5m])",
            "legendFormat": "C2 Beaconing",
            "refId": "C"
          }
        ]
      },
      {
        "id": 4,
        "title": "HTTP Requests",
        "type": "graph",
        "gridPos": {"x": 0, "y": 6, "w": 12, "h": 6},
        "targets": [{
          "expr": "rate(http_requests_total[5m])",
          "legendFormat": "{{method}}",
          "refId": "A"
        }]
      },
      {
        "id": 5,
        "title": "LLM Analysis Duration (p95)",
        "type": "graph",
        "gridPos": {"x": 12, "y": 6, "w": 12, "h": 6},
        "targets": [{
          "expr": "histogram_quantile(0.95, llm_analysis_duration_seconds)",
          "legendFormat": "95th percentile",
          "refId": "A"
        }]
      },
      {
        "id": 6,
        "title": "Active Threats",
        "type": "stat",
        "gridPos": {"x": 0, "y": 12, "w": 6, "h": 4},
        "targets": [{
          "expr": "sum(network_threats_total)",
          "refId": "A"
        }],
        "options": {
          "colorMode": "background"
        },
        "fieldConfig": {
          "defaults": {
            "thresholds": {
              "mode": "absolute",
              "steps": [
                {"value": 0, "color": "green"},
                {"value": 5, "color": "yellow"},
                {"value": 10, "color": "red"}
              ]
            }
          }
        }
      },
      {
        "id": 7,
        "title": "Packet Processing Rate",
        "type": "graph",
        "gridPos": {"x": 6, "y": 12, "w": 9, "h": 6},
        "targets": [{
          "expr": "rate(packets_processed_total[1m])",
          "legendFormat": "Packets/sec",
          "refId": "A"
        }]
      },
      {
        "id": 8,
        "title": "Graph Nodes by Type",
        "type": "piechart",
        "gridPos": {"x": 15, "y": 12, "w": 9, "h": 6},
        "targets": [{
          "expr": "graph_nodes_total",
          "legendFormat": "{{node_type}}",
          "refId": "A"
        }]
      }
    ]
  }
}
EOFDASH

echo -e "${GREEN}✓ Dashboard créé${NC}"

# ============================================
# PARTIE 5: NEO4J - Cypher Scripts
# ============================================

echo -e "${BLUE}[5/6] Création scripts Neo4j...${NC}"

mkdir -p neo4j/scripts

# Script d'initialisation
cat > neo4j/scripts/init-schema.cypher << 'EOFNEO4J'
// Création des contraintes
CREATE CONSTRAINT ip_unique IF NOT EXISTS FOR (ip:IPAddress) REQUIRE ip.address IS UNIQUE;
CREATE CONSTRAINT domain_unique IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE;

// Index pour performance
CREATE INDEX ip_risk IF NOT EXISTS FOR (ip:IPAddress) ON (ip.risk_score);
CREATE INDEX domain_risk IF NOT EXISTS FOR (d:Domain) ON (d.risk_score);
CREATE INDEX connection_time IF NOT EXISTS FOR ()-[r:QUERIED]->() ON (r.timestamp);

RETURN "Schema initialized" as status;
EOFNEO4J

# Requêtes d'analyse
cat > neo4j/scripts/analyze-threats.cypher << 'EOFANALYZE'
// Top 10 domaines les plus contactés
MATCH (ip:IPAddress)-[r:QUERIED]->(domain:Domain)
RETURN domain.name as domain, count(r) as queries, avg(domain.risk_score) as avg_risk
ORDER BY queries DESC
LIMIT 10;

// Détection de hubs (IPs avec beaucoup de connexions)
MATCH (ip:IPAddress)
WITH ip, size((ip)--()) as connections
WHERE connections > 10
RETURN ip.address, connections, ip.risk_score
ORDER BY connections DESC;

// Patterns de C2 (connexions bidirectionnelles suspectes)
MATCH path = (ip1:IPAddress)-[:QUERIED*2..3]->(ip2:IPAddress)
WHERE ip1 <> ip2 AND ip1.risk_score > 50
RETURN path
LIMIT 5;

// Nœuds isolés (potentiel C2)
MATCH (n)
WHERE size((n)--()) <= 2 AND size((n)--()) > 0
RETURN labels(n)[0] as type, 
       CASE WHEN n.address IS NOT NULL THEN n.address ELSE n.name END as identifier,
       size((n)--()) as connections
ORDER BY connections;

// Domaines à haut risque
MATCH (d:Domain)
WHERE d.risk_score > 70
RETURN d.name, d.risk_score, size((d)<--()) as incoming_connections
ORDER BY d.risk_score DESC;
EOFANALYZE

# Script d'import depuis JSON
cat > neo4j/scripts/import-from-json.sh << 'EOFIMPORT'
#!/bin/bash
# Import graph data from JSON to Neo4j

LOGS_DIR="/home/maj/ai-network-observer/ai-network/logs"
LATEST_GRAPH=$(ls -t $LOGS_DIR/session_*_network_graph.json 2>/dev/null | head -1)

if [ -z "$LATEST_GRAPH" ]; then
    echo "No graph data found"
    exit 1
fi

echo "Importing from: $LATEST_GRAPH"

# Extract nodes and create Cypher
cat $LATEST_GRAPH | jq -r '
.nodes[] |
"MERGE (n:\(.type // "Unknown") {id: \"\(.id)\"})
 SET n.label = \"\(.label // .id)\";"
' > /tmp/import_nodes.cypher

# Extract edges
cat $LATEST_GRAPH | jq -r '
.links[] |
"MATCH (a {id: \"\(.source)\"}), (b {id: \"\(.target)\"})
 MERGE (a)-[r:CONNECTED]->(b)
 SET r.type = \"\(.type // "generic")\";"
' > /tmp/import_edges.cypher

# Execute via cypher-shell
docker exec network-graph-db cypher-shell -u neo4j -p networksecurity < /tmp/import_nodes.cypher
docker exec network-graph-db cypher-shell -u neo4j -p networksecurity < /tmp/import_edges.cypher

echo "Import completed"
EOFIMPORT

chmod +x neo4j/scripts/import-from-json.sh

echo -e "${GREEN}✓ Scripts Neo4j créés${NC}"

# ============================================
# PARTIE 6: Scripts de Monitoring CLI
# ============================================

echo -e "${BLUE}[6/6] Création scripts de monitoring CLI...${NC}"

# Script de monitoring Prometheus
cat > monitor-prometheus.sh << 'EOFMONPROM'
#!/bin/bash
# Monitoring Prometheus en CLI

echo "=== PROMETHEUS METRICS ==="
echo ""

# Targets status
echo "Targets Status:"
curl -s http://localhost:9090/api/v1/targets | jq -r '.data.activeTargets[] | "\(.job): \(.health)"'

echo ""
echo "Latest Metrics:"

# DNS queries
DNS=$(curl -s 'http://localhost:9090/api/v1/query?query=dns_queries_total' | jq -r '.data.result[0].value[1] // 0')
echo "  DNS Queries: $DNS"

# Risk score
RISK=$(curl -s 'http://localhost:9090/api/v1/query?query=network_risk_score' | jq -r '.data.result[0].value[1] // 0')
echo "  Risk Score: $RISK"

# HTTP requests
HTTP=$(curl -s 'http://localhost:9090/api/v1/query?query=http_requests_total' | jq -r '.data.result[0].value[1] // 0')
echo "  HTTP Requests: $HTTP"

# Active alerts
echo ""
echo "Active Alerts:"
curl -s http://localhost:9090/api/v1/alerts | jq -r '.data.alerts[] | select(.state=="firing") | "  ⚠ \(.labels.alertname): \(.annotations.summary)"'
EOFMONPROM

chmod +x monitor-prometheus.sh

# Script de monitoring Neo4j
cat > monitor-neo4j.sh << 'EOFMONNEO'
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
EOFMONNEO

chmod +x monitor-neo4j.sh

# Script de monitoring Grafana
cat > monitor-grafana.sh << 'EOFMONGRAF'
#!/bin/bash
# Vérifier status Grafana

echo "=== GRAFANA STATUS ==="
echo ""

# Health check
HEALTH=$(curl -s http://localhost:3000/api/health | jq -r '.database')
echo "Database: $HEALTH"

# Datasources
echo ""
echo "Configured Datasources:"
curl -s -u admin:networksecurity http://localhost:3000/api/datasources | jq -r '.[] | "  \(.name): \(.type)"'

# Dashboards
echo ""
echo "Available Dashboards:"
curl -s -u admin:networksecurity http://localhost:3000/api/search?type=dash-db | jq -r '.[] | "  \(.title) (id: \(.id))"'
EOFMONGRAF

chmod +x monitor-grafana.sh

# Script tout-en-un
cat > monitor-all.sh << 'EOFMONALL'
#!/bin/bash
# Monitoring complet du stack

echo "=========================================="
echo "  NETWORK OBSERVER - MONITORING STATUS"
echo "=========================================="
echo ""

# Containers
echo "=== CONTAINERS ==="
docker-compose ps

echo ""
./monitor-prometheus.sh

echo ""
./monitor-neo4j.sh

echo ""
./monitor-grafana.sh

echo ""
echo "=== LATEST ANALYSIS ==="
LATEST=$(ls -t logs/session_*_llm_analysis.json 2>/dev/null | head -1)
if [ -n "$LATEST" ]; then
    echo "File: $(basename $LATEST)"
    cat $LATEST | jq -r '"Severity: \(.analysis.severity)\nConfidence: \(.analysis.confidence)%\nThreat: \(.analysis.threat_type)"'
else
    echo "No analysis found yet"
fi
EOFMONALL

chmod +x monitor-all.sh

echo -e "${GREEN}✓ Scripts de monitoring créés${NC}"

# ============================================
# REDÉMARRAGE
# ============================================

echo ""
echo -e "${BLUE}Redémarrage du stack...${NC}"

docker-compose down
docker-compose up -d

echo ""
echo -e "${GREEN}✓ Configuration terminée !${NC}"
echo ""
echo "=========================================="
echo "  UTILISATION"
echo "=========================================="
echo ""
echo "Monitoring complet:"
echo "  ./monitor-all.sh"
echo ""
echo "Prometheus uniquement:"
echo "  ./monitor-prometheus.sh"
echo ""
echo "Neo4j uniquement:"
echo "  ./monitor-neo4j.sh"
echo ""
echo "Grafana uniquement:"
echo "  ./monitor-grafana.sh"
echo ""
echo "Import graph dans Neo4j:"
echo "  ./neo4j/scripts/import-from-json.sh"
echo ""
echo "Accès web (optionnel):"
echo "  Grafana: http://localhost:3000 (admin/networksecurity)"
echo "  Prometheus: http://localhost:9090"
echo "  Neo4j: http://localhost:7474 (neo4j/networksecurity)"
echo ""
echo "=========================================="
