# 🚨 AI Network Observer

> **AI-Powered Network Security Monitoring Platform**  
> Real-time threat detection with Machine Learning + LLM hybrid analysis

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![AI](https://img.shields.io/badge/AI-Powered-green.svg)](https://ollama.ai/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production-green.svg)]()

---

## 🎯 Overview

AI Network Observer is an advanced network security monitoring platform that combines **Machine Learning**, **Large Language Models (LLM)**, and **automated threat response** to detect and analyze sophisticated cyber threats in real-time.

### Key Features

🤖 **Hybrid AI Detection**
- Isolation Forest ML model for anomaly detection
- LLM-powered deep threat analysis (Ollama)
- 30+ behavioral network features
- Auto-retraining pipeline

⚡ **Advanced Threat Detection**
- DGA (Domain Generation Algorithm) malware
- C2 Command & Control beaconing
- DNS tunneling & exfiltration
- HTTP attacks (SQLi, XSS, etc.)
- TLS certificate anomalies
- Network graph anomalies

🔧 **Automated Response**
- Playbook-based remediation
- Self-healing capabilities
- SOAR integration ready (TheHive, Cortex)
- Threat intelligence enrichment

📊 **Enterprise Monitoring**
- Prometheus metrics export
- Grafana dashboards
- Neo4j graph visualization
- Elasticsearch logging
- Full Docker stack

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Network Traffic (ens33)                   │
└────────────────────────┬────────────────────────────────────┘
                         │
                ┌────────▼─────────┐
                │  Scapy Capture   │
                │  DNS/HTTP/TLS    │
                └────────┬─────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
    ┌───▼────┐      ┌───▼────┐      ┌───▼────┐
    │  DNS   │      │  HTTP  │      │  TLS   │
    │Analyzer│      │Analyzer│      │Analyzer│
    └───┬────┘      └───┬────┘      └───┬────┘
        │                │                │
        └────────────────┼────────────────┘
                         │
                ┌────────▼─────────┐
                │ Feature Extract  │
                │   (30+ metrics)  │
                └────────┬─────────┘
                         │
                ┌────────▼─────────┐
                │   ML Detector    │
                │(Isolation Forest)│
                └────────┬─────────┘
                         │
                    Anomaly? ──No──> Log Only
                         │
                        Yes
                         │
                ┌────────▼─────────┐
                │   LLM Analysis   │
                │   (Ollama LLM)   │
                └────────┬─────────┘
                         │
                ┌────────▼─────────┐
                │  Auto-Remediation│
                │    (Playbooks)   │
                └────────┬─────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
    ┌───▼────┐      ┌───▼────┐      ┌───▼────┐
    │ Neo4j  │      │Grafana │      │  SOAR  │
    │ Graph  │      │Dashboard│      │ Alert  │
    └────────┘      └────────┘      └────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Linux VM or bare metal (Ubuntu recommended)
- Ollama running locally or remotely
- 4GB RAM minimum, 8GB recommended

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/ai-network-observer.git
cd ai-network-observer/ai-network

# Configure Ollama endpoint
cp .env.example .env
nano .env  # Set OLLAMA_BASE_URL

# Start monitoring stack
docker-compose up -d

# Verify all services running
docker-compose ps
```

### Train ML Model (First Time)

```bash
# Generate training data (10+ sessions)
# Let it run for 20 minutes to collect baseline

# Train the model
./train-ml-model.sh

# Test detection
./test-ml-detection.sh

# Verify model created
ls -lh models/baseline_model.pkl
```

### Access Dashboards

| Service | URL | Credentials |
|---------|-----|-------------|
| **Grafana** | http://localhost:3000 | admin / networksecurity |
| **Prometheus** | http://localhost:9090 | - |
| **Neo4j** | http://localhost:7474 | neo4j / networksecurity |
| **Elasticsearch** | http://localhost:9200 | - |

---

## 📊 Usage

### Monitor Network in Real-Time

```bash
# View live logs
docker-compose logs -f observer

# Check monitoring status
./monitor-all.sh

# View latest AI analysis
cat logs/session_*_llm_analysis.json | tail -1 | jq .
```

### Import Network Graph to Neo4j

```bash
# Import latest session graph
./neo4j/scripts/import-from-json.sh

# Access Neo4j Browser
firefox http://localhost:7474

# Run Cypher queries
MATCH (n) RETURN n LIMIT 50;
```

### View Prometheus Metrics

```bash
# Check metrics exposure
curl http://localhost:8080/metrics

# Query specific metrics
curl -s 'http://localhost:9090/api/v1/query?query=network_risk_score'
```

---

## 🔍 Detection Capabilities

### Machine Learning Features (30+)

**Temporal Features**
- Session duration, hour of day, day of week
- DNS query intervals, regularity patterns
- HTTP request timing

**Volume Features**
- Total packets, bytes, DNS/HTTP/TLS counts
- Packets per minute, bytes per minute
- Query rates and distributions

**Protocol Features**
- DNS unique domains, high-risk ratio
- HTTP unique hosts, methods diversity
- TLS unknown client ratio

**Behavioral Features**
- Domain entropy (randomness)
- Query diversity, graph density
- Isolated nodes ratio (C2 indicator)

### Threat Detection

| Threat Type | Detection Method | Severity |
|-------------|-----------------|----------|
| **DGA Malware** | Entropy analysis + ML | CRITICAL |
| **C2 Beaconing** | Timing patterns + ML | CRITICAL |
| **DNS Tunneling** | Payload size + entropy | HIGH |
| **Data Exfiltration** | Volume anomalies + ML | HIGH |
| **HTTP Attacks** | Pattern matching | MEDIUM |
| **Network Anomalies** | ML baseline deviation | VARIABLE |

---

## 🤖 AI/ML Components

### Isolation Forest (Unsupervised)

```python
# Baseline learning from normal traffic
detector = NetworkAnomalyDetector()
detector.train(historical_sessions)

# Real-time prediction
result = detector.predict(current_session)
# Returns: is_anomaly, score, confidence
```

### LLM Analysis (Ollama)

```python
# Deep analysis triggered by ML anomaly
llm_analysis = ollama.analyze_network_session(session)
# Returns: severity, threats, recommendations, IOCs
```

### Hybrid Approach

- **Fast Path**: ML detector (milliseconds)
- **Deep Path**: LLM analysis (30 seconds)
- **Smart Triage**: LLM only for anomalies

---

## ⚙️ Configuration

### Session Duration

```yaml
# docker-compose.yml
command: ["-i", "ens33", "--duration", "2", "--enable-llm"]
#                                       ↑ minutes
```

### ML Model Settings

```json
// config/ml_config.json
{
  "ml": {
    "contamination": 0.15,  // Expected anomaly rate
    "auto_retrain": true,
    "retrain_interval_days": 7
  }
}
```

### Ollama Configuration

```bash
# .env
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2
ENABLE_LLM=true
```

---

## 🔧 Automated Remediation

### Playbooks

Located in `playbooks/`:

**DGA Malware Response**
```json
{
  "severity": "CRITICAL",
  "actions": [
    "block_domain",
    "isolate_host",
    "capture_memory",
    "alert_soc"
  ]
}
```

**C2 Beaconing Response**
```json
{
  "severity": "CRITICAL",
  "actions": [
    "block_ip",
    "kill_suspicious_process",
    "quarantine_host",
    "forensic_capture"
  ]
}
```

### Execution Modes

- **Auto-Execute**: Immediate response (CRITICAL only)
- **Approval Required**: Manual confirmation (HIGH)
- **Log Only**: Passive monitoring (MEDIUM/LOW)

---

## 🔗 SOAR Integration

### TheHive Integration

```python
# Automatic alert creation
soar.create_alert(analysis)

# Threat intelligence enrichment
enriched_iocs = soar.enrich_with_threat_intel(iocs)
# Queries: VirusTotal, AbuseIPDB, etc.
```

### Supported Platforms

- ✅ TheHive
- ✅ Cortex
- ✅ XSOAR (Palo Alto)
- ✅ Splunk Phantom
- ✅ Custom webhooks

---

## 📈 Metrics & Monitoring

### Prometheus Metrics

```
# DNS metrics
dns_queries_total
dns_high_risk_total
dns_dga_detected_total
dns_tunneling_detected_total

# HTTP metrics
http_requests_total{method="GET|POST|..."}
http_attacks_total{attack_type="sqli|xss|..."}

# ML metrics
llm_analysis_duration_seconds
llm_analysis_success_total
network_risk_score  # 0-100

# Graph metrics
graph_nodes_total{node_type="ip|domain"}
graph_anomalies_total
```

### Grafana Queries

```promql
# Network risk score
network_risk_score

# DNS threat rate
rate(dns_high_risk_total[5m])

# LLM analysis latency (p95)
histogram_quantile(0.95, llm_analysis_duration_seconds)
```

---

## 🧪 Testing

### Generate Test Traffic

```bash
# Simulate normal traffic
for i in {1..10}; do
    curl -s https://google.com > /dev/null
    nslookup github.com
    sleep 5
done
```

### Simulate DGA Malware

```bash
# Generate random domains (DGA pattern)
for i in {1..5}; do
    nslookup $(head /dev/urandom | tr -dc a-z | head -c 15).com
    sleep 2
done
```

### Simulate C2 Beaconing

```bash
# Regular interval connections
for i in {1..10}; do
    curl -s http://suspicious-domain.com
    sleep 10  # Regular 10s interval
done
```

---

## 📁 Project Structure

```
ai-network-observer/
├── src/
│   ├── core/              # Packet capture engine
│   ├── analyzers/         # DNS, HTTP, TLS analyzers
│   ├── intelligence/      # LLM connector
│   ├── ml/               # ML models & training
│   ├── automation/       # Remediation engine
│   ├── integrations/     # SOAR connectors
│   └── graph/            # Network graph builder
├── config/               # Configuration files
├── models/               # Trained ML models
├── playbooks/            # Remediation playbooks
├── logs/                 # Session logs & analyses
├── prometheus/           # Prometheus config & alerts
├── grafana/              # Dashboards & datasources
├── neo4j/                # Graph schema & queries
└── docker-compose.yml    # Full stack deployment
```

---

## 🎓 Academic Context

This project was developed as part of a **Master's degree in Cybersecurity** with focus on:

- AI/ML for threat detection
- Network security monitoring
- Automated incident response
- Security orchestration (SOAR)

### Research Areas

- Unsupervised learning for network baseline
- LLM applications in cybersecurity
- Hybrid AI architectures (ML + LLM)
- Self-healing security systems

---

## 🛠️ Development

### Add New Detector

```python
# src/analyzers/custom_detector.py
class CustomDetector:
    def analyze(self, packets):
        # Your detection logic
        pass
```

### Add New Playbook

```json
// playbooks/custom_threat.json
{
  "threat_type": "CustomThreat",
  "severity": "HIGH",
  "actions": [
    "custom_action_1",
    "custom_action_2"
  ]
}
```

### Retrain ML Model

```bash
# Automatic retraining (weekly)
./train-ml-model.sh

# Or via cron
0 2 * * 0 /path/to/train-ml-model.sh
```

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open Pull Request

---

## 📜 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file.

---

## 📧 Contact

**Ja3l** - Master's Student in Cybersecurity  
📧 Email: your-email@example.com  
💼 LinkedIn: [linkedin.com/in/your-profile](https://linkedin.com/in/your-profile)  
🐙 GitHub: [@yourusername](https://github.com/yourusername)

---

## 🙏 Acknowledgments

- **Scapy** - Packet manipulation
- **Ollama** - Local LLM inference
- **scikit-learn** - Machine learning
- **Neo4j** - Graph database
- **Prometheus/Grafana** - Monitoring
- **Docker** - Containerization

---

## 🚀 Roadmap

- [ ] LSTM for time-series forecasting
- [ ] Multi-class threat classification (Random Forest)
- [ ] Kubernetes deployment manifests
- [ ] REST API for external integrations
- [ ] Multi-tenant support
- [ ] Real-time dashboard (WebSocket)
- [ ] Mobile app for alerts

---

**⭐ Star this repo if you find it useful!**

**🔗 Perfect for SOC automation, threat hunting, and security research.**
