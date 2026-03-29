# 🔒 AI Network Observer

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)](https://www.docker.com/)

**AI-Powered Network Security Monitoring** - Détection et analyse automatique des menaces réseau grâce à l'Intelligence Artificielle.

Projet de Master en Cybersécurité combinant Machine Learning (Isolation Forest) et Large Language Models (Ollama) pour une surveillance réseau intelligente en temps réel.

---

## 🎯 Caractéristiques

### 🤖 Détection Hybride IA
- **Machine Learning** : Isolation Forest pour détection d'anomalies statistiques
- **LLM Analysis** : Ollama (llama3.2) pour analyse contextuelle approfondie
- **Corrélation intelligente** : Fusion ML + LLM pour réduction des faux positifs

### ⚡ Menaces Détectées
- **DGA Malware** : Domain Generation Algorithm detection
- **C2 Beaconing** : Command & Control communication patterns
- **DNS Tunneling** : Exfiltration de données via DNS
- **Port Scanning** : Reconnaissance réseau
- **Anomalies comportementales** : Déviations des patterns normaux

### 📊 Stack Technique Complète
```
┌─────────────────────────────────────────────────┐
│  Capture    │  Scapy / eBPF (AF_PACKET)        │
│  Analysis   │  Python 3.8+ / NetworkX          │
│  ML Engine  │  scikit-learn (Isolation Forest) │
│  LLM        │  Ollama (llama3.2)               │
│  Storage    │  Neo4j / Elasticsearch           │
│  Monitoring │  Prometheus / Grafana            │
│  Deploy     │  Docker / Docker Compose         │
└─────────────────────────────────────────────────┘
```

---

## 🚀 Démarrage Rapide

### Prérequis
- Docker & Docker Compose
- 4GB RAM minimum (8GB recommandé)
- Interface réseau accessible

### Installation (5 minutes)
```bash
# 1. Cloner le repository
git clone https://github.com/majflower/ai-network-observer.git
cd ai-network-observer

# 2. Configuration (optionnel - LLM)
echo "ENABLE_LLM=true" > .env
echo "OLLAMA_BASE_URL=http://localhost:11434" >> .env

# 3. Lancer la stack complète
docker-compose up -d

# 4. Vérifier les services
docker-compose ps
```

### Test Rapide (Sans Ollama)
```bash
# Test en 2 minutes sans LLM
echo "ENABLE_LLM=false" > .env
docker-compose up observer

# Les résultats apparaissent dans logs/ après 1-2 minutes
tail -f logs/alerts_*.json
```

---

## 📊 Interface & Visualisation

### Dashboards Grafana
- **URL** : http://localhost:3000
- **Login** : admin / networksecurity
- **Dashboards** :
  - Network Security Overview
  - ML Anomaly Detection
  - Threat Timeline

### Neo4j Graph Database
- **URL** : http://localhost:7474
- **Login** : neo4j / networksecurity
- **Visualisation** : Graphe réseau interactif

### Prometheus Metrics
- **URL** : http://localhost:9090
- **Métriques temps réel** : Packets, Anomalies, Alerts

---

## 🎓 Cas d'Usage

### 1. Surveillance Réseau Continue
```bash
# Monitoring 24/7 avec alertes
docker-compose up -d
# Consulter Grafana pour vue temps réel
```

### 2. Analyse Post-Incident
```bash
# Rejouer du trafic capturé
python src/main.py --pcap capture.pcap --enable-llm
```

### 3. Threat Hunting
```bash
# Recherche proactive de menaces
# Utiliser Neo4j pour explorer le graphe réseau
# Cypher query: MATCH (h:Host)-[r:DNS_QUERY]->(d:Domain) 
#               WHERE d.risk_score > 70 RETURN h,r,d
```

---

## 🧪 Tests de Validation

### Scénarios d'Attaque Simulés
```bash
# Simuler du trafic DGA
bash tests/simulate-dga.sh

# Simuler C2 beaconing
bash tests/simulate-c2.sh

# Simuler DNS tunneling
bash tests/simulate-dns-tunnel.sh

# Vérifier les détections
grep "DGA" logs/alerts_*.json
grep "C2_BEACONING" logs/alerts_*.json
```

---

## 🏗️ Architecture
```
┌─────────────────────────────────────────────────────┐
│                  AI Network Observer                │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    │
│  │ Capture  │───▶│ Analysis │───▶│ ML Model │    │
│  │  Engine  │    │  Engine  │    │ (Isol.F) │    │
│  └──────────┘    └──────────┘    └──────────┘    │
│       │                                  │         │
│       ▼                                  ▼         │
│  ┌──────────┐                    ┌──────────┐    │
│  │   Neo4j  │◀──────────────────▶│  Ollama  │    │
│  │  Graph   │                    │   LLM    │    │
│  └──────────┘                    └──────────┘    │
│       │                                  │         │
│       ▼                                  ▼         │
│  ┌──────────────────────────────────────────┐    │
│  │        Prometheus + Grafana              │    │
│  │        Monitoring & Alerting             │    │
│  └──────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

---

## 🔧 Configuration Avancée

### Variables d'Environnement (.env)
```bash
# LLM Configuration
ENABLE_LLM=true
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2

# Capture Settings
CAPTURE_INTERFACE=eth0
CAPTURE_BACKEND=scapy  # ou 'ebpf'
PERFORMANCE_MODE=false

# ML Settings
ML_CONTAMINATION=0.1
ML_TRAINING_SESSIONS=10
```

### Mode Performance (Production)
```bash
# Utiliser eBPF au lieu de Scapy
CAPTURE_BACKEND=ebpf
PERFORMANCE_MODE=true

# Build avec eBPF support
docker build -f Dockerfile.ubuntu-ebpf -t observer-ebpf .
```

---

## 📈 Machine Learning

### Entraînement du Modèle
```bash
# Collecter données normales (10 sessions minimum)
docker-compose exec observer python -c "
from src.ml.training_pipeline import MLTrainingPipeline
pipeline = MLTrainingPipeline()
pipeline.collect_training_session()
"

# Entraîner le modèle
bash train-ml-model.sh

# Évaluer performance
docker-compose exec observer python -c "
from src.ml.training_pipeline import MLTrainingPipeline
p = MLTrainingPipeline()
print(p.evaluate_model())
"
```

### Métriques ML
- **Precision** : Taux de vrais positifs
- **Recall** : Taux de détection
- **F1-Score** : Moyenne harmonique
- **Contamination** : Seuil d'anomalies (défaut: 10%)

---

## 🛡️ Sécurité & Production

### ⚠️ Avertissement Sécurité

**Ce projet utilise des mots de passe par défaut pour la démo :**
- Neo4j : `networksecurity`
- Grafana : `networksecurity`

**🔴 EN PRODUCTION, CHANGEZ-LES IMMÉDIATEMENT !**
```bash
# Modifier docker-compose.yml
NEO4J_PASSWORD=VotreMotDePasseSecurisé
GF_SECURITY_ADMIN_PASSWORD=VotreMotDePasseSecurisé
```

### Configuration Firewall
```bash
# Restreindre l'accès aux dashboards
# Exemple avec ufw (Ubuntu)
sudo ufw allow from 192.168.1.0/24 to any port 3000  # Grafana
sudo ufw allow from 192.168.1.0/24 to any port 7474  # Neo4j
```

### Docker Privileged Mode

Le container observer nécessite `privileged: true` pour :
- Accès CAP_NET_RAW (capture de paquets)
- Interface réseau en mode promiscuous

**C'est normal et requis pour la capture réseau.**

---

## 📚 Documentation

- **[TESTING_GUIDE.md](TESTING_GUIDE.md)** : Guide de test complet
- **[ML_README.md](ML_README.md)** : Documentation Machine Learning
- **[SECURITY.md](SECURITY.md)** : Politique de sécurité
- **[CONTRIBUTING.md](CONTRIBUTING.md)** : Guide de contribution

---

## 🎯 Roadmap

- [x] Capture réseau Scapy
- [x] Analyse DNS/HTTP/TLS
- [x] Intégration LLM (Ollama)
- [x] Machine Learning (Isolation Forest)
- [x] Graphe Neo4j
- [x] Dashboards Grafana
- [ ] Support eBPF complet
- [ ] Intégration SIEM (Splunk/ELK)
- [ ] API REST
- [ ] Interface Web React

---

## 🤝 Contribution

Les contributions sont les bienvenues ! Consultez [CONTRIBUTING.md](CONTRIBUTING.md).

### Développement Local
```bash
# Installation environnement dev
pip install -r requirements-dev.txt

# Pre-commit hooks
pre-commit install

# Tests
pytest tests/

# Linting
pylint src/
```

---

## 📄 Licence

MIT License - Voir [LICENSE](LICENSE) pour détails.

---

## 🙏 Remerciements

- **Anthropic** : Claude API pour l'analyse LLM
- **Ollama** : LLM local open-source
- **Neo4j** : Graph database
- **Scapy** : Packet manipulation
- **scikit-learn** : Machine Learning

---

## 📧 Contact

- **GitHub** : [@majflower](https://github.com/majflower)
- **Project** : [ai-network-observer](https://github.com/majflower/ai-network-observer)

---

## 🎓 Contexte Académique

Projet réalisé dans le cadre d'un Master en Cybersécurité, démontrant l'application pratique de l'IA pour la détection de menaces réseau en temps réel.

**Objectifs pédagogiques atteints :**
- ✅ Intégration ML/LLM pour la sécurité
- ✅ Architecture microservices avec Docker
- ✅ Stack de monitoring complète
- ✅ Analyse de protocoles réseau
- ✅ Détection de menaces avancées

---

<div align="center">

**⭐ Si ce projet vous aide, n'hésitez pas à lui donner une étoile ! ⭐**

Made with ❤️ for Network Security

</div>
