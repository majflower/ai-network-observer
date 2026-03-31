# 🔒 AI Network Observer

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)](https://www.docker.com/)

**Détection intelligente des menaces réseau par IA** - Projet Master Cybersécurité

Système de monitoring combinant **Machine Learning** (Isolation Forest) et **LLM** (Ollama) pour détecter automatiquement les menaces réseau en temps réel.

---

## 🎯 Fonctionnalités

### Détection Automatique
- **DGA Malware** : Détection de Domain Generation Algorithms
- **C2 Beaconing** : Identification de communications Command & Control
- **DNS Tunneling** : Détection d'exfiltration de données via DNS
- **Port Scanning** : Reconnaissance réseau
- **Anomalies** : Déviations comportementales

### Stack Technique
```
Capture     : Scapy / eBPF
Analysis    : Python 3.8+
ML Engine   : scikit-learn (Isolation Forest)
LLM         : Ollama (llama3.2)
Storage     : Neo4j + Elasticsearch
Monitoring  : Prometheus + Grafana
Deploy      : Docker Compose
```

---

## 🎯 Modes d'Utilisation

### Mode 1 : Détection ML (Rapide) ⚡
- Installation en 5 minutes
- Détection d'anomalies par ML
- Alertes automatiques
- **Pas besoin d'Ollama**

**Idéal pour :** Tests rapides, ressources limitées

### Mode 2 : ML + LLM (Complet) 🧠
- Détection ML + Analyse IA approfondie
- Rapports en langage naturel
- Recommandations de remédiation
- **Nécessite Ollama**

**Idéal pour :** Analyse approfondie, apprentissage complet

---

## 📦 Installation d'Ollama (Mode 2 uniquement)

**Linux :**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.2
ollama serve &
```

**macOS :**
```bash
brew install ollama
ollama pull llama3.2
ollama serve &
```

**Windows :**
1. Télécharger depuis https://ollama.ai/download
2. Installer l'application
3. Dans PowerShell : `ollama pull llama3.2`

**Vérification :**
```bash
curl http://localhost:11434/api/tags
# Devrait retourner la liste incluant llama3.2
```

**Taille :** ~4.7 GB | **RAM requise :** 8-16 GB

---

## 🚀 Démarrage Rapide

### Mode 1 : SANS Ollama (Recommandé pour débuter)

```bash
# 1. Cloner
git clone https://github.com/majflower/ai-network-observer.git
cd ai-network-observer

# 2. Configuration
echo "ENABLE_LLM=false" > .env

# 3. Lancer
docker-compose up -d

# 4. Vérifier
docker-compose ps
```

**Résultats disponibles dans 2-3 minutes** → `logs/alerts_*.json`

---

### Mode 2 : AVEC Ollama

```bash
# 1. Cloner
git clone https://github.com/majflower/ai-network-observer.git
cd ai-network-observer

# 2. Vérifier Ollama
curl http://localhost:11434/api/tags

# 3. Configuration
cat > .env << 'EOF'
ENABLE_LLM=true
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2
EOF

# 4. Lancer
docker-compose up -d

# 5. Vérifier
docker-compose logs observer | grep -i ollama
```

---

## 📊 Accès aux Dashboards

### Grafana (Visualisation)
- **URL** : http://localhost:3000
- **Login** : admin / networksecurity
- Dashboards : Network Security Overview, ML Anomaly Detection

### Neo4j (Graphe Réseau)
- **URL** : http://localhost:7474
- **Login** : neo4j / networksecurity
- Query exemple :
```cypher
MATCH (h:Host)-[r:DNS_QUERY]->(d:Domain)
WHERE d.risk_score > 50
RETURN h, r, d LIMIT 25
```

### Prometheus (Métriques)
- **URL** : http://localhost:9090
- Query exemple : `network_packets_total`

⚠️ **IMPORTANT** : Changez les mots de passe par défaut en production !

---

## 🧪 Tests & Validation

### Simuler des Attaques (Sur VM isolée uniquement)

```bash
# DGA Malware
bash tests/simulate-dga.sh

# C2 Beaconing
bash tests/simulate-c2.sh

# DNS Tunneling
bash tests/simulate-dns-tunnel.sh

# Vérifier les détections
grep "DGA\|C2_BEACONING\|DNS_TUNNELING" logs/alerts_*.json
```

---

## 🔧 Commandes Utiles

```bash
# Démarrer
docker-compose up -d

# Arrêter
docker-compose down

# Logs en temps réel
docker-compose logs -f observer

# État des services
docker-compose ps

# Redémarrer un service
docker-compose restart observer

# Voir les alertes
tail -f logs/alerts_*.json
```

---

## 📚 Documentation Détaillée

- **[TESTING_GUIDE.md](TESTING_GUIDE.md)** - Guide de test complet
- **[ML_README.md](ML_README.md)** - Documentation Machine Learning
- **[CHANGELOG.md](CHANGELOG.md)** - Historique des versions

---

## ❓ FAQ

**Q : Ça ralentit mon réseau ?**  
R : Non, écoute passive sans interception.

**Q : C'est légal ?**  
R : Oui, sur VOTRE réseau/VM uniquement.

**Q : Détection 100% fiable ?**  
R : Non, outil d'aide à la détection, pas de garantie absolue.

**Q : Observer ne capture rien ?**  
R : Vérifier l'interface réseau dans `docker-compose.yml` (ligne `CAPTURE_INTERFACE`)

**Q : Ollama connection refused ?**  
R : Vérifier qu'Ollama tourne : `ps aux | grep ollama` puis `ollama serve &`

**Q : Grafana vide ?**  
R : Normal au début, attendre 5-10 minutes de collecte.

---

## 🔒 Sécurité & Production

**⚠️ Ce projet utilise des mots de passe par défaut pour la démo.**

En production, CHANGEZ-LES :
```yaml
# Dans docker-compose.yml
NEO4J_PASSWORD=VotreMotDePasseSecurise
GF_SECURITY_ADMIN_PASSWORD=VotreMotDePasseSecurise
```

**Docker privileged mode** : Requis pour capture réseau (CAP_NET_RAW).

---

## 🎓 Contexte Académique

Projet Master Cybersécurité démontrant :
- ✅ Intégration ML/LLM pour la sécurité
- ✅ Architecture microservices Docker
- ✅ Stack monitoring complète
- ✅ Détection de menaces avancées

---

## 🤝 Contribution

Issues & Pull Requests bienvenues sur [GitHub](https://github.com/majflower/ai-network-observer/issues)

---

## 📄 Licence

MIT License - Voir [LICENSE](LICENSE)

---

## 📧 Contact

- **GitHub** : [@majflower](https://github.com/majflower)
- **Projet** : [ai-network-observer](https://github.com/majflower/ai-network-observer)

---

<div align="center">

**⭐ Si ce projet vous aide, donnez-lui une étoile ! ⭐**

Made with ❤️ for Cybersecurity Education

</div>
