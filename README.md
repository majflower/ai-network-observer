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
LLM         : Ollama (llama3.2 / qwen2.5 / mistral)
Storage     : Neo4j + Elasticsearch
Monitoring  : Prometheus + Grafana
Deploy      : Docker Compose
```

---

## 🎯 Modes d'Utilisation

### Mode 1 : Détection ML Seule (Rapide) ⚡
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

### Linux / WSL
```bash
# 1. Installer Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# 2. Choisir et télécharger un modèle LLM
# Option A : llama3.2 (Recommandé - Équilibre performance/qualité)
ollama pull llama3.2

# Option B : qwen2.5:3b (Plus rapide, moins de RAM)
ollama pull qwen2.5:3b

# Option C : mistral (Alternative puissante)
ollama pull mistral

# 3. Démarrer le service Ollama
ollama serve &

# 4. Vérifier l'installation
ollama list
```

### macOS
```bash
# Option 1 : Homebrew
brew install ollama

# Option 2 : Application (https://ollama.ai)
# Télécharger et installer l'app

# Télécharger un modèle (choisir selon vos ressources)
ollama pull llama3.2        # Recommandé (4.7 GB)
# OU
ollama pull qwen2.5:3b      # Plus léger (1.9 GB)
# OU
ollama pull mistral         # Alternatif (4.1 GB)

# Démarrer
ollama serve &
```

### Windows
```powershell
# 1. Télécharger depuis https://ollama.ai/download
# 2. Installer l'application (.exe)
# 3. Ouvrir PowerShell et télécharger un modèle :

# Option recommandée
ollama pull llama3.2

# OU version plus légère
ollama pull qwen2.5:3b

# OU alternative
ollama pull mistral
```

### Comparaison des Modèles

| Modèle | Taille | RAM Requise | Vitesse | Qualité | Recommandation |
|--------|--------|-------------|---------|---------|----------------|
| **llama3.2** | 4.7 GB | 8-16 GB | Moyenne | ⭐⭐⭐⭐⭐ | **Recommandé** |
| **qwen2.5:3b** | 1.9 GB | 4-8 GB | Rapide | ⭐⭐⭐⭐ | PC limités |
| **mistral** | 4.1 GB | 8-16 GB | Moyenne | ⭐⭐⭐⭐⭐ | Alternative |

### Vérification de l'Installation
```bash
# Vérifier qu'Ollama fonctionne
curl http://localhost:11434/api/tags

# Devrait retourner :
# {"models":[{"name":"llama3.2:latest",...}]}

# Lister les modèles installés
ollama list

# Tester un modèle
ollama run llama3.2 "Bonjour"
```

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

**✅ Résultats disponibles dans 2-3 minutes** → `logs/alerts_*.json`

---

### Mode 2 : AVEC Ollama
```bash
# 1. Cloner
git clone https://github.com/majflower/ai-network-observer.git
cd ai-network-observer

# 2. Vérifier Ollama (doit retourner les modèles)
curl http://localhost:11434/api/tags

# 3. Configuration
cat > .env << 'EOF'
ENABLE_LLM=true
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2
EOF

# Si vous utilisez qwen2.5 ou mistral, changez OLLAMA_MODEL :
# OLLAMA_MODEL=qwen2.5:3b
# OU
# OLLAMA_MODEL=mistral

# 4. Lancer
docker-compose up -d

# 5. Vérifier la connexion LLM
docker-compose logs observer | grep -i ollama
# Devrait afficher : "✓ Connected to Ollama"
```

---

## 📊 Accès aux Dashboards

### Grafana (Visualisation)
- **URL** : http://localhost:3000
- **Login** : admin / networksecurity
- **Dashboards** : Network Security Overview, ML Anomaly Detection

### Neo4j (Graphe Réseau)
- **URL** : http://localhost:7474
- **Login** : neo4j / networksecurity
- **Query exemple** :
```cypher
MATCH (h:Host)-[r:DNS_QUERY]->(d:Domain)
WHERE d.risk_score > 50
RETURN h, r, d LIMIT 25
```

### Prometheus (Métriques)
- **URL** : http://localhost:9090
- **Query exemple** : `network_packets_total`

⚠️ **IMPORTANT** : Changez les mots de passe par défaut en production !

---

## 🧪 Tests & Validation

### Simuler des Attaques (Sur VM isolée uniquement ⚠️)
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
# Démarrer tous les services
docker-compose up -d

# Arrêter tous les services
docker-compose down

# Logs en temps réel
docker-compose logs -f observer

# État des services
docker-compose ps

# Redémarrer un service
docker-compose restart observer

# Voir les alertes
tail -f logs/alerts_*.json

# Changer de modèle LLM (sans redémarrage complet)
# 1. Modifier .env : OLLAMA_MODEL=qwen2.5:3b
# 2. Redémarrer observer : docker-compose restart observer
```

---

## 📚 Documentation Détaillée

- **[TESTING_GUIDE.md](TESTING_GUIDE.md)** - Guide de test complet
- **[ML_README.md](ML_README.md)** - Documentation Machine Learning

---

## ❓ FAQ

**Q : Ça ralentit mon réseau ?**  
R : Non, écoute passive sans interception.

**Q : C'est légal ?**  
R : Oui, sur VOTRE réseau/VM uniquement. Jamais sans autorisation.

**Q : Détection 100% fiable ?**  
R : Non, outil d'aide à la détection, pas de garantie absolue.

**Q : Observer ne capture rien ?**  
R : Vérifier l'interface réseau dans `docker-compose.yml` (ligne `CAPTURE_INTERFACE`)

**Q : Ollama connection refused ?**  
R : Vérifier qu'Ollama tourne : `ps aux | grep ollama` puis `ollama serve &`

**Q : Grafana vide ?**  
R : Normal au début, attendre 5-10 minutes de collecte.

**Q : Quel modèle LLM choisir ?**  
R : 
- **8+ GB RAM** → llama3.2 (recommandé)
- **4-8 GB RAM** → qwen2.5:3b (plus rapide)
- **Alternative** → mistral

**Q : Puis-je changer de modèle après installation ?**  
R : Oui ! Téléchargez le nouveau modèle (`ollama pull nom_modele`), modifiez `.env`, et redémarrez l'observer.

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

Projet de fin d'études - Master Cybersécurité 2026

**Objectifs pédagogiques :**
- ✅ Intégration ML/LLM pour la sécurité
- ✅ Architecture microservices Docker
- ✅ Stack monitoring complète (Prometheus, Grafana, Neo4j)
- ✅ Détection de menaces avancées (DGA, C2, DNS Tunneling)

---

## 🤝 Contribution

Issues & Pull Requests bienvenues sur [GitHub](https://github.com/majflower/ai-network-observer/issues)

---

## 📄 Licence

MIT License - Voir [LICENSE](LICENSE)

Copyright (c) 2026 MAJ (MAJFLOWER)

---

## 👤 Auteur

**MAJ (MAJFLOWER)**
- 🎓 Master Cybersécurité
- 🎯 Spécialisation : IA & Détection de Menaces Réseau
- 🔬 Projet de fin d'études : AI Network Observer

## 📧 Contact

- **GitHub** : [@majflower](https://github.com/majflower)
- **LinkedIn** : [bflore-maj](https://www.linkedin.com/in/bflore-maj/)
- **Projet** : [ai-network-observer](https://github.com/majflower/ai-network-observer)

---

<div align="center">

**⭐ Si ce projet vous aide, donnez-lui une étoile ! ⭐**

Made with ❤️ by MAJ for Cybersecurity Education

*Projet Master Cybersécurité - 2026*

</div>
