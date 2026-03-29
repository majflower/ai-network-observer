# 🧪 GUIDE DE TEST - AI Network Observer

> Comment les utilisateurs peuvent tester votre projet

---

## 🚀 Quick Test (5 minutes)

Pour tester rapidement sans installation complète :

### Option 1: Docker Hub (Recommandé)

```bash
# Pull image pré-compilée
docker pull yourusername/ai-network-observer:latest

# Run avec config minimale
docker run -d \
  --name ai-observer-test \
  --network host \
  -e OLLAMA_BASE_URL=http://host.docker.internal:11434 \
  -e ENABLE_LLM=false \
  yourusername/ai-network-observer:latest

# Voir les résultats après 2 min
docker exec ai-observer-test ls /app/logs/
docker exec ai-observer-test cat /app/logs/session_*_summary.json
```

### Option 2: Docker Compose Simple

```bash
git clone https://github.com/yourusername/ai-network-observer.git
cd ai-network-observer

# Test minimal (sans Ollama)
cat > docker-compose.test.yml << 'EOF'
version: '3.8'
services:
  observer:
    build: ./ai-network
    network_mode: host
    environment:
      - ENABLE_LLM=false
    command: ["-i", "eth0", "--duration", "1"]
    volumes:
      - ./test-results:/app/logs
EOF

docker-compose -f docker-compose.test.yml up

# Résultats dans test-results/ après 1 min
```

---

## 🎯 Test Complet (30 minutes)

### Étape 1: Installation

```bash
# Clone
git clone https://github.com/yourusername/ai-network-observer.git
cd ai-network-observer/ai-network

# Configuration
cp .env.example .env

# Si vous n'avez pas Ollama, désactiver LLM
sed -i 's/ENABLE_LLM=true/ENABLE_LLM=false/' .env

# Démarrer stack complet
docker-compose up -d

# Vérifier services
docker-compose ps
```

### Étape 2: Génération de Trafic

```bash
# Option A: Automatique (script fourni)
./tests/generate-test-traffic.sh

# Option B: Manuel
# Terminal 1: Trafic normal
for i in {1..10}; do
    curl -s https://google.com > /dev/null
    nslookup github.com
    sleep 5
done

# Terminal 2: Trafic suspect (simulation DGA)
for i in {1..5}; do
    nslookup $(head /dev/urandom | tr -dc a-z | head -c 12).com
    sleep 3
done
```

### Étape 3: Voir Résultats

```bash
# Logs en temps réel
docker-compose logs -f observer

# Analyses générées
ls -lh logs/

# Dernière analyse
cat logs/session_*_summary.json | tail -1 | jq .

# Dashboards
firefox http://localhost:3000  # Grafana
firefox http://localhost:7474  # Neo4j
```

---

## 🧪 Scénarios de Test

### Test 1: Détection DGA

**Objectif**: Vérifier détection de Domain Generation Algorithm

```bash
# Générer domaines aléatoires (malware simulation)
./tests/simulate-dga.sh

# OU manuel:
for i in {1..10}; do
    random_domain=$(head /dev/urandom | tr -dc a-z | head -c 15)
    nslookup ${random_domain}.com
    sleep 2
done

# Vérifier détection
cat logs/session_*_summary.json | jq '.dns_analysis.summary.dga_detected'
# Devrait être > 0
```

### Test 2: Détection C2 Beaconing

**Objectif**: Détecter communication régulière (Command & Control)

```bash
# Requêtes à intervalle régulier
./tests/simulate-c2.sh

# OU manuel:
for i in {1..15}; do
    curl -s http://example-c2.com
    sleep 10  # Intervalle régulier = suspect
done

# Vérifier
cat logs/session_*_summary.json | jq '.dns_analysis.summary.beaconing_detected'
```

### Test 3: Détection DNS Tunneling

**Objectif**: Identifier exfiltration via DNS

```bash
# Longues requêtes DNS (data exfil)
./tests/simulate-dns-tunnel.sh

# OU manuel:
for i in {1..5}; do
    long_query=$(head /dev/urandom | tr -dc a-z0-9 | head -c 200)
    nslookup ${long_query}.tunnel.example.com
    sleep 3
done

# Vérifier
cat logs/session_*_summary.json | jq '.dns_analysis.summary.tunneling_detected'
```

### Test 4: ML Anomaly Detection

**Objectif**: Tester modèle ML (nécessite training)

```bash
# 1. Générer baseline (10 sessions normales)
for i in {1..10}; do
    curl -s https://google.com > /dev/null
    sleep 130  # 2min + marge
    docker-compose restart observer
done

# 2. Entraîner modèle
./train-ml-model.sh

# 3. Générer trafic anormal
./tests/simulate-dga.sh

# 4. Vérifier détection ML
./test-ml-detection.sh
```

---

## 📊 Benchmarks & Performance

### Test de Charge

```bash
# Générer beaucoup de trafic
./tests/load-test.sh

# Mesurer performance
docker stats observer

# Métriques attendues:
# - CPU: <30% (capture normale)
# - RAM: <500MB
# - Latence détection: <100ms
```

### Test de Précision

```bash
# Dataset de test fourni
./tests/evaluate-model.sh

# Résultats attendus:
# - Précision: >90%
# - Faux positifs: <10%
# - Recall: >85%
```

---

## 🐛 Troubleshooting

### Observer ne démarre pas

```bash
# Vérifier logs
docker-compose logs observer

# Problèmes fréquents:
# 1. Interface réseau invalide
docker-compose exec observer ip link show

# 2. Permission denied
docker-compose exec observer id
# Devrait être root ou avoir CAP_NET_RAW

# 3. Ollama inaccessible (si LLM activé)
curl http://localhost:11434/api/tags
```

### Pas d'analyses générées

```bash
# Vérifier durée session
docker-compose logs observer | grep "Session duration"

# Vérifier captures
docker-compose exec observer ls -lh /app/logs/

# Forcer nouvelle session
docker-compose restart observer
```

### Grafana vide

```bash
# Vérifier Prometheus targets
curl -s http://localhost:9090/api/v1/targets | jq .

# Vérifier métriques exposées
curl -s http://localhost:8080/metrics | head

# Si vide: métriques non implémentées (feature optionnelle)
```

---

## ✅ Validation Checklist

Après tests, vous devriez avoir :

**Fonctionnel**
- [ ] Observer capture du trafic
- [ ] Fichiers JSON générés dans logs/
- [ ] Analyses DNS/HTTP/TLS présentes
- [ ] Graphe réseau exporté

**Détection**
- [ ] DGA détecté sur trafic simulé
- [ ] C2 beaconing identifié
- [ ] DNS tunneling flaggé
- [ ] Anomalies réseau trouvées

**ML (si entraîné)**
- [ ] Modèle créé dans models/
- [ ] Prédictions fonctionnelles
- [ ] Précision >80%

**Dashboards (optionnel)**
- [ ] Grafana accessible
- [ ] Neo4j importe graphe
- [ ] Prometheus scrape métriques

---

## 📝 Rapporter un Bug

Si vous trouvez un bug :

```bash
# Collecter infos debug
./scripts/collect-debug-info.sh

# Créer issue GitHub avec:
# 1. Logs: debug-info.tar.gz
# 2. Config: .env (sans secrets)
# 3. Commande exécutée
# 4. Comportement attendu vs obtenu
```

---

## 🤝 Contribuer

Après avoir testé, vous pouvez :

1. **Améliorer les tests**
   - Ajouter scénarios dans tests/
   - Améliorer datasets

2. **Optimiser détection**
   - Tuner seuils ML
   - Ajouter features

3. **Documentation**
   - Corriger README
   - Ajouter exemples

4. **Partager résultats**
   - Twitter: @mention
   - LinkedIn: tag dans post
   - GitHub: star + fork

---

## 🎓 Tests Académiques

Pour évaluation universitaire :

### Méthodologie

```bash
# 1. Baseline establishment (1 semaine)
# Capturer trafic normal quotidien

# 2. Model training
./train-ml-model.sh

# 3. Attack simulation
./tests/all-attack-scenarios.sh

# 4. Evaluation
./tests/evaluate-performance.sh

# 5. Report generation
./scripts/generate-academic-report.sh
```

### Métriques Collectées

- True Positive Rate (TPR)
- False Positive Rate (FPR)
- Precision, Recall, F1-Score
- Detection latency
- Resource usage

---

## 📞 Support

**Questions ?**
- GitHub Issues: [lien]
- Email: your-email@example.com
- LinkedIn: [profil]

**Temps de réponse:** <48h

---

**Merci de tester AI Network Observer !** 🚀

Si le projet vous plaît :
⭐ Star sur GitHub
🔄 Partage sur LinkedIn
💬 Feedback apprécié
