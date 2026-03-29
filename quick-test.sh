#!/bin/bash
# Test rapide avec session de 2 minutes

echo "=========================================="
echo "  Test Rapide AI Network Observer"
echo "=========================================="
echo ""

cd /home/maj/ai-network-observer/ai-network

# 1. Modifier durée
echo "[1/5] Configuration durée 2 minutes..."
sed -i 's/--duration", "[0-9]*"/--duration", "2"/g' docker-compose.yml
grep "duration" docker-compose.yml | grep command

# 2. Redémarrer
echo "[2/5] Redémarrage observer..."
docker-compose restart observer
sleep 5

# 3. Attendre début capture
echo "[3/5] Attente début capture..."
sleep 5

# 4. Générer trafic
echo "[4/5] Génération trafic (60 secondes)..."
for i in {1..10}; do
    echo "  Requête $i/10"
    nslookup google.com > /dev/null 2>&1
    curl -s https://github.com > /dev/null 2>&1
    sleep 5
done

# 5. Attendre fin analyse
echo "[5/5] Attente fin analyse (90 secondes)..."
sleep 90

# 6. Afficher résultats
echo ""
echo "=========================================="
echo "  RÉSULTATS"
echo "=========================================="

LATEST=$(ls -t logs/session_*_llm_analysis.json 2>/dev/null | head -1)

if [ -n "$LATEST" ]; then
    echo "✓ Analyse trouvée: $(basename $LATEST)"
    echo ""
    
    if command -v jq &> /dev/null; then
        echo "SEVERITY: $(cat $LATEST | jq -r '.analysis.severity')"
        echo "CONFIDENCE: $(cat $LATEST | jq -r '.analysis.confidence')%"
        echo "THREAT: $(cat $LATEST | jq -r '.analysis.threat_type')"
        echo ""
        echo "SUMMARY:"
        cat $LATEST | jq -r '.analysis.summary'
    else
        cat $LATEST
    fi
else
    echo "✗ Aucune analyse trouvée"
    echo "Vérifiez les logs:"
    echo "  docker-compose logs observer | tail -50"
fi

echo ""
echo "=========================================="
