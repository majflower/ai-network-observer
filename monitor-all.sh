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
