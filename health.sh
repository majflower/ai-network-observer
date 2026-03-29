#!/bin/bash
# Check system health

echo "=== Network Observer Health Check ==="

# Check containers
docker-compose ps | grep -q "Up" && echo "✓ Containers running" || echo "✗ Containers down"

# Check Ollama
curl -s http://localhost:11434/api/tags > /dev/null && echo "✓ Ollama connected" || echo "✗ Ollama unreachable"

# Check logs directory
[ -d logs ] && [ "$(ls -A logs)" ] && echo "✓ Logs present" || echo "⚠ No logs"

# Check latest analysis
LATEST=$(ls -t logs/session_*_llm_analysis.json 2>/dev/null | head -1)
if [ -n "$LATEST" ]; then
    AGE=$(($(date +%s) - $(stat -c %Y $LATEST)))
    if [ $AGE -lt 3600 ]; then
        echo "✓ Recent analysis (${AGE}s ago)"
    else
        echo "⚠ Last analysis was $((AGE/60)) minutes ago"
    fi
fi
