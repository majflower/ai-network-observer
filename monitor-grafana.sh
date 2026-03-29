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
