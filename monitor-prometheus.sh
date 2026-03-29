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
