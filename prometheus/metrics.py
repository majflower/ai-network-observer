{
  "dashboard": {
    "title": "AI Network Observer - Security Overview",
    "tags": ["network", "security", "ai"],
    "timezone": "browser",
    "schemaVersion": 38,
    "version": 1,
    "refresh": "10s",
    
    "panels": [
      {
        "id": 1,
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
        "type": "stat",
        "title": "Current Risk Score",
        "targets": [{
          "expr": "network_risk_score",
          "refId": "A",
          "datasource": {"type": "prometheus", "uid": "prometheus"}
        }],
        "fieldConfig": {
          "defaults": {
            "thresholds": {
              "mode": "absolute",
              "steps": [
                {"value": 0, "color": "green"},
                {"value": 40, "color": "yellow"},
                {"value": 70, "color": "red"}
              ]
            },
            "unit": "short",
            "min": 0,
            "max": 100
          }
        }
      },
      
      {
        "id": 2,
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
        "type": "stat",
        "title": "Active Threats",
        "targets": [{
          "expr": "sum(rate(dns_high_risk_total[5m])) + sum(rate(http_attacks_total[5m]))",
          "refId": "A"
        }],
        "fieldConfig": {
          "defaults": {
            "color": {"mode": "thresholds"},
            "thresholds": {
              "steps": [
                {"value": 0, "color": "green"},
                {"value": 1, "color": "orange"},
                {"value": 10, "color": "red"}
              ]
            }
          }
        }
      },
      
      {
        "id": 3,
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8},
        "type": "timeseries",
        "title": "Threat Activity Over Time",
        "targets": [
          {
            "expr": "rate(dns_dga_detected_total[1m])",
            "legendFormat": "DGA Detected",
            "refId": "A"
          },
          {
            "expr": "rate(dns_tunneling_detected_total[1m])",
            "legendFormat": "DNS Tunneling",
            "refId": "B"
          },
          {
            "expr": "rate(dns_beaconing_detected_total[1m])",
            "legendFormat": "C2 Beaconing",
            "refId": "C"
          },
          {
            "expr": "rate(http_attacks_total[1m])",
            "legendFormat": "HTTP Attacks",
            "refId": "D"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "custom": {
              "drawStyle": "line",
              "lineInterpolation": "smooth",
              "fillOpacity": 10
            }
          }
        }
      },
      
      {
        "id": 4,
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16},
        "type": "piechart",
        "title": "Threats by Type",
        "targets": [
          {
            "expr": "sum by (threat_type) (rate(network_threats_total[5m]))",
            "legendFormat": "{{threat_type}}",
            "refId": "A"
          }
        ]
      },
      
      {
        "id": 5,
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16},
        "type": "gauge",
        "title": "Packet Processing Rate",
        "targets": [{
          "expr": "rate(packets_processed_total[1m])",
          "refId": "A"
        }],
        "fieldConfig": {
          "defaults": {
            "unit": "pps",
            "thresholds": {
              "steps": [
                {"value": 0, "color": "green"},
                {"value": 500, "color": "yellow"},
                {"value": 1000, "color": "red"}
              ]
            }
          }
        }
      },
      
      {
        "id": 6,
        "gridPos": {"h": 10, "w": 24, "x": 0, "y": 24},
        "type": "table",
        "title": "Recent High-Risk Domains",
        "targets": [{
          "expr": "topk(10, dns_domain_risk_score)",
          "refId": "A",
          "format": "table"
        }],
        "transformations": [{
          "id": "organize",
          "options": {
            "excludeByName": {"Time": true},
            "indexByName": {},
            "renameByName": {
              "domain": "Domain",
              "Value": "Risk Score"
            }
          }
        }]
      },
      
      {
        "id": 7,
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 34},
        "type": "graph",
        "title": "LLM Analysis Response Time",
        "targets": [{
          "expr": "histogram_quantile(0.95, rate(llm_analysis_duration_seconds_bucket[5m]))",
          "legendFormat": "95th percentile",
          "refId": "A"
        }],
        "yaxes": [{"format": "s"}]
      },
      
      {
        "id": 8,
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 34},
        "type": "stat",
        "title": "LLM Analysis Success Rate",
        "targets": [{
          "expr": "rate(llm_analysis_success_total[5m]) / (rate(llm_analysis_success_total[5m]) + rate(llm_analysis_errors_total[5m]))",
          "refId": "A"
        }],
        "fieldConfig": {
          "defaults": {
            "unit": "percentunit",
            "thresholds": {
              "steps": [
                {"value": 0, "color": "red"},
                {"value": 0.9, "color": "yellow"},
                {"value": 0.95, "color": "green"}
              ]
            }
          }
        }
      },
      
      {
        "id": 9,
        "gridPos": {"h": 10, "w": 24, "x": 0, "y": 42},
        "type": "logs",
        "title": "Security Event Logs",
        "targets": [{
          "expr": "{job=\"network-observer\", level=~\"warning|error|critical\"}",
          "refId": "A",
          "datasource": {"type": "elasticsearch", "uid": "elasticsearch"}
        }]
      }
    ],
    
    "templating": {
      "list": [
        {
          "name": "interval",
          "type": "interval",
          "query": "1m,5m,10m,30m,1h",
          "current": {"text": "5m", "value": "5m"}
        }
      ]
    },
    
    "annotations": {
      "list": [{
        "datasource": {"type": "prometheus", "uid": "prometheus"},
        "enable": true,
        "expr": "ALERTS{alertstate=\"firing\"}",
        "name": "Active Alerts",
        "tagKeys": "alertname,severity"
      }]
    }
  },
  
  "folderId": 0,
  "overwrite": true
}
