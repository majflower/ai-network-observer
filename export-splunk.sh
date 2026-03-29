#!/bin/bash
# Forward alerts to Splunk

SPLUNK_HEC="http://splunk-server:8088/services/collector"
SPLUNK_TOKEN="your-hec-token"

for alert in logs/*_ALERT.json; do
    curl -k $SPLUNK_HEC \
      -H "Authorization: Splunk $SPLUNK_TOKEN" \
      -d @$alert
done
