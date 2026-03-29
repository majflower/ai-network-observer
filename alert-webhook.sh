#!/bin/bash
# Envoyer alerte sur Slack/Discord

LOGS_DIR="/home/maj/ai-network-observer/ai-network/logs"

# Surveiller les fichiers ALERT
inotifywait -m -e create $LOGS_DIR |
while read path action file; do
    if [[ "$file" == *"ALERT.json" ]]; then
        SEVERITY=$(cat $LOGS_DIR/$file | jq -r '.severity')
        THREAT=$(cat $LOGS_DIR/$file | jq -r '.threat_type')
        SUMMARY=$(cat $LOGS_DIR/$file | jq -r '.summary')
        
        # Webhook Slack
        curl -X POST https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
          -H 'Content-Type: application/json' \
          -d "{
            \"text\": \"🚨 SECURITY ALERT\",
            \"attachments\": [{
              \"color\": \"danger\",
              \"fields\": [
                {\"title\": \"Severity\", \"value\": \"$SEVERITY\", \"short\": true},
                {\"title\": \"Threat\", \"value\": \"$THREAT\", \"short\": true},
                {\"title\": \"Summary\", \"value\": \"$SUMMARY\"}
              ]
            }]
          }"
    fi
done
