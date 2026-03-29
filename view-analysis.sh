#!/bin/bash
cd logs
LATEST=$(ls -t session_*_llm_analysis.json | head -1)
echo "=== DERNIÈRE ANALYSE ==="
cat $LATEST | jq -r '
"SEVERITY: \(.analysis.severity)
CONFIDENCE: \(.analysis.confidence)%
THREAT: \(.analysis.threat_type)

SUMMARY:
\(.analysis.summary)

THREATS:
\(.analysis.threats | join("\n  - "))

RECOMMENDATIONS:
\(.analysis.recommendations | join("\n  - "))"
'
