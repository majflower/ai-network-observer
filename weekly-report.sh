#!/bin/bash
echo "# Network Security Report - $(date +%Y-%m-%d)"
echo ""
echo "## Sessions Analyzed"
ls -1 logs/session_*_summary.json | wc -l

echo ""
echo "## Threat Distribution"
cat logs/session_*_llm_analysis.json | jq -r '.analysis.severity' | sort | uniq -c

echo ""
echo "## Most Common Threats"
cat logs/session_*_llm_analysis.json | jq -r '.analysis.threats[]' | sort | uniq -c | sort -rn | head -5
