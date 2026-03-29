#!/usr/bin/env python3
"""
Multi-session correlation analysis
"""
import json
import glob
from collections import defaultdict
from datetime import datetime, timedelta

def correlate_sessions(days=7):
    """Analyze patterns across multiple sessions"""
    
    # Load all sessions from last N days
    cutoff = datetime.now() - timedelta(days=days)
    sessions = []
    
    for file in glob.glob("logs/session_*_summary.json"):
        with open(file) as f:
            data = json.load(f)
            session_time = datetime.fromisoformat(data['start_time'])
            if session_time > cutoff:
                sessions.append(data)
    
    # Aggregate metrics
    total_dns = sum(s.get('total_dns_queries', 0) for s in sessions)
    total_threats = sum(len(s.get('dns_analysis', {}).get('suspicious_domains', [])) for s in sessions)
    
    # Find persistent threats
    all_domains = defaultdict(int)
    for session in sessions:
        for domain in session.get('dns_analysis', {}).get('suspicious_domains', []):
            all_domains[domain['domain']] += 1
    
    persistent = {d: c for d, c in all_domains.items() if c >= 3}
    
    print(f"=== CORRELATION ANALYSIS (Last {days} days) ===")
    print(f"Sessions analyzed: {len(sessions)}")
    print(f"Total DNS queries: {total_dns}")
    print(f"Total threats: {total_threats}")
    print(f"\nPersistent threats (seen 3+ times):")
    for domain, count in sorted(persistent.items(), key=lambda x: x[1], reverse=True):
        print(f"  - {domain}: {count} sessions")

if __name__ == "__main__":
    correlate_sessions()
