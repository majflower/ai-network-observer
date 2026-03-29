#!/usr/bin/env python3
"""
ML-based baseline establishment
"""
import json
import glob
import numpy as np
from sklearn.ensemble import IsolationForest

def create_baseline():
    """Create ML baseline from historical data"""
    
    features = []
    
    for file in glob.glob("logs/session_*_summary.json"):
        with open(file) as f:
            data = json.load(f)
            
            # Extract features
            feature_vector = [
                data.get('total_dns_queries', 0),
                data.get('total_http_requests', 0),
                data.get('duration_minutes', 0),
                len(data.get('dns_analysis', {}).get('suspicious_domains', [])),
                data.get('graph_analysis', {}).get('total_nodes', 0)
            ]
            features.append(feature_vector)
    
    # Train Isolation Forest
    X = np.array(features)
    clf = IsolationForest(contamination=0.1, random_state=42)
    clf.fit(X)
    
    print(f"Baseline created from {len(features)} sessions")
    print(f"Normal behavior profile established")
    
    # Save model
    import pickle
    with open('baseline_model.pkl', 'wb') as f:
        pickle.dump(clf, f)
    
    return clf

if __name__ == "__main__":
    create_baseline()
