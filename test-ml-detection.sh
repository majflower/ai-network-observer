#!/bin/bash
# Test ML detection on latest session

echo "🔍 Testing ML Detection..."

python3 << 'EOFPY'
import sys
import json
import glob
sys.path.insert(0, '/app')

from src.ml.anomaly_detector import NetworkAnomalyDetector

# Load latest session
sessions = sorted(glob.glob('logs/session_*_summary.json'))
if not sessions:
    print("No sessions found")
    sys.exit(1)

with open(sessions[-1]) as f:
    session = json.load(f)

# Load model and predict
detector = NetworkAnomalyDetector()
try:
    detector.load('models/baseline_model.pkl')
    result = detector.predict(session)
    
    print(f"Session: {sessions[-1].split('/')[-1]}")
    print(f"Anomaly: {result['is_anomaly']}")
    print(f"Score: {result['score']:.3f}")
    print(f"Confidence: {result['confidence']}%")
except Exception as e:
    print(f"Error: {e}")
EOFPY
