#!/usr/bin/env python3
"""ML Training Pipeline"""

import glob
import json
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class MLTrainingPipeline:
    """Automated ML training and retraining"""
    
    def __init__(self, logs_dir='./logs', model_dir='./models'):
        self.logs_dir = logs_dir
        self.model_dir = model_dir
    
    def load_historical_sessions(self, days=7):
        """Load session summaries from last N days"""
        cutoff = datetime.now() - timedelta(days=days)
        sessions = []
        
        pattern = f"{self.logs_dir}/session_*_summary.json"
        
        for filepath in glob.glob(pattern):
            try:
                with open(filepath, 'r') as f:
                    session = json.load(f)
                
                # Check if recent enough
                session_time = datetime.fromisoformat(
                    session['start_time'].replace('Z', '+00:00')
                )
                
                if session_time > cutoff:
                    sessions.append(session)
            except Exception as e:
                logger.warning(f"Failed to load {filepath}: {e}")
        
        logger.info(f"Loaded {len(sessions)} sessions from last {days} days")
        return sessions
    
    def train_model(self):
        """Train ML model on historical data"""
        from src.ml.anomaly_detector import NetworkAnomalyDetector
        
        # Load data
        sessions = self.load_historical_sessions(days=30)
        
        if len(sessions) < 10:
            logger.error(f"Not enough sessions ({len(sessions)}), need 10+")
            return False
        
        # Train
        detector = NetworkAnomalyDetector()
        success = detector.train(sessions)
        
        if success:
            # Save
            import os
            os.makedirs(self.model_dir, exist_ok=True)
            detector.save(f"{self.model_dir}/baseline_model.pkl")
            logger.info("✓ Model trained and saved")
            return True
        
        return False
    
    def evaluate_model(self):
        """Evaluate model performance"""
        # Load test data
        sessions = self.load_historical_sessions(days=7)
        
        if len(sessions) < 5:
            return None
        
        from src.ml.anomaly_detector import NetworkAnomalyDetector
        
        # Load model
        detector = NetworkAnomalyDetector()
        try:
            detector.load(f"{self.model_dir}/baseline_model.pkl")
        except:
            logger.error("No model to evaluate")
            return None
        
        # Predict on each session
        results = []
        for session in sessions:
            pred = detector.predict(session)
            results.append(pred)
        
        # Calculate metrics
        anomalies = sum(1 for r in results if r['is_anomaly'])
        avg_confidence = sum(r['confidence'] for r in results) / len(results)
        
        metrics = {
            'total_sessions': len(sessions),
            'anomalies_detected': anomalies,
            'anomaly_rate': anomalies / len(sessions),
            'avg_confidence': avg_confidence
        }
        
        logger.info(f"Model evaluation: {metrics}")
        return metrics
