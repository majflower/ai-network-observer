#!/usr/bin/env python3
"""ML-based Anomaly Detection"""

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
import numpy as np
import logging

logger = logging.getLogger(__name__)

class NetworkAnomalyDetector:
    """Isolation Forest for network anomaly detection"""
    
    def __init__(self):
        self.model = IsolationForest(
            contamination=0.15,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.feature_names = None
        self.is_trained = False
    
    def train(self, sessions):
        """Train on historical sessions"""
        from src.ml.feature_extractor import NetworkFeatureExtractor
        
        if len(sessions) < 10:
            logger.warning(f"Only {len(sessions)} sessions, need 10+ for training")
            return False
        
        extractor = NetworkFeatureExtractor()
        
        # Extract features
        features_list = []
        for session in sessions:
            try:
                features = extractor.extract_features(session)
                features_list.append(features)
            except Exception as e:
                logger.warning(f"Feature extraction failed: {e}")
        
        if not features_list:
            return False
        
        # Convert to array
        import pandas as pd
        df = pd.DataFrame(features_list).fillna(0)
        self.feature_names = df.columns.tolist()
        
        # Normalize
        X = self.scaler.fit_transform(df)
        
        # Train
        logger.info(f"Training on {len(X)} sessions...")
        self.model.fit(X)
        self.is_trained = True
        
        logger.info("✓ ML model trained successfully")
        return True
    
    def predict(self, session):
        """Predict if session is anomalous"""
        if not self.is_trained:
            return {
                'is_anomaly': False,
                'score': 0,
                'confidence': 0
            }
        
        from src.ml.feature_extractor import NetworkFeatureExtractor
        
        # Extract features
        extractor = NetworkFeatureExtractor()
        features = extractor.extract_features(session)
        
        # Convert to array
        import pandas as pd
        df = pd.DataFrame([features]).reindex(columns=self.feature_names, fill_value=0)
        
        # Predict
        X = self.scaler.transform(df)
        prediction = self.model.predict(X)[0]
        score = self.model.score_samples(X)[0]
        
        # Convert to confidence
        confidence = int((score + 0.5) * 100)
        confidence = max(0, min(100, confidence))
        
        return {
            'is_anomaly': prediction == -1,
            'score': float(score),
            'confidence': confidence,
            'features': features
        }
    
    def save(self, path):
        """Save model"""
        data = {
            'model': self.model,
            'scaler': self.scaler,
            'features': self.feature_names,
            'trained': self.is_trained
        }
        with open(path, 'wb') as f:
            pickle.dump(data, f)
        logger.info(f"✓ Model saved to {path}")
    
    def load(self, path):
        """Load model"""
        with open(path, 'rb') as f:
            data = pickle.load(f)
        self.model = data['model']
        self.scaler = data['scaler']
        self.feature_names = data['features']
        self.is_trained = data['trained']
        logger.info(f"✓ Model loaded from {path}")
