#!/bin/bash
# Train ML model on historical data

echo "🤖 Training ML Model..."

python3 << 'EOFPY'
import sys
sys.path.insert(0, '/home/maj/ai-network-observer/ai-network')

from src.ml.training_pipeline import MLTrainingPipeline

pipeline = MLTrainingPipeline()
success = pipeline.train_model()

if success:
    print("✓ Model trained successfully")
    metrics = pipeline.evaluate_model()
    if metrics:
        print(f"✓ Evaluation: {metrics}")
else:
    print("✗ Training failed")
EOFPY
