# 🤖 AI/ML Automation Features

## Quick Start

### 1. Train ML Model (First Time)

```bash
./train-ml-model.sh
```

Requires: 10+ historical sessions in `logs/`

### 2. Test ML Detection

```bash
./test-ml-detection.sh
```

### 3. Run Observer with ML

```bash
docker-compose up observer
# ML detection runs automatically
```

---

## Features

### ✅ Machine Learning
- **Baseline Learning**: Isolation Forest for anomaly detection
- **Feature Engineering**: 30+ network behavioral features
- **Auto-Training**: Periodic model retraining on historical data

### ✅ Automation
- **Auto-Remediation**: Automated response to threats
- **Playbook Execution**: Pre-defined response workflows
- **SOAR Integration**: TheHive, Cortex compatibility

### ✅ Hybrid Approach
- **ML** (fast): Real-time anomaly scoring
- **LLM** (deep): Detailed threat analysis when needed

---

## Architecture

```
Session → Feature Extraction → ML Model → Anomaly?
                                    ↓ Yes
                         LLM Deep Analysis → Remediation
                                    ↓
                              SOAR Alert
```

---

## Configuration

Edit `config/ml_config.json`:

```json
{
  "ml": {
    "enabled": true,
    "model_path": "models/baseline_model.pkl",
    "contamination": 0.15,
    "auto_retrain": true,
    "retrain_days": 7
  },
  "automation": {
    "auto_execute": false,
    "require_approval": ["CRITICAL", "HIGH"]
  },
  "soar": {
    "enabled": false,
    "thehive_url": "http://localhost:9000",
    "api_key": "your-key-here"
  }
}
```

---

## Playbooks

Located in `playbooks/`:

- `dga_malware.json` - DGA detection response
- `c2_beaconing.json` - C2 communication response
- `dns_tunneling.json` - DNS tunneling response

---

## Metrics

View ML performance:

```bash
python3 -c "
from src.ml.training_pipeline import MLTrainingPipeline
p = MLTrainingPipeline()
print(p.evaluate_model())
"
```
