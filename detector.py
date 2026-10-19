from __future__ import annotations
import os
from typing import List
import lightgbm as lgb
from feature_extraction import FEATURE_NAMES, WindowFeatures

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "ransomware_lgbm.txt")


class RansomwareDetector:
    def __init__(self, model_path: str = MODEL_PATH, threshold: float = 0.7):
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"No model at {model_path}. Run train_model.py first."
            )
        self.booster = lgb.Booster(model_file=model_path)
        self.threshold = threshold

    def score(self, window: WindowFeatures):
        vector = [window.as_vector()]
        return float(self.booster.predict(vector)[0])

    def is_suspicious(self, window: WindowFeatures):
        return self.score(window) >= self.threshold

    def score_many(self, windows: List[WindowFeatures]):
        if not windows:
            return []
        matrix = [w.as_vector() for w in windows]
        return list(self.booster.predict(matrix))

    def explain(self, window: WindowFeatures):
        importances = dict(
            zip(FEATURE_NAMES, self.booster.feature_importance(importance_type="gain"))
        )
        vector = dict(zip(FEATURE_NAMES, window.as_vector()))
        ranked = sorted(importances.items(), key=lambda kv: kv[1], reverse=True)
        top_features = [
            {"feature": name, "value": vector[name], "importance": imp}
            for name, imp in ranked[:5]
        ]
        return {"score": self.score(window), "top_features": top_features}