import joblib
import pandas as pd
import numpy as np
from typing import Tuple, List, Union
from .traffic_analyzer import TrafficAnalyzer, DataValidationError
from .feature_schema import EXPECTED_FEATURES

class Predictor:
    """Central engine for loading the ML pipeline and generating predictions."""
    
    def __init__(
        self, 
        model_path: str = "models/nids_pipeline.pkl", 
        encoder_path: str = "models/label_encoder.pkl",
        unsupervised_path: str = "models/isolation_forest_pipeline.pkl"
    ):
        self.model_path = model_path
        self.encoder_path = encoder_path
        self.unsupervised_path = unsupervised_path
        self.pipeline = None
        self.label_encoder = None
        self.unsupervised_pipeline = None
        self._load_model()
        
    def _load_model(self):
        try:
            self.pipeline = joblib.load(self.model_path)
            try:
                self.label_encoder = joblib.load(self.encoder_path)
            except FileNotFoundError:
                self.label_encoder = None
        except FileNotFoundError:
            raise RuntimeError(f"Could not load the saved pipeline from {self.model_path}. Ensure it exists.")

        # Load Unsupervised Isolation Forest if present
        try:
            self.unsupervised_pipeline = joblib.load(self.unsupervised_path)
        except FileNotFoundError:
            self.unsupervised_pipeline = None
            
    def predict_batch(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Predict a batch of flows. Returns (predictions, probabilities)."""
        # Validate and sanitize features
        clean_df = TrafficAnalyzer.validate_and_prepare(df)
        
        # Predict using the loaded pipeline (this applies scaling & encoding automatically)
        preds = self.pipeline.predict(clean_df)
        
        if self.label_encoder:
            preds = self.label_encoder.inverse_transform(preds)
            
        # Get probabilities if the model supports it
        probs = None
        if hasattr(self.pipeline, "predict_proba"):
            probs = self.pipeline.predict_proba(clean_df)
            probs = np.max(probs, axis=1) # Get the confidence of the predicted class
            
        return preds, probs
    
    def predict_single(self, flow_data: dict) -> Tuple[str, Union[float, None]]:
        """Predict a single flow from a dictionary."""
        df = pd.DataFrame([flow_data])
        preds, probs = self.predict_batch(df)
        return preds[0], probs[0] if probs is not None else None

    def predict_unsupervised_batch(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Unsupervised anomaly prediction using Isolation Forest.
        Returns: (is_anomaly_array, anomaly_scores, labels)
        """
        if self.unsupervised_pipeline is None:
            return np.zeros(len(df), dtype=bool), np.zeros(len(df)), np.array(["Unknown"] * len(df))
            
        clean_df = TrafficAnalyzer.validate_and_prepare(df)
        # Isolation Forest: +1 = inlier (Normal), -1 = outlier (Anomaly)
        raw_preds = self.unsupervised_pipeline.predict(clean_df)
        is_anomaly = (raw_preds == -1)
        
        # Score: higher = more anomalous
        detector = self.unsupervised_pipeline.named_steps.get('detector')
        prep = self.unsupervised_pipeline.named_steps.get('preprocessor')
        if detector and prep:
            transformed = prep.transform(clean_df)
            scores = -detector.decision_function(transformed)
        else:
            scores = np.zeros(len(df))
            
        labels = np.where(is_anomaly, "Anomaly", "Normal")
        return is_anomaly, scores, labels

    def predict_unsupervised_single(self, flow_data: dict) -> dict:
        """Evaluate a single flow using the unsupervised Isolation Forest model."""
        if self.unsupervised_pipeline is None:
            return {
                "active": False,
                "model": "Isolation Forest",
                "label": "Not Loaded",
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "interpretation": "Unsupervised model not found"
            }
        
        df = pd.DataFrame([flow_data])
        is_anomaly, scores, labels = self.predict_unsupervised_batch(df)
        
        score_val = float(scores[0])
        flagged = bool(is_anomaly[0])
        
        interpretation = (
            "Flagged as Statistical Outlier (Zero-Day Anomaly) — unusual traffic velocity/byte distribution isolated at shallow tree depth."
            if flagged else
            "Conforms to Baseline Normal Network Profile — required deep random partitions to isolate."
        )
        
        return {
            "active": True,
            "model": "Isolation Forest (Unsupervised)",
            "label": labels[0],
            "is_anomaly": flagged,
            "anomaly_score": round(score_val, 4),
            "score_pct": f"{min(max((score_val + 0.5) * 100, 0), 100):.1f}%",
            "interpretation": interpretation
        }

