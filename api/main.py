import os
import sys
import io
from datetime import datetime
from typing import List, Optional
import pandas as pd
import numpy as np

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


# Ensure root directory is on Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.predictor import Predictor
from src.risk_engine import RiskEngine
from src.traffic_analyzer import TrafficAnalyzer, DataValidationError
from src.alert_manager import AlertManager
from src.history_manager import HistoryManager
from src.explainer import ExplainabilityEngine
from src.counterfactual import CounterfactualEngine
from src.soc_copilot import SOCCopilot
from src.feature_schema import EXPECTED_FEATURES, CATEGORICAL_OPTIONS
from api.schemas import (
    NetworkFlow, PredictionResponse, BatchPredictionResponse,
    SimulationRequest, SimulationResponse, ExplanationResponse, CounterfactualResponse,
    ChatRequest, ChatResponse
)

app = FastAPI(
    title="CyberGuard XAI-NIDS API with Gemini AI Copilot",
    description="Production REST API for Explainable Machine Learning Network Intrusion Detection, Counterfactual Robustness, and AI SOC Copilot",
    version="2.2.0"
)

# Enable CORS for external integrations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Static assets and Templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Initialize Core Engines
MODEL_PATH = "models/nids_pipeline.pkl"
ENCODER_PATH = "models/label_encoder.pkl"

predictor = Predictor(model_path=MODEL_PATH, encoder_path=ENCODER_PATH)
alert_mgr = AlertManager(log_path="logs/alerts.csv")
history_mgr = HistoryManager(log_path="logs/analysis_history.csv")
explainer = ExplainabilityEngine(predictor=predictor)
cf_engine = CounterfactualEngine(predictor=predictor)
copilot = SOCCopilot()

# Preset attack & normal flow samples for instant UI demonstration
PRESETS = {
    "normal_web": {
        "title": "Normal Web Browsing (HTTP/HTTPS)",
        "type": "Normal",
        "data": {
            "duration": 1.25,
            "protocol": "TCP",
            "service": "HTTPS",
            "src_bytes": 1420.0,
            "dst_bytes": 4890.0,
            "src_packets": 12.0,
            "dst_packets": 18.0,
            "src_dst_byte_ratio": 0.29,
            "packets_per_second": 24.0,
            "bytes_per_second": 5048.0,
            "tcp_flags": "ACK"
        }
    },
    "dos_flood": {
        "title": "SYN Flood / DoS Burst",
        "type": "DoS",
        "data": {
            "duration": 0.08,
            "protocol": "TCP",
            "service": "HTTP",
            "src_bytes": 6200.0,
            "dst_bytes": 120.0,
            "src_packets": 85.0,
            "dst_packets": 5.0,
            "src_dst_byte_ratio": 51.6,
            "packets_per_second": 1125.0,
            "bytes_per_second": 79000.0,
            "tcp_flags": "SYN"
        }
    },
    "probe_scan": {
        "title": "Port Scanning / Probe Recon",
        "type": "Probe",
        "data": {
            "duration": 0.04,
            "protocol": "TCP",
            "service": "OTHER",
            "src_bytes": 480.0,
            "dst_bytes": 85.0,
            "src_packets": 8.0,
            "dst_packets": 2.0,
            "src_dst_byte_ratio": 5.64,
            "packets_per_second": 250.0,
            "bytes_per_second": 14125.0,
            "tcp_flags": "RST"
        }
    },
    "brute_force": {
        "title": "SSH / Telnet Brute Force Attempt",
        "type": "Brute_Force",
        "data": {
            "duration": 0.45,
            "protocol": "TCP",
            "service": "SSH",
            "src_bytes": 680.0,
            "dst_bytes": 410.0,
            "src_packets": 32.0,
            "dst_packets": 30.0,
            "src_dst_byte_ratio": 1.65,
            "packets_per_second": 137.7,
            "bytes_per_second": 2422.0,
            "tcp_flags": "PSH-ACK"
        }
    },
    "botnet_traffic": {
        "title": "Botnet C2 Beaconing",
        "type": "Botnet",
        "data": {
            "duration": 2.15,
            "protocol": "DNS",
            "service": "DNS",
            "src_bytes": 1250.0,
            "dst_bytes": 980.0,
            "src_packets": 16.0,
            "dst_packets": 11.0,
            "src_dst_byte_ratio": 1.27,
            "packets_per_second": 12.5,
            "bytes_per_second": 1037.0,
            "tcp_flags": "ACK"
        }
    }
}

# --- PAGE ROUTE ---
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def serve_dashboard(request: Request):
    """Serves the interactive CyberGuard Dashboard."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "features": EXPECTED_FEATURES,
            "categorical_options": CATEGORICAL_OPTIONS,
            "presets": PRESETS
        }
    )

# --- API ENDPOINTS ---
@app.get("/api/health", tags=["System"])
async def health_check():
    """Returns system status, model health, and detection classes."""
    classes = list(predictor.label_encoder.classes_) if predictor.label_encoder else []
    return {
        "status": "healthy",
        "service": "CyberGuard XAI-NIDS API",
        "version": "2.2.0",
        "xai_engine_active": True,
        "counterfactual_engine_active": True,
        "gemini_copilot_active": True,
        "model_loaded": predictor.pipeline is not None,
        "classes_detected": classes,
        "features_analyzed": EXPECTED_FEATURES
    }

@app.get("/api/presets", tags=["Detection"])
async def get_presets():
    """Returns realistic test flow presets for single flow evaluation."""
    return PRESETS

@app.post("/api/predict", response_model=PredictionResponse, tags=["Detection"])
async def predict_single_flow(flow: NetworkFlow, include_xai: bool = True):
    """
    Classify a single network flow and return attack category, confidence, severity, 
    local XAI attribution, and counterfactual mitigation boundary.
    """
    flow_dict = flow.model_dump()
    try:
        pred, prob = predictor.predict_single(flow_dict)
        severity = RiskEngine.get_severity(pred)
        is_anomaly = (pred != "Normal")
        
        confidence_val = float(prob) if prob is not None else 0.0
        
        explanation_data = None
        counterfactual_data = None
        
        if include_xai:
            try:
                explanation_data = explainer.explain_flow(flow_dict)
                counterfactual_data = cf_engine.find_counterfactual(flow_dict, target_class="Normal")
            except Exception as e:
                print(f"XAI calculation warning: {e}")
        
        # Log to alert manager if it's an anomaly
        if is_anomaly:
            alert_mgr.generate_alert(
                attack_type=pred,
                severity=severity,
                confidence=confidence_val,
                src_info=f"Proto: {flow.protocol} | Service: {flow.service}",
                dst_info=f"{flow.dst_packets} pkts, {flow.dst_bytes} B"
            )
            
        unsupervised_data = None
        try:
            unsupervised_data = predictor.predict_unsupervised_single(flow_dict)
        except Exception as e:
            print(f"Unsupervised calculation warning: {e}")

        return PredictionResponse(
            prediction=pred,
            confidence=confidence_val,
            confidence_pct=f"{confidence_val * 100:.1f}%",
            severity=severity,
            is_anomaly=is_anomaly,
            traffic_profile=flow_dict,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            explanation=explanation_data,
            counterfactual=counterfactual_data,
            unsupervised=unsupervised_data
        )
    except DataValidationError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")

@app.post("/api/explain", response_model=ExplanationResponse, tags=["Explainable AI"])
async def explain_flow_prediction(flow: NetworkFlow):
    """
    Computes local Shapley-style feature attributions and natural-language rationale for a network flow.
    """
    try:
        return explainer.explain_flow(flow.model_dump())
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Explanation calculation failed: {str(e)}")

@app.post("/api/counterfactual", response_model=CounterfactualResponse, tags=["Explainable AI & Robustness"])
async def compute_counterfactual_robustness(flow: NetworkFlow, target_class: str = "Normal"):
    """
    Computes minimal perturbation counterfactual trajectory and adversarial evasion robustness margin.
    """
    try:
        return cf_engine.find_counterfactual(flow.model_dump(), target_class=target_class)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Counterfactual calculation failed: {str(e)}")

@app.post("/api/chat", response_model=ChatResponse, tags=["AI SOC Copilot"])
async def chat_with_soc_copilot(req: ChatRequest):
    """
    Context-aware interactive AI SOC Analyst Chatbot powered by Google Gemini API.
    Can answer queries about specific flow telemetry, generate firewall rules, and provide mitigation playbooks.
    """
    try:
        res = copilot.chat(
            user_message=req.message,
            flow_context=req.flow_context,
            api_key=req.api_key,
            history=req.history
        )
        return ChatResponse(
            reply=res.get("reply", ""),
            provider=res.get("provider", "CyberGuard Copilot"),
            status=res.get("status", "success"),
            error_detail=res.get("error_detail")
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Copilot error: {str(e)}")

@app.post("/api/predict/batch-file", response_model=BatchPredictionResponse, tags=["Batch Analysis"])
async def predict_batch_file(file: UploadFile = File(...)):
    """
    Analyze network traffic flows from an uploaded CSV dataset.
    """
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files are supported.")
        
    try:
        contents = await file.read()
        df = pd.read_csv(io.BytesIO(contents))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read CSV file: {str(e)}")
        
    return process_batch_dataframe(df, source_name=file.filename)

@app.get("/api/demo-data", response_model=BatchPredictionResponse, tags=["Batch Analysis"])
async def run_demo_dataset():
    """
    Runs batch detection on the pre-loaded synthetic benchmark dataset.
    """
    path = "data/cyberguard_synthetic_demo (1).csv"
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Demo dataset not found.")
    df = pd.read_csv(path)
    return process_batch_dataframe(df, source_name="cyberguard_synthetic_demo.csv")

def process_batch_dataframe(df: pd.DataFrame, source_name: str = "batch") -> BatchPredictionResponse:
    try:
        preds, probs = predictor.predict_batch(df)
        unsupervised_anom, unsupervised_scores, unsupervised_labels = predictor.predict_unsupervised_batch(df)
    except DataValidationError as e:
        raise HTTPException(status_code=422, detail=f"Dataset validation failed: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch processing error: {str(e)}")
        
    results = []
    distribution = {}
    severity_breakdown = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    normal_count = 0
    anomaly_count = 0
    
    for i in range(len(df)):
        pred = str(preds[i])
        conf = float(probs[i]) if probs is not None else 0.0
        sev = RiskEngine.get_severity(pred)
        
        distribution[pred] = distribution.get(pred, 0) + 1
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
        
        if pred == "Normal":
            normal_count += 1
        else:
            anomaly_count += 1
            
        row_dict = df.iloc[i].to_dict()
        row_dict["Flow_ID"] = i + 1
        row_dict["prediction"] = pred
        row_dict["confidence"] = round(conf, 4)
        row_dict["confidence_pct"] = f"{conf * 100:.1f}%"
        row_dict["severity"] = sev
        row_dict["is_anomaly"] = (pred != "Normal")
        row_dict["unsupervised_label"] = str(unsupervised_labels[i]) if i < len(unsupervised_labels) else "N/A"
        row_dict["unsupervised_score"] = round(float(unsupervised_scores[i]), 4) if i < len(unsupervised_scores) else 0.0
        results.append(row_dict)
        
    total = len(df)
    rate = round((anomaly_count / total * 100), 2) if total > 0 else 0.0
    
    # Log session history
    most_common = max(distribution, key=distribution.get) if distribution else "None"
    history_mgr.log_session(
        analysis_type="Batch CSV",
        total_flows=total,
        normal_flows=normal_count,
        attacks_detected=anomaly_count,
        critical_threats=severity_breakdown.get("Critical", 0),
        most_common_attack=most_common,
        file_name=source_name
    )
    
    return BatchPredictionResponse(
        total_flows=total,
        normal_flows=normal_count,
        anomalies_detected=anomaly_count,
        detection_rate_pct=rate,
        distribution=distribution,
        severity_breakdown=severity_breakdown,
        results=results
    )

@app.post("/api/simulate", response_model=SimulationResponse, tags=["Investigation"])
async def simulate_what_if(sim: SimulationRequest):
    """
    What-If Simulator: compare baseline flow prediction vs. modified network metrics in real time.
    """
    base_dict = sim.base_flow.model_dump()
    mod_dict = base_dict.copy()
    mod_dict.update(sim.modified_features)
    
    try:
        base_pred, base_prob = predictor.predict_single(base_dict)
        sim_pred, sim_prob = predictor.predict_single(mod_dict)
        
        base_conf = float(base_prob) if base_prob is not None else 0.0
        sim_conf = float(sim_prob) if sim_prob is not None else 0.0
        
        return SimulationResponse(
            baseline={
                "prediction": base_pred,
                "confidence": base_conf,
                "confidence_pct": f"{base_conf * 100:.1f}%",
                "severity": RiskEngine.get_severity(base_pred),
                "features": base_dict
            },
            simulated={
                "prediction": sim_pred,
                "confidence": sim_conf,
                "confidence_pct": f"{sim_conf * 100:.1f}%",
                "severity": RiskEngine.get_severity(sim_pred),
                "features": mod_dict
            },
            delta={
                "prediction_changed": (base_pred != sim_pred),
                "confidence_delta": round((sim_conf - base_conf) * 100, 2),
                "modified_features": list(sim.modified_features.keys())
            }
        )
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Simulation error: {str(e)}")

@app.get("/api/alerts", tags=["Incident Management"])
async def get_recent_alerts(limit: int = 20):
    """Retrieve security incident alerts from the persistent log."""
    df = alert_mgr.get_recent_alerts(limit=limit)
    if df.empty:
        return []
    return df.fillna("").to_dict(orient="records")

@app.get("/api/history", tags=["Incident Management"])
async def get_analysis_history():
    """Retrieve analysis session history."""
    df = history_mgr.get_all_history()
    if df.empty:
        return []
@app.get("/api/unsupervised/metrics", tags=["Unsupervised Anomaly Detection"])
async def get_unsupervised_metrics():
    """Retrieve performance metrics comparing Supervised RF vs Unsupervised Isolation Forest."""
    return {
        "status": "active" if predictor.unsupervised_pipeline is not None else "unavailable",
        "primary_model": "Isolation Forest (Unsupervised)",
        "comparison": [
            {
                "algorithm": "Random Forest (Supervised)",
                "paradigm": "Supervised (Trained on labels)",
                "accuracy": "95.00%",
                "precision": "97.14%",
                "recall": "89.47%",
                "f1_score": "93.15%",
                "roc_auc": "98.80%"
            },
            {
                "algorithm": "Isolation Forest (Unsupervised)",
                "paradigm": "Unsupervised (Zero labels used)",
                "accuracy": "68.00%",
                "precision": "56.82%",
                "recall": "65.79%",
                "f1_score": "60.98%",
                "roc_auc": "73.07%"
            },
            {
                "algorithm": "One-Class SVM (Unsupervised)",
                "paradigm": "Unsupervised (Zero labels used)",
                "accuracy": "69.00%",
                "precision": "57.95%",
                "recall": "67.11%",
                "f1_score": "62.20%",
                "roc_auc": "72.93%"
            }
        ],
        "attack_detection_rates": {
            "DoS": "90.5%",
            "Botnet": "71.4%",
            "Probe": "70.0%",
            "Other": "87.5%",
            "Brute_Force": "30.0%",
            "Web_Attack": "20.0%"
        }
    }

@app.get("/api/unsupervised/chart", tags=["Unsupervised Anomaly Detection"])
async def get_unsupervised_chart():
    """Serve the 4-panel evaluation chart comparing Supervised vs Unsupervised learning."""
    chart_path = "outputs/unsupervised_evaluation.png"
    if not os.path.exists(chart_path):
        chart_path = "unsupervised_evaluation.png"
    if not os.path.exists(chart_path):
        raise HTTPException(status_code=404, detail="Evaluation chart not found.")
    return FileResponse(chart_path, media_type="image/png")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)

