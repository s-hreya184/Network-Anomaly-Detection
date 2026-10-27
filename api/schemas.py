from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Tuple

class NetworkFlow(BaseModel):
    duration: float = Field(default=0.0, description="Duration of connection in seconds", ge=0.0)
    protocol: str = Field(default="TCP", description="Protocol used (TCP, UDP, ICMP, DNS)")
    service: str = Field(default="HTTP", description="Network service (HTTP, HTTPS, DNS, FTP, SSH, TELNET, ICMP, OTHER)")
    src_bytes: float = Field(default=0.0, description="Source to destination bytes", ge=0.0)
    dst_bytes: float = Field(default=0.0, description="Destination to source bytes", ge=0.0)
    src_packets: float = Field(default=0.0, description="Source to destination packets", ge=0.0)
    dst_packets: float = Field(default=0.0, description="Destination to source packets", ge=0.0)
    src_dst_byte_ratio: float = Field(default=0.0, description="Ratio of source to destination bytes", ge=0.0)
    packets_per_second: float = Field(default=0.0, description="Packets transmitted per second", ge=0.0)
    bytes_per_second: float = Field(default=0.0, description="Bytes transmitted per second", ge=0.0)
    tcp_flags: str = Field(default="ACK", description="TCP flag pattern (ACK, SYN, FIN, RST, PSH-ACK, SYN-ACK, FIN-ACK, SYN-RST)")

    class Config:
        json_schema_extra = {
            "example": {
                "duration": 0.12,
                "protocol": "TCP",
                "service": "HTTP",
                "src_bytes": 215.0,
                "dst_bytes": 456.0,
                "src_packets": 3.0,
                "dst_packets": 4.0,
                "src_dst_byte_ratio": 0.47,
                "packets_per_second": 58.33,
                "bytes_per_second": 5591.67,
                "tcp_flags": "ACK"
            }
        }

class ExplanationResponse(BaseModel):
    prediction: str
    confidence_pct: str
    attributions: Dict[str, float]
    top_drivers: List[Tuple[str, float]]
    top_risk_factors: List[str]
    natural_language_rationale: str

class CounterfactualResponse(BaseModel):
    original_prediction: str
    target_prediction: str
    counterfactual_prediction: str
    counterfactual_confidence: str
    modifications_required: Dict[str, Any]
    num_features_modified: int
    evasion_robustness_margin: float
    evasion_risk_level: str
    counterfactual_flow: Dict[str, Any]

class PredictionResponse(BaseModel):
    prediction: str
    confidence: float
    confidence_pct: str
    severity: str
    is_anomaly: bool
    traffic_profile: Dict[str, Any]
    timestamp: str
    explanation: Optional[ExplanationResponse] = None
    counterfactual: Optional[CounterfactualResponse] = None
    unsupervised: Optional[Dict[str, Any]] = None

class BatchPredictionResponse(BaseModel):
    total_flows: int
    normal_flows: int
    anomalies_detected: int
    detection_rate_pct: float
    distribution: Dict[str, int]
    severity_breakdown: Dict[str, int]
    results: List[Dict[str, Any]]

class SimulationRequest(BaseModel):
    base_flow: NetworkFlow
    modified_features: Dict[str, Any]

class SimulationResponse(BaseModel):
    baseline: Dict[str, Any]
    simulated: Dict[str, Any]
    delta: Dict[str, Any]

class ChatRequest(BaseModel):
    message: str
    flow_context: Optional[Dict[str, Any]] = None
    api_key: Optional[str] = None
    history: Optional[List[Dict[str, str]]] = None

class ChatResponse(BaseModel):
    reply: str
    provider: str
    status: str
    error_detail: Optional[str] = None
