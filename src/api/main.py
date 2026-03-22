"""
FastAPI server for the MITRE ATT&CK Knowledge Graph API
Provides REST endpoints for log analysis and risk assessment
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import logging
import sys
from pathlib import Path

# Add both src directory AND project root to path
current_file = Path(__file__).resolve()
src_path = current_file.parent.parent  # src/api/main.py -> src/
project_root = src_path.parent  # src/ -> project root

# Add both paths
sys.path.insert(0, str(src_path))  # For modules in src/
sys.path.insert(0, str(project_root))  # For config.py in root

from hybrid_retriever import HybridRetriever
from bayesian_engine import BayesianAttackPredictor, TACTICS
from log_processor import SecurityLogProcessor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="MITRE ATT&CK Knowledge Graph API",
    description="Hybrid retrieval and Bayesian risk assessment for threat intelligence",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances (initialized on startup)
retriever: Optional[HybridRetriever] = None
predictor: Optional[BayesianAttackPredictor] = None


# ============ Request/Response Models ============

class LogEntry(BaseModel):
    message: str
    timestamp: Optional[str] = None
    source: Optional[str] = None

class LogBatchRequest(BaseModel):
    logs: List[LogEntry]

class SearchRequest(BaseModel):
    query: str
    observed_tactics: Optional[List[str]] = None
    top_k: Optional[int] = 10

class RiskAssessmentRequest(BaseModel):
    observed_tactics: List[str]

class PathProbabilityRequest(BaseModel):
    observed_tactics: List[str]
    target_tactic: str


# ============ Startup/Shutdown ============

@app.on_event("startup")
async def startup():
    global retriever, predictor
    logger.info("Initializing services...")
    retriever = HybridRetriever()
    predictor = BayesianAttackPredictor()
    predictor.build_bayesian_network()
    logger.info("Services initialized")

@app.on_event("shutdown")
async def shutdown():
    global retriever, predictor
    if retriever:
        retriever.close()
    if predictor:
        predictor.close()


# ============ API Endpoints ============

@app.get("/")
async def root():
    return {
        "service": "MITRE ATT&CK Knowledge Graph API",
        "status": "running",
        "endpoints": [
            "/search",
            "/analyze/log",
            "/analyze/batch",
            "/risk/assess",
            "/risk/path",
            "/tactics"
        ]
    }

@app.get("/tactics")
async def get_tactics():
    """Get all MITRE ATT&CK tactics in kill chain order."""
    return {
        "tactics": TACTICS,
        "count": len(TACTICS)
    }

@app.post("/search")
async def hybrid_search(request: SearchRequest):
    """
    Hybrid search for MITRE techniques.
    Combines vector similarity, graph traversal, and Bayesian inference.
    """
    if not retriever:
        raise HTTPException(status_code=503, detail="Service not initialized")
    
    results = retriever.hybrid_search(
        query=request.query,
        observed_tactics=request.observed_tactics,
        top_k=request.top_k or 10
    )
    
    return {
        "query": request.query,
        "observed_tactics": request.observed_tactics,
        "results": [
            {
                "technique_id": r.technique_id,
                "technique_name": r.technique_name,
                "description": r.description,
                "tactics": r.tactics,
                "scores": {
                    "hybrid": r.hybrid_score,
                    "vector": r.vector_score,
                    "graph": r.graph_score,
                    "bayesian": r.bayesian_score
                },
                "related_groups": r.related_groups,
                "mitigations": r.mitigations
            }
            for r in results
        ]
    }

@app.post("/analyze/log")
async def analyze_single_log(entry: LogEntry):
    """Analyze a single log entry."""
    if not retriever:
        raise HTTPException(status_code=503, detail="Service not initialized")
    
    analysis = retriever.analyze_log_entry(entry.message)
    
    return {
        "log_message": entry.message,
        "matches": analysis['matches'],
        "observed_tactics": analysis['observed_tactics'],
        "risk_assessment": analysis['risk_assessment']
    }

@app.post("/analyze/batch")
async def analyze_log_batch(request: LogBatchRequest):
    """Analyze multiple log entries with cumulative context."""
    if not retriever:
        raise HTTPException(status_code=503, detail="Service not initialized")
    
    log_messages = [log.message for log in request.logs]
    analysis = retriever.batch_analyze_logs(log_messages)
    
    return {
        "total_logs": analysis['total_logs_analyzed'],
        "unique_techniques": analysis['unique_techniques_detected'],
        "unique_tactics": analysis['unique_tactics_detected'],
        "risk_assessment": analysis['final_risk_assessment'],
        "individual_results": analysis['individual_results'][:20]  # Limit for response size
    }

@app.post("/risk/assess")
async def assess_risk(request: RiskAssessmentRequest):
    """Get full risk assessment for observed tactics."""
    if not predictor:
        raise HTTPException(status_code=503, detail="Service not initialized")
    
    assessment = predictor.get_full_risk_assessment(request.observed_tactics)
    
    return {
        "observed_tactics": request.observed_tactics,
        "risk_level": assessment['risk_level'],
        "risk_score": assessment['risk_score'],
        "attack_stage": assessment['attack_stage'],
        "impact_probability": assessment['impact_probability'],
        "exfiltration_probability": assessment['exfiltration_probability'],
        "predicted_next_tactics": [
            {"tactic": t, "probability": p}
            for t, p in assessment['next_tactic_predictions']
        ],
        "likely_path_to_impact": assessment['likely_path_to_impact']
    }

@app.post("/risk/path")
async def calculate_path_probability(request: PathProbabilityRequest):
    """Calculate probability of reaching a target tactic."""
    if not predictor:
        raise HTTPException(status_code=503, detail="Service not initialized")
    
    result = predictor.calculate_attack_path_probability(
        request.observed_tactics,
        request.target_tactic
    )
    
    return {
        "observed_tactics": request.observed_tactics,
        "target_tactic": request.target_tactic,
        "probability": result['probability'],
        "likely_path": result['path'],
        "path_probability": result['path_probability']
    }

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "retriever_ready": retriever is not None,
        "predictor_ready": predictor is not None
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)