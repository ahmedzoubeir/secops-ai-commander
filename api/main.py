from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import AGENT_CONFIG
from agents.orchestrator.orchestrator import OrchestratorAgent

from agents.network_scanner.network_scanner import NetworkScannerAgent
from agents.incident_response.incident_responder import IncidentResponderAgent


app = FastAPI(
    title="SecOps AI Commander",
    description="Multi-Agent AI Security Operations System",
    version="1.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from config import AGENT_CONFIG, redis_manager  # Add redis_manager import

# Initialize orchestrator with Redis
orchestrator = OrchestratorAgent({
    'log_analyzer': AGENT_CONFIG['log_analyzer'],
    'threat_intel': AGENT_CONFIG['threat_intel'],
    'cve_scanner': AGENT_CONFIG['cve_scanner'],
    'network_scanner': AGENT_CONFIG['network_scanner'],
    'incident_responder': AGENT_CONFIG['incident_responder']
}, redis_manager=redis_manager)  # Pass Redis here

# Add request models
class NetworkScanRequest(BaseModel):
    target: str
    scan_type: Optional[str] = "quick"
    context: Optional[str] = "Security audit"

class IncidentResponseRequest(BaseModel):
    incident_data: str
    threat_context: Optional[str] = ""
    system_state: Optional[str] = "Production"
# Request models
class LogAnalysisRequest(BaseModel):
    log_entry: str
    context: Optional[str] = "Security monitoring"

class ThreatIntelRequest(BaseModel):
    threat_description: str
    indicators: Optional[list] = []

class CVEScanRequest(BaseModel):  # ADD THIS
    service: str
    version: str
    keywords: Optional[List[str]] = []

class FullAnalysisRequest(BaseModel):
    log_entry: str
    context: Optional[str] = "Security monitoring"
    service: Optional[str] = ""
    version: Optional[str] = ""

# Routes
@app.get("/")
async def root():
    return {
        "service": "SecOps AI Commander",
        "version": "1.0.0",
        "status": "operational",
        "agents": [
            "log_analyzer",
            "threat_intel", 
            "cve_scanner",
            "network_scanner",
            "incident_responder",
            "orchestrator"
        ],
        "endpoints": {
            "log_analysis": "/api/analyze/log",
            "threat_intel": "/api/analyze/threat",
            "cve_scan": "/api/scan/cve",
            "network_scan": "/api/scan/network",
            "incident_response": "/api/incident/respond",
            "full_analysis": "/api/analyze/full",
            "health": "/health"
        }
    }
    
@app.get("/health")
async def health_check():
    return {
        "status": "healthy", 
        "agents": ["log_analyzer", "threat_intel", "cve_scanner", "orchestrator"]
    }

@app.post("/api/analyze/log")
async def analyze_log(request: LogAnalysisRequest):
    """Analyze a single security log entry"""
    try:
        result = orchestrator.process({
            'request_type': 'log_analysis',
            'data': {
                'log_entry': request.log_entry,
                'context': request.context
            }
        })
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/analyze/threat")
async def analyze_threat(request: ThreatIntelRequest):
    """Get threat intelligence analysis"""
    try:
        result = orchestrator.process({
            'request_type': 'threat_intel',
            'data': {
                'threat_description': request.threat_description,
                'indicators': request.indicators
            }
        })
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/cve")  # ADD THIS ENDPOINT
async def scan_cve(request: CVEScanRequest):
    """Scan for CVE vulnerabilities"""
    try:
        result = orchestrator.process({
            'request_type': 'cve_scan',
            'data': {
                'service': request.service,
                'version': request.version,
                'keywords': request.keywords if request.keywords else [request.service]
            }
        })
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/analyze/full")
async def full_analysis(request: FullAnalysisRequest):
    """Run complete multi-agent security analysis"""
    try:
        result = orchestrator.process({
            'request_type': 'full_analysis',
            'data': {
                'log_entry': request.log_entry,
                'context': request.context,
                'service': request.service,
                'version': request.version
            }
        })
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Add endpoints
@app.post("/api/scan/network")
async def scan_network(request: NetworkScanRequest):
    """Scan network for open ports and services"""
    try:
        result = orchestrator.process({
            'request_type': 'network_scan',
            'data': {
                'target': request.target,
                'scan_type': request.scan_type,
                'context': request.context
            }
        })
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/incident/respond")
async def respond_incident(request: IncidentResponseRequest):
    """Get incident response recommendations"""
    try:
        result = orchestrator.process({
            'request_type': 'incident_response',
            'data': {
                'incident_data': request.incident_data,
                'threat_context': request.threat_context,
                'system_state': request.system_state
            }
        })
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)