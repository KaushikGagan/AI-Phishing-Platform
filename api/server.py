"""
FastAPI layer — exposes phishing detection as REST endpoints.
Run with: uvicorn api.server:app --reload
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

from main import process_email
from url_analysis.url_analyzer import analyze_url, analyze_urls_batch

app = FastAPI(
    title="PhishGuard AI API",
    description="AI-Powered Phishing Detection & Threat Intelligence API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class EmailRequest(BaseModel):
    sender: str
    sender_name: Optional[str] = ""
    subject: str
    body: str
    timestamp: Optional[str] = None
    urls: Optional[List[str]] = []


class URLRequest(BaseModel):
    urls: List[str]


@app.get("/")
def root():
    return {"message": "PhishGuard AI API is running", "version": "1.0.0"}


@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.post("/analyze/email")
def analyze_email(req: EmailRequest):
    email_data = {
        "id": f"API-{datetime.now().strftime('%H%M%S%f')}",
        "sender": req.sender,
        "sender_name": req.sender_name,
        "subject": req.subject,
        "body": req.body,
        "timestamp": req.timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "urls": req.urls or [],
    }
    try:
        result = process_email(email_data)
        return {
            "email_id": result["email_id"],
            "risk_level": result["risk_report"]["risk_level"],
            "final_score": result["risk_report"]["final_score"],
            "explanation": result["explanation"]["summary"],
            "recommended_action": result["risk_report"]["recommended_action"],
            "flags": result["risk_report"]["flags"],
            "score_breakdown": {
                "nlp_score": result["risk_report"]["nlp_score"],
                "url_risk_score": result["risk_report"]["url_risk_score"],
                "anomaly_score": result["risk_report"]["anomaly_score"],
                "domain_reputation_score": result["risk_report"]["domain_reputation_score"],
            },
            "language": result["language"],
            "url_results": result["url_results"],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/urls")
def analyze_urls(req: URLRequest):
    if not req.urls:
        raise HTTPException(status_code=400, detail="No URLs provided")
    results = [analyze_url(u) for u in req.urls]
    return {"results": results, "count": len(results)}


@app.post("/analyze/url")
def analyze_single_url(url: str):
    return analyze_url(url)
