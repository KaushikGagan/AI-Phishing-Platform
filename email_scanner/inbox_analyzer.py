"""
inbox_analyzer.py — feeds Gmail emails through the full PhishGuard pipeline.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import process_email
from .gmail_fetcher import fetch_latest_emails


def analyze_inbox(
    gmail_address: str,
    app_password: str,
    limit: int = 20
) -> dict:
    """
    Fetch emails from Gmail and run full phishing detection on each.

    Returns:
    {
        "success": bool,
        "error": str | None,
        "total": int,
        "results": [ full process_email() output, ... ],
        "summary": { "safe": n, "suspicious": n, "high_risk": n }
    }
    """
    emails, error = fetch_latest_emails(gmail_address, app_password, limit)

    if error:
        return {"success": False, "error": error, "total": 0, "results": [], "summary": {}}

    results = []
    for email_data in emails:
        try:
            result = process_email(email_data)
            results.append(result)
        except Exception as e:
            # Don't let one bad email crash the whole scan
            results.append({
                "email_id": email_data.get("id", "UNKNOWN"),
                "sender": email_data.get("sender", ""),
                "subject": email_data.get("subject", ""),
                "timestamp": email_data.get("timestamp", ""),
                "language": "unknown",
                "risk_report": {
                    "risk_level": "unknown",
                    "final_score": 0,
                    "nlp_score": 0,
                    "url_risk_score": 0,
                    "anomaly_score": 0,
                    "domain_reputation_score": 0,
                    "flags": [],
                    "recommended_action": f"Parse error: {str(e)}",
                },
                "explanation": {"summary": f"Could not analyze: {str(e)}"},
                "url_results": [],
                "text_features": {},
            })

    summary = {
        "safe": sum(1 for r in results if r["risk_report"]["risk_level"] == "safe"),
        "suspicious": sum(1 for r in results if r["risk_report"]["risk_level"] == "suspicious"),
        "high_risk": sum(1 for r in results if r["risk_report"]["risk_level"] == "high_risk"),
    }

    return {
        "success": True,
        "error": None,
        "total": len(results),
        "results": results,
        "summary": summary,
    }
