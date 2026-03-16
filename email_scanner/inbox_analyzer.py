"""
inbox_analyzer.py — feeds Gmail emails through the full PhishGuard pipeline.
URLs in email bodies are deep-scanned; HIGH RISK URLs auto-flag the email.
"""
import re
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import process_email
from .gmail_fetcher import fetch_latest_emails


def extract_urls_from_body(text: str) -> list[str]:
    """Extract all URLs from email body text."""
    return re.findall(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", text)


def scan_urls_in_email(email_data: dict) -> dict:
    """
    Extract URLs from email body and run deep URL analysis on each.
    Returns a summary of URL scan results and whether any HIGH RISK URL was found.
    """
    from url_analysis.url_analyzer import analyze_url

    body = email_data.get("body", "")
    explicit_urls = email_data.get("urls", []) or []
    body_urls = extract_urls_from_body(body)

    # Deduplicate, prefer explicit list
    all_urls = list(dict.fromkeys(explicit_urls + body_urls))

    url_results = []
    high_risk_urls = []

    for url in all_urls[:10]:  # cap at 10 per email to avoid timeout
        try:
            result = analyze_url(url, live=True)
            url_results.append(result)
            if result["risk_level"] == "HIGH RISK":
                high_risk_urls.append({
                    "url": result["url"],
                    "domain": result["domain"],
                    "risk_score": result["risk_score"],
                    "category": result["category"],
                    "detection_reasons": result["detection_reasons"],
                    "threat_sources": result["threat_sources"],
                })
        except Exception:
            continue

    return {
        "url_results": url_results,
        "high_risk_urls": high_risk_urls,
        "has_high_risk_url": bool(high_risk_urls),
        "max_url_risk_score": max((r["risk_score"] for r in url_results), default=0),
    }


def analyze_inbox(
    gmail_address: str,
    app_password: str,
    limit: int = 20,
) -> dict:
    """
    Fetch emails from Gmail and run full phishing detection on each.
    URLs in each email are deep-scanned; HIGH RISK URLs escalate the email to phishing.

    Returns:
    {
        "success": bool,
        "error": str | None,
        "total": int,
        "results": [ enriched process_email() output, ... ],
        "summary": { "safe": n, "suspicious": n, "high_risk": n }
    }
    """
    emails, error = fetch_latest_emails(gmail_address, app_password, limit)

    if error:
        return {"success": False, "error": error, "total": 0, "results": [], "summary": {}}

    results = []
    for email_data in emails:
        try:
            # Deep URL scan first
            url_scan = scan_urls_in_email(email_data)

            # Inject deep-scanned URL results back so process_email uses them
            email_data["urls"] = [r["url"] for r in url_scan["url_results"]]

            result = process_email(email_data)

            # Attach deep URL scan details
            result["url_results"] = url_scan["url_results"]
            result["high_risk_urls"] = url_scan["high_risk_urls"]

            # If any URL is HIGH RISK, escalate the email classification
            if url_scan["has_high_risk_url"]:
                rr = result["risk_report"]
                rr["risk_level"] = "high_risk"
                rr["final_score"] = max(rr["final_score"], url_scan["max_url_risk_score"])
                rr["flags"].append("HIGH RISK URL detected in email body")
                rr["recommended_action"] = "BLOCK immediately. Malicious URL detected in email."

                # Build phishing flag entry for each high-risk URL
                for hr in url_scan["high_risk_urls"]:
                    rr["flags"].append(
                        f"Malicious URL: {hr['url']} "
                        f"[Score:{hr['risk_score']} | {hr['category']}]"
                    )

            results.append(result)

        except Exception as e:
            results.append({
                "email_id": email_data.get("id", "UNKNOWN"),
                "sender": email_data.get("sender", ""),
                "subject": email_data.get("subject", ""),
                "timestamp": email_data.get("timestamp", ""),
                "language": "unknown",
                "high_risk_urls": [],
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
