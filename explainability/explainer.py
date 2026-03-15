"""
Explainability module — generates human-readable explanations for phishing detections.
Uses feature contribution analysis (SHAP-style) on the ML model and rule-based signals.
"""
from typing import Optional


FEATURE_EXPLANATIONS = {
    "urgency_score": "contains urgency manipulation language (e.g., 'act now', 'within 24 hours')",
    "credential_score": "requests sensitive credentials (OTP, password, card details)",
    "keyword_hits": "contains multiple phishing keywords",
    "suspicious_tld": "sender domain uses a suspicious TLD (.xyz, .tk, .ml)",
    "has_ip_in_sender": "sender address contains an IP address instead of domain name",
    "domain_spoofing": "sender name impersonates a known brand but domain doesn't match",
    "is_odd_hour": "email sent at an unusual hour (late night / early morning)",
    "has_url_in_body": "contains embedded URLs",
    "caps_ratio": "excessive use of capital letters (urgency tactic)",
    "exclamation_count": "excessive exclamation marks (urgency tactic)",
}

RISK_LEVEL_COLORS = {
    "safe": "#2ecc71",
    "suspicious": "#f39c12",
    "high_risk": "#e74c3c",
}


def generate_explanation(risk_report_dict: dict, text_features: dict, anomaly_features: dict) -> dict:
    """Generate structured explanation for a risk report."""
    contributing_factors = []
    score_breakdown = {}

    nlp_score = risk_report_dict.get("nlp_score", 0)
    url_score = risk_report_dict.get("url_risk_score", 0)
    anomaly_score = risk_report_dict.get("anomaly_score", 0)
    domain_score = risk_report_dict.get("domain_reputation_score", 0)

    score_breakdown = {
        "NLP Phishing Score": f"{nlp_score:.0f}/100",
        "URL Risk Score": f"{url_score:.0f}/100",
        "Sender Anomaly Score": f"{anomaly_score:.0f}/100",
        "Domain Reputation Score": f"{domain_score:.0f}/100",
    }

    # Text feature contributions
    for feat, explanation in FEATURE_EXPLANATIONS.items():
        val = text_features.get(feat, anomaly_features.get(feat, 0))
        if feat == "urgency_score" and val >= 2:
            contributing_factors.append({"factor": explanation, "weight": "high", "value": val})
        elif feat == "credential_score" and val >= 2:
            contributing_factors.append({"factor": explanation, "weight": "high", "value": val})
        elif feat == "keyword_hits" and val >= 3:
            contributing_factors.append({"factor": explanation, "weight": "medium", "value": val})
        elif feat in ("suspicious_tld", "has_ip_in_sender", "domain_spoofing") and val:
            contributing_factors.append({"factor": explanation, "weight": "high", "value": val})
        elif feat == "is_odd_hour" and val:
            contributing_factors.append({"factor": explanation, "weight": "medium", "value": val})
        elif feat == "caps_ratio" and val > 0.15:
            contributing_factors.append({"factor": explanation, "weight": "low", "value": round(val, 2)})

    # URL flags
    for url_info in risk_report_dict.get("top_urls", []):
        if url_info.get("label") in ("malicious", "suspicious"):
            contributing_factors.append({
                "factor": f"URL '{url_info['url'][:50]}...' classified as {url_info['label']}",
                "weight": "high" if url_info["label"] == "malicious" else "medium",
                "value": url_info["score"]
            })

    summary = _build_summary(risk_report_dict["risk_level"], contributing_factors)

    return {
        "risk_level": risk_report_dict["risk_level"],
        "final_score": risk_report_dict["final_score"],
        "summary": summary,
        "score_breakdown": score_breakdown,
        "contributing_factors": contributing_factors,
        "recommended_action": risk_report_dict.get("recommended_action", ""),
        "color": RISK_LEVEL_COLORS.get(risk_report_dict["risk_level"], "#95a5a6"),
    }


def _build_summary(risk_level: str, factors: list) -> str:
    if risk_level == "safe":
        return "This email appears legitimate. No significant phishing indicators were detected."

    high_factors = [f["factor"] for f in factors if f["weight"] == "high"]
    med_factors = [f["factor"] for f in factors if f["weight"] == "medium"]

    parts = high_factors[:2] + med_factors[:1]
    if not parts:
        return "Email flagged based on combined risk signals across multiple detection modules."

    prefix = "[SUSPICIOUS]" if risk_level == "suspicious" else "[HIGH RISK PHISHING]"
    return f"{prefix}: Email flagged because it {'; '.join(parts)}."
