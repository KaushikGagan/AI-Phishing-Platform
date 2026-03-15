from dataclasses import dataclass, field
from typing import Optional


WEIGHTS = {
    "nlp_score": 0.35,
    "url_risk_score": 0.30,
    "anomaly_score": 0.20,
    "domain_reputation_score": 0.15,
}

RISK_THRESHOLDS = {
    "safe": (0, 30),
    "suspicious": (31, 60),
    "high_risk": (61, 100),
}


@dataclass
class RiskReport:
    email_id: str
    final_score: float
    risk_level: str
    nlp_score: float
    url_risk_score: float
    anomaly_score: float
    domain_reputation_score: float
    explanation: str
    flags: list = field(default_factory=list)
    top_urls: list = field(default_factory=list)
    language: str = "english"
    recommended_action: str = ""

    def to_dict(self) -> dict:
        return {
            "email_id": self.email_id,
            "final_score": self.final_score,
            "risk_level": self.risk_level,
            "nlp_score": self.nlp_score,
            "url_risk_score": self.url_risk_score,
            "anomaly_score": self.anomaly_score,
            "domain_reputation_score": self.domain_reputation_score,
            "explanation": self.explanation,
            "flags": self.flags,
            "top_urls": self.top_urls,
            "language": self.language,
            "recommended_action": self.recommended_action,
        }


def compute_domain_reputation(sender: str, anomaly_features: dict) -> float:
    """Simple domain reputation score (0=good, 100=bad)."""
    score = 0.0
    if anomaly_features.get("suspicious_tld"):
        score += 40
    if anomaly_features.get("domain_spoofing"):
        score += 35
    if not anomaly_features.get("is_known_domain"):
        score += 15
    if anomaly_features.get("has_numbers_in_domain"):
        score += 10
    return min(score, 100.0)


def compute_url_risk_score(url_results: list) -> float:
    if not url_results:
        return 0.0
    return max(r.get("risk_score", 0) for r in url_results)


def score_email(
    email_id: str,
    nlp_result: dict,
    url_results: list,
    anomaly_result: dict,
    text_features: dict,
    sender: str,
    language: str = "english"
) -> RiskReport:

    nlp_score = nlp_result.get("nlp_score", 0.0)
    url_risk_score = compute_url_risk_score(url_results)
    anomaly_score = anomaly_result.get("anomaly_score", 0.0)
    domain_rep_score = compute_domain_reputation(
        sender, anomaly_result.get("features", {})
    )

    final_score = (
        nlp_score * WEIGHTS["nlp_score"] +
        url_risk_score * WEIGHTS["url_risk_score"] +
        anomaly_score * WEIGHTS["anomaly_score"] +
        domain_rep_score * WEIGHTS["domain_reputation_score"]
    )
    final_score = round(min(final_score, 100.0), 1)

    if final_score <= 30:
        risk_level = "safe"
        action = "No action required. Email appears legitimate."
    elif final_score <= 60:
        risk_level = "suspicious"
        action = "Caution advised. Review email carefully before clicking any links."
    else:
        risk_level = "high_risk"
        action = "BLOCK immediately. Do not click links or share any information."

    flags = list(anomaly_result.get("flags", []))
    if nlp_score > 60:
        flags.append("phishing language detected by NLP model")
    if url_risk_score > 60:
        flags.append("malicious URL detected")
    if text_features.get("urgency_score", 0) >= 2:
        flags.append("urgency manipulation language")
    if text_features.get("credential_score", 0) >= 2:
        flags.append("credential harvesting patterns")

    explanation_parts = []
    if nlp_score > 50:
        explanation_parts.append(f"NLP model confidence {nlp_score:.0f}%")
    if url_risk_score > 50:
        explanation_parts.append(f"URL risk score {url_risk_score:.0f}%")
    if anomaly_score > 40:
        explanation_parts.append("sender behavioral anomaly")
    if domain_rep_score > 40:
        explanation_parts.append("poor domain reputation")

    if explanation_parts:
        explanation = "Flagged due to: " + ", ".join(explanation_parts) + "."
    else:
        explanation = "Email appears safe based on all analysis modules."

    top_urls = [
        {"url": r["url"], "label": r["label"], "score": r["risk_score"]}
        for r in url_results
    ]

    return RiskReport(
        email_id=email_id,
        final_score=final_score,
        risk_level=risk_level,
        nlp_score=nlp_score,
        url_risk_score=url_risk_score,
        anomaly_score=anomaly_score,
        domain_reputation_score=domain_rep_score,
        explanation=explanation,
        flags=flags,
        top_urls=top_urls,
        language=language,
        recommended_action=action,
    )
