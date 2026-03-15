import re
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from datetime import datetime
from typing import Optional


KNOWN_LEGIT_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "irctc.co.in", "gov.in", "nic.in", "microsoft.com", "amazon.com"
}

SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".click"}


def extract_sender_features(email: dict) -> dict:
    sender = email.get("sender", "")
    sender_name = email.get("sender_name", "")
    timestamp = email.get("timestamp", "2024-01-15 09:00:00")

    try:
        dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        hour = dt.hour
        is_odd_hour = int(hour < 6 or hour > 22)
    except Exception:
        hour = 9
        is_odd_hour = 0

    domain = sender.split("@")[-1].lower() if "@" in sender else ""
    tld = "." + domain.split(".")[-1] if "." in domain else ""

    # Domain spoofing: sender_name mentions a brand but domain doesn't match
    brand_keywords = ["paypal", "sbi", "hdfc", "icici", "axis", "amazon",
                      "microsoft", "google", "irctc", "bank", "lottery"]
    name_lower = sender_name.lower()
    brand_in_name = any(b in name_lower for b in brand_keywords)
    brand_in_domain = any(b in domain for b in brand_keywords)
    domain_spoofing = int(brand_in_name and not brand_in_domain)

    is_known_domain = int(domain in KNOWN_LEGIT_DOMAINS)
    suspicious_tld = int(tld in SUSPICIOUS_TLDS)
    has_numbers_in_domain = int(bool(re.search(r'\d', domain.split(".")[0])))
    domain_length = len(domain)
    has_hyphen = int("-" in domain)
    subdomain_count = max(len(domain.split(".")) - 2, 0)

    return {
        "hour": hour,
        "is_odd_hour": is_odd_hour,
        "domain_spoofing": domain_spoofing,
        "is_known_domain": is_known_domain,
        "suspicious_tld": suspicious_tld,
        "has_numbers_in_domain": has_numbers_in_domain,
        "domain_length": domain_length,
        "has_hyphen": has_hyphen,
        "subdomain_count": subdomain_count,
    }


def rule_based_anomaly_score(features: dict) -> float:
    score = 0.0
    if features["domain_spoofing"]:
        score += 40
    if features["suspicious_tld"]:
        score += 25
    if features["is_odd_hour"]:
        score += 15
    if not features["is_known_domain"]:
        score += 10
    if features["has_numbers_in_domain"]:
        score += 10
    if features["has_hyphen"]:
        score += 5
    if features["subdomain_count"] > 1:
        score += 10
    return min(score, 100.0)


class BehavioralAnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.3, random_state=42)
        self._trained = False
        self._fit_on_defaults()

    def _fit_on_defaults(self):
        """Pre-train on synthetic normal/anomalous sender patterns."""
        normal = [
            [9, 0, 0, 1, 0, 0, 12, 0, 0],
            [10, 0, 0, 1, 0, 0, 11, 0, 0],
            [14, 0, 0, 1, 0, 0, 13, 0, 0],
            [11, 0, 0, 1, 0, 0, 10, 0, 0],
            [15, 0, 0, 1, 0, 0, 14, 0, 0],
        ]
        anomalous = [
            [2, 1, 1, 0, 1, 1, 25, 1, 2],
            [3, 1, 1, 0, 1, 0, 30, 1, 3],
            [1, 1, 0, 0, 1, 1, 20, 1, 1],
        ]
        X = np.array(normal + anomalous)
        self.model.fit(X)
        self._trained = True

    def analyze(self, email: dict) -> dict:
        features = extract_sender_features(email)
        rule_score = rule_based_anomaly_score(features)

        feat_vec = np.array([[
            features["hour"], features["is_odd_hour"], features["domain_spoofing"],
            features["is_known_domain"], features["suspicious_tld"],
            features["has_numbers_in_domain"], features["domain_length"],
            features["has_hyphen"], features["subdomain_count"]
        ]])

        iso_pred = self.model.decision_function(feat_vec)[0]
        iso_score = max(0, min(100, (1 - iso_pred) * 50))

        combined = round((rule_score * 0.7 + iso_score * 0.3), 1)

        flags = []
        if features["domain_spoofing"]:
            flags.append("domain spoofing detected")
        if features["is_odd_hour"]:
            flags.append(f"sent at unusual hour ({features['hour']}:00)")
        if features["suspicious_tld"]:
            flags.append("suspicious TLD in sender domain")
        if not features["is_known_domain"]:
            flags.append("unknown sender domain")

        return {
            "anomaly_score": combined,
            "flags": flags,
            "features": features
        }


_detector = None


def get_detector() -> BehavioralAnomalyDetector:
    global _detector
    if _detector is None:
        _detector = BehavioralAnomalyDetector()
    return _detector


def analyze_sender(email: dict) -> dict:
    return get_detector().analyze(email)
