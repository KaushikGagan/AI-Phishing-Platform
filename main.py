"""
Main pipeline orchestrator for the AI-Powered Phishing Detection Platform.
Processes emails through all detection modules and produces a unified risk report.
"""
import json
import sys
import os
import re
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.dirname(__file__))

from preprocessing.text_processor import extract_text_features, detect_language
from nlp_engine.phishing_detector import predict_phishing, explain_prediction
from url_analysis.url_analyzer import analyze_url
from anomaly_detection.behavioral_analyzer import analyze_sender
from risk_scoring.scorer import score_email
from explainability.explainer import generate_explanation


def extract_urls_from_text(text: str) -> list:
    return re.findall(r'https?://\S+|www\.\S+', text)


def process_email(email: dict) -> dict:
    """Full pipeline: email dict → unified risk report dict."""
    email_id = email.get("id", "UNKNOWN")
    sender = email.get("sender", "")
    subject = email.get("subject", "")
    body = email.get("body", "")

    # 1. Text feature extraction
    text_features = extract_text_features(subject, body, sender)
    language = text_features.get("language", "english")

    # 2. NLP phishing detection
    nlp_input = text_features.get("cleaned_text", f"{subject} {body}")
    nlp_result = predict_phishing(nlp_input)

    # 3. URL analysis
    urls = email.get("urls", []) or extract_urls_from_text(body)
    url_results = [analyze_url(u) for u in urls] if urls else []

    # 4. Behavioral anomaly detection
    anomaly_result = analyze_sender(email)

    # 5. Risk scoring
    risk_report = score_email(
        email_id=email_id,
        nlp_result=nlp_result,
        url_results=url_results,
        anomaly_result=anomaly_result,
        text_features=text_features,
        sender=sender,
        language=language,
    )

    # 6. Explainability
    explanation = generate_explanation(
        risk_report.to_dict(),
        text_features,
        anomaly_result.get("features", {})
    )

    return {
        "email_id": email_id,
        "sender": sender,
        "subject": subject,
        "timestamp": email.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "language": language,
        "risk_report": risk_report.to_dict(),
        "explanation": explanation,
        "nlp_result": nlp_result,
        "url_results": url_results,
        "anomaly_result": {
            "anomaly_score": anomaly_result.get("anomaly_score", 0),
            "flags": anomaly_result.get("flags", []),
        },
        "text_features": {
            k: v for k, v in text_features.items() if k != "cleaned_text"
        },
    }


def process_batch(emails: list) -> list:
    return [process_email(e) for e in emails]


def load_and_process_sample():
    data_path = os.path.join(os.path.dirname(__file__), "data", "sample_emails.json")
    with open(data_path, "r", encoding="utf-8") as f:
        emails = json.load(f)
    results = process_batch(emails)
    return results


def _safe_print(text: str):
    sys.stdout.buffer.write((text + "\n").encode("utf-8", errors="replace"))
    sys.stdout.buffer.flush()


def print_report(result: dict):
    rr = result["risk_report"]
    exp = result["explanation"]
    lines = [
        f"\n{'='*60}",
        f"Email ID : {result['email_id']}",
        f"From     : {result['sender']}",
        f"Subject  : {result['subject'][:60]}",
        f"Language : {result['language'].upper()}",
        f"Risk     : {rr['risk_level'].upper()} ({rr['final_score']}/100)",
        f"Summary  : {exp['summary']}",
        f"Action   : {rr['recommended_action']}",
    ]
    if rr["flags"]:
        lines.append(f"Flags    : {', '.join(rr['flags'])}")
    lines.append(
        f"Scores   -> NLP:{rr['nlp_score']:.0f} | URL:{rr['url_risk_score']:.0f} | "
        f"Anomaly:{rr['anomaly_score']:.0f} | Domain:{rr['domain_reputation_score']:.0f}"
    )
    for line in lines:
        _safe_print(line)


if __name__ == "__main__":
    print("[*] AI-Powered Phishing Detection Platform")
    print("Training NLP model...")
    from nlp_engine.phishing_detector import train_model
    _, report, _ = train_model(save=True)
    print(f"[+] Model trained - F1 (phishing): {report['phishing']['f1-score']:.2f}")

    print("\nProcessing sample emails...\n")
    results = load_and_process_sample()
    for r in results:
        print_report(r)

    safe = sum(1 for r in results if r["risk_report"]["risk_level"] == "safe")
    suspicious = sum(1 for r in results if r["risk_report"]["risk_level"] == "suspicious")
    high_risk = sum(1 for r in results if r["risk_report"]["risk_level"] == "high_risk")
    print(f"\n{'='*60}")
    print(f"SUMMARY: {len(results)} emails processed")
    print(f"  [SAFE]       : {safe}")
    print(f"  [SUSPICIOUS] : {suspicious}")
    print(f"  [HIGH RISK]  : {high_risk}")
