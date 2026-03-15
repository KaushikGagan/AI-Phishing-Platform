import re
import json
import pickle
import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import warnings
warnings.filterwarnings("ignore")

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "nlp_model.pkl")
VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "tfidf_vectorizer.pkl")

# ── Synthetic training data ────────────────────────────────────────────────────
SYNTHETIC_PHISHING = [
    "urgent your account has been suspended click here to verify immediately",
    "dear customer your bank account will be blocked within 24 hours update kyc now",
    "congratulations you have won a prize of 50 lakhs claim your reward now",
    "otp share karo account band hone wala hai turant verify karo",
    "your password has expired login immediately to reset your credentials",
    "security alert unusual activity detected on your account verify now",
    "account suspend hone wala hai abhi action lein otp bhejo",
    "dear user your debit card has been blocked enter your pin to unblock",
    "final notice your account will be terminated unless you verify within 2 hours",
    "free recharge offer claim your 500 rupees cashback enter your bank details",
    "your netflix subscription has expired update payment information immediately",
    "income tax refund pending click here to claim your refund now",
    "your aadhaar card is linked to suspicious activity verify immediately",
    "bank verification immediately required account will be closed",
    "enter your credit card number to confirm your identity urgent action required",
    "you have been selected for government scheme apply now limited time offer",
    "your sim card will be deactivated update your kyc details immediately",
    "lottery winner congratulations claim your prize by providing bank details",
    "phishing attempt detected on your account login to secure your account now",
    "dear valued customer please confirm your account details to avoid suspension",
    "aapka account verify karna zaroori hai abhi otp share karein",
    "ungal account suspend aagum udane verify pannungal otp kodungal",
    "meeru account suspend avutundi venta verify cheyyandi otp ivvandi",
    "your paypal account needs immediate verification click the link below",
    "act now your account expires in 24 hours provide your credentials",
]

SYNTHETIC_SAFE = [
    "your order has been shipped and will arrive by friday",
    "please find attached the meeting agenda for tomorrow",
    "your subscription will renew next month no action required",
    "team lunch is scheduled for friday at 1pm please confirm attendance",
    "quarterly performance review schedule has been shared please check",
    "your flight booking is confirmed pnr number is attached",
    "new product features have been released check the changelog",
    "your invoice for last month is ready for download",
    "reminder your annual leave balance is 12 days",
    "the project deadline has been extended to next friday",
    "welcome to our newsletter here are this weeks top stories",
    "your appointment is confirmed for january 20 at 10am",
    "the office will be closed on republic day january 26",
    "please complete the employee satisfaction survey by friday",
    "your github pull request has been approved and merged",
    "monthly report is ready for review please check the dashboard",
    "your domain renewal is due in 30 days no immediate action needed",
    "team building event is scheduled for next saturday",
    "your salary has been credited to your account",
    "the new policy document has been uploaded to the intranet",
    "your train ticket has been booked successfully",
    "meeting rescheduled to 3pm tomorrow please update your calendar",
    "your annual tax statement is ready for download",
    "new security patches have been applied to the system",
    "your feedback has been received thank you for your response",
]


def build_training_data():
    texts = SYNTHETIC_PHISHING + SYNTHETIC_SAFE
    labels = [1] * len(SYNTHETIC_PHISHING) + [0] * len(SYNTHETIC_SAFE)
    return texts, labels


def train_model(save=True):
    texts, labels = build_training_data()
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=5000, sublinear_tf=True)),
        ("clf", RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced"))
    ])
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=["safe", "phishing"], output_dict=True)
    cm = confusion_matrix(y_test, y_pred)

    if save:
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(pipeline, f)

    return pipeline, report, cm


def load_model():
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    return train_model(save=True)[0]


_model = None


def get_model():
    global _model
    if _model is None:
        _model = load_model()
    return _model


def predict_phishing(text: str) -> dict:
    model = get_model()
    prob = model.predict_proba([text])[0]
    phishing_prob = float(prob[1])
    label = "phishing" if phishing_prob >= 0.5 else "safe"

    # Extract top contributing keywords
    tfidf = model.named_steps["tfidf"]
    clf = model.named_steps["clf"]
    vec = tfidf.transform([text])
    feature_names = tfidf.get_feature_names_out()
    importances = clf.feature_importances_
    nonzero_idx = vec.nonzero()[1]
    top_features = sorted(
        [(feature_names[i], importances[i]) for i in nonzero_idx],
        key=lambda x: x[1], reverse=True
    )[:5]

    return {
        "label": label,
        "confidence": round(phishing_prob, 3),
        "nlp_score": round(phishing_prob * 100, 1),
        "top_features": [f[0] for f in top_features]
    }


def explain_prediction(email_data: dict, prediction: dict) -> str:
    reasons = []
    features = email_data.get("features", {})

    if prediction["confidence"] >= 0.8:
        reasons.append("high-confidence phishing language detected by ML model")
    if features.get("urgency_score", 0) >= 2:
        reasons.append("urgency manipulation language present")
    if features.get("credential_score", 0) >= 2:
        reasons.append("credential harvesting patterns detected")
    if features.get("suspicious_tld"):
        reasons.append("sender uses suspicious domain extension")
    if features.get("keyword_hits", 0) >= 3:
        reasons.append(f"contains {features['keyword_hits']} phishing keywords")
    if prediction.get("top_features"):
        reasons.append(f"key trigger words: {', '.join(prediction['top_features'][:3])}")

    if not reasons:
        reasons.append("pattern analysis indicates potential phishing")

    return "Email flagged as phishing because: " + "; ".join(reasons) + "."
