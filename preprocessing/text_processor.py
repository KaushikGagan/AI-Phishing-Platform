import re
import string
from typing import Optional
import pandas as pd

PHISHING_KEYWORDS = {
    "english": ["urgent", "verify", "suspend", "account", "login", "password", "otp",
                "click here", "immediate", "confirm", "update", "bank", "credential",
                "winner", "prize", "claim", "free", "limited time", "act now",
                "security alert", "unusual activity", "blocked", "expired"],
    "hindi": ["खाता", "बंद", "तुरंत", "सत्यापन", "पासवर्ड", "ओटीपी", "बैंक"],
    "hinglish": ["otp share karo", "account band", "turant", "verify karo", "suspend",
                 "abhi action", "account block", "password bhejo"],
    "tamil": ["கணக்கு", "சரிபார்", "OTP", "வங்கி", "நிலுவை"],
    "telugu": ["ఖాతా", "నిలిపివేయ", "OTP", "వెంటనే", "పాస్వర్డ్"]
}

URGENCY_PATTERNS = [
    r'\b(urgent|immediate|immediately|asap|right now|act now|within \d+ hours?)\b',
    r'\b(abhi|turant|jaldi|फ़ौरन|तुरंत)\b',
    r'\b(suspended?|blocked?|expired?|terminated?|closed?)\b',
    r'\b(last chance|final notice|account will be)\b'
]

CREDENTIAL_PATTERNS = [
    r'\b(password|passwd|otp|pin|cvv|credit card|debit card|account number)\b',
    r'\b(username|user id|login|sign in|verify|confirm)\b',
    r'\b(पासवर्ड|ओटीपी|पिन|खाता संख्या)\b'
]


def clean_text(text: str) -> str:
    text = text.lower()
    text = re.sub(r'http\S+|www\S+', ' URL ', text)
    text = re.sub(r'\S+@\S+', ' EMAIL ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def detect_language(text: str) -> str:
    telugu_range = re.compile(r'[\u0C00-\u0C7F]')
    tamil_range = re.compile(r'[\u0B80-\u0BFF]')
    hindi_range = re.compile(r'[\u0900-\u097F]')
    latin = re.compile(r'[a-zA-Z]')

    has_telugu = bool(telugu_range.search(text))
    has_tamil = bool(tamil_range.search(text))
    has_hindi = bool(hindi_range.search(text))
    has_latin = bool(latin.search(text))

    if has_telugu:
        return "telugu"
    if has_tamil:
        return "tamil"
    if has_hindi and has_latin:
        return "hinglish"
    if has_hindi:
        return "hindi"
    return "english"


def extract_text_features(subject: str, body: str, sender: str) -> dict:
    full_text = f"{subject} {body}".lower()
    lang = detect_language(full_text)

    urgency_score = sum(
        len(re.findall(p, full_text, re.IGNORECASE)) for p in URGENCY_PATTERNS
    )
    credential_score = sum(
        len(re.findall(p, full_text, re.IGNORECASE)) for p in CREDENTIAL_PATTERNS
    )

    all_keywords = []
    for kw_list in PHISHING_KEYWORDS.values():
        all_keywords.extend(kw_list)
    keyword_hits = sum(1 for kw in all_keywords if kw.lower() in full_text)

    sender_domain = sender.split("@")[-1] if "@" in sender else ""
    suspicious_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".net", ".info"]
    suspicious_tld = any(sender_domain.endswith(t) for t in suspicious_tlds)

    has_ip_in_sender = bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', sender))
    exclamation_count = full_text.count("!")
    caps_ratio = sum(1 for c in f"{subject} {body}" if c.isupper()) / max(len(f"{subject} {body}"), 1)

    return {
        "language": lang,
        "urgency_score": min(urgency_score, 10),
        "credential_score": min(credential_score, 10),
        "keyword_hits": min(keyword_hits, 20),
        "suspicious_tld": int(suspicious_tld),
        "has_ip_in_sender": int(has_ip_in_sender),
        "exclamation_count": min(exclamation_count, 10),
        "caps_ratio": round(caps_ratio, 3),
        "body_length": len(body),
        "subject_length": len(subject),
        "has_url_in_body": int("http" in body.lower() or "www." in body.lower()),
        "cleaned_text": clean_text(full_text)
    }


def preprocess_email_df(df: pd.DataFrame) -> pd.DataFrame:
    features = df.apply(
        lambda r: extract_text_features(
            str(r.get("subject", "")),
            str(r.get("body", "")),
            str(r.get("sender", ""))
        ), axis=1
    )
    return pd.concat([df, pd.DataFrame(list(features))], axis=1)
