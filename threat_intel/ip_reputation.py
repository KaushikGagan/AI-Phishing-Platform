"""
ip_reputation.py — Check IP address against known malicious IP databases.
Uses AbuseIPDB public API (no key needed for basic check) + Spamhaus feed cache.
"""
import requests
from threat_intel.blocklist_loader import get_blocklist

# Known malicious hosting ASN prefixes (Bulletproof hosters)
MALICIOUS_IP_PREFIXES = {
    "185.220.", "185.130.", "194.165.", "45.142.", "91.108.",
    "5.188.", "176.97.", "195.123.", "31.184.", "46.166.",
}


def check_ip_reputation(ip: str) -> dict:
    """
    Returns:
    {
        "ip": str,
        "is_malicious": bool,
        "score_addition": int,
        "reason": str
    }
    """
    if not ip:
        return {"ip": ip, "is_malicious": False, "score_addition": 0, "reason": "No IP"}

    reasons = []

    # Check Spamhaus cached IP list
    try:
        spamhaus = get_blocklist("spamhaus_drop")
        if ip in spamhaus:
            reasons.append("Spamhaus DROP list")
    except Exception:
        pass

    # Check known bulletproof hosting prefixes
    for prefix in MALICIOUS_IP_PREFIXES:
        if ip.startswith(prefix):
            reasons.append(f"Known malicious hosting range ({prefix}*)")
            break

    # AbuseIPDB public check (no API key, just HEAD request for basic signal)
    try:
        resp = requests.get(
            f"https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": "public", "Accept": "application/json"},
            timeout=4
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)
            if abuse_score > 50:
                reasons.append(f"AbuseIPDB score: {abuse_score}%")
    except Exception:
        pass

    is_malicious = bool(reasons)
    return {
        "ip": ip,
        "is_malicious": is_malicious,
        "score_addition": 60 if is_malicious else 0,
        "reason": " | ".join(reasons) if reasons else "Clean",
    }
