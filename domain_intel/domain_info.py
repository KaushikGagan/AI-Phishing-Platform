"""
domain_info.py — WHOIS lookup for domain age, registrar, country.
"""
import datetime


def get_domain_info(domain: str) -> dict:
    """
    Returns:
    {
        "domain": str,
        "domain_age_days": int,
        "registration_date": str,
        "registrar": str,
        "country": str,
        "score_addition": int,
        "reason": str
    }
    """
    result = {
        "domain": domain,
        "domain_age_days": -1,
        "registration_date": "Unknown",
        "registrar": "Unknown",
        "country": "Unknown",
        "score_addition": 0,
        "reason": "",
    }
    try:
        import whois
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age = (datetime.datetime.utcnow() - creation).days
            result["domain_age_days"] = age
            result["registration_date"] = creation.strftime("%Y-%m-%d")
            if age < 30:
                result["score_addition"] = 25
                result["reason"] = f"Very new domain ({age} days old)"
            elif age < 90:
                result["score_addition"] = 10
                result["reason"] = f"Recently registered ({age} days old)"
        result["registrar"] = str(w.registrar or "Unknown")[:60]
        result["country"] = str(w.country or "Unknown")[:30] if hasattr(w, "country") else "Unknown"
    except Exception:
        pass
    return result
