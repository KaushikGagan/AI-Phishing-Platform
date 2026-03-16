"""
domain_reputation.py — Check domain against public threat intelligence feeds.
Feeds: PhishTank, OpenPhish, URLHaus, MalwareDomains, Spamhaus
"""
import requests
from threat_intel.blocklist_loader import check_domain_in_feeds
from url_analysis.url_analyzer import BLACKLISTED_DOMAINS

PHISHTANK_API = "https://checkurl.phishtank.com/checkurl/"


def _check_phishtank(domain: str) -> bool:
    """Check domain against PhishTank API (no key required for basic check)."""
    try:
        resp = requests.post(
            PHISHTANK_API,
            data={"url": f"http://{domain}/", "format": "json"},
            headers={"User-Agent": "PhishGuard-ThreatIntel/1.0"},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("results", {}).get("in_database", False) and \
                   data.get("results", {}).get("valid", False)
    except Exception:
        pass
    return False


def check_domain_reputation(domain: str) -> dict:
    """
    Returns:
    {
        "domain": str,
        "is_malicious": bool,
        "score_addition": int,
        "sources": [str],
        "reason": str
    }
    """
    domain = domain.lower().replace("www.", "").split(":")[0]
    parts = domain.split(".")
    candidates = {".".join(parts[i:]) for i in range(len(parts) - 1)}
    candidates.add(domain)

    sources = []

    # Static blacklist
    if candidates & BLACKLISTED_DOMAINS:
        sources.append("PhishGuard Static Blacklist")

    # Live threat feeds (OpenPhish, URLHaus, MalwareDomains, Spamhaus)
    try:
        is_blocked, feeds = check_domain_in_feeds(domain)
        if is_blocked:
            sources.extend(feeds)
    except Exception:
        pass

    # PhishTank live check
    if _check_phishtank(domain):
        sources.append("PhishTank")

    is_malicious = bool(sources)
    return {
        "domain": domain,
        "is_malicious": is_malicious,
        "score_addition": 80 if is_malicious else 0,
        "sources": sources,
        "reason": f"Flagged by: {', '.join(sources)}" if sources else "Clean",
    }
