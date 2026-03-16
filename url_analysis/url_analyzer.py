"""
url_analyzer.py — Deep threat-intelligence URL analysis engine.
Combines domain reputation, IP reputation, WHOIS, content analysis,
piracy/adult detection, and structural analysis into a unified risk score.
"""
import re
import math
import socket
import datetime
from urllib.parse import urlparse
import pandas as pd

# ── Keyword lists ─────────────────────────────────────────────────────────────

PHISHING_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "bank", "confirm",
    "password", "otp", "kyc", "suspend", "blocked", "urgent", "free",
    "winner", "prize", "claim", "reward", "lucky", "signin", "webscr",
    "ebayisapi", "paypal", "credential", "validate",
]

SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".click",
    ".link", ".download", ".win", ".buzz", ".rest", ".monster", ".icu",
    ".work", ".party", ".xxx", ".adult", ".sex",
}

TRUSTED_DOMAINS = {
    "google.com", "amazon.com", "microsoft.com", "apple.com", "github.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "irctc.co.in", "gov.in", "nic.in", "flipkart.com", "paytm.com",
    "youtube.com", "facebook.com", "twitter.com", "linkedin.com",
    "instagram.com", "wikipedia.org", "stackoverflow.com",
}

PIRACY_KEYWORDS = [
    "torrent", "yts", "rarbg", "1337x", "piratebay", "kickass", "kat",
    "moviesfree", "download-movies", "free-movies", "watch-free",
    "cracked-software", "full-movie", "hdmovies", "streamfree", "mp4moviez",
    "filmyzilla", "tamilrockers", "moviesflix", "worldfree4u", "pirate",
    "crack", "keygen", "warez", "nulled", "hdrip", "bluray", "dvdrip",
    "mkv-download", "720p", "1080p", "4k-download", "leaked", "ibomma",
    "movierulz", "bollyflix", "kuttymovie", "isaimini", "tamilgun",
    "cinemavilla", "moviesda", "netmirror", "vegamovie", "hdhub",
    "skymovie", "filmywap", "9xmovie", "jiorockers", "isaidub",
    "downloadhub", "coolmoviez", "extramovies", "katmoviehd",
    "moviescounter", "afilmywap", "openload", "streamango",
    "skidrowreloaded", "fitgirl", "oceanofgames", "igg-games",
    "steamunlocked", "apunkagames", "libgen", "freecoursesite",
    "watchfree", "fullmovie",
]

ADULT_KEYWORDS = [
    "porn", "xxx", "sex", "adult", "nude", "hentai", "escort",
    "hotgirls", "freeporn", "pornhub", "xvideos", "xhamster",
    "redtube", "sexvideo", "livecam", "erotic", "cam4", "onlyfans",
    "brazzers", "bangbros", "naughty", "milf", "fetish", "nsfw", "cam",
]

BLACKLISTED_DOMAINS = {
    "ibomma.com", "ibomma.net", "ibomma.in", "ibomma.org",
    "netmirror.org", "netmirror.net", "netmirror.in",
    "tamilrockers.com", "tamilrockers.net", "tamilrockers.ws",
    "movierulz.com", "movierulz.net", "movierulz.tc",
    "filmyzilla.com", "filmyzilla.net", "filmyzilla.in",
    "123movies.com", "123movies.net", "gomovies.com",
    "fmovies.to", "fmovies.com", "putlocker.com", "putlockers.com",
    "yts.mx", "yts.am", "yts.lt", "rarbg.to", "rarbg.com",
    "1337x.to", "1337x.st", "thepiratebay.org", "thepiratebay.com",
    "kickasstorrents.com", "kat.cr", "katcr.co",
    "bollyflix.com", "bollyflix.in", "bolly4u.org",
    "9xmovies.com", "9xmovies.net", "9xmovies.in",
    "jiorockers.com", "isaimini.com", "isaidub.com",
    "kuttymovies.com", "kuttymovies.net",
    "tamilgun.com", "tamilgun.net", "tamilyogi.com",
    "cinemavilla.com", "moviesda.com", "moviesda.net",
    "downloadhub.com", "downloadhub.in", "mp4moviez.com",
    "worldfree4u.com", "worldfree4u.net", "world4ufree.com",
    "coolmoviez.com", "pagalworld.com", "djpunjab.com",
    "skymovies.com", "skymovies.in", "skymovieshd.com",
    "vegamovies.com", "vegamovies.nl", "vegamovies.in",
    "hdhub4u.com", "hdhub4u.net", "hdhub4u.in",
    "sdmoviespoint.com", "sdmoviespoint.in",
    "extramovies.com", "extramovies.in",
    "katmoviehd.com", "katmoviehd.net",
    "moviescounter.com", "moviescounter.net",
    "afilmywap.com", "afilmywap.in", "filmywap.com",
    "openload.co", "streamango.com",
    "crackedpc.com", "crackwatch.com", "skidrowreloaded.com",
    "fitgirl-repacks.site", "oceanofgames.com", "igg-games.com",
    "steamunlocked.net", "apunkagames.com",
    "libgen.is", "libgen.rs", "libgen.fun", "z-lib.org",
    "booksc.org", "freecoursesite.com", "coursesghar.com",
    "xvideos.com", "xnxx.com", "pornhub.com", "xhamster.com",
    "redtube.com", "youporn.com", "tube8.com", "spankbang.com",
    "bet365.com", "1xbet.com", "betway.com",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_domain(url: str) -> tuple[str, str]:
    """Return (domain, path) from a URL string."""
    if not url.startswith("http"):
        url = "http://" + url
    parsed = urlparse(url)
    domain = parsed.netloc.lower().replace("www.", "").split(":")[0]
    return domain, parsed.path.lower()


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return round(-sum(p * math.log2(p) for p in freq.values()), 3)


def _is_ip_address(s: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))


# ── Detection helpers ─────────────────────────────────────────────────────────

def detect_piracy_keywords(domain: str, path: str = "") -> tuple[bool, str]:
    text = (domain + " " + path).lower()
    for kw in PIRACY_KEYWORDS:
        if kw in text:
            return True, kw
    return False, ""


def detect_adult_keywords(domain: str, path: str = "") -> tuple[bool, str]:
    text = (domain + " " + path).lower()
    for kw in ADULT_KEYWORDS:
        if kw in text:
            return True, kw
    return False, ""


def check_domain_blocklists(domain: str) -> tuple[bool, str, int]:
    """Returns (is_blocked, reason, score_addition)."""
    domain = domain.lower().replace("www.", "").split(":")[0]
    parts = domain.split(".")
    candidates = {".".join(parts[i:]) for i in range(len(parts) - 1)}
    candidates.add(domain)

    if candidates & BLACKLISTED_DOMAINS:
        return True, "known illegal/piracy/adult domain", 90

    try:
        from threat_intel.blocklist_loader import check_domain_in_feeds
        is_blocked, feeds = check_domain_in_feeds(domain)
        if is_blocked:
            return True, f"threat feed match: {', '.join(feeds)}", 90
    except Exception:
        pass

    return False, "", 0


# ── Structural feature extraction ─────────────────────────────────────────────

def _structural_score(url: str, domain: str, path: str) -> tuple[int, list[str]]:
    """Score URL based on structural features. Returns (score, reasons)."""
    score = 0
    reasons = []
    parts = domain.split(".")
    tld = "." + parts[-1] if parts else ""
    num_subdomains = max(len(parts) - 2, 0)

    if _is_ip_address(domain):
        score += 35
        reasons.append("IP address used instead of domain")
    if tld in SUSPICIOUS_TLDS:
        score += 30
        reasons.append(f"Suspicious TLD: {tld}")
    if len(url) > 75:
        score += 10
        reasons.append(f"Long URL ({len(url)} chars)")
    if num_subdomains > 2:
        score += 15
        reasons.append(f"Excessive subdomains ({num_subdomains})")
    if "@" in url:
        score += 20
        reasons.append("@ symbol in URL")
    if "//" in path:
        score += 10
        reasons.append("Double slash in path")
    if _entropy(domain) > 3.5:
        score += 10
        reasons.append(f"High domain entropy ({_entropy(domain):.2f})")
    digit_ratio = sum(c.isdigit() for c in domain) / max(len(domain), 1)
    if digit_ratio > 0.3:
        score += 10
        reasons.append(f"High digit ratio in domain ({digit_ratio:.0%})")
    kw_hits = sum(1 for kw in PHISHING_KEYWORDS if kw in url.lower())
    if kw_hits:
        score += kw_hits * 8
        reasons.append(f"{kw_hits} phishing keyword(s) in URL")

    return score, reasons


# ── Main analysis engine ──────────────────────────────────────────────────────

def analyze_url(url: str, live: bool = True) -> dict:
    """
    Deep threat-intelligence URL analysis.

    Returns:
    {
        "url", "domain", "ip_address", "domain_age", "category",
        "threat_sources", "risk_score", "risk_level",
        "detection_reasons", "label", ...feature keys
    }
    """
    if not url.startswith("http"):
        url = "http://" + url

    try:
        domain, path = _extract_domain(url)
    except Exception:
        return _error_result(url)

    risk_score = 0
    threat_sources = []
    detection_reasons = []
    category = "Unknown"
    ip_address = ""
    domain_age = "Unknown"
    domain_age_days = -1
    registrar = "Unknown"
    country = "Unknown"

    # ── 1. Trusted domain fast-pass ───────────────────────────────────────────
    is_trusted = any(domain == td or domain.endswith("." + td) for td in TRUSTED_DOMAINS)
    if is_trusted:
        return {
            "url": url, "domain": domain, "ip_address": "", "domain_age": "Established",
            "category": "Legitimate", "threat_sources": [], "risk_score": 0,
            "risk_level": "SAFE", "detection_reasons": [], "label": "safe",
            "blacklisted": False, "blacklist_reason": "",
            "is_trusted_domain": 1, "is_https": int(url.startswith("https")),
        }

    # ── 2. Piracy detection (+60) ─────────────────────────────────────────────
    piracy_found, piracy_kw = detect_piracy_keywords(domain, path)
    if piracy_found:
        risk_score += 60
        category = "Piracy"
        detection_reasons.append(f"Piracy keyword detected: '{piracy_kw}'")

    # ── 3. Adult content detection (+60) ──────────────────────────────────────
    adult_found, adult_kw = detect_adult_keywords(domain, path)
    if adult_found:
        risk_score += 60
        category = "Adult Content" if not piracy_found else category
        detection_reasons.append(f"Adult keyword detected: '{adult_kw}'")

    # ── 4. Domain blocklist / reputation check (+80) ──────────────────────────
    is_blocked, block_reason, _ = check_domain_blocklists(domain)
    if is_blocked:
        risk_score += 80
        detection_reasons.append(f"Blocklist: {block_reason}")

    if live:
        try:
            from threat_intel.domain_reputation import check_domain_reputation
            rep = check_domain_reputation(domain)
            if rep["is_malicious"]:
                risk_score += rep["score_addition"]
                threat_sources.extend(rep["sources"])
                detection_reasons.append(rep["reason"])
                if not category or category == "Unknown":
                    category = "Malware/Phishing"
        except Exception:
            pass

        # ── 5. DNS & IP resolution ────────────────────────────────────────────
        try:
            from threat_intel.dns_lookup import resolve_domain
            dns_result = resolve_domain(domain)
            ip_address = dns_result.get("ip_address", "")
        except Exception:
            ip_address = ""

        # ── 6. IP reputation check (+60) ──────────────────────────────────────
        if ip_address:
            try:
                from threat_intel.ip_reputation import check_ip_reputation
                ip_rep = check_ip_reputation(ip_address)
                if ip_rep["is_malicious"]:
                    risk_score += ip_rep["score_addition"]
                    detection_reasons.append(f"IP reputation: {ip_rep['reason']}")
                    threat_sources.append(f"IP {ip_address} flagged")
            except Exception:
                pass

        # ── 7. WHOIS / domain age check (+25 if < 30 days) ───────────────────
        try:
            from domain_intel.domain_info import get_domain_info
            whois_info = get_domain_info(domain)
            domain_age_days = whois_info.get("domain_age_days", -1)
            registrar = whois_info.get("registrar", "Unknown")
            country = whois_info.get("country", "Unknown")
            if domain_age_days >= 0:
                domain_age = f"{domain_age_days} days"
            if whois_info["score_addition"] > 0:
                risk_score += whois_info["score_addition"]
                detection_reasons.append(whois_info["reason"])
        except Exception:
            pass

        # ── 8. Content / page analysis (+40) ──────────────────────────────────
        try:
            from content_scanner.page_analyzer import analyze_page
            page = analyze_page(url)
            if page["score_addition"] > 0:
                risk_score += page["score_addition"]
                detection_reasons.extend(page["reasons"])
                threat_sources.append("Page content analysis")
        except Exception:
            pass

    # ── 9. Structural URL analysis ────────────────────────────────────────────
    struct_score, struct_reasons = _structural_score(url, domain, path)
    risk_score += struct_score
    detection_reasons.extend(struct_reasons)

    # ── 10. Final scoring & classification ────────────────────────────────────
    risk_score = min(int(risk_score), 100)

    if risk_score < 30:
        risk_level = "SAFE"
        label = "safe"
    elif risk_score < 60:
        risk_level = "SUSPICIOUS"
        label = "suspicious"
    else:
        risk_level = "HIGH RISK"
        label = "malicious"

    if category == "Unknown":
        category = "Suspicious" if risk_level == "SUSPICIOUS" else (
            "Malware/Phishing" if risk_level == "HIGH RISK" else "Normal"
        )

    # Deduplicate threat sources
    threat_sources = list(dict.fromkeys(threat_sources))

    return {
        "url": url,
        "domain": domain,
        "ip_address": ip_address,
        "domain_age": domain_age,
        "domain_age_days": domain_age_days,
        "registrar": registrar,
        "country": country,
        "category": category,
        "threat_sources": threat_sources,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "label": label,
        "detection_reasons": detection_reasons,
        "blacklisted": is_blocked,
        "blacklist_reason": block_reason if is_blocked else "",
        # Structural features (kept for backward compat with dashboard/scorer)
        "url_length": len(url),
        "domain_length": len(domain),
        "num_dots": url.count("."),
        "num_subdomains": max(len(domain.split(".")) - 2, 0),
        "num_hyphens": domain.count("-"),
        "has_ip": int(_is_ip_address(domain)),
        "is_https": int(url.startswith("https")),
        "suspicious_tld": int(("." + domain.split(".")[-1]) in SUSPICIOUS_TLDS),
        "is_trusted_domain": int(is_trusted),
        "keyword_count": sum(1 for kw in PHISHING_KEYWORDS if kw in url.lower()),
        "domain_entropy": _entropy(domain),
    }


def _error_result(url: str) -> dict:
    return {
        "url": url, "domain": "", "ip_address": "", "domain_age": "Unknown",
        "domain_age_days": -1, "registrar": "Unknown", "country": "Unknown",
        "category": "Unknown", "threat_sources": [], "risk_score": 0,
        "risk_level": "SAFE", "label": "safe", "detection_reasons": ["Parse error"],
        "blacklisted": False, "blacklist_reason": "",
        "url_length": 0, "domain_length": 0, "num_dots": 0, "num_subdomains": 0,
        "num_hyphens": 0, "has_ip": 0, "is_https": 0, "suspicious_tld": 0,
        "is_trusted_domain": 0, "keyword_count": 0, "domain_entropy": 0.0,
    }


def analyze_urls_batch(urls: list, live: bool = True) -> pd.DataFrame:
    return pd.DataFrame([analyze_url(u, live=live) for u in urls])
