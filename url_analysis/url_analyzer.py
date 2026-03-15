"""
url_analyzer.py — URL risk analysis with piracy, adult, and threat feed detection.
"""
import re
import math
import socket
import ssl
import datetime
import requests
from urllib.parse import urlparse
import pandas as pd

PHISHING_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "bank", "confirm",
    "password", "otp", "kyc", "suspend", "blocked", "urgent", "free",
    "winner", "prize", "claim", "reward", "lucky", "signin", "webscr",
    "ebayisapi", "paypal", "credential", "validate"
]

SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".click",
    ".link", ".download", ".win", ".buzz", ".rest", ".monster", ".icu",
    ".work", ".party", ".xxx", ".adult", ".sex"
}

TRUSTED_DOMAINS = {
    "google.com", "amazon.com", "microsoft.com", "apple.com", "github.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "irctc.co.in", "gov.in", "nic.in", "flipkart.com", "paytm.com",
    "youtube.com", "facebook.com", "twitter.com", "linkedin.com",
    "instagram.com", "wikipedia.org", "stackoverflow.com"
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
    "steamunlocked", "apunkagames", "libgen", "freecoursesite"
]

ADULT_KEYWORDS = [
    "porn", "xxx", "sex", "adult", "nude", "hentai", "escort",
    "hotgirls", "freeporn", "pornhub", "xvideos", "xhamster",
    "redtube", "sexvideo", "livecam", "erotic", "cam4", "onlyfans",
    "brazzers", "bangbros", "naughty", "milf", "fetish", "nsfw"
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


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return round(-sum(p * math.log2(p) for p in freq.values()), 3)


def _dns_resolve(domain: str) -> tuple:
    try:
        ip = socket.gethostbyname(domain)
        return ip, True
    except Exception:
        return "", False


def _is_ip_address(s: str) -> bool:
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', s))


def _check_ssl(domain: str, port: int = 443) -> dict:
    result = {"ssl_valid": 0, "ssl_days_left": -1, "ssl_issuer": ""}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(4)
            s.connect((domain, port))
            cert = s.getpeercert()
            expire_str = cert.get("notAfter", "")
            if expire_str:
                expire_dt = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_dt - datetime.datetime.utcnow()).days
                result["ssl_valid"] = 1 if days_left > 0 else 0
                result["ssl_days_left"] = days_left
            issuer = dict(x[0] for x in cert.get("issuer", []))
            result["ssl_issuer"] = issuer.get("organizationName", "")
    except Exception:
        pass
    return result


def _check_whois(domain: str) -> dict:
    result = {"domain_age_days": -1, "registrar": "", "whois_available": 0}
    try:
        import whois
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age = (datetime.datetime.utcnow() - creation).days
            result["domain_age_days"] = age
            result["whois_available"] = 1
        result["registrar"] = str(w.registrar or "")[:60]
    except Exception:
        pass
    return result


def _check_http(url: str) -> dict:
    result = {
        "http_status": 0, "redirect_count": 0, "final_url": url,
        "response_time_ms": -1, "page_title": "", "server_header": ""
    }
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        start = datetime.datetime.utcnow()
        resp = requests.get(url, timeout=6, allow_redirects=True, headers=headers, verify=False)
        elapsed = (datetime.datetime.utcnow() - start).total_seconds() * 1000
        result["http_status"] = resp.status_code
        result["redirect_count"] = len(resp.history)
        result["final_url"] = resp.url
        result["response_time_ms"] = round(elapsed, 1)
        result["server_header"] = resp.headers.get("Server", "")[:40]
        title_match = re.search(r'<title[^>]*>(.*?)</title>', resp.text[:3000], re.IGNORECASE | re.DOTALL)
        if title_match:
            result["page_title"] = title_match.group(1).strip()[:80]
    except Exception:
        pass
    return result


# ── Detection functions ───────────────────────────────────────────────────────

def detect_piracy_keywords(domain: str, path: str = "") -> tuple:
    """Returns (bool, matched_keyword). Checks domain + path for piracy indicators."""
    text = (domain + " " + path).lower()
    for kw in PIRACY_KEYWORDS:
        if kw in text:
            return True, kw
    return False, ""


def detect_adult_keywords(domain: str, path: str = "") -> tuple:
    """Returns (bool, matched_keyword). Checks domain + path for adult content indicators."""
    text = (domain + " " + path).lower()
    for kw in ADULT_KEYWORDS:
        if kw in text:
            return True, kw
    return False, ""


def check_domain_blocklists(domain: str) -> tuple:
    """
    Check domain against static blacklist + live threat feeds.
    Returns (is_blocked, reason_string, score_addition).
    """
    domain = domain.lower().replace("www.", "").split(":")[0]
    parts = domain.split(".")
    candidates = {".".join(parts[i:]) for i in range(len(parts) - 1)}
    candidates.add(domain)

    # Static blacklist check
    if candidates & BLACKLISTED_DOMAINS:
        return True, "known illegal/piracy/adult domain", 90

    # Live threat feed check
    try:
        from threat_intel.blocklist_loader import check_domain_in_feeds
        is_blocked, feeds = check_domain_in_feeds(domain)
        if is_blocked:
            return True, f"threat feed match: {', '.join(feeds)}", 90
    except Exception:
        pass

    return False, "", 0


def _check_blacklist(domain: str) -> tuple:
    """Legacy wrapper — used by analyze_url for fast pre-check."""
    is_blocked, reason, _ = check_domain_blocklists(domain)
    if is_blocked:
        return True, reason

    domain_clean = domain.lower().replace("www.", "")
    found, kw = detect_piracy_keywords(domain_clean)
    if found:
        return True, f"piracy keyword: {kw}"

    found, kw = detect_adult_keywords(domain_clean)
    if found:
        return True, f"adult keyword: {kw}"

    return False, ""


def extract_url_features(url: str, live: bool = True) -> dict:
    try:
        if not url.startswith("http"):
            url = "http://" + url
        parsed = urlparse(url)
    except Exception:
        return _empty_features()

    domain = parsed.netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    domain_clean = domain.split(":")[0]
    path = parsed.path.lower()
    full = url.lower()
    parts = domain_clean.split(".")
    tld = "." + parts[-1] if parts else ""

    has_ip = _is_ip_address(domain_clean)
    is_trusted = any(domain_clean == td or domain_clean.endswith("." + td) for td in TRUSTED_DOMAINS)
    keyword_count = sum(1 for kw in PHISHING_KEYWORDS if kw in full)
    num_subdomains = max(len(parts) - 2, 0)

    features = {
        "url_length":        len(url),
        "domain_length":     len(domain_clean),
        "num_dots":          url.count("."),
        "num_subdomains":    num_subdomains,
        "num_hyphens":       domain_clean.count("-"),
        "num_slashes":       url.count("/"),
        "num_params":        len(parsed.query.split("&")) if parsed.query else 0,
        "has_ip":            int(has_ip),
        "is_https":          int(parsed.scheme == "https"),
        "suspicious_tld":    int(tld in SUSPICIOUS_TLDS),
        "is_trusted_domain": int(is_trusted),
        "keyword_count":     keyword_count,
        "has_at_symbol":     int("@" in url),
        "has_double_slash":  int("//" in path),
        "domain_entropy":    _entropy(domain_clean),
        "path_length":       len(path),
        "has_port":          int(bool(parsed.port)),
        "subdomain_count":   num_subdomains,
        "digit_ratio":       round(sum(c.isdigit() for c in domain_clean) / max(len(domain_clean), 1), 3),
    }

    if live and not has_ip:
        ip, resolved = _dns_resolve(domain_clean)
        features["resolved_ip"]  = ip
        features["dns_resolved"] = int(resolved)
        ssl_info = _check_ssl(domain_clean) if parsed.scheme == "https" else \
                   {"ssl_valid": 0, "ssl_days_left": -1, "ssl_issuer": ""}
        features.update(ssl_info)
        features.update(_check_whois(domain_clean))
        features.update(_check_http(url))
    elif live and has_ip:
        features.update({
            "resolved_ip": domain_clean, "dns_resolved": 1,
            "ssl_valid": 0, "ssl_days_left": -1, "ssl_issuer": "",
            "domain_age_days": -1, "registrar": "", "whois_available": 0
        })
        features.update(_check_http(url))

    return features


def _empty_features() -> dict:
    return {k: 0 for k in [
        "url_length", "domain_length", "num_dots", "num_subdomains",
        "num_hyphens", "num_slashes", "num_params", "has_ip", "is_https",
        "suspicious_tld", "is_trusted_domain", "keyword_count", "has_at_symbol",
        "has_double_slash", "domain_entropy", "path_length", "has_port",
        "subdomain_count", "digit_ratio"
    ]}


def rule_based_url_score(features: dict) -> tuple:
    score = 0.0

    if features.get("is_trusted_domain"):   score -= 35
    if features.get("is_https"):            score -= 10
    if features.get("ssl_valid", 0):        score -= 10
    if features.get("dns_resolved", 0):     score -= 5
    age = features.get("domain_age_days", -1)
    if age > 365:                           score -= 10
    elif age > 90:                          score -= 5

    if features.get("has_ip"):              score += 35
    if features.get("suspicious_tld"):      score += 30
    if not features.get("dns_resolved", 1): score += 20
    score += features.get("keyword_count", 0) * 8
    score += features.get("num_subdomains", 0) * 5
    if features.get("url_length", 0) > 75:  score += 10
    if features.get("domain_entropy", 0) > 3.5: score += 10
    if features.get("has_at_symbol"):       score += 20
    if features.get("digit_ratio", 0) > 0.3: score += 10
    if features.get("redirect_count", 0) > 2: score += 15
    if 0 < age < 30:                        score += 25
    elif 30 <= age < 90:                    score += 10
    if features.get("http_status", 0) in (0, 403, 404, 500): score += 10
    if not features.get("ssl_valid", 1) and features.get("is_https"): score += 15

    # Piracy / adult scoring
    score += features.get("_piracy_score", 0)
    score += features.get("_adult_score", 0)
    score += features.get("_blocklist_score", 0)

    score = max(0.0, min(100.0, score))
    label = "safe" if score < 30 else "suspicious" if score < 60 else "malicious"
    return round(score, 1), label


def analyze_url(url: str, live: bool = True) -> dict:
    try:
        parsed_check = urlparse(url if url.startswith("http") else "http://" + url)
        domain_check = parsed_check.netloc.lower().replace("www.", "").split(":")[0]
        path_check = parsed_check.path.lower()
    except Exception:
        domain_check = ""
        path_check = ""

    # ── Content classification ────────────────────────────────────────────────
    piracy_found, piracy_kw   = detect_piracy_keywords(domain_check, path_check)
    adult_found,  adult_kw    = detect_adult_keywords(domain_check, path_check)
    is_blocked, block_reason, blocklist_score = check_domain_blocklists(domain_check)

    parsed_tld = "." + domain_check.split(".")[-1] if "." in domain_check else ""

    # Build detection_reasons
    detection_reasons = []
    if piracy_found:
        detection_reasons.append(f"Piracy keyword: {piracy_kw}")
    if adult_found:
        detection_reasons.append(f"Adult keyword: {adult_kw}")
    if is_blocked:
        detection_reasons.append(f"Blocklist match: {block_reason}")
    if parsed_tld in SUSPICIOUS_TLDS:
        detection_reasons.append(f"Suspicious TLD: {parsed_tld}")

    is_high_risk = bool(piracy_found or adult_found or is_blocked)

    # Compute scores from booleans
    piracy_score    = 50 if piracy_found else 0
    adult_score     = 60 if adult_found  else 0

    if is_high_risk:
        features = extract_url_features(url, live=False)
        features["_piracy_score"]    = piracy_score
        features["_adult_score"]     = adult_score
        features["_blocklist_score"] = blocklist_score
        features["is_blacklisted"]   = 1
        features["blacklist_reason"] = " | ".join(detection_reasons)
        return {
            "url": url,
            "risk_score": 100.0,
            "label": "malicious",
            "risk_level": "HIGH RISK",
            "blacklisted": True,
            "blacklist_reason": " | ".join(detection_reasons),
            "detection_reasons": detection_reasons,
            "category": "adult" if adult_found else "piracy" if piracy_found else "malware",
            **features
        }

    # Normal analysis path
    features = extract_url_features(url, live=live)
    features["_piracy_score"]    = 0
    features["_adult_score"]     = 0
    features["_blocklist_score"] = 0
    features["is_blacklisted"]   = 0
    features["blacklist_reason"] = ""

    risk_score, label = rule_based_url_score(features)
    risk_level = "SAFE" if risk_score < 30 else "SUSPICIOUS" if risk_score < 60 else "HIGH RISK"

    return {
        "url": url,
        "risk_score": risk_score,
        "label": label,
        "risk_level": risk_level,
        "blacklisted": False,
        "blacklist_reason": " | ".join(detection_reasons),
        "detection_reasons": detection_reasons,
        "category": "normal",
        **features
    }


def analyze_urls_batch(urls: list, live: bool = True) -> pd.DataFrame:
    return pd.DataFrame([analyze_url(u, live=live) for u in urls])
