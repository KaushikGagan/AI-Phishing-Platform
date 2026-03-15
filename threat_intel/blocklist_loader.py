"""
blocklist_loader.py — Downloads and caches public threat feed blocklists.
Feeds: OpenPhish, URLHaus, MalwareDomains, Spamhaus (public mirror)
Cache TTL: 6 hours. Falls back to cached data on network failure.
"""
import os
import re
import time
import json
import hashlib
import requests
from urllib.parse import urlparse

CACHE_DIR = os.path.join(os.path.dirname(__file__), "_cache")
CACHE_TTL_SECONDS = 6 * 3600  # 6 hours

# Public threat feeds — all return plain-text domain/URL lists
FEEDS = {
    "openphish": {
        "url": "https://openphish.com/feed.txt",
        "type": "url",          # each line is a full URL → extract domain
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "type": "url",
    },
    "malwaredomains": {
        "url": "https://mirror1.malwaredomains.com/files/justdomains",
        "type": "domain",       # each line is a bare domain
    },
    "spamhaus_drop": {
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "type": "ip",           # CIDR blocks — we store as-is for IP checks
    },
}

os.makedirs(CACHE_DIR, exist_ok=True)


def _cache_path(feed_name: str) -> str:
    return os.path.join(CACHE_DIR, f"{feed_name}.json")


def _is_stale(path: str) -> bool:
    if not os.path.exists(path):
        return True
    return (time.time() - os.path.getmtime(path)) > CACHE_TTL_SECONDS


def _fetch_feed(feed_name: str, feed_cfg: dict) -> set:
    """Download a feed and return a set of domains/IPs."""
    domains = set()
    try:
        resp = requests.get(feed_cfg["url"], timeout=10,
                            headers={"User-Agent": "PhishGuard-ThreatIntel/1.0"})
        if resp.status_code != 200:
            return domains
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if feed_cfg["type"] == "url":
                try:
                    parsed = urlparse(line if "://" in line else "http://" + line)
                    d = parsed.netloc.lower().replace("www.", "").split(":")[0]
                    if d:
                        domains.add(d)
                except Exception:
                    pass
            elif feed_cfg["type"] == "domain":
                d = line.lower().replace("www.", "")
                if d:
                    domains.add(d)
            elif feed_cfg["type"] == "ip":
                # Store raw CIDR for IP matching
                ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    domains.add(ip_match.group(1))
    except Exception:
        pass
    return domains


def _load_cached(path: str) -> set:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return set(json.load(f))
    except Exception:
        return set()


def _save_cache(path: str, data: set) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(list(data), f)
    except Exception:
        pass


def get_blocklist(feed_name: str) -> set:
    """Return cached blocklist for a feed, refreshing if stale."""
    path = _cache_path(feed_name)
    if _is_stale(path):
        data = _fetch_feed(feed_name, FEEDS[feed_name])
        if data:
            _save_cache(path, data)
            return data
        # Network failed — fall back to stale cache
        return _load_cached(path)
    return _load_cached(path)


def get_all_blocklists() -> dict:
    """Return {feed_name: set_of_domains} for all feeds."""
    return {name: get_blocklist(name) for name in FEEDS}


def check_domain_in_feeds(domain: str) -> tuple[bool, list[str]]:
    """
    Check if domain (or any parent) appears in any threat feed.
    Returns (is_blocked, [matching_feed_names]).
    """
    domain = domain.lower().replace("www.", "").split(":")[0]
    parts = domain.split(".")
    # Build candidate list: full domain + all parent domains
    candidates = {".".join(parts[i:]) for i in range(len(parts) - 1)}
    candidates.add(domain)

    matched_feeds = []
    for feed_name in FEEDS:
        blocklist = get_blocklist(feed_name)
        if candidates & blocklist:
            matched_feeds.append(feed_name)

    return bool(matched_feeds), matched_feeds


def get_feed_stats() -> dict:
    """Return count of entries per feed (from cache)."""
    stats = {}
    for name in FEEDS:
        path = _cache_path(name)
        cached = _load_cached(path)
        stats[name] = {
            "count": len(cached),
            "stale": _is_stale(path),
            "cache_path": path,
        }
    return stats
