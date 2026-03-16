"""
dns_lookup.py — Resolve domain to IP address.
"""
import socket


def resolve_domain(domain: str) -> dict:
    domain = domain.lower().replace("www.", "").split(":")[0]
    try:
        ip = socket.gethostbyname(domain)
        return {"domain": domain, "ip_address": ip, "resolved": True}
    except Exception:
        return {"domain": domain, "ip_address": "", "resolved": False}
