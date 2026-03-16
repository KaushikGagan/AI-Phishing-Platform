"""
page_analyzer.py — Fetch and scan webpage HTML for phishing indicators using BeautifulSoup.
"""
import re
import requests

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}


def analyze_page(url: str) -> dict:
    result = {
        "has_login_form": False,
        "has_password_field": False,
        "has_hidden_inputs": False,
        "has_suspicious_js": False,
        "has_redirect_script": False,
        "has_obfuscated_js": False,
        "score_addition": 0,
        "reasons": [],
        "page_title": "",
        "fetch_success": False,
    }
    try:
        resp = requests.get(url, timeout=6, headers=HEADERS, verify=False)
        html = resp.text
        result["fetch_success"] = True

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")

            title_tag = soup.find("title")
            if title_tag:
                result["page_title"] = title_tag.get_text(strip=True)[:80]

            # Login form: form containing login/signin/credential text
            for form in soup.find_all("form"):
                form_text = form.get_text().lower()
                form_action = (form.get("action") or "").lower()
                if any(kw in form_text + form_action for kw in ("login", "signin", "credential", "username")):
                    result["has_login_form"] = True
                    result["reasons"].append("Login/credential form detected")
                    break

            # Password field
            if soup.find("input", {"type": "password"}):
                result["has_password_field"] = True
                result["reasons"].append("Password input field detected")

            # Hidden inputs (>3 is suspicious)
            hidden = soup.find_all("input", {"type": "hidden"})
            if len(hidden) > 3:
                result["has_hidden_inputs"] = True
                result["reasons"].append(f"{len(hidden)} hidden input fields")

            # Inline script analysis
            scripts = " ".join(s.get_text() for s in soup.find_all("script"))
            scripts_lower = scripts.lower()

        except ImportError:
            # Fallback to regex if BeautifulSoup not installed
            html_lower = html.lower()
            scripts_lower = html_lower

            t = re.search(r"<title[^>]*>(.*?)</title>", html[:3000], re.I | re.S)
            if t:
                result["page_title"] = t.group(1).strip()[:80]

            if re.search(r"<form[^>]*>", html_lower) and any(
                kw in html_lower for kw in ("login", "signin", "credential")
            ):
                result["has_login_form"] = True
                result["reasons"].append("Login/credential form detected")

            if re.search(r'<input[^>]*type=["\']password["\']', html_lower):
                result["has_password_field"] = True
                result["reasons"].append("Password input field detected")

            hidden = re.findall(r'<input[^>]*type=["\']hidden["\']', html_lower)
            if len(hidden) > 3:
                result["has_hidden_inputs"] = True
                result["reasons"].append(f"{len(hidden)} hidden input fields")

        # Redirect scripts
        if re.search(r"window\.location|document\.location|location\.href|location\.replace", scripts_lower):
            result["has_redirect_script"] = True
            result["reasons"].append("JavaScript redirect detected")

        # Obfuscated JS
        if re.search(r"eval\s*\(|unescape\s*\(|fromcharcode|atob\s*\(", scripts_lower):
            result["has_obfuscated_js"] = True
            result["reasons"].append("Obfuscated JavaScript detected")

        # Suspicious JS (keylogger / cookie theft)
        if re.search(r"document\.cookie|keylogger|onkeypress|onkeydown", scripts_lower):
            result["has_suspicious_js"] = True
            result["reasons"].append("Suspicious JavaScript (cookie/keylogger)")

        flags = sum([
            result["has_login_form"],
            result["has_password_field"],
            result["has_hidden_inputs"],
            result["has_suspicious_js"],
            result["has_redirect_script"],
            result["has_obfuscated_js"],
        ])
        result["score_addition"] = 40 if flags >= 2 else (15 if flags == 1 else 0)

    except Exception:
        pass
    return result
