"""
email_parser.py — parses raw email objects from imaplib into clean dicts.
"""
import re
import email
import quopri
from email.header import decode_header
from datetime import datetime
from typing import Optional


URL_RE = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', re.IGNORECASE)


def _decode_str(value: str) -> str:
    if not value:
        return ""
    parts = decode_header(value)
    decoded = []
    for part, enc in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(enc or "utf-8", errors="replace"))
        else:
            decoded.append(str(part))
    return " ".join(decoded).strip()


def _get_body(msg: email.message.Message) -> str:
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            if ct == "text/plain" and "attachment" not in cd:
                try:
                    charset = part.get_content_charset() or "utf-8"
                    body += part.get_payload(decode=True).decode(charset, errors="replace")
                except Exception:
                    pass
    else:
        try:
            charset = msg.get_content_charset() or "utf-8"
            body = msg.get_payload(decode=True).decode(charset, errors="replace")
        except Exception:
            body = str(msg.get_payload())
    return body.strip()


def parse_email(raw_bytes: bytes) -> dict:
    """Parse raw IMAP email bytes into a structured dict."""
    msg = email.message_from_bytes(raw_bytes)

    sender = _decode_str(msg.get("From", ""))
    subject = _decode_str(msg.get("Subject", "(No Subject)"))
    date_str = msg.get("Date", "")

    try:
        from email.utils import parsedate_to_datetime
        ts = parsedate_to_datetime(date_str).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    body = _get_body(msg)
    urls = list(set(URL_RE.findall(body)))

    # Extract clean sender email address
    sender_email_match = re.search(r'[\w.\-+]+@[\w.\-]+', sender)
    sender_email = sender_email_match.group(0) if sender_email_match else sender

    # Extract display name
    sender_name = re.sub(r'<.*?>', '', sender).strip().strip('"')

    return {
        "sender": sender_email,
        "sender_name": sender_name or sender_email,
        "subject": subject,
        "body": body[:3000],        # cap at 3KB for performance
        "timestamp": ts,
        "urls": urls,
    }
