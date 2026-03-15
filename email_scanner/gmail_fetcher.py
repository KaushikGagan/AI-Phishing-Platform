"""
gmail_fetcher.py — connects to Gmail via IMAP and fetches latest emails.

Gmail setup required:
  1. Enable 2-Step Verification on your Google account
  2. Go to myaccount.google.com/apppasswords
  3. Generate an App Password for "Mail"
  4. Use that 16-character password here (NOT your Gmail login password)
"""
import imaplib
import os
from typing import Optional
from .email_parser import parse_email

GMAIL_IMAP_HOST = "imap.gmail.com"
GMAIL_IMAP_PORT = 993


class GmailFetcher:
    def __init__(self):
        self._imap: Optional[imaplib.IMAP4_SSL] = None
        self.connected = False
        self.error: Optional[str] = None

    def connect(self, gmail_address: str, app_password: str) -> bool:
        """
        Connect and authenticate to Gmail IMAP.
        Returns True on success, False on failure.
        app_password: 16-char Google App Password (spaces optional).
        """
        try:
            app_password = app_password.replace(" ", "")
            self._imap = imaplib.IMAP4_SSL(GMAIL_IMAP_HOST, GMAIL_IMAP_PORT)
            self._imap.login(gmail_address, app_password)
            self.connected = True
            self.error = None
            return True
        except imaplib.IMAP4.error as e:
            self.error = f"Authentication failed: {str(e)}"
            self.connected = False
            return False
        except Exception as e:
            self.error = f"Connection error: {str(e)}"
            self.connected = False
            return False

    def fetch_latest_emails(self, limit: int = 20, folder: str = "INBOX") -> list[dict]:
        """
        Fetch the latest `limit` emails from the specified folder.
        Returns list of parsed email dicts.
        """
        if not self.connected or not self._imap:
            raise RuntimeError("Not connected. Call connect() first.")

        self._imap.select(folder)
        _, data = self._imap.search(None, "ALL")
        all_ids = data[0].split()

        # Take the most recent `limit` emails
        latest_ids = all_ids[-limit:] if len(all_ids) >= limit else all_ids
        latest_ids = list(reversed(latest_ids))     # newest first

        emails = []
        for uid in latest_ids:
            try:
                _, msg_data = self._imap.fetch(uid, "(RFC822)")
                raw = msg_data[0][1]
                parsed = parse_email(raw)
                parsed["id"] = f"GMAIL-{uid.decode()}"
                emails.append(parsed)
            except Exception:
                continue

        return emails

    def fetch_unseen(self, limit: int = 20) -> list[dict]:
        """Fetch only unread emails."""
        if not self.connected or not self._imap:
            raise RuntimeError("Not connected.")

        self._imap.select("INBOX")
        _, data = self._imap.search(None, "UNSEEN")
        unseen_ids = data[0].split()[-limit:]
        unseen_ids = list(reversed(unseen_ids))

        emails = []
        for uid in unseen_ids:
            try:
                _, msg_data = self._imap.fetch(uid, "(RFC822)")
                raw = msg_data[0][1]
                parsed = parse_email(raw)
                parsed["id"] = f"GMAIL-{uid.decode()}"
                emails.append(parsed)
            except Exception:
                continue

        return emails

    def disconnect(self):
        if self._imap:
            try:
                self._imap.logout()
            except Exception:
                pass
        self.connected = False
        self._imap = None


# ── Module-level convenience functions ───────────────────────────────────────
def connect_to_gmail(gmail_address: str, app_password: str) -> GmailFetcher:
    """Create and return a connected GmailFetcher instance."""
    fetcher = GmailFetcher()
    fetcher.connect(gmail_address, app_password)
    return fetcher


def fetch_latest_emails(
    gmail_address: str,
    app_password: str,
    limit: int = 20
) -> tuple[list[dict], Optional[str]]:
    """
    One-shot fetch: connect, fetch, disconnect.
    Returns (emails, error_message).
    error_message is None on success.
    """
    fetcher = GmailFetcher()
    if not fetcher.connect(gmail_address, app_password):
        return [], fetcher.error

    try:
        emails = fetcher.fetch_latest_emails(limit=limit)
        return emails, None
    except Exception as e:
        return [], str(e)
    finally:
        fetcher.disconnect()
