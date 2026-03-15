"""
data_loader.py — loads public phishing datasets for retraining.

Supported sources:
  1. PhishTank  — live URL feed (CSV download)
  2. Kaggle CSV — any phishing email CSV with 'text'/'label' columns
  3. SpamAssassin — folder of raw .txt email files
  4. Built-in synthetic — always available offline
"""
import os
import re
import csv
import json
import urllib.request
from typing import Optional

PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.csv"
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


# ── PhishTank ─────────────────────────────────────────────────────────────────
def load_phishtank(max_rows: int = 500) -> list[dict]:
    """
    Downloads PhishTank online-valid.csv and returns list of
    {"text": url, "label": 1} dicts.
    Falls back to local cache if download fails.
    """
    cache_path = os.path.join(DATA_DIR, "phishtank_cache.csv")
    rows = []

    try:
        print("[*] Downloading PhishTank feed...")
        urllib.request.urlretrieve(PHISHTANK_URL, cache_path)
        print("[+] PhishTank feed downloaded.")
    except Exception as e:
        print(f"[!] PhishTank download failed: {e}")
        if not os.path.exists(cache_path):
            return []
        print("[*] Using cached PhishTank data.")

    with open(cache_path, encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            url = row.get("url", "").strip()
            if url:
                rows.append({"text": url, "label": 1, "source": "phishtank"})

    print(f"[+] Loaded {len(rows)} PhishTank URLs.")
    return rows


# ── Kaggle CSV ────────────────────────────────────────────────────────────────
def load_kaggle_csv(filepath: str, text_col: str = "text", label_col: str = "label") -> list[dict]:
    """
    Loads any Kaggle-style phishing CSV.
    Expects columns: text_col (email body/subject) and label_col (0=safe, 1=phishing).
    """
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        return []

    rows = []
    with open(filepath, encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = row.get(text_col, "").strip()
            raw_label = str(row.get(label_col, "0")).strip().lower()
            label = 1 if raw_label in ("1", "phishing", "spam", "yes", "true") else 0
            if text:
                rows.append({"text": text, "label": label, "source": "kaggle"})

    print(f"[+] Loaded {len(rows)} rows from {os.path.basename(filepath)}.")
    return rows


# ── SpamAssassin ──────────────────────────────────────────────────────────────
def load_spamassassin(folder: str, label: int = 1, max_files: int = 200) -> list[dict]:
    """
    Loads raw .txt email files from a SpamAssassin-style folder.
    label=1 for spam/phishing folders, label=0 for ham folders.
    """
    if not os.path.exists(folder):
        print(f"[!] Folder not found: {folder}")
        return []

    rows = []
    for fname in os.listdir(folder)[:max_files]:
        fpath = os.path.join(folder, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, encoding="utf-8", errors="ignore") as f:
                content = f.read(2000)           # first 2KB is enough
            text = re.sub(r'\s+', ' ', content).strip()
            if text:
                rows.append({"text": text, "label": label, "source": "spamassassin"})
        except Exception:
            continue

    print(f"[+] Loaded {len(rows)} SpamAssassin emails from {folder}.")
    return rows


# ── Built-in synthetic (always available) ────────────────────────────────────
def load_synthetic() -> list[dict]:
    from nlp_engine.phishing_detector import SYNTHETIC_PHISHING, SYNTHETIC_SAFE
    rows = (
        [{"text": t, "label": 1, "source": "synthetic"} for t in SYNTHETIC_PHISHING] +
        [{"text": t, "label": 0, "source": "synthetic"} for t in SYNTHETIC_SAFE]
    )
    print(f"[+] Loaded {len(rows)} synthetic training samples.")
    return rows


# ── Combined loader ───────────────────────────────────────────────────────────
def load_all(
    kaggle_csv: Optional[str] = None,
    spamassassin_spam_dir: Optional[str] = None,
    spamassassin_ham_dir: Optional[str] = None,
    include_phishtank: bool = False,
) -> list[dict]:
    """
    Combines all available sources into one dataset list.
    Always includes synthetic data as baseline.
    """
    data = load_synthetic()

    if kaggle_csv:
        data += load_kaggle_csv(kaggle_csv)

    if spamassassin_spam_dir:
        data += load_spamassassin(spamassassin_spam_dir, label=1)

    if spamassassin_ham_dir:
        data += load_spamassassin(spamassassin_ham_dir, label=0)

    if include_phishtank:
        data += load_phishtank()

    phishing = sum(1 for d in data if d["label"] == 1)
    safe = sum(1 for d in data if d["label"] == 0)
    print(f"[+] Total dataset: {len(data)} samples | Phishing: {phishing} | Safe: {safe}")
    return data
