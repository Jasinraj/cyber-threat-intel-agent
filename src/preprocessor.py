"""
preprocessor.py  —  Day 2
Loads raw JSON from data/raw/, cleans and normalizes records,
deduplicates, then saves to SQLite (outputs/threats.db) and CSV.
"""

import re
import json
import sqlite3
import logging
import pandas as pd
from pathlib import Path
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────────────────
RAW_DIR   = Path("data/raw")
OUT_DIR   = Path("outputs")
DB_PATH   = OUT_DIR / "threats.db"
CSV_PATH  = OUT_DIR / "threats_clean.csv"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ── Text cleaning ─────────────────────────────────────────────────────────────
def clean_text(text: str) -> str:
    """Remove HTML tags, URLs, extra whitespace from a string."""
    if not text or not isinstance(text, str):
        return ""
    text = re.sub(r"<[^>]+>", " ", text)        # strip HTML tags
    text = re.sub(r"http\S+", " ", text)          # strip URLs
    text = re.sub(r"\s+", " ", text)              # collapse whitespace
    text = text.encode("ascii", "ignore").decode() # drop non-ASCII
    return text.strip()


# ── Severity normalizer ───────────────────────────────────────────────────────
def normalize_severity(severity: str | None,
                       cvss_score: float | None) -> str:
    """
    Map raw severity strings and CVSS scores to a clean 4-tier label.
    Priority: explicit severity string → CVSS numeric → Unknown
    """
    if severity and isinstance(severity, str):
        s = severity.upper().strip()
        if s == "CRITICAL":            return "Critical"
        if s == "HIGH":                return "High"
        if s in ("MEDIUM", "MODERATE"): return "Medium"
        if s == "LOW":                 return "Low"

    # Fallback to CVSS numeric score
    try:
        score = float(cvss_score)
        if score >= 9.0: return "Critical"
        if score >= 7.0: return "High"
        if score >= 4.0: return "Medium"
        return "Low"
    except (TypeError, ValueError):
        pass

    return "Unknown"


# ── Load raw JSON ─────────────────────────────────────────────────────────────
def load_latest_raw() -> list[dict]:
    """
    Load the most recently created JSON file from data/raw/.
    Returns a list of raw threat dicts.
    """
    json_files = sorted(RAW_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime)
    if not json_files:
        raise FileNotFoundError(f"No JSON files found in {RAW_DIR}. "
                                 "Run fetcher.py first.")

    latest = json_files[-1]
    log.info(f"Loading raw file: {latest}")

    with open(latest, encoding="utf-8") as fh:
        data = json.load(fh)

    log.info(f"Loaded {len(data)} raw records")
    return data


# ── Main preprocessor ─────────────────────────────────────────────────────────
def preprocess(raw: list[dict]) -> pd.DataFrame:
    """
    Clean, normalize, and deduplicate raw threat records.

    Returns a pandas DataFrame with these columns:
        id, source, title, description, text,
        cvss_score, severity_normalized,
        published, url, raw_type, ingested_at
    """
    df = pd.DataFrame(raw)
    log.info(f"Starting with {len(df)} raw records")

    # ── 1. Clean text fields ──────────────────────────────────────────────────
    df["title"]       = df["title"].fillna("").apply(clean_text)
    df["description"] = df["description"].fillna("").apply(clean_text)

    # Combined text field — used later by the AI classifier
    df["text"] = (df["title"] + ". " + df["description"]).str.strip()
    df["text"] = df["text"].str[:512]   # cap at 512 chars for transformer input

    # ── 2. Normalize severity ─────────────────────────────────────────────────
    df["cvss_score"] = pd.to_numeric(df.get("cvss_score"), errors="coerce")

    df["severity_normalized"] = df.apply(
        lambda r: normalize_severity(
            r.get("severity"),
            r.get("cvss_score")
        ),
        axis=1
    )

    # ── 3. Deduplicate on ID ──────────────────────────────────────────────────
    before = len(df)
    df = df.drop_duplicates(subset=["id"], keep="first")
    dupes_removed = before - len(df)
    if dupes_removed:
        log.info(f"Removed {dupes_removed} duplicate records")

    # ── 4. Drop near-empty records ────────────────────────────────────────────
    df = df[df["text"].str.len() > 20]
    log.info(f"After cleaning: {len(df)} records remain")

    # ── 5. Add metadata ───────────────────────────────────────────────────────
    df["ingested_at"] = datetime.now().isoformat()

    # Keep only the columns we need
    keep_cols = [
        "id", "source", "title", "description", "text",
        "cvss_score", "severity_normalized",
        "published", "url", "raw_type", "ingested_at"
    ]
    # Only keep columns that actually exist in the dataframe
    keep_cols = [c for c in keep_cols if c in df.columns]
    df = df[keep_cols].reset_index(drop=True)

    return df


# ── Save to SQLite ────────────────────────────────────────────────────────────
def save_to_db(df: pd.DataFrame) -> None:
    """Write the cleaned DataFrame to SQLite threats table."""
    OUT_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    df.to_sql("threats", conn, if_exists="replace", index=False)
    conn.close()
    log.info(f"Saved {len(df)} records to SQLite → {DB_PATH}")


# ── Save to CSV ───────────────────────────────────────────────────────────────
def save_to_csv(df: pd.DataFrame) -> None:
    """Write the cleaned DataFrame to CSV for easy inspection."""
    OUT_DIR.mkdir(exist_ok=True)
    df.to_csv(CSV_PATH, index=False)
    log.info(f"Saved clean CSV  → {CSV_PATH}")


# ── Summary printer ───────────────────────────────────────────────────────────
def print_summary(df: pd.DataFrame) -> None:
    """Print a clean breakdown of the preprocessed data."""
    print("\n" + "═" * 62)
    print("  PREPROCESSOR — DAY 2 SUMMARY")
    print("═" * 62)
    print(f"  Clean records   : {len(df)}")

    valid_scores = df["cvss_score"].dropna()
    if not valid_scores.empty:
        print(f"  CVSS avg        : {valid_scores.mean():.2f}")
        print(f"  CVSS max        : {valid_scores.max():.1f}")

    print("\n  Severity breakdown:")
    for sev, cnt in df["severity_normalized"].value_counts().items():
        bar = "█" * min(cnt, 35)
        print(f"    {sev:<10}  {bar}  ({cnt})")

    print("\n  Sources:")
    for src, cnt in df["source"].value_counts().items():
        print(f"    {src:<20}  {cnt}")

    print("\n  Sample records (first 5):")
    cols = ["id", "source", "cvss_score", "severity_normalized"]
    cols = [c for c in cols if c in df.columns]
    print(df[cols].head(5).to_string(index=False))
    print("═" * 62 + "\n")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Load → preprocess → save
    raw      = load_latest_raw()
    df       = preprocess(raw)
    save_to_db(df)
    save_to_csv(df)
    print_summary(df)