"""
classifier.py  —  Day 3
Zero-shot threat classification using HuggingFace transformers.
No training data needed. Works fully offline after first download.
Model: facebook/bart-large-mnli (~1.6 GB, downloaded once and cached)
"""

import logging
import sqlite3
import pandas as pd
from pathlib import Path
from transformers import pipeline

# ── Config ────────────────────────────────────────────────────────────────────
DB_PATH = Path("outputs/threats.db")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Threat labels the AI will classify into ───────────────────────────────────
THREAT_LABELS = [
    "malware attack",
    "phishing attack",
    "ransomware attack",
    "software vulnerability",
    "data breach",
    "DDoS attack",
    "supply chain attack",
    "zero day exploit",
    "social engineering",
    "APT nation state attack",
]

# Short display names for the dashboard
LABEL_MAP = {
    "malware attack"        : "Malware",
    "phishing attack"       : "Phishing",
    "ransomware attack"     : "Ransomware",
    "software vulnerability": "Vulnerability",
    "data breach"           : "Data Breach",
    "DDoS attack"           : "DDoS",
    "supply chain attack"   : "Supply Chain",
    "zero day exploit"      : "Zero-Day",
    "social engineering"    : "Social Engineering",
    "APT nation state attack": "APT",
}

# ── Lazy-load the model (downloads once, cached forever) ──────────────────────
_classifier = None

def get_classifier():
    global _classifier
    if _classifier is None:
        log.info("Loading HuggingFace model (first run = download ~1.6 GB)...")
        log.info("This takes 5-10 mins on first run. Subsequent runs are instant.")
        _classifier = pipeline(
            "zero-shot-classification",
            model="facebook/bart-large-mnli",
            device=-1       # CPU mode; change to 0 if you have a GPU
        )
        log.info("Model loaded successfully.")
    return _classifier


# ── Classify a single text ────────────────────────────────────────────────────
def classify_one(text: str) -> tuple[str, float]:
    """
    Classify a single threat description.
    Returns (threat_type_label, confidence_score)
    """
    clf    = get_classifier()
    result = clf(text[:512], candidate_labels=THREAT_LABELS)
    top    = result["labels"][0]
    score  = result["scores"][0]
    return LABEL_MAP.get(top, top), round(score, 3)


# ── Classify a batch efficiently ──────────────────────────────────────────────
def classify_batch(texts: list[str],
                   batch_size: int = 8) -> list[tuple[str, float]]:
    """
    Classify a list of texts in batches.
    Returns list of (threat_type, confidence) tuples.
    """
    results = []
    total   = len(texts)
    clf     = get_classifier()

    for i in range(0, total, batch_size):
        batch = texts[i : i + batch_size]
        pct   = int((i / total) * 100)
        log.info(f"  Classifying {i+1}–{min(i+batch_size, total)} "
                 f"of {total} ({pct}%) ...")

        batch_out = clf(batch, candidate_labels=THREAT_LABELS)

        # pipeline returns a dict (not list) when batch has 1 item
        if isinstance(batch_out, dict):
            batch_out = [batch_out]

        for r in batch_out:
            top   = r["labels"][0]
            score = r["scores"][0]
            results.append((LABEL_MAP.get(top, top), round(score, 3)))

    return results


# ── Risk scorer (composite) ───────────────────────────────────────────────────
CRITICAL_KEYWORDS = [
    "zero-day", "0-day", "actively exploited", "in the wild",
    "ransomware", "remote code execution", "rce", "unauthenticated",
    "no patch available", "nation state", "apt", "worm",
    "critical infrastructure", "cisa kev",
]
HIGH_KEYWORDS = [
    "exploit", "proof of concept", "poc", "privilege escalation",
    "sql injection", "credential theft", "backdoor", "malware",
    "trojan", "phishing campaign", "data breach", "keylogger",
]
MEDIUM_KEYWORDS = [
    "vulnerability", "cve", "patch", "advisory", "xss",
    "csrf", "denial of service", "ddos", "information disclosure",
]

def keyword_bonus(text: str) -> int:
    """Return 0–3 based on severity keywords found in text."""
    t = text.lower()
    if any(k in t for k in CRITICAL_KEYWORDS): return 3
    if any(k in t for k in HIGH_KEYWORDS):     return 2
    if any(k in t for k in MEDIUM_KEYWORDS):   return 1
    return 0

def compute_risk(cvss_score, severity_normalized: str,
                 text: str, source: str) -> str:
    """
    Composite risk score:
      base  = CVSS numeric (0-10) or estimated from severity tier
      bonus = keyword signals (0-3)
      bonus = CISA-KEV source (+2, actively exploited)

    Thresholds:
      >= 11  → Critical
      >= 8   → High
      >= 5   → Medium
      <  5   → Low
    """
    # Base score from CVSS or severity tier
    try:
        base = float(cvss_score)
    except (TypeError, ValueError):
        tier_map = {
            "Critical": 9.0, "High": 7.5,
            "Medium":   5.0, "Low": 2.0, "Unknown": 4.0,
        }
        base = tier_map.get(severity_normalized, 4.0)

    bonus  = keyword_bonus(str(text))
    source_bonus = 2 if "CISA" in str(source).upper() else 0

    composite = base + bonus + source_bonus

    if composite >= 11: return "Critical"
    if composite >= 8:  return "High"
    if composite >= 5:  return "Medium"
    return "Low"


# ── Load from SQLite ──────────────────────────────────────────────────────────
def load_from_db() -> pd.DataFrame:
    conn = sqlite3.connect(DB_PATH)
    df   = pd.read_sql("SELECT * FROM threats", conn)
    conn.close()
    log.info(f"Loaded {len(df)} records from {DB_PATH}")
    return df


# ── Save back to SQLite ───────────────────────────────────────────────────────
def save_to_db(df: pd.DataFrame) -> None:
    conn = sqlite3.connect(DB_PATH)
    df.to_sql("threats", conn, if_exists="replace", index=False)
    conn.close()
    log.info(f"Saved {len(df)} classified records → {DB_PATH}")


# ── Terminal report ───────────────────────────────────────────────────────────
def print_report(df: pd.DataFrame) -> None:
    """Print a rich colored summary using the rich library."""
    from rich.console import Console
    from rich.table   import Table
    from rich import box

    console = Console()

    console.print("\n" + "═" * 62)
    console.print("[bold]  AI THREAT CLASSIFICATION — DAY 3 REPORT[/bold]")
    console.print("═" * 62)

    # Risk level breakdown
    risk_colors = {
        "Critical": "bold red",
        "High":     "bold yellow",
        "Medium":   "cyan",
        "Low":      "green",
    }
    console.print("\n[bold]Risk level breakdown:[/bold]")
    for risk, cnt in df["risk_level"].value_counts().items():
        bar   = "█" * min(int(cnt / 2), 30)
        color = risk_colors.get(risk, "white")
        console.print(f"  [{color}]{risk:<10}[/{color}]  {bar}  ({cnt})")

    # Threat type breakdown
    console.print("\n[bold]Threat types detected:[/bold]")
    for ttype, cnt in df["threat_type"].value_counts().items():
        console.print(f"  {ttype:<22}  {cnt}")

    # Top 10 critical threats table
    console.print("\n[bold]Top 10 highest-risk threats:[/bold]")
    table = Table(box=box.SIMPLE, show_header=True,
                  header_style="bold white")
    table.add_column("ID",          style="dim",         width=18)
    table.add_column("Type",        style="cyan",        width=16)
    table.add_column("Risk",        style="bold",        width=10)
    table.add_column("CVSS",        justify="right",     width=6)
    table.add_column("Source",      style="dim",         width=16)

    risk_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    top = df.copy()
    top["_order"] = top["risk_level"].map(risk_order).fillna(4)
    top = top.sort_values(["_order", "cvss_score"],
                           ascending=[True, False]).head(10)

    for _, row in top.iterrows():
        risk  = row.get("risk_level", "")
        color = risk_colors.get(risk, "white")
        table.add_row(
            str(row.get("id", ""))[:18],
            str(row.get("threat_type", "")),
            f"[{color}]{risk}[/{color}]",
            str(row.get("cvss_score", "N/A")),
            str(row.get("source", "")),
        )
    console.print(table)
    console.print("═" * 62 + "\n")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # 1. Load cleaned data from Day 2
    df = load_from_db()

    # 2. AI classification
    log.info("\n[AI] Starting zero-shot classification ...")
    texts = df["text"].tolist()
    classifications = classify_batch(texts, batch_size=8)

    df["threat_type"]    = [c[0] for c in classifications]
    df["ai_confidence"]  = [c[1] for c in classifications]

    # 3. Risk scoring
    log.info("\n[RISK] Computing composite risk scores ...")
    df["risk_level"] = df.apply(
        lambda r: compute_risk(
            r.get("cvss_score"),
            r.get("severity_normalized", "Unknown"),
            r.get("text", ""),
            r.get("source", ""),
        ),
        axis=1,
    )

    # 4. Save results
    save_to_db(df)
    df.to_csv("outputs/threats_classified.csv", index=False)
    log.info("Saved → outputs/threats_classified.csv")

    # 5. Print report
    print_report(df) 