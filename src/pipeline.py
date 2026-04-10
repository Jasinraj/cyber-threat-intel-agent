"""
pipeline.py  —  Day 6
Orchestrates the full CTI pipeline in sequence:
  fetch → preprocess → classify → extract entities → save
"""

import logging
import sqlite3
import pandas as pd
from pathlib import Path
from datetime import datetime

log = logging.getLogger(__name__)

DB_PATH = Path("outputs/threats.db")


def run_pipeline(skip_classify: bool = False) -> dict:
    """
    Run the full pipeline end to end.
    Returns a summary dict with counts and timings.

    Args:
        skip_classify: Set True to skip AI classification
                       (much faster, useful for testing)
    """
    summary = {
        "started_at"  : datetime.now().isoformat(),
        "steps"       : {},
        "errors"      : [],
        "total_threats": 0,
    }

    print("\n" + "═" * 62)
    print("  CYBER THREAT INTELLIGENCE AGENT — FULL PIPELINE")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("═" * 62)

    # ── Step 1: Fetch ─────────────────────────────────────────────────────────
    print("\n[1/4] Fetching threat data from all sources...")
    t0 = datetime.now()
    try:
        from src.fetcher import fetch_all
        raw = fetch_all(save=True)
        elapsed = (datetime.now() - t0).seconds
        summary["steps"]["fetch"] = {
            "count": len(raw), "seconds": elapsed
        }
        print(f"      ✓ Fetched {len(raw)} raw records in {elapsed}s")
    except Exception as e:
        summary["errors"].append(f"Fetch error: {e}")
        print(f"      ✗ Fetch failed: {e}")
        return summary

    # ── Step 2: Preprocess ────────────────────────────────────────────────────
    print("\n[2/4] Preprocessing and cleaning data...")
    t0 = datetime.now()
    try:
        from src.preprocessor import preprocess, save_to_db, save_to_csv
        df      = preprocess(raw)
        save_to_db(df)
        save_to_csv(df)
        elapsed = (datetime.now() - t0).seconds
        summary["steps"]["preprocess"] = {
            "count": len(df), "seconds": elapsed
        }
        print(f"      ✓ Cleaned {len(df)} records in {elapsed}s")
    except Exception as e:
        summary["errors"].append(f"Preprocess error: {e}")
        print(f"      ✗ Preprocess failed: {e}")
        return summary

    # ── Step 3: Classify ──────────────────────────────────────────────────────
    if skip_classify:
        print("\n[3/4] Skipping AI classification (--fast mode)")
        summary["steps"]["classify"] = {"skipped": True}
    else:
        print("\n[3/4] Running AI classification + risk scoring...")
        print("      (This takes 20-40 mins on first run — model is cached)")
        t0 = datetime.now()
        try:
            from src.classifier import classify_batch, compute_risk

            texts           = df["text"].tolist()
            classifications = classify_batch(texts, batch_size=8)

            df["threat_type"]   = [c[0] for c in classifications]
            df["ai_confidence"] = [c[1] for c in classifications]
            df["risk_level"]    = df.apply(
                lambda r: compute_risk(
                    r.get("cvss_score"),
                    r.get("severity_normalized", "Unknown"),
                    r.get("text", ""),
                    r.get("source", ""),
                ), axis=1
            )

            # Save classified data
            conn = sqlite3.connect(DB_PATH)
            df.to_sql("threats", conn, if_exists="replace", index=False)
            conn.close()

            elapsed = (datetime.now() - t0).seconds
            summary["steps"]["classify"] = {
                "count": len(df), "seconds": elapsed
            }
            print(f"      ✓ Classified {len(df)} records in {elapsed}s")

        except Exception as e:
            summary["errors"].append(f"Classify error: {e}")
            print(f"      ✗ Classification failed: {e}")

    # ── Step 4: Entity extraction ─────────────────────────────────────────────
    print("\n[4/4] Extracting entities and IOCs...")
    t0 = datetime.now()
    try:
        from src.entity_extractor import process_database
        df      = process_database()
        elapsed = (datetime.now() - t0).seconds
        summary["steps"]["extract"] = {
            "count": len(df), "seconds": elapsed
        }
        print(f"      ✓ Extracted IOCs from {len(df)} records in {elapsed}s")
    except Exception as e:
        summary["errors"].append(f"Extract error: {e}")
        print(f"      ✗ Extraction failed: {e}")

    # ── Done ──────────────────────────────────────────────────────────────────
    summary["finished_at"]   = datetime.now().isoformat()
    summary["total_threats"] = len(df)

    print("\n" + "═" * 62)
    print(f"  PIPELINE COMPLETE")
    print(f"  Total threats : {summary['total_threats']}")
    print(f"  Errors        : {len(summary['errors'])}")
    print(f"  Finished      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("═" * 62 + "\n")

    return summary