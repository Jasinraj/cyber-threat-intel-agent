"""
entity_extractor.py  —  Day 5
Extracts Indicators of Compromise (IOCs) and named entities
from threat descriptions using regex + spaCy NER.
"""

import re
import json
import sqlite3
import logging
import pandas as pd
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

DB_PATH = Path("outputs/threats.db")

# ── Lazy-load spaCy ───────────────────────────────────────────────────────────
_nlp = None

def get_nlp():
    global _nlp
    if _nlp is None:
        import spacy
        log.info("Loading spaCy model...")
        _nlp = spacy.load("en_core_web_sm")
    return _nlp


# ── Regex patterns for IOCs ───────────────────────────────────────────────────
PATTERNS = {
    "cve_ids": re.compile(
        r"CVE-\d{4}-\d{4,7}",
        re.IGNORECASE
    ),
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "domains": re.compile(
        r"\b(?:[a-zA-Z0-9\-]+\.)"
        r"+(?:com|net|org|io|gov|mil|edu|ru|cn|info|biz|co)\b"
    ),
    "md5": re.compile(
        r"\b[a-fA-F0-9]{32}\b"
    ),
    "sha256": re.compile(
        r"\b[a-fA-F0-9]{64}\b"
    ),
    "emails": re.compile(
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
    ),
}

# Common words that match domain regex but aren't domains — filter them out
DOMAIN_BLOCKLIST = {
    "version", "versions", "example.com", "test.com",
    "user.name", "file.ext", "path.to",
}


# ── Core extractor ────────────────────────────────────────────────────────────
def extract_iocs(text: str) -> dict:
    """
    Extract all IOCs from a piece of text using regex patterns.
    Returns a dict with keys: cve_ids, ipv4, domains, md5, sha256, emails
    """
    if not text or not isinstance(text, str):
        return {}

    iocs = {}

    for key, pattern in PATTERNS.items():
        matches = list(set(pattern.findall(text)))

        # Extra filtering for domains
        if key == "domains":
            matches = [
                m for m in matches
                if len(m) > 5
                and m.lower() not in DOMAIN_BLOCKLIST
                and not m[0].isdigit()
            ]

        if matches:
            iocs[key] = matches

    return iocs


# ── spaCy NER extractor ───────────────────────────────────────────────────────
def extract_entities(text: str) -> dict:
    """
    Use spaCy NER to extract organizations, products, and locations
    from threat text. Useful for finding affected vendors.
    """
    if not text or not isinstance(text, str):
        return {}

    nlp = get_nlp()
    doc = nlp(text[:500])   # limit for speed

    entities = {}
    for ent in doc.ents:
        label = ent.label_
        if label in ("ORG", "PRODUCT", "GPE", "PERSON"):
            if label not in entities:
                entities[label] = []
            if ent.text not in entities[label]:
                entities[label].append(ent.text)

    return entities


# ── Combined extractor ────────────────────────────────────────────────────────
def extract_all(text: str) -> dict:
    """Run both regex IOC extraction and spaCy NER on a text."""
    iocs     = extract_iocs(text)
    entities = extract_entities(text)
    return {**iocs, **entities}


# ── Process full database ─────────────────────────────────────────────────────
def process_database() -> pd.DataFrame:
    """
    Load all threats from SQLite, extract IOCs from each,
    add results as a new column, save back to DB.
    """
    # Load
    conn = sqlite3.connect(DB_PATH)
    df   = pd.read_sql("SELECT * FROM threats", conn)
    conn.close()
    log.info(f"Loaded {len(df)} records for entity extraction")

    # Extract IOCs from each record
    log.info("Extracting IOCs and entities...")
    results = []
    for i, row in df.iterrows():
        text   = str(row.get("text", "")) + " " + str(row.get("description", ""))
        result = extract_all(text)
        results.append(json.dumps(result) if result else "{}")

        if (i + 1) % 50 == 0:
            log.info(f"  Processed {i+1}/{len(df)} records...")

    df["iocs"] = results
    log.info("Entity extraction complete")

    # Save back to SQLite
    conn = sqlite3.connect(DB_PATH)
    df.to_sql("threats", conn, if_exists="replace", index=False)
    conn.close()
    log.info(f"Saved {len(df)} records with IOCs → {DB_PATH}")

    return df


# ── Summary printer ───────────────────────────────────────────────────────────
def print_summary(df: pd.DataFrame) -> None:
    """Show what was extracted across all records."""
    print("\n" + "═" * 62)
    print("  ENTITY EXTRACTOR — DAY 5 SUMMARY")
    print("═" * 62)

    # Count totals across all records
    total_cves     = 0
    total_ips      = 0
    total_domains  = 0
    total_hashes   = 0
    total_orgs     = 0
    records_with_iocs = 0

    for ioc_str in df["iocs"]:
        try:
            ioc = json.loads(ioc_str)
            if ioc:
                records_with_iocs += 1
                total_cves    += len(ioc.get("cve_ids", []))
                total_ips     += len(ioc.get("ipv4", []))
                total_domains += len(ioc.get("domains", []))
                total_hashes  += len(ioc.get("md5", [])) + \
                                  len(ioc.get("sha256", []))
                total_orgs    += len(ioc.get("ORG", []))
        except Exception:
            pass

    print(f"  Records processed    : {len(df)}")
    print(f"  Records with IOCs    : {records_with_iocs}")
    print(f"  CVE IDs extracted    : {total_cves}")
    print(f"  IP addresses found   : {total_ips}")
    print(f"  Domains found        : {total_domains}")
    print(f"  Hashes found         : {total_hashes}")
    print(f"  Organizations found  : {total_orgs}")

    # Show 5 detailed examples
    print("\n  Sample extractions (5 records with IOCs):")
    print("  " + "─" * 58)

    shown = 0
    for _, row in df.iterrows():
        try:
            ioc = json.loads(row.get("iocs", "{}"))
            if not ioc:
                continue

            print(f"\n  ID     : {row.get('id', 'N/A')}")
            print(f"  Source : {row.get('source', 'N/A')}")
            print(f"  Risk   : {row.get('risk_level', 'N/A')}")
            print(f"  Type   : {row.get('threat_type', 'N/A')}")

            if ioc.get("cve_ids"):
                print(f"  CVEs   : {', '.join(ioc['cve_ids'][:3])}")
            if ioc.get("ipv4"):
                print(f"  IPs    : {', '.join(ioc['ipv4'][:3])}")
            if ioc.get("domains"):
                print(f"  Domains: {', '.join(ioc['domains'][:3])}")
            if ioc.get("ORG"):
                print(f"  Orgs   : {', '.join(ioc['ORG'][:4])}")
            if ioc.get("md5") or ioc.get("sha256"):
                hashes = ioc.get("md5", []) + ioc.get("sha256", [])
                print(f"  Hashes : {hashes[0][:32]}...")

            shown += 1
            if shown >= 5:
                break

        except Exception:
            continue

    print("\n" + "═" * 62 + "\n")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    df = process_database()
    print_summary(df)
    df.to_csv("outputs/threats_with_iocs.csv", index=False)
    log.info("Saved → outputs/threats_with_iocs.csv")