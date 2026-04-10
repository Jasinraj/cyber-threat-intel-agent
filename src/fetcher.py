"""
fetcher.py — pulls threat data from 4 free sources
Sources: NVD API, GitHub Advisories, RSS feeds, CISA KEV
"""

import requests
import feedparser
import json
import os
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

RAW_DIR = Path("data/raw")
RAW_DIR.mkdir(parents=True, exist_ok=True)


# ── 1. NVD (National Vulnerability Database) ──────────────────────────────────
def fetch_nvd_cves(days_back: int = 7, max_results: int = 200) -> list[dict]:
    """
    Fetch recent CVEs from NVD REST API v2.
    Docs: https://nvd.nist.gov/developers/vulnerabilities
    No API key required (rate limit: 5 req/30s unauthenticated).
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days_back)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
        "resultsPerPage": max_results,
        "startIndex": 0,
    }

    headers = {"User-Agent": "CyberThreatIntelAgent/1.0"}
    threats = []

    try:
        logger.info(f"Fetching NVD CVEs (last {days_back} days)...")
        resp = requests.get(base_url, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"), ""
            )

            # Extract CVSS score (try v3.1 first, fallback to v2)
            metrics = cve.get("metrics", {})
            cvss_score = None
            severity = "UNKNOWN"

            if "cvssMetricV31" in metrics:
                m = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = m.get("baseScore")
                severity = m.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV30" in metrics:
                m = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_score = m.get("baseScore")
                severity = m.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV2" in metrics:
                m = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_score = m.get("baseScore")

            threats.append({
                "id": cve_id,
                "source": "NVD",
                "title": cve_id,
                "description": desc,
                "cvss_score": cvss_score,
                "severity": severity,
                "published": cve.get("published", ""),
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "raw_type": "vulnerability",
            })

        logger.info(f"  ✓ Fetched {len(threats)} NVD CVEs")
        time.sleep(6)  # NVD rate limit: 5 req/30s

    except Exception as e:
        logger.error(f"NVD fetch error: {e}")

    return threats


# ── 2. RSS Security News Feeds ─────────────────────────────────────────────────
RSS_FEEDS = {
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "TheHackerNews": "https://feeds.feedburner.com/TheHackersNews",
    "SecurityWeek": "https://www.securityweek.com/feed",
    "KrebsOnSecurity": "https://krebsonsecurity.com/feed/",
}

def fetch_rss_feeds(max_per_feed: int = 20) -> list[dict]:
    """
    Parse security news RSS feeds using feedparser.
    No authentication needed. Free.
    """
    threats = []
    for source_name, url in RSS_FEEDS.items():
        try:
            logger.info(f"Fetching RSS: {source_name}...")
            feed = feedparser.parse(url)

            for entry in feed.entries[:max_per_feed]:
                threats.append({
                    "id": entry.get("id", entry.get("link", "")),
                    "source": source_name,
                    "title": entry.get("title", ""),
                    "description": entry.get("summary", "")[:1000],
                    "cvss_score": None,
                    "severity": None,
                    "published": entry.get("published", ""),
                    "url": entry.get("link", ""),
                    "raw_type": "news",
                })

            logger.info(f"  ✓ {len(feed.entries[:max_per_feed])} articles from {source_name}")

        except Exception as e:
            logger.error(f"RSS error ({source_name}): {e}")

    return threats


# ── 3. CISA Known Exploited Vulnerabilities (KEV) ─────────────────────────────
def fetch_cisa_kev() -> list[dict]:
    """
    CISA publishes a free JSON catalog of actively exploited vulnerabilities.
    Docs: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    """
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    threats = []

    try:
        logger.info("Fetching CISA KEV catalog...")
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        # Only grab the most recent 50 to keep it manageable
        vulns = sorted(
            data.get("vulnerabilities", []),
            key=lambda x: x.get("dateAdded", ""),
            reverse=True
        )[:50]

        for v in vulns:
            threats.append({
                "id": v.get("cveID", ""),
                "source": "CISA-KEV",
                "title": f"{v.get('cveID')} — {v.get('vulnerabilityName', '')}",
                "description": v.get("shortDescription", ""),
                "cvss_score": None,
                "severity": "HIGH",   # KEV = actively exploited = at least HIGH
                "published": v.get("dateAdded", ""),
                "url": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}",
                "raw_type": "vulnerability",
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
            })

        logger.info(f"  ✓ Fetched {len(threats)} CISA KEV entries")

    except Exception as e:
        logger.error(f"CISA fetch error: {e}")

    return threats


# ── 4. Main fetch orchestrator ─────────────────────────────────────────────────
def fetch_all(save: bool = True) -> list[dict]:
    """Run all fetchers and combine results."""
    all_threats = []

    all_threats.extend(fetch_nvd_cves(days_back=7))
    all_threats.extend(fetch_rss_feeds())
    all_threats.extend(fetch_cisa_kev())

    logger.info(f"\n📦 Total raw threats fetched: {len(all_threats)}")

    if save:
        out_path = RAW_DIR / f"raw_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
        with open(out_path, "w") as f:
            json.dump(all_threats, f, indent=2, default=str)
        logger.info(f"  💾 Saved to {out_path}")

    return all_threats


if __name__ == "__main__":
    threats = fetch_all()
    print(f"\n✅ Fetched {len(threats)} total threat records")