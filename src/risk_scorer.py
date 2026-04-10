"""
risk_scorer.py — compute composite risk score from CVSS + keyword signals
"""

import re

# High-signal keywords that bump risk level
CRITICAL_KEYWORDS = [
    "zero-day", "0-day", "actively exploited", "in the wild",
    "ransomware", "worm", "critical infrastructure", "rce",
    "remote code execution", "unauthenticated", "no patch",
    "cisa kev", "nation state", "apt"
]

HIGH_KEYWORDS = [
    "exploit", "proof of concept", "poc", "privilege escalation",
    "sql injection", "data breach", "credential theft", "backdoor",
    "malware", "trojan", "keylogger", "phishing campaign"
]

MEDIUM_KEYWORDS = [
    "vulnerability", "cve", "patch", "advisory", "disclosure",
    "xss", "csrf", "denial of service", "ddos", "information disclosure"
]


def keyword_score(text: str) -> int:
    """
    Return a keyword-based severity score: 0–3
    0 = no signals, 1 = medium signals, 2 = high, 3 = critical
    """
    t = text.lower()
    if any(k in t for k in CRITICAL_KEYWORDS):
        return 3
    if any(k in t for k in HIGH_KEYWORDS):
        return 2
    if any(k in t for k in MEDIUM_KEYWORDS):
        return 1
    return 0


def compute_risk(
    cvss_score: float | None,
    severity_normalized: str,
    text: str,
    source: str = ""
) -> str:
    """
    Composite risk: combines CVSS score + keyword signals + source weight.

    Scoring logic:
      base_score = CVSS (0-10) or estimated from severity tier
      + keyword_bonus (0-3)
      + source_bonus (CISA-KEV gets +2 = actively exploited)

    Final thresholds:
      ≥ 11  → Critical
      ≥ 8   → High
      ≥ 5   → Medium
      < 5   → Low
    """
    # Base: use CVSS if available, else estimate from severity string
    if cvss_score and cvss_score > 0:
        base = float(cvss_score)
    else:
        base_map = {
            "Critical": 9.0,
            "High": 7.5,
            "Medium": 5.0,
            "Low": 2.0,
            "Unknown": 4.0,
        }
        base = base_map.get(severity_normalized, 4.0)

    # Keyword bonus
    k_bonus = keyword_score(text)

    # Source bonus: CISA KEV items are actively exploited
    s_bonus = 2 if "CISA" in source.upper() else 0

    composite = base + k_bonus + s_bonus

    if composite >= 11:  return "Critical"
    if composite >= 8:   return "High"
    if composite >= 5:   return "Medium"
    return "Low"