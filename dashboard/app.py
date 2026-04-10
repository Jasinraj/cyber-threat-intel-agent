"""
app.py  —  Day 4
Flask web dashboard for the Cyber Threat Intelligence Agent.
Serves threat data from SQLite with filtering and search.
Run: python dashboard/app.py
Open: http://localhost:5000
"""

import sqlite3
import pandas as pd
from flask import Flask, jsonify, request, render_template
from pathlib import Path

app = Flask(__name__)
DB_PATH = Path("outputs/threats.db")


# ── DB helper ─────────────────────────────────────────────────────────────────
def query_db(sql: str, params: tuple = ()) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/api/threats")
def get_threats():
    """Return threats with optional filters."""
    risk    = request.args.get("risk")
    source  = request.args.get("source")
    search  = request.args.get("search")
    limit   = int(request.args.get("limit", 200))

    sql    = "SELECT * FROM threats WHERE 1=1"
    params = []

    if risk and risk != "All":
        sql += " AND risk_level = ?"
        params.append(risk)
    if source and source != "All":
        sql += " AND source = ?"
        params.append(source)
    if search:
        sql += " AND (id LIKE ? OR description LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])

    sql += " ORDER BY cvss_score DESC NULLS LAST"
    sql += f" LIMIT {limit}"

    rows = query_db(sql, tuple(params))
    return jsonify({"count": len(rows), "threats": rows})


@app.route("/api/stats")
def get_stats():
    """Return summary stats for charts."""
    risk_dist = query_db(
        "SELECT risk_level, COUNT(*) as count FROM threats "
        "GROUP BY risk_level ORDER BY count DESC"
    )
    type_dist = query_db(
        "SELECT threat_type, COUNT(*) as count FROM threats "
        "WHERE threat_type IS NOT NULL "
        "GROUP BY threat_type ORDER BY count DESC"
    )
    source_dist = query_db(
        "SELECT source, COUNT(*) as count FROM threats "
        "GROUP BY source ORDER BY count DESC"
    )
    total = query_db("SELECT COUNT(*) as total FROM threats")[0]["total"]
    critical = query_db(
        "SELECT COUNT(*) as cnt FROM threats WHERE risk_level='Critical'"
    )[0]["cnt"]
    avg_cvss = query_db(
        "SELECT ROUND(AVG(cvss_score),2) as avg FROM threats "
        "WHERE cvss_score IS NOT NULL"
    )[0]["avg"]

    return jsonify({
        "total"           : total,
        "critical_count"  : critical,
        "avg_cvss"        : avg_cvss,
        "risk_distribution": risk_dist,
        "threat_types"    : type_dist,
        "sources"         : source_dist,
    })


if __name__ == "__main__":
    print("\n  Cyber Threat Intelligence Dashboard")
    print("  Open http://localhost:5000 in your browser\n")
    app.run(debug=True, port=5000)