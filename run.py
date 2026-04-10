"""
run.py  —  Day 6
Single entry point for the Cyber Threat Intelligence Agent.

Usage:
  python run.py pipeline        # run full pipeline once
  python run.py pipeline --fast # skip AI (faster, for testing)
  python run.py dashboard       # start web dashboard
  python run.py schedule        # run pipeline every 6 hours
  python run.py all             # pipeline + dashboard together
"""

import sys
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ── Commands ──────────────────────────────────────────────────────────────────
def cmd_pipeline(fast: bool = False):
    """Run the full data pipeline once."""
    from src.pipeline import run_pipeline
    summary = run_pipeline(skip_classify=fast)

    if summary["errors"]:
        print("\n  Errors encountered:")
        for err in summary["errors"]:
            print(f"    - {err}")
    else:
        print("  All steps completed successfully.")


def cmd_dashboard():
    """Start the Flask web dashboard."""
    print("\n  Starting Cyber Threat Intelligence Dashboard...")
    print("  Open http://localhost:5000 in your browser")
    print("  Press Ctrl+C to stop\n")

    import sys
    sys.path.insert(0, "dashboard")
    from dashboard.app import app
    app.run(debug=False, port=5000)


def cmd_schedule():
    """
    Run the pipeline immediately, then repeat every 6 hours.
    Keeps your threat data fresh automatically.
    """
    from apscheduler.schedulers.blocking import BlockingScheduler
    from src.pipeline import run_pipeline

    print("\n  Scheduled pipeline mode")
    print("  Running now, then every 6 hours")
    print("  Press Ctrl+C to stop\n")

    # Run once immediately
    run_pipeline(skip_classify=True)

    # Then schedule
    scheduler = BlockingScheduler()
    scheduler.add_job(
        lambda: run_pipeline(skip_classify=True),
        trigger="interval",
        hours=6,
        id="cti_pipeline",
    )

    print("  Next run in 6 hours. Scheduler is running...")
    try:
        scheduler.start()
    except KeyboardInterrupt:
        print("\n  Scheduler stopped.")


def cmd_all():
    """Run pipeline once, then start dashboard."""
    import threading

    print("\n  Running pipeline first, then starting dashboard...")

    # Run pipeline in background thread
    from src.pipeline import run_pipeline
    pipeline_thread = threading.Thread(
        target=lambda: run_pipeline(skip_classify=True),
        daemon=True
    )
    pipeline_thread.start()
    pipeline_thread.join()

    # Start dashboard
    cmd_dashboard()


# ── Help ──────────────────────────────────────────────────────────────────────
def print_help():
    print("""
  Cyber Threat Intelligence Agent
  ════════════════════════════════

  Commands:
    python run.py pipeline          Run full AI pipeline
    python run.py pipeline --fast   Run pipeline, skip AI classify
    python run.py dashboard         Start web dashboard
    python run.py schedule          Auto-refresh every 6 hours
    python run.py all               Pipeline + dashboard together

  Examples:
    python run.py pipeline --fast   (quick test, ~30 seconds)
    python run.py dashboard         (view results in browser)
    """)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    args = sys.argv[1:]

    if not args or args[0] in ("help", "--help", "-h"):
        print_help()

    elif args[0] == "pipeline":
        fast = "--fast" in args
        cmd_pipeline(fast=fast)

    elif args[0] == "dashboard":
        cmd_dashboard()

    elif args[0] == "schedule":
        cmd_schedule()

    elif args[0] == "all":
        cmd_all()

    else:
        print(f"\n  Unknown command: {args[0]}")
        print_help()