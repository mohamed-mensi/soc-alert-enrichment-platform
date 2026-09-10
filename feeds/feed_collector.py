"""
feeds/feed_collector.py
=========================
Orchestrator — runs all configured threat intel feed collectors in
sequence and returns a combined summary.

This module runs the feeds ONCE per call. The 24h scheduling loop
lives in scheduler.py, which imports and calls run_all_feeds().

Each collector is independent: if one fails to even initialize
(e.g. missing API key) or throws during run(), the others still
execute. Nothing here should let a single feed's problem take down
the whole collection cycle.

Usage:
    python feed_collector.py          # run all feeds once, right now

    # or, from scheduler.py / main.py:
    from feeds.feed_collector import run_all_feeds
    from database.db_manager import DBManager

    db = DBManager()
    summary = run_all_feeds(db)
"""

import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Make sure the project root (the folder ABOVE feeds/) is on sys.path
# BEFORE the package-style imports below. Without this, running
# `python feed_collector.py` from inside feeds/ fails with
# "ModuleNotFoundError: No module named 'feeds'" — Python can't see
# its own parent package. This must run before the imports, so it
# can't live inside the __main__ block further down.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from feeds.abusech_urlhaus import URLhausCollector
from feeds.abusech_threatfox import ThreatFoxCollector
from feeds.otx_collector import OTXCollector

logger = logging.getLogger(__name__)

# Each entry: (source_name, collector_class) — add new feeds here only.
COLLECTORS = [
    ("abusech_urlhaus", URLhausCollector),
    ("threatfox",       ThreatFoxCollector),
    ("otx",             OTXCollector),
]


def run_all_feeds(db) -> dict:
    """
    Run every configured collector once and return a combined summary.

    Parameters
    ----------
    db : DBManager
        Shared database connection passed to every collector.

    Returns
    -------
    dict with:
        status        : "success" | "partial" — partial if ANY feed failed
        started_at    : ISO-ish UTC timestamp
        duration_secs : total wall time for the whole run
        totals        : combined fetched/new/updated/errors across feeds
        feeds         : per-feed result dict, keyed by source name
    """
    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    t0 = time.monotonic()

    logger.info(f"[feed_collector] Starting collection cycle — {len(COLLECTORS)} feed(s) configured")

    feed_results = {}
    any_failed = False

    for source_name, collector_cls in COLLECTORS:
        feed_results[source_name] = _run_one_feed(source_name, collector_cls, db)
        if feed_results[source_name]["status"] in ("failed", "error"):
            any_failed = True

    duration = round(time.monotonic() - t0, 2)
    totals = _aggregate_totals(feed_results)
    status = "partial" if any_failed else "success"

    logger.info(
        f"[feed_collector] Cycle complete in {duration}s — "
        f"status={status} — "
        f"{totals['fetched']} fetched, {totals['new']} new, "
        f"{totals['updated']} updated, {totals['errors']} errors "
        f"across {len(COLLECTORS)} feed(s)"
    )

    return {
        "status": status,
        "started_at": started_at,
        "duration_secs": duration,
        "totals": totals,
        "feeds": feed_results,
    }


def _run_one_feed(source_name: str, collector_cls, db) -> dict:
    """
    Initialize and run a single collector, catching failures at both
    stages so one bad feed (e.g. missing API key) doesn't stop the rest.
    """
    try:
        collector = collector_cls(db)
    except Exception as exc:
        logger.error(f"[feed_collector] {source_name} could not be initialized: {exc}")
        return {
            "status": "failed",
            "fetched": 0, "new": 0, "updated": 0, "errors": 0,
            "error": str(exc),
        }

    try:
        result = collector.run()
        return result
    except Exception as exc:
        logger.error(f"[feed_collector] {source_name} raised during run(): {exc}")
        return {
            "status": "error",
            "fetched": 0, "new": 0, "updated": 0, "errors": 0,
            "error": str(exc),
        }


def _aggregate_totals(feed_results: dict) -> dict:
    """Sum fetched/new/updated/errors across all feed result dicts."""
    totals = {"fetched": 0, "new": 0, "updated": 0, "errors": 0}
    for result in feed_results.values():
        for key in totals:
            totals[key] += result.get(key, 0) or 0
    return totals


if __name__ == "__main__":
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent.parent / ".env")

    from database.db_manager import DBManager

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    db = DBManager()
    summary = run_all_feeds(db)

    print("\n--- Feed Collection Summary ---")
    for source, result in summary["feeds"].items():
        print(f"{source:20s} status={result.get('status'):10s} "
              f"fetched={result.get('fetched', 0):>6} "
              f"new={result.get('new', 0):>6} "
              f"updated={result.get('updated', 0):>6} "
              f"errors={result.get('errors', 0):>4}")
    print(f"\nOverall: {summary['status']} in {summary['duration_secs']}s")
    print(f"Totals:  {summary['totals']}")