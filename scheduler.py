"""
scheduler.py
=============
Runs two independent background loops:

  1. Feed collection loop  — pulls IOCs from all feeds every 24 hours
  2. Enrichment poll loop  — enriches new case management platform alerts/cases every 30 seconds

Both loops run in separate threads so a slow feed run (10-30s) never
delays the enrichment polling cycle. Both are designed to run forever
until a stop event is set (by main.py on Ctrl+C or SIGTERM).

Each loop catches all exceptions internally — one crashed cycle does
not stop the scheduler. The error is logged and the loop continues on
the next tick.

Usage (called by main.py — do not run this file directly):
    from scheduler import Scheduler

    scheduler = Scheduler(engine, db)
    scheduler.start()           # starts both threads
    scheduler.stop()            # signals both threads to stop
    scheduler.join()            # waits for clean shutdown
"""

import logging
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── Default intervals (can be overridden via config or env) ──────────────────
FEED_INTERVAL_HOURS   = 24
ENRICH_INTERVAL_SECS  = 30


class Scheduler:
    """
    Manages the feed collection and enrichment polling loops.

    Parameters
    ----------
    engine : EnrichmentEngine
        Fully initialized enrichment engine (case_platform_client, ioc_lookup,
        ad_lookup already wired in).
    db : DBManager
        Database manager — passed to feed_collector for IOC storage.
    feed_interval_hours : int
        How often to run the full feed collection cycle. Default: 24h.
    enrich_interval_secs : int
        How often to poll case management platform for new alerts/cases. Default: 30s.
    """

    def __init__(
        self,
        engine,
        db,
        feed_interval_hours: int = FEED_INTERVAL_HOURS,
        enrich_interval_secs: int = ENRICH_INTERVAL_SECS,
    ):
        self.engine = engine
        self.db = db
        self.feed_interval_hours  = feed_interval_hours
        self.enrich_interval_secs = enrich_interval_secs

        self._stop_event = threading.Event()
        self._feed_thread   = threading.Thread(
            target=self._feed_loop,
            name="feed-collector",
            daemon=True,
        )
        self._enrich_thread = threading.Thread(
            target=self._enrich_loop,
            name="enrichment-poller",
            daemon=True,
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self):
        """Start both background threads."""
        logger.info(
            f"Scheduler starting — "
            f"feed every {self.feed_interval_hours}h, "
            f"enrichment every {self.enrich_interval_secs}s"
        )
        self._feed_thread.start()
        self._enrich_thread.start()

    def stop(self):
        """Signal both threads to stop after their current cycle."""
        logger.info("Scheduler stop requested")
        self._stop_event.set()

    def join(self, timeout: float = 10.0):
        """Wait for both threads to exit cleanly."""
        self._feed_thread.join(timeout=timeout)
        self._enrich_thread.join(timeout=timeout)
        logger.info("Scheduler stopped")

    # ── Feed loop ─────────────────────────────────────────────────────────────

    def _feed_loop(self):
        """
        Run feed collection immediately on startup, then every
        feed_interval_hours. Catches all exceptions so one bad
        run doesn't kill the loop.
        """
        from feeds.feed_collector import run_all_feeds

        interval_secs = self.feed_interval_hours * 3600

        while not self._stop_event.is_set():
            self._run_feeds(run_all_feeds)

            # Sleep in 1-second ticks so stop_event is checked frequently
            # rather than sleeping for the full 24h interval uninterruptibly.
            elapsed = 0
            while elapsed < interval_secs and not self._stop_event.is_set():
                time.sleep(1)
                elapsed += 1

        logger.info("[feed-collector] Loop exiting cleanly")

    def _run_feeds(self, run_all_feeds_fn):
        """Run one feed collection cycle with full error handling."""
        started = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        logger.info(f"[feed-collector] Cycle starting at {started}")
        try:
            summary = run_all_feeds_fn(self.db)
            totals = summary.get("totals", {})
            logger.info(
                f"[feed-collector] Cycle complete — "
                f"status={summary.get('status')} — "
                f"{totals.get('new', 0)} new, "
                f"{totals.get('updated', 0)} updated, "
                f"{totals.get('errors', 0)} errors"
            )
        except Exception as exc:
            logger.error(f"[feed-collector] Cycle failed: {exc}", exc_info=True)

    # ── Enrichment loop ───────────────────────────────────────────────────────

    def _enrich_loop(self):
        """
        Poll case management platform every enrich_interval_secs for new alerts and cases
        and run the enrichment pipeline on each one. Catches all exceptions
        so one bad poll doesn't kill the loop.
        """
        while not self._stop_event.is_set():
            self._run_enrichment()
            # Same tick-based sleep as the feed loop
            elapsed = 0
            while elapsed < self.enrich_interval_secs and not self._stop_event.is_set():
                time.sleep(1)
                elapsed += 1

        logger.info("[enrichment-poller] Loop exiting cleanly")

    def _run_enrichment(self):
        """Run one enrichment poll cycle with full error handling."""
        try:
            records = self.engine.run_once()
            if records:
                logger.info(
                    f"[enrichment-poller] Enriched {len(records)} "
                    f"alert(s)/case(s)"
                )
            else:
                logger.debug("[enrichment-poller] No new alerts/cases")
        except Exception as exc:
            logger.error(
                f"[enrichment-poller] Poll failed: {exc}", exc_info=True
            )