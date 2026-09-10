"""
enrichment/llm_analyzer.py
===========================
Generates a human-readable analyst narrative for an enrichment record
using a locally-running LLM via Ollama.

The narrative combines:
  - The raw alert description (SIEM rule name, log context, behavior summary)
  - Structured enrichment signals (IOC reputation, identity context, risk level)
  - The overall verdict level (ESCALATE / NEEDS_REVIEW / LIKELY_FP)

Into a 3-4 sentence paragraph that tells the analyst:
  - What happened (from the description)
  - Why it is significant (from the signals)
  - What to look at first (from the verdict + highest signals)

Design principles:
  - The LLM can ONLY reference facts explicitly passed in the prompt.
    It cannot invent IPs, usernames, malware families, or context.
    This is enforced by the prompt, not by post-processing.
  - If Ollama is not running, the module returns None gracefully.
    The enrichment pipeline continues without the narrative.
    The LLM is additive — never a blocker.
  - No data leaves the machine. Ollama runs fully locally.
    This is important for a financial institution context.

Requirements:
  - Install Ollama: https://ollama.com/download
  - Pull a model: `ollama pull phi3` (CPU-friendly, ~2GB)
                  `ollama pull mistral` (better quality, needs more RAM)
  - Start Ollama: `ollama serve` (or it auto-starts on Windows/Mac)
  - Install the Python library: `pip install ollama`

Configuration (.env):
  LLM_MODEL   : model name to use (default: phi3)
  LLM_URL     : Ollama base URL (default: http://localhost:11434)
  LLM_ENABLED : set to "false" to disable entirely (default: true)
  LLM_TIMEOUT : seconds to wait for a response (default: 60)

Usage:
    from enrichment.llm_analyzer import LLMAnalyzer

    analyzer = LLMAnalyzer()
    narrative = analyzer.generate_narrative(record)
    # Returns a string paragraph, or None if Ollama is unavailable
"""

import logging
import os
import time
from typing import Optional

from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
DEFAULT_MODEL   = "phi3"
DEFAULT_URL     = "http://localhost:11434"
DEFAULT_TIMEOUT = 60

# Maximum characters of description to send to the LLM
# Real SIEM descriptions can be very long — truncate to avoid
# hitting context limits on smaller models
MAX_DESCRIPTION_CHARS = 1500

# ── System prompt ─────────────────────────────────────────────────────────────
# This is the core of hallucination prevention — the system prompt
# explicitly constrains the model to only reference provided facts.
SYSTEM_PROMPT = """You are a SOC analyst assistant at a financial institution.
Your job is to produce structured triage summaries for security alerts.

STRICT RULES:
- Only reference facts explicitly provided in the alert data.
- Never invent IP addresses, usernames, malware names, or any other details.
- Never speculate beyond what the data shows.
- If the log section is empty or unclear, skip it — do not guess.
- Do not repeat the same fact twice.
- Output exactly three sections with bullet points as shown below.
- Each bullet point must be one clear, direct sentence.

OUTPUT FORMAT (use exactly these headers):
### Extracted from logs
- <fact extracted from the raw log description>

### Risk assessment
- <signal from enrichment data>

### Analyst should check first
- <specific actionable investigation step>"""


class LLMAnalyzer:
    """
    Generates analyst narratives for enrichment records using a local LLM.

    Parameters
    ----------
    model   : str — Ollama model name (default: phi3)
    url     : str — Ollama base URL (default: http://localhost:11434)
    timeout : int — seconds to wait for response (default: 60)
    enabled : bool — set False to disable entirely (default: from env)
    """

    def __init__(
        self,
        model: Optional[str] = None,
        url: Optional[str] = None,
        timeout: Optional[int] = None,
        enabled: Optional[bool] = None,
    ):
        self.model   = model   or os.getenv("LLM_MODEL",   DEFAULT_MODEL)
        self.url     = url     or os.getenv("LLM_URL",     DEFAULT_URL)
        self.timeout = timeout or int(os.getenv("LLM_TIMEOUT", DEFAULT_TIMEOUT))

        # Respect LLM_ENABLED env var — allows disabling without code changes
        if enabled is not None:
            self.enabled = enabled
        else:
            self.enabled = os.getenv("LLM_ENABLED", "true").lower() != "false"

        if not self.enabled:
            logger.info("LLMAnalyzer disabled (LLM_ENABLED=false)")
            return

        # Verify ollama library is installed
        try:
            import ollama as _ollama  # noqa: F401
            self._ollama_available = True
        except ImportError:
            logger.warning(
                "ollama library not installed — LLM narrative disabled. "
                "Run: pip install ollama"
            )
            self._ollama_available = False
            return

        # Verify Ollama service is running
        self._service_available = self._check_service()
        if self._service_available:
            logger.info(
                f"LLMAnalyzer initialized — model: {self.model} "
                f"at {self.url}"
            )
        else:
            logger.warning(
                f"Ollama service not reachable at {self.url} — "
                f"LLM narrative will be skipped. "
                f"Start with: ollama serve"
            )

    # ── Public API ────────────────────────────────────────────────────────────

    def generate_narrative(self, record: dict) -> Optional[str]:
        """
        Generate a triage narrative for an enrichment record.

        Parameters
        ----------
        record : dict — enrichment record from enrichment_engine._enrich_target()
            Expected keys: title, description, risk_signals, summary

        Returns
        -------
        str  — the narrative paragraph, or
        None — if LLM is disabled, unavailable, or times out
        """
        if not self.enabled or not getattr(self, "_ollama_available", False):
            return None
        if not getattr(self, "_service_available", False):
            return None

        prompt = self._build_prompt(record)
        if not prompt:
            return None

        start = time.monotonic()
        try:
            narrative = self._call_ollama(prompt)
            duration = round(time.monotonic() - start, 1)
            if narrative:
                logger.info(
                    f"LLM narrative generated for {record.get('target_id')} "
                    f"in {duration}s ({len(narrative)} chars)"
                )
            return narrative
        except Exception as exc:
            logger.warning(
                f"LLM narrative failed for {record.get('target_id')}: {exc}"
            )
            return None

    def is_available(self) -> bool:
        """Return True if the LLM is enabled and the service is reachable."""
        return (
            self.enabled
            and getattr(self, "_ollama_available", False)
            and getattr(self, "_service_available", False)
        )

    # ── Prompt builder ────────────────────────────────────────────────────────

    def _build_prompt(self, record: dict) -> Optional[str]:
        title        = record.get("title", "Unknown Alert")
        description  = record.get("description") or ""
        risk_signals = record.get("risk_signals") or []
        summary      = record.get("summary") or {}
        verdict      = record.get("verdict_level", "NEEDS_REVIEW")

        if len(description) > MAX_DESCRIPTION_CHARS:
            description = description[:MAX_DESCRIPTION_CHARS] + "... [truncated]"

        if risk_signals:
            signals_text = "\n".join(
                f"  - [{s['level'].upper()}] {s['message']}"
                for s in risk_signals
            )
        else:
            signals_text = "  - No significant risk signals detected"

        if not description and not risk_signals:
            logger.debug(
                f"Skipping LLM for {record.get('target_id')} — "
                f"no description or signals"
            )
            return None

        prompt = f"""Produce a structured triage summary for this security alert.

    ALERT TITLE: {title}
    PRIORITY LEVEL: {verdict}

    RAW LOG / ALERT DESCRIPTION (from SIEM — extract key facts from here):
    {description if description else "(no description provided)"}

    ENRICHMENT SIGNALS (from threat feeds and identity lookup):
    {signals_text}

    ADDITIONAL CONTEXT:
    - Malicious observables detected: {summary.get('any_malicious', False)}
    - High risk identity involved: {summary.get('high_risk_identity', False)}
    - Max reputation score: {summary.get('max_reputation_score', 0)}/100

    Using the format specified, produce the three-section summary.
    Extract specific facts from the log (IPs, usernames, times, counts, protocols).
    Only reference facts above. Do not invent any details."""

        return prompt

    # ── Ollama call ───────────────────────────────────────────────────────────

    def _call_ollama(self, prompt: str) -> Optional[str]:
        """
        Call the local Ollama API and return the response text.
        Uses stream=False so we get the complete response at once
        before writing to case management platform.
        """
        import ollama

        client = ollama.Client(host=self.url)
        response = client.chat(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
            stream=False,
            options={
                "temperature": 0.2,   # low temp = more factual, less creative
                "num_predict": 300,   # ~3-4 sentences, prevents rambling
            },
        )

        # Extract content from the response object
        content = None
        if hasattr(response, "message"):
            content = response.message.content
        elif isinstance(response, dict):
            content = response.get("message", {}).get("content")

        if not content:
            return None

        # Clean up any thinking-model artifacts (<think>...</think>)
        content = self._strip_thinking_tags(content)
        return content.strip() if content else None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _check_service(self) -> bool:
        """Check if the Ollama service is reachable."""
        try:
            import requests
            response = requests.get(
                f"{self.url}/api/tags", timeout=3
            )
            return response.status_code == 200
        except Exception:
            return False

    @staticmethod
    def _strip_thinking_tags(text: str) -> str:
        """
        Remove <think>...</think> blocks produced by reasoning models
        (e.g. qwen3, deepseek-r1) so only the final answer is returned.
        """
        import re
        return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    import logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    analyzer = LLMAnalyzer()

    if not analyzer.is_available():
        print("\n⚠️  Ollama is not available.")
        print("To enable the LLM layer:")
        print("  1. Install Ollama: https://ollama.com/download")
        print(f"  2. Pull a model:   ollama pull {analyzer.model}")
        print("  3. Start service:  ollama serve")
        print("  4. Re-run this script")
        sys.exit(0)

    # Test with a realistic enrichment record matching the actual output
    # of enrichment_engine._enrich_target()
    test_record = {
        "target_type": "alert",
        "target_id":   "~364704",
        "title": "Suspicious Login - Finance User from Unusual Location",
        "description": (
            "SIEM Rule: 'Authentication from Unusual Geographic Location'\n"
            "User adele.vance@example-corp.com authenticated successfully from "
            "62.0.120.51 at 02:30 AM after 4 failed attempts. This IP is "
            "outside the user's normal login pattern (Tunis, business hours)."
        ),
        "risk_signals": [
            {
                "level":   "high",
                "message": "IP 62.0.120.51 matched threatfox (Cobalt Strike) — score 75/100"
            },
            {
                "level":   "high",
                "message": "Adele Vance (Finance) — HIGH criticality asset"
            },
            {
                "level":   "high",
                "message": "Adele Vance has no MFA registered"
            },
            {
                "level":   "high",
                "message": "corporate directory Identity Protection risk: HIGH for Adele Vance"
            },
            {
                "level":   "medium",
                "message": "Adele Vance is member of privileged groups: Finance-Team, ERP-Access"
            },
        ],
        "summary": {
            "any_malicious":        True,
            "max_reputation_score": 75,
            "high_risk_identity":   True,
        },
        "verdict_level": "NEEDS_REVIEW",
    }

    print(f"\nGenerating narrative for: {test_record['title']}")
    print("=" * 60)

    narrative = analyzer.generate_narrative(test_record)

    if narrative:
        print("\n📝 AI NARRATIVE:")
        print(narrative)
        print("\n✅ LLM layer is working correctly")
    else:
        print("\n❌ No narrative returned — check logs above")