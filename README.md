# SOC Alert Enrichment Platform

> **Internship proof-of-concept — anonymized.** No production data or internal infrastructure details are included. The platform is presented as a generic integration that works with any SIEM, case management platform and corporate directory.

A Python service that automatically enriches security alerts with contextual information — threat intelligence, identity context and domain intelligence — and publishes structured, analyst-readable reports. The enrichment is explainable and never issues a final verdict; the analyst always decides.

## Highlights

- **Threat intel aggregation** — collectors for abuse.ch (Feodo, ThreatFox, URLhaus) and AlienVault OTX, normalized into a local SQLite IOC database with deduplication and feed-run history
- **Enrichment engine** — polls the case management platform for new alerts/cases, partitions observables (internal IPs/e-mails → identity, external IPs/hashes/URLs/domains → reputation) and builds explicit risk signals
- **Identity context** — corporate directory lookup with offline mock mode and real API mode (e.g., Microsoft Entra ID / any LDAP/Graph-compatible directory)
- **Reputation context** — local IOC lookup with multi-source score aggregation and malware-family / threat-actor attribution
- **DLP workflow** (internal → external) — sender identity, recipient classification (personal webmail / disposable / suspicious), WHOIS, self-send detection, sensitive-keyword scoring, file analysis and contextual risk scoring
- **Phishing workflow** (external → internal) — SPF/DKIM/DMARC, WHOIS, homoglyph detection, IOC checks and per-alert signals/summary/narrative
- **Recipient business context** — descriptive enrichment for external domains, explicitly kept out of scoring
- **Local LLM layer** — optional advisory narrative via a locally-running model (e.g., Ollama). No data leaves the machine; the deterministic report is always complete without it
- **Reporting** — JSON reports + Flask viewer with per-type templates

## Architecture

```
[Threat feeds] ──► [Feed collector] ──► [IOC database (SQLite)]
                                          │
[Case platform API] ──► [Enrichment engine] ◄── [Directory / Identity]
                              │
                              ├──► [Observable tagging + Summary report] ──► Case platform
                              └──► [JSON report] ──► [Report viewer]
```

Two independent scheduler threads: feed collection (default 24h) and enrichment polling (default 30s).

## Quick start

```bash
# 1. Clone and configure
git clone https://github.com/mohamed-mensi/soc-alert-enrichment-platform.git
cd soc-alert-enrichment-platform
cp .env.example .env   # fill in your keys

# 2. Start the case management platform (example with an OSS platform)
docker compose up -d

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run
python main.py
# Reports are at http://localhost:5000/report/<alert_id>
```

## Configuration

See `.env.example`:

```
CASE_PLATFORM_URL=http://localhost:9000
CASE_PLATFORM_API_KEY=your_key_here
DIRECTORY_TENANT_ID=...
DIRECTORY_CLIENT_ID=...
DIRECTORY_CLIENT_SECRET=...
OTX_API_KEY=...
COMPANIES_API_KEY=...
```

All directory / intel providers have an offline mock mode so the platform and tests run without real credentials.

## Project structure

```
database/        SQLite persistence (IOCs, feed runs)
feeds/           Threat-intel collectors
case_platform/   Case platform client (poll) + updater (write-back)
enrichment/      Engine, IOC lookup, identity lookup, LLM, reporting
phishing/        E-mail parser, DLP & phishing workflows
templates/       Report HTML templates
tests/           Offline, deterministic test suite
```

## Testing

```bash
python -m pytest tests/test_dlp_and_phishing.py -v
# or
python -m unittest tests.test_dlp_and_phishing -v
```

No network, case platform, WHOIS or LLM required — directory, IOC DB, WHOIS and LLM are stubbed.

## Disclaimer

This repository is a portfolio / internship project. It contains no customer data, no internal hostnames, credentials or infrastructure details. Any organization, domain or integration mentioned is an example among others and does not imply a specific deployment.

## Acknowledgements

Built during an internship — thanks to the SOC team and supervisors for their guidance.
