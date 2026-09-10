# SOC Alert Enrichment Platform

> **SOC automation project developed during a cybersecurity internship — sanitized public portfolio version.**

An automated enrichment platform designed to provide SOC analysts with contextual information around security alerts, including **threat intelligence, identity context, phishing/DLP analysis, domain intelligence, and explainable risk signals**.

The platform is designed as **analyst decision support**: enrichment and risk signals are transparent and explainable, while the final security decision always remains with the analyst.

> [!WARNING]
> **Public Portfolio Version**
>
> The original internship implementation operated within an enterprise financial SOC environment. This repository is a sanitized reconstruction for portfolio purposes.
>
> It contains **no production alerts, customer data, credentials, internal hostnames, proprietary configurations, or internal infrastructure details**. Organization-specific integrations are represented through generic adapters, synthetic data, and offline mocks.

---

## Internship Context

**Organization:** ODDO BHF Tunis  
**Environment:** Financial Services SOC  
**Role:** SOC Automation & Enrichment Intern  
**Period:** June – August 2026

The production implementation integrated with the organization's existing **SIEM and case-management infrastructure** to support automated alert enrichment and analyst triage.

The public repository reconstructs the core engineering concepts and workflows without exposing organization-specific implementation details.

### Project Goals

The platform was designed to:

- Reduce repetitive manual alert enrichment
- Centralize threat-intelligence context
- Correlate alerts with identity and business context
- Provide explainable risk signals before analyst assignment
- Automate phishing and DLP investigation workflows
- Generate structured, analyst-readable reports
- Support local AI-assisted triage without sending sensitive alert data to external LLM APIs

---

## Highlights

### Threat Intelligence

- Collectors for **abuse.ch** feeds:
  - Feodo Tracker
  - ThreatFox
  - URLhaus
- **AlienVault OTX** integration
- IOC normalization and deduplication
- Local **SQLite** IOC database
- Feed execution history and persistence
- Multi-source reputation aggregation
- Malware-family and threat-actor attribution where available

### Alert Enrichment Engine

- Polls the case-management platform for new alerts/cases
- Automatically partitions observables by type and context
- Internal IPs and email addresses → identity enrichment
- External IPs, hashes, URLs and domains → reputation enrichment
- Generates explicit, explainable risk signals
- Produces structured reports for analyst review
- Writes enrichment results back to the case-management platform

### Identity Context

- Corporate directory integration
- Microsoft Entra ID / Graph-compatible architecture
- LDAP-compatible integration model
- Offline mock mode for development and testing
- User and organizational context enrichment

### DLP Workflow

For **internal → external** data-transfer scenarios:

- Sender identity enrichment
- Recipient classification
- Personal webmail / disposable / suspicious-domain detection
- WHOIS enrichment
- Self-send detection
- Sensitive-keyword analysis
- File analysis
- Contextual risk scoring

### Phishing Workflow

For **external → internal** email scenarios:

- SPF validation
- DKIM validation
- DMARC validation
- WHOIS analysis
- Homoglyph detection
- IOC reputation checks
- Per-alert security signals
- Structured analyst summary and narrative

### Recipient Business Context

External domains can optionally be enriched with descriptive business information using an external company-information API.

This context is deliberately **kept separate from security scoring** and is provided only to help analysts understand the organization associated with a recipient domain.

### Local LLM Layer

An optional locally running LLM, such as **Ollama**, can generate analyst-facing triage narratives.

The architecture follows a fail-safe approach:

- The deterministic enrichment report is always generated
- The LLM is optional
- No external LLM API is required
- Sensitive alert data can remain within the local environment
- The LLM provides advisory context rather than a final verdict

---

## Project Scale

The internship implementation included:

- **60,000+** threat-intelligence indicators collected and normalized
- **3** automated phishing attack scenarios
- **6** phishing validation checks
- **4-layer** DLP enrichment workflow
- Automated alert enrichment before analyst assignment
- Multi-source IOC reputation analysis
- Local LLM-assisted analyst narratives

> Metrics describe the internship implementation and are presented at a non-sensitive level.

---

## Architecture

```text
                         ┌──────────────────────┐
                         │    Threat Feeds      │
                         │ abuse.ch / OTX       │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │   Feed Collectors    │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │    IOC Database      │
                         │       SQLite         │
                         └──────────┬───────────┘
                                    │
                                    │
┌──────────────────┐                ▼
│ Case Management  │──────► ┌──────────────────────┐
│    Platform      │         │  Enrichment Engine   │
└──────────────────┘         │       Python         │
                             └──────────┬───────────┘
                                        │
                   ┌────────────────────┼────────────────────┐
                   │                    │                    │
                   ▼                    ▼                    ▼
          ┌────────────────┐   ┌────────────────┐   ┌────────────────┐
          │ Identity       │   │ Threat Intel   │   │ Phishing / DLP │
          │ Context        │   │ Reputation     │   │ Workflows      │
          └────────────────┘   └────────────────┘   └────────────────┘
                   │                    │                    │
                   └────────────────────┼────────────────────┘
                                        ▼
                              ┌──────────────────────┐
                              │ Explainable Signals  │
                              │ + Risk Context       │
                              └──────────┬───────────┘
                                         │
                         ┌───────────────┼───────────────┐
                         ▼               ▼               ▼
                  ┌────────────┐  ┌────────────┐  ┌──────────────┐
                  │ Case       │  │ JSON       │  │ Local LLM    │
                  │ Platform   │  │ Report     │  │ Narrative    │
                  └────────────┘  └─────┬──────┘  └──────────────┘
                                        │
                                        ▼
                                ┌────────────────┐
                                │ Report Viewer  │
                                │     Flask      │
                                └────────────────┘
