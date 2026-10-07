---
tags:
  - 🔮
aliases:
  - Predictive Intelligence Enumeration 2026-01-01
date_created: 2026-01-01
last_updated: 2026-01-01
template_version: 1.0
validation_status: draft
run_date: 2026-01-01
total_chains_enumerated: 4
overlap_filtered_count: 0
emitted_count: 4
engine_version: 1.0
---

# 🔮 Predictive Intelligence Enumeration — 2026-01-01

**Engine v1.0** · **Run** 2026-01-01 · **Top-N** 4 · **Total chains** 4 · **Duplicates filtered** 0

> Combinatorially-enumerated plausible attack chains derived from cross-linking actors × recipes × surfaces. Each chain is a *candidate campaign* not yet manually authored. Scoring rubric: see `config/scoring.yaml`.

> **How to use:** read the top-N. For each NEW high-score candidate, decide — promote to a standalone campaign, or convert directly to an emulation draft. Lower-score / EXTENDS items are backlog.

---

## 🏆 Ranked Candidate Catalog

| Rank | ID | Actor | Score | Overlap | Priority | Emulation |
|---|---|---|---|---|---|---|
| 1 | PRED-2026-01-01-001 | APT-RAVEN (tier-1) | 59.0 | EXTENDS:CAMP-2026-001 | P2 | READY |
| 2 | PRED-2026-01-01-002 | APT-RAVEN (tier-1) | 52.0 | EXTENDS:CAMP-2026-001 | P3 | NEEDS-RECIPE |
| 3 | PRED-2026-01-01-003 | COMMODITY-CRIMSON (tier-2) | 47.4 | NEW | P3 | READY |
| 4 | PRED-2026-01-01-004 | COMMODITY-CRIMSON (tier-2) | 42.4 | EXTENDS:CAMP-2026-001 | P3 | NEEDS-RECIPE |

---

## 1. PRED-2026-01-01-001 — APT-RAVEN

**Actor:** [[EXAMPLE-apt-raven|APT-RAVEN]] (tier-1, priority P1)  
**Composite score:** **59.0 / 100** → recommended priority: **P2**  
**Overlap with existing campaigns:** EXTENDS:CAMP-2026-001  
**Emulation-conversion readiness:** READY

### Generated chain

- **    ENTRY** → [[EXAMPLE-phish-sso|REC-0001]] *(SSO credential phishing)* — Valid SSO credentials / session for initial access
- **ESTABLISH** → [[EXAMPLE-oauth-persist|REC-0002]] *(OAuth application persistence)* — Durable access via consented OAuth app, surviving password reset
- ** ESCALATE** → [[EXAMPLE-token-theft|REC-0003]] *(Session token theft)* — Elevated access by replaying stolen valid session tokens
- **   IMPACT** → [[EXAMPLE-repo-exfil|REC-0004]] *(Source code exfiltration)* — Bulk source-code and secrets theft from the repository

### Target surfaces

- [[EXAMPLE-sso-portal|SURF-001]] — `identity/SSO` (state: `osint-confirmed`)
- [[EXAMPLE-code-repo|SURF-002]] — `source-code/git` (state: `validated`)

### Score breakdown

| Component | Weight | Raw (0-1) | Contribution |
|---|---|---|---|
| strategic relevance | 30 | 0.30 | 9.0 |
| actor probability | 20 | 1.00 | 20.0 |
| detection gap | 20 | 0.80 | 16.0 |
| sensitivity exposure | 20 | 0.50 | 10.0 |
| operational simplicity | 10 | 0.40 | 4.0 |
| **Composite** | **100** | — | **59.0** |

---

## 2. PRED-2026-01-01-002 — APT-RAVEN

**Actor:** [[EXAMPLE-apt-raven|APT-RAVEN]] (tier-1, priority P1)  
**Composite score:** **52.0 / 100** → recommended priority: **P3**  
**Overlap with existing campaigns:** EXTENDS:CAMP-2026-001  
**Emulation-conversion readiness:** NEEDS-RECIPE

### Generated chain

- **    ENTRY** → [[EXAMPLE-phish-sso|REC-0001]] *(SSO credential phishing)* — Valid SSO credentials / session for initial access

### Target surfaces

- [[EXAMPLE-sso-portal|SURF-001]] — `identity/SSO` (state: `osint-confirmed`)

### Score breakdown

| Component | Weight | Raw (0-1) | Contribution |
|---|---|---|---|
| strategic relevance | 30 | 0.40 | 12.0 |
| actor probability | 20 | 1.00 | 20.0 |
| detection gap | 20 | 0.20 | 4.0 |
| sensitivity exposure | 20 | 0.40 | 8.0 |
| operational simplicity | 10 | 0.80 | 8.0 |
| **Composite** | **100** | — | **52.0** |

---

## 3. PRED-2026-01-01-003 — COMMODITY-CRIMSON

**Actor:** [[EXAMPLE-commodity-crimson|COMMODITY-CRIMSON]] (tier-2, priority P2)  
**Composite score:** **47.4 / 100** → recommended priority: **P3**  
**Overlap with existing campaigns:** NEW  
**Emulation-conversion readiness:** READY

### Generated chain

- **    ENTRY** → [[EXAMPLE-phish-sso|REC-0001]] *(SSO credential phishing)* — Valid SSO credentials / session for initial access
- **   IMPACT** → [[EXAMPLE-ransomware-encrypt|REC-0005]] *(Ransomware encryption)* — Business disruption via mass encryption

### Target surfaces

- [[EXAMPLE-sso-portal|SURF-001]] — `identity/SSO` (state: `osint-confirmed`)

### Score breakdown

| Component | Weight | Raw (0-1) | Contribution |
|---|---|---|---|
| strategic relevance | 30 | 0.28 | 8.4 |
| actor probability | 20 | 0.70 | 14.0 |
| detection gap | 20 | 0.40 | 8.0 |
| sensitivity exposure | 20 | 0.40 | 8.0 |
| operational simplicity | 10 | 0.90 | 9.0 |
| **Composite** | **100** | — | **47.4** |

---

## 4. PRED-2026-01-01-004 — COMMODITY-CRIMSON

**Actor:** [[EXAMPLE-commodity-crimson|COMMODITY-CRIMSON]] (tier-2, priority P2)  
**Composite score:** **42.4 / 100** → recommended priority: **P3**  
**Overlap with existing campaigns:** EXTENDS:CAMP-2026-001  
**Emulation-conversion readiness:** NEEDS-RECIPE

### Generated chain

- **    ENTRY** → [[EXAMPLE-phish-sso|REC-0001]] *(SSO credential phishing)* — Valid SSO credentials / session for initial access

### Target surfaces

- [[EXAMPLE-sso-portal|SURF-001]] — `identity/SSO` (state: `osint-confirmed`)

### Score breakdown

| Component | Weight | Raw (0-1) | Contribution |
|---|---|---|---|
| strategic relevance | 30 | 0.28 | 8.4 |
| actor probability | 20 | 0.70 | 14.0 |
| detection gap | 20 | 0.20 | 4.0 |
| sensitivity exposure | 20 | 0.40 | 8.0 |
| operational simplicity | 10 | 0.80 | 8.0 |
| **Composite** | **100** | — | **42.4** |

---

## Methodology Summary

Chains are enumerated from each actor's plausible-recipe set (union of: the actor card's `linked_recipes`, recipes naming the actor in `actor_uses`, and recipes whose MITRE-ATT&CK IDs overlap the actor's TTP inventory). Target surfaces intersect the actor's `linked_surfaces` with each recipe's `linked_surfaces`. See `docs/METHOD.md` for the full method and `config/scoring.yaml` for the rubric.
