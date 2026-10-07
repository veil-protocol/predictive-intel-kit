---
actor_id: APT-RAVEN
aliases: [Raven Group, STORM-EXAMPLE]
relevance_tier: tier-1
priority: P1
mitre_attck: [T1566, T1078, T1550, T1213]
linked_recipes: [REC-0001]
linked_surfaces: [SURF-001, SURF-002]
primary_tradecraft: "Identity-first intrusion — phish SSO, persist via OAuth, exfiltrate source code"
tags: [actor]
---

# APT-RAVEN  *(fictional — example data only)*

A tier-1 example actor used to demonstrate the kit. Identity-first operator:
credential-phishes an SSO portal, establishes OAuth persistence, steals session
tokens, and exfiltrates source code.

Note the engine will also attribute **REC-0003 (token theft)** to APT-RAVEN even
though it is NOT in `linked_recipes` — because REC-0003's `mitre_attck` (`T1078`)
overlaps this actor's TTP inventory. That MITRE-overlap branch is how the engine
surfaces chains you never hand-wired.
