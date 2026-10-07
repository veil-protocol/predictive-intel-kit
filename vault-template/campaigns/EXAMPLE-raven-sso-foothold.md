---
campaign_id: CAMP-2026-001
primary_actor: APT-RAVEN
recipes_orchestrated: [REC-0001, REC-0002]
surface_targets: [SURF-001]
tags: [campaign]
---

# CAMP-2026-001 — RAVEN SSO Foothold  *(fictional — example data only)*

An already-authored campaign: APT-RAVEN phishes SSO (REC-0001) then persists via
OAuth (REC-0002) against SURF-001. Its presence makes the engine flag the
RAVEN phish→persist candidate as **EXTENDS** (not NEW), steering you toward the
longer, un-authored chains that reach the code repo instead.
