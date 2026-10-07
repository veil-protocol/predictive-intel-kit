---
# ─── SURFACE / ASSET NOTE — required contract fields ────────────────────────
surface_id: SURF-000            # canonical ID; must be unique across surfaces
interface_type: ""              # e.g. identity/SSO, web/CMS, source-code/git, api/graph
state: unconfirmed              # unconfirmed | osint-confirmed | validated
owner_entity: ""                # team / vendor / business unit that owns it
surface_layers: []              # technical layers exposed (used as a strategic proxy)
pir: []                         # which standing Priority Intel Requirements this touches
data_sensitivity: []            # pii | crown_jewel | mnpi | regulated  (drives sensitivity score)
linked_recipes: []              # recipe_ids applicable to this surface
linked_actors: []               # actor_ids likely to target it
tags: [surface]
---

# SURF-000

> Replace this file. One surface (interface / asset) per note. `data_sensitivity`
> and `pir` drive the scoring; set them honestly. If you omit `data_sensitivity`,
> the engine falls back to substring-matching the indicators in scoring.yaml.

## Description

## Exposure / state evidence
