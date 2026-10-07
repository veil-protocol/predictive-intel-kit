---
# ─── ACTOR CARD — required contract fields (see docs/DATA-CONTRACT.md) ───────
actor_id: APT-EXAMPLE            # canonical ID; must be unique across actors
aliases: []                     # other names/campaigns this actor is known by
relevance_tier: tier-3          # tier-1 | tier-2 | tier-3 | tier-4 | reference-only
priority: P3                    # free-form, your own backlog priority
mitre_attck: []                 # ATT&CK technique IDs the actor is known to use
linked_recipes: []              # recipe_ids the actor is KNOWN to use (operator-curated)
linked_surfaces: []             # surface_ids this actor is likely to target in your env
primary_tradecraft: ""          # one-line signature
# ─── free metadata below is ignored by the engine ──────────────────────────
tags: [actor]
---

# APT-EXAMPLE

> Replace this file. One actor per note. The engine reads ONLY the frontmatter
> above; the prose is for humans. `mitre_attck` is the most important field —
> it lets the engine discover chains through recipes you have NOT hand-linked.

## Overview

## Known tradecraft

## Sourcing
