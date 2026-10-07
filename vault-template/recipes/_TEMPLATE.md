---
# ─── RECIPE NOTE — one single-step technique. Required contract fields ──────
recipe_id: REC-0000             # canonical ID; must be unique across recipes
recipe_name: ""                 # human label
phase: entry                    # entry | establish | escalate | pivot | impact
                                # (also inferable from a /phase/ subfolder path)
mitre_attck: []                 # ATT&CK technique IDs — drives actor attribution
actor_uses: []                  # actor_ids/aliases known to use this (optional)
linked_surfaces: []             # surface_ids this recipe applies to
opsec: medium                   # burn-on-use | low | low-to-medium | medium | medium-to-high | high
achieves: ""                    # one line: what the operator gains
tags: [recipe]
---

# REC-0000

> Replace this file. One technique per note; file it under the matching phase
> subfolder (recipes/entry/, recipes/establish/, ...). `mitre_attck` is the key
> field: it lets an actor "inherit" this recipe even if no actor card links it.

## Procedure

## Detection / telemetry
