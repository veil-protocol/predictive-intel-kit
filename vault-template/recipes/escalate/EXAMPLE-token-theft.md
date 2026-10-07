---
recipe_id: REC-0003
recipe_name: Session token theft
phase: escalate
mitre_attck: [T1078]
actor_uses: []
linked_surfaces: [SURF-001]
opsec: medium-to-high
achieves: "Elevated access by replaying stolen valid session tokens"
tags: [recipe]
---

# REC-0003 — Session token theft  *(fictional — example data only)*

Escalate-phase technique. Note `actor_uses` is EMPTY: the engine still attributes
this to APT-RAVEN because its `mitre_attck` (`T1078`) overlaps the actor's TTP
inventory. This is the mechanism that generates non-obvious, un-hand-wired chains.
