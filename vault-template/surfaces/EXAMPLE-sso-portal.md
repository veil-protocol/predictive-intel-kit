---
surface_id: SURF-001
interface_type: identity/SSO
state: osint-confirmed
owner_entity: IT Identity Team
surface_layers: [web-login, oauth, mfa]
pir: [PIR-1, PIR-2]
data_sensitivity: [pii]
linked_recipes: [REC-0001, REC-0002, REC-0003]
linked_actors: [APT-RAVEN, COMMODITY-CRIMSON]
tags: [surface]
---

# SURF-001 — SSO Portal  *(fictional — example data only)*

Internet-facing single-sign-on portal. PII-class (every employee identity flows
through it) and OSINT-confirmed, so chains targeting it score on both
`sensitivity_exposure` and `emulation_readiness`.
