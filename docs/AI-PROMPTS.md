---
title: AI Prompts — Populate & Maintain Your Predictive-Intelligence Vault
tags: [🔮, guide, ai]
description: A copy-paste prompt library for using any AI assistant to turn raw threat intel into schema-valid actor, surface, recipe, and campaign notes the enumeration engine can read — for authorised defensive / threat-informed-defense use.
---

# 🔮 AI Prompts for the Predictive-Intelligence Kit

This is a library of copy-paste prompts for using **any** AI assistant (Claude,
ChatGPT, a local model) to populate and maintain your vault. The enumeration
engine (`engine/enumerate.py`) reads **YAML frontmatter** from four note types —
**actors**, **surfaces**, **recipes**, **campaigns** — cross-links them, and
ranks plausible multi-step attack chains for emulation planning.

These prompts produce **planning / classification artifacts**: frontmatter plus
concise descriptive prose. They are a threat-informed-defense aid (in the spirit
of MITRE ATT&CK, CALDERA, and Atomic Red Team) for **authorised** purple-team and
detection-engineering work. They do **not** produce working exploit code or live
attack commands.

---

## 1. How to use these prompts

1. Open your AI assistant.
2. Paste the **system preamble** (§2) first, then **one** note-type prompt (§3)
   or a batch prompt (§4).
3. Paste your **source material** where the prompt says to (a CTI report, vendor
   advisory, blog post, incident writeup, ATT&CK group page, etc.).
4. The model returns **one fenced markdown block per note**. Save each block as a
   `.md` file in the matching vault folder:
   - actors → `actors/`
   - surfaces → `surfaces/`
   - recipes → `recipes/<phase>/` (phase subfolder: `entry/`, `establish/`,
     `escalate/`, `pivot/`, `impact/`)
   - campaigns → `campaigns/`

**Verify everything against primary sources.** AI assistants hallucinate — they
will invent MITRE technique IDs, mis-attribute actors, and over-confidently fill
fields the source never stated. The engine is only as good as the notes you feed
it. Treat AI output as a **first draft**, then check every `mitre_attck` ID at
<https://attack.mitre.org> and every attribution against the cited report.

**Keep ID conventions consistent** so cross-links resolve:

| Note type | ID field | Convention | Example |
|---|---|---|---|
| Actor | `actor_id` | `UPPER-KEBAB` name/handle | `APT-RAVEN` |
| Surface | `surface_id` | `SURF-NNN` | `SURF-001` |
| Recipe | `recipe_id` | `REC-NNNN` | `REC-0001` |
| Campaign | `campaign_id` | `CAMP-YYYY-NNN` | `CAMP-2026-001` |

Links between notes are made by putting those IDs into the list fields
(`linked_recipes`, `linked_surfaces`, `actor_uses`, `recipes_orchestrated`, …).
IDs must match **exactly** — the engine keys registries by the literal string.

---

## 2. System preamble (prepend to any prompt below)

```text
You are a threat-intelligence structuring assistant for an AUTHORISED defensive
/ purple-team program (threat-informed defense, in the spirit of MITRE ATT&CK and
Atomic Red Team). Your job is to convert threat-intel source material into
schema-valid Obsidian notes for a predictive-intelligence vault.

Rules:
- Output ONLY note files: YAML frontmatter + concise descriptive prose. One
  fenced ```markdown block per note. No preamble, no commentary outside blocks.
- These are PLANNING and CLASSIFICATION artifacts. Describe capabilities and
  intent at a high level. NEVER output working exploit code, payloads, shell
  commands, or step-by-step live-attack instructions. The `achieves` field and
  all prose stay at the capability-description level (what is accomplished, not
  how to execute it live).
- Use REAL MITRE ATT&CK technique IDs (e.g. T1566, T1078, T1550). Use the exact
  IDs stated in the source. If the source implies a technique but states no ID,
  pick the closest real ID and add a prose line "⚠ MITRE ID inferred, verify".
  NEVER invent an ID that does not exist in ATT&CK.
- If a required field is not supported by the source, DO NOT invent a value.
  Use a clearly-marked placeholder (e.g. state: unconfirmed) and note the gap in
  prose. Mark uncertainty rather than fabricate certainty.
- Keep IDs consistent: actors UPPER-KEBAB, surfaces SURF-NNN, recipes REC-NNNN,
  campaigns CAMP-YYYY-NNN. Cross-link by exact ID string.
- Prefer concise prose (2–5 sentences). The frontmatter is what the engine reads.
```

---

## 3. One prompt per note type

### 3a. Actor card

```text
[PASTE THE SYSTEM PREAMBLE FROM §2 FIRST]

From the source material below, produce ONE actor card. Emit this frontmatter:

  actor_id:            UPPER-KEBAB handle (e.g. APT-RAVEN)
  aliases:             [list of other names the source uses]
  relevance_tier:      one of: tier-1 | tier-2 | tier-3 | tier-4 | reference-only
                       (how relevant to MY org — if unknown, use tier-3)
  priority:            P1 | P2 | P3   (planning priority; default P3)
  mitre_attck:         [real ATT&CK technique IDs attributed to this actor]
  linked_recipes:      [REC-NNNN ids of techniques I already have notes for, else []]
  linked_surfaces:     [SURF-NNN ids this actor is known to target, else []]
  primary_tradecraft:  one-line summary of how this actor operates
  tags:                [actor]

Then 2–4 sentences of prose describing the actor's intent and tradecraft at the
capability level. No operational attack instructions.

SOURCE MATERIAL:
<<< paste report / advisory / ATT&CK group page here >>>
```

**Expected output (fictional example — mirrors the vault template):**

```markdown
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

A tier-1 identity-first operator: credential-phishes an SSO portal, establishes
OAuth persistence, and exfiltrates source code. The engine will also attribute
recipes NOT in `linked_recipes` when their `mitre_attck` overlaps this actor's
TTP inventory (`T1078` → REC-0003), surfacing chains you never hand-wired.
```

> The richer the `mitre_attck` inventory on an actor, the more recipes the engine
> can attribute to it via MITRE-overlap — see §4b.

---

### 3b. Surface

```text
[PASTE THE SYSTEM PREAMBLE FROM §2 FIRST]

From the source material below (an asset, service, or attack-surface
description), produce ONE surface note. Emit this frontmatter:

  surface_id:        SURF-NNN  (next free number in my surfaces/ folder)
  interface_type:    short category, e.g. identity/SSO, web/app, repo/SCM, email
  state:             one of: unconfirmed | osint-confirmed | validated
                     (unconfirmed = asserted, not verified; osint-confirmed =
                      verified from open sources; validated = confirmed present)
  owner_entity:      which team / org unit owns it (else "unknown")
  surface_layers:    [sub-components, e.g. web-login, oauth, mfa]
  pir:               [priority-intel-requirement ids this surface informs, else []]
  data_sensitivity:  [any of: pii | crown_jewel | mnpi | regulated | ... ]
  linked_recipes:    [REC-NNNN ids known to target it, else []]
  linked_actors:     [actor_ids known to target it, else []]
  tags:              [surface]

Then 1–3 sentences on why this surface matters (data it exposes, exposure state).

SOURCE MATERIAL:
<<< paste asset / service description here >>>
```

**Expected output (fictional example):**

```markdown
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
`sensitivity_exposure` and emulation-readiness.
```

> `data_sensitivity: [pii]` or `[crown_jewel]` / `[mnpi]` drives the engine's
> sensitivity-exposure score directly. If you omit it, the engine falls back to
> keyword-matching the interface type / id — explicit is always better.

---

### 3c. Recipe

```text
[PASTE THE SYSTEM PREAMBLE FROM §2 FIRST]

From the source material below, produce ONE recipe note for a SINGLE technique.
A recipe is a technique classified by kill-chain phase — a planning label, NOT
an executable procedure. Emit this frontmatter:

  recipe_id:     REC-NNNN  (next free number)
  recipe_name:   short human name of the technique
  phase:         one of: entry | establish | escalate | pivot | impact
  mitre_attck:   [real ATT&CK technique IDs for THIS technique]
  actor_uses:    [actor_ids observed using it; [] is fine — see note below]
  linked_surfaces: [SURF-NNN ids this technique applies to, else []]
  opsec:         one of: burn-on-use | low | low-to-medium | medium |
                 medium-to-high | high   (how noisy/detectable; default medium)
  achieves:      one capability-level sentence of WHAT it accomplishes
                 (NOT how to run it)
  tags:          [recipe]

Then 1–2 sentences of prose. Capability description only — no commands/payloads.

SOURCE MATERIAL:
<<< paste technique description here >>>
```

**Expected output (fictional example):**

```markdown
---
recipe_id: REC-0001
recipe_name: SSO credential phishing
phase: entry
mitre_attck: [T1566]
actor_uses: [APT-RAVEN]
linked_surfaces: [SURF-001]
opsec: low-to-medium
achieves: "Valid SSO credentials / session for initial access"
tags: [recipe]
---

# REC-0001 — SSO credential phishing  *(fictional — example data only)*

Entry-phase technique targeting the SSO portal (SURF-001). Classification only —
execution is left to authorised humans and dedicated BAS tooling.
```

> **`actor_uses` can be empty.** The engine still attributes a recipe to an actor
> when the recipe's `mitre_attck` overlaps the actor's TTP inventory. That
> MITRE-overlap branch is what surfaces non-obvious, un-hand-wired chains — so
> accurate `mitre_attck` on recipes matters as much as on actors.

---

### 3d. Campaign

```text
[PASTE THE SYSTEM PREAMBLE FROM §2 FIRST]

From the source material below (an end-to-end intrusion / campaign writeup),
produce ONE campaign note stitching existing recipes into an ordered chain.
Emit this frontmatter:

  campaign_id:          CAMP-YYYY-NNN  (year + next free number)
  primary_actor:        the actor_id driving it
  recipes_orchestrated: [REC-NNNN ids in kill-chain order]
  surface_targets:      [SURF-NNN ids it targets]
  tags:                 [campaign]

Then 2–3 sentences describing the campaign arc at the capability level. Only
reference recipe/surface IDs that already exist in my vault; if a step has no
recipe yet, note it in prose as a gap rather than inventing an ID.

SOURCE MATERIAL:
<<< paste campaign / intrusion writeup here >>>
```

**Expected output (fictional example):**

```markdown
---
campaign_id: CAMP-2026-001
primary_actor: APT-RAVEN
recipes_orchestrated: [REC-0001, REC-0002]
surface_targets: [SURF-001]
tags: [campaign]
---

# CAMP-2026-001 — RAVEN SSO Foothold  *(fictional — example data only)*

Authored campaign: APT-RAVEN phishes SSO (REC-0001) then persists via OAuth
(REC-0002) against SURF-001. Its presence makes the engine flag the equivalent
enumerated candidate as EXTENDS (not NEW), steering attention to longer chains
you have not yet authored.
```

> Authoring campaigns feeds the engine's overlap detector: enumerated chains that
> match an existing campaign are marked `DUPLICATE` / `EXTENDS`, so the ranked
> catalog highlights genuinely NEW chains you haven't planned.

---

## 4. Bulk / batch prompts

### 4a. Extract every technique from a report as separate recipes

```text
[PASTE THE SYSTEM PREAMBLE FROM §2 FIRST]

Read the threat report below. Extract EVERY distinct technique as its OWN recipe
note (one fenced ```markdown block each), using the recipe schema from §3c:
recipe_id (sequential REC-NNNN starting at REC-0010), recipe_name, phase
(entry|establish|escalate|pivot|impact), mitre_attck (real IDs), actor_uses,
linked_surfaces, opsec, achieves, tags: [recipe].

Assign phase by where the technique sits in the kill chain. If the report maps a
technique to a MITRE ID, use it verbatim; if it only describes behaviour, infer
the closest real ID and flag "⚠ MITRE ID inferred, verify" in prose. Keep
`achieves` at the capability level — no commands or payloads.

THREAT REPORT:
<<< paste full report here >>>
```

### 4b. Suggest missing MITRE tags on actors (improves chain discovery)

```text
[PASTE THE SYSTEM PREAMBLE FROM §2 FIRST]

Below are my actor cards and recipe notes (frontmatter). The enumeration engine
attributes a recipe to an actor when the recipe's `mitre_attck` overlaps the
actor's `mitre_attck` inventory. For each actor, list ATT&CK technique IDs that
are (a) present on recipes/campaigns credibly associated with that actor but
(b) MISSING from the actor's `mitre_attck`. For each suggestion give: the ID, the
recipe(s) that carry it, and a one-line justification from the source. Output a
per-actor table, then the corrected `mitre_attck:` line to paste back.

Adding these tags directly increases how many recipes the engine can attribute to
each actor (the MITRE-overlap branch), which surfaces more candidate chains — so
only suggest IDs genuinely supported by the actor's known tradecraft. Flag any
you are unsure of rather than padding the list.

MY ACTOR CARDS:
<<< paste actor frontmatter >>>

MY RECIPE NOTES:
<<< paste recipe frontmatter >>>
```

### 4c. Audit the vault for missing / empty required fields

```text
[PASTE THE SYSTEM PREAMBLE FROM §2 FIRST]

Below is the frontmatter of every note in my vault. Audit it. The engine SKIPS or
mis-handles notes missing required keys. Produce a table of problems:

  | file | note_type | problem | proposed fix |

Flag, at minimum:
  - surfaces missing or with empty `surface_id` (engine skips them entirely)
  - recipes missing or with empty `recipe_id` (engine skips them entirely)
  - recipes with a `phase` not in [entry, establish, escalate, pivot, impact]
  - any actor/recipe with empty `mitre_attck` (breaks MITRE-overlap attribution)
  - broken cross-links: IDs in linked_* / actor_uses / recipes_orchestrated /
    surface_targets that don't match any note's id
  - surfaces with empty `data_sensitivity` (weakens sensitivity scoring)

Propose a concrete fix per row. Do not rewrite files — just the fix list.

VAULT FRONTMATTER:
<<< paste all frontmatter blocks (with filenames) here >>>
```

---

## 5. Triage prompt (after an enumeration run)

Run the engine, then feed the catalog or JSON to the AI to accelerate operator
triage:

```bash
python3 engine/enumerate.py --vault my-vault --top 25 --json > /tmp/preds.json
```

```text
[PASTE THE SYSTEM PREAMBLE FROM §2 FIRST]

Below is the output of my predictive-intelligence enumeration run (ranked
candidate attack chains — each has an id, actor, composite score, overlap status
NEW/EXTENDS/DUPLICATE, priority, and emulation-readiness). I need to triage which
to promote to emulation plans.

Do this:
  1. List the top NEW candidates (ignore DUPLICATE; call out high-score EXTENDS
     separately).
  2. Group them BY ACTOR.
  3. For each candidate, draft a ONE-PARAGRAPH emulation rationale: why this chain
     is plausible for this actor, which surface/data it threatens, and what a
     purple-team emulation would validate. Keep it at the planning level — what to
     test and why, NOT how to execute the attack live.
  4. End with a 5-item recommended order of work with one-line justifications.

ENUMERATION OUTPUT:
<<< paste the markdown catalog or the --json payload here >>>
```

---

## 6. Guardrails

These prompts, and this kit, produce **planning and classification artifacts**
for **authorised** defensive work only. Keep the following firm:

- **No live tradecraft from the AI.** Do not ask the model to generate working
  exploit payloads, malware, C2 configurations, or step-by-step live-attack
  commands. If a model offers them, discard them — they are out of scope.
- **`achieves` and all prose stay at the capability-description level** — *what*
  an action accomplishes and *why it matters for defense*, never an executable
  *how*. ATT&CK-style classification, not an operator runbook.
- **The kit plans; it does not attack.** Enumerated chains are hypotheses for
  **emulation planning**. Humans and dedicated BAS tooling (CALDERA, Atomic Red
  Team, SCYTHE, etc.) execute them — only under explicit written authorization
  and scope.
- **Verify before you trust.** Every AI-asserted MITRE ID, attribution, and
  surface claim must be checked against the primary source before it drives a
  decision. Mark uncertainty in prose; never let a confident hallucination become
  a "fact" in your vault.
- **Organisation-neutral.** The bundled examples (APT-RAVEN, SURF-001, REC-0001,
  CAMP-2026-001) are fictional. Nothing here implies a real target.
