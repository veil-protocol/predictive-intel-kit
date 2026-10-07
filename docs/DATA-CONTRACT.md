---
title: Data Contract — Frontmatter Schema Reference
tags: [🔮, reference]
description: Authoritative frontmatter-field schema for the four note types (actors, surfaces, recipes, campaigns) that the predictive-intel-kit enumeration engine parses. Matches engine/enumerate.py exactly.
---

# Data Contract

This is the **authoritative schema** for the markdown notes that
`engine/enumerate.py` reads. The engine walks a vault, extracts **YAML
frontmatter** from four note types, and builds an in-memory graph. Everything
below is derived directly from the engine source (`load_vault()` and the
`Actor` / `Surface` / `Recipe` / `Campaign` dataclasses). If the engine and this
doc ever disagree, the engine wins — but they are kept in lockstep.

The prose body of a note is **ignored**. Only frontmatter is parsed.

## Universal rules

These apply to every note type:

- **Frontmatter is required.** A note with no `--- ... ---` frontmatter block
  parses to `{}` and is **skipped** (not an error).
- **File-name skips.** Within each folder, files whose name starts with
  `README` or `_TEMPLATE` are skipped (so templates and index files never load).
- **Recursive discovery.** Every folder is searched recursively (`rglob`), so
  subfolders are fine — most importantly for `recipes/` phase subfolders.
- **Unknown keys are ignored.** You may add any extra frontmatter you like
  (`tags`, `date_created`, custom metadata); the engine only reads the fields
  documented here.
- **Last-write-wins on duplicate IDs.** Registries are keyed by ID; two notes
  with the same ID means the later-sorted file silently overwrites the earlier.

### List parsing

Any field documented as a **list** is normalised through one helper, which
accepts all of the following and yields a clean list of trimmed strings:

```yaml
# 1. YAML block list
mitre_attck:
  - T1566
  - T1078

# 2. YAML inline list
mitre_attck: [T1566, T1078]

# 3. Comma-separated bare string in a single scalar
mitre_attck: T1566, T1078

# 4. Single bare string -> one-element list
mitre_attck: T1566
```

Empty, missing, or `null` → empty list. Blank items are dropped.

> **Parser note:** PyYAML is used when installed. If it is missing, a
> hand-rolled fallback parser handles the same subset (scalars, inline lists,
> block lists — no nesting). Install PyYAML (`pip install pyyaml`) for full
> fidelity.

### Folder configurability

The four folder names are **not hard-coded**. They come from the `vault:`
section of `config/scoring.yaml`, defaulting to:

```yaml
vault:
  actors_dir: actors
  surfaces_dir: surfaces
  recipes_dir: recipes        # searched recursively (phase subfolders OK)
  campaigns_dir: campaigns
```

Point these at whatever folder layout your vault uses.

### ID conventions

IDs are **free-form strings**; the engine does not validate format. The bundled
examples follow these conventions purely for readability:

| Type     | Convention      | Example        |
|----------|-----------------|----------------|
| Actor    | free-form       | `APT-RAVEN`    |
| Surface  | `SURF-NNN`      | `SURF-014`     |
| Recipe   | `REC-NNNN`      | `REC-0231`     |
| Campaign | `CAMP-YYYY-NNN` | `CAMP-2025-003`|

These are conventions, not constraints. Use whatever is stable and unique.

### Cross-reference integrity

The `linked_*`, `actor_uses`, `recipes_orchestrated`, and `surface_targets`
arrays reference other notes **by ID**. Keep them pointing at IDs that actually
exist. A dangling ID is **not fatal** — it simply doesn't resolve to a note and
is ignored during graph traversal. Broken links quietly reduce the chains the
engine can build; they never crash it.

---

## ACTOR

**Folder:** `actors/` (recursive) · **Dataclass:** `Actor`

Represents a threat actor. The engine attributes recipes to actors and
enumerates attack chains per actor.

| Field | Type | Required? | Default | What it does / accepted values |
|---|---|---|---|---|
| `actor_id` | string | no | **filename stem** | Canonical unique ID. If absent, the note's filename (without `.md`) is used. Keyed in the actor registry. |
| `aliases` | list | no | `[]` | Other names this actor is known by. Matched against recipe `actor_uses` and campaign `primary_actor`. |
| `relevance_tier` | string | no | `tier-3` | Normalised to one of `tier-1` / `tier-2` / `tier-3` / `tier-4` / `reference-only`. See normalisation below. Drives actor-probability + strategic scoring. |
| `priority` | string | no | `P3` | Free-form backlog priority label. Display-only. |
| `mitre_attck` | list | no | `[]` | ATT&CK technique IDs. **The key attribution field** — lets an actor "inherit" any recipe whose MITRE IDs overlap, discovering chains you never hand-linked. |
| `linked_recipes` | list | no | `[]` | `recipe_id`s the actor is operator-curated to use. |
| `linked_surfaces` | list | no | `[]` | `surface_id`s this actor is likely to target; intersected with recipe surfaces to pick chain targets. |
| `primary_tradecraft` | string | no | `""` | One-line signature. Display-only. |

**`relevance_tier` normalisation** (case-insensitive substring match):

- contains `tier-1`, `critical`, or `flagship` → `tier-1`
- contains `tier-2` → `tier-2`
- contains `tier-3` → `tier-3`
- contains `tier-4` → `tier-4`
- contains `reference` → `reference-only`
- anything else → `tier-3`

**Back-compat fallbacks** (prefer the canonical names):

- `relevance_tier` falls back to the legacy field `voya_relevance` if absent.
- `priority` falls back to the legacy field `quarterly_priority` if absent.
- `mitre_attck` falls back to the legacy spelling `mitre_attack` if the
  canonical key yields nothing.

> **Minimum viable actor:** `actor_id` (or filename) plus **at least one of
> `mitre_attck` or `linked_recipes`**. With no recipes attributable through
> either path, the actor generates **zero chains** and is effectively inert.

```yaml
---
actor_id: APT-RAVEN
aliases: [Raven Crew, TA-RAVEN]
relevance_tier: tier-1
priority: P1
mitre_attck: [T1566, T1078, T1021]
linked_recipes: [REC-0101, REC-0220]
linked_surfaces: [SURF-003, SURF-014]
primary_tradecraft: "Phishing-to-identity pivot against SSO tenants"
tags: [actor]
---
```

---

## SURFACE

**Folder:** `surfaces/` (recursive) · **Dataclass:** `Surface`

Represents an interface / asset / attack surface in your environment. Surfaces
supply the strategic and sensitivity weight for scoring, plus confirmation
state for emulation readiness.

| Field | Type | Required? | Default | What it does / accepted values |
|---|---|---|---|---|
| `surface_id` | string | **YES** | — | Canonical unique ID. **Note is skipped if absent or empty.** Keyed in the surface registry. |
| `interface_type` | string | no | `""` | e.g. `identity/SSO`, `web/CMS`, `source-code/git`, `api/graph`. Also fed into the sensitivity substring fallback. |
| `state` | string | no | `""` | e.g. `unconfirmed` / `osint-confirmed` / `validated`. The substrings **`confirmed`** or **`validated`** appearing here drive emulation readiness (a chain needs ≥1 confirmed/validated surface to be `READY`). |
| `owner_entity` | string | no | `""` | Owning team / vendor / business unit. Also fed into the sensitivity substring fallback. |
| `surface_layers` | list | no | `[]` | Technical layers exposed. Used as a **strategic proxy** when `pir` is empty. Legacy fallback: `tpf_layers`. |
| `pir` | list | no | `[]` | Standing Priority Intelligence Requirements this surface touches. Primary driver of `strategic_relevance` (5 PIRs = max weight). |
| `data_sensitivity` | list | no | `[]` | **Preferred** explicit sensitivity classes. Recognised values below. Overrides the substring fallback entirely when present. |
| `linked_recipes` | list | no | `[]` | `recipe_id`s applicable to this surface. |
| `linked_actors` | list | no | `[]` | `actor_id`s likely to target it. |

**`data_sensitivity` recognised classes:**

- **Sensitive / regulated (PII-class):** `pii`, `sensitive`, `personal`,
  `regulated`
- **High-value (crown-jewel / MNPI-class):** `crown_jewel`, `mnpi`,
  `high_value`, `material`

If `data_sensitivity` is set, it is authoritative. If it is **omitted**, the
engine falls back to substring-matching the `sensitive_data_indicators` /
`high_value_indicators` token lists from `scoring.yaml` against a blob of
`interface_type` + `surface_id` + `owner_entity` + filename. Declaring
`data_sensitivity` explicitly is strongly preferred — the fallback is noisy.

> **Minimum viable surface:** `surface_id` only. Without it the note is dropped.
> To contribute meaningfully to scoring, add `pir` (or `surface_layers`) and
> `data_sensitivity`, and set `state` to a confirmed/validated value so chains
> targeting it can reach `READY`.

```yaml
---
surface_id: SURF-014
interface_type: identity/SSO
state: osint-confirmed
owner_entity: "Platform Identity Team"
surface_layers: [auth, session, federation]
pir: [PIR-01, PIR-04]
data_sensitivity: [pii, crown_jewel]
linked_recipes: [REC-0101]
linked_actors: [APT-RAVEN]
tags: [surface]
---
```

---

## RECIPE

**Folder:** `recipes/` (recursive — phase subfolders like `recipes/entry/` are
expected and encouraged) · **Dataclass:** `Recipe`

Represents a single-step technique slotted into one kill-chain phase. Recipes
are the building blocks the engine chains together per actor.

| Field | Type | Required? | Default | What it does / accepted values |
|---|---|---|---|---|
| `recipe_id` | string | **YES** | — | Canonical unique ID. **Note is skipped if absent or empty.** Keyed in the recipe registry. |
| `recipe_name` | string | no | **filename stem** | Human label (stored internally as `name`). Falls back to the filename if absent. Display-only. |
| `phase` | string | no | `entry` | One of `entry` / `establish` / `escalate` / `pivot` / `impact`. See resolution below. |
| `mitre_attck` | list | no | `[]` | ATT&CK technique IDs. Drives **attribution** (actor inherits recipe on overlap) and **emulation readiness** (every recipe in a chain needs MITRE coverage for `READY`). Legacy fallback: `mitre_attack`. |
| `actor_uses` | list | no | `[]` | `actor_id`s / aliases known to use this recipe. A direct attribution path and a tie-break preference during chaining. |
| `linked_surfaces` | list | no | `[]` | `surface_id`s this recipe applies to. Unioned to form a chain's candidate target surfaces. |
| `opsec` | string | no | `medium` | Operational-cost tier → operational-simplicity score. Matched by substring of the **first `;`-delimited token** against the table below. |
| `achieves` | string | no | `""` | One line: what the operator gains. Display-only (truncated to 120 chars in output). |

**`phase` resolution** (in order):

1. If the frontmatter `phase` (lower-cased, trimmed) is one of the five valid
   phases, use it.
2. Otherwise, scan the file path for a `/<phase>/` segment (e.g. a file under
   `recipes/escalate/` is inferred as `escalate`).
3. Otherwise, default to the **first** phase in the configured order (`entry`).

**`opsec` accepted values** (substring-matched against the first token):
`burn-on-use` · `low` · `low-to-medium` · `medium` · `medium-to-high` · `high`.
Anything unmatched scores as `medium`.

> **Minimum viable recipe:** `recipe_id` + a resolvable `phase`, and ideally
> `mitre_attck`. Without MITRE IDs (and no actor linking it directly) a recipe
> is only reachable via `linked_recipes` / `actor_uses`, and it can never push a
> chain to `READY` emulation status.

```yaml
---
recipe_id: REC-0101
recipe_name: "SSO phishing with device-code abuse"
phase: entry
mitre_attck: [T1566.002, T1078.004]
actor_uses: [APT-RAVEN, "Raven Crew"]
linked_surfaces: [SURF-014]
opsec: low-to-medium
achieves: "Valid session token for a federated identity"
tags: [recipe]
---
```

---

## CAMPAIGN

**Folder:** `campaigns/` (recursive) · **Dataclass:** `Campaign`

Represents an already-authored multi-step chain. Campaigns are **not** chained
by the engine — they exist so newly enumerated candidates can be checked for
overlap and de-duplicated against work you have already done.

| Field | Type | Required? | Default | What it does / accepted values |
|---|---|---|---|---|
| `campaign_id` | string | no | **filename stem** | Canonical ID. Falls back to the filename if absent. |
| `primary_actor` | string | no | `""` | `actor_id` this campaign emulates. Used to match candidates to the right campaign for overlap. |
| `recipes_orchestrated` | list | no | `[]` | `recipe_id`s the campaign chains together. Compared by **Jaccard similarity** against each candidate's recipe set: ≥0.8 → candidate filtered as `DUPLICATE`; 0.4–0.8 → flagged `EXTENDS`; <0.4 → `NEW`. |
| `surface_targets` | list | no | `[]` | `surface_id`s it targets. Display / reference. |

> **Minimum viable campaign:** `campaign_id` (or filename) plus
> `recipes_orchestrated`. An empty `recipes_orchestrated` list contributes
> nothing to overlap detection — the campaign will never dedupe any candidate.

```yaml
---
campaign_id: CAMP-2025-003
primary_actor: APT-RAVEN
recipes_orchestrated: [REC-0101, REC-0220]
surface_targets: [SURF-014, SURF-003]
tags: [campaign]
---
```

---

## Quick reference

| Note type | Folder (default) | ID field | ID required? | ID fallback |
|---|---|---|---|---|
| Actor | `actors/` | `actor_id` | no | filename stem |
| Surface | `surfaces/` | `surface_id` | **yes** | — (skipped) |
| Recipe | `recipes/` | `recipe_id` | **yes** | — (skipped) |
| Campaign | `campaigns/` | `campaign_id` | no | filename stem |

All folders are recursive, skip `README*` / `_TEMPLATE*` files, and require a
frontmatter block. See `config/scoring.yaml` to retarget folder names and tune
scoring, and `docs/METHOD.md` for how chains are enumerated and scored.
