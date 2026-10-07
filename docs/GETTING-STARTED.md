---
title: Getting Started
tags: [🔮, guide]
description: Walk a bare Obsidian vault to a first predictive-enumeration run — and learn to read the ranked catalog it produces.
---

# 🔮 Getting Started

This guide takes you from **nothing but a markdown vault and an AI assistant** to your
first ranked catalog of predicted attack chains. It is a defensive purple-team
planning aid — in the spirit of MITRE CALDERA and Atomic Red Team — that helps you
decide which adversary behaviours to emulate next. It plans; it never executes anything.

By the end you will have run the engine against the bundled example, stood up your own
vault, authored your first notes, tuned scoring to your environment, and read a real
catalog well enough to act on it.

---

## 1. Prerequisites

- **Python 3.9+** — check it:
  ```bash
  python3 --version
  ```
- **PyYAML (optional)** — better YAML fidelity, but the engine ships a bundled
  fallback parser that produces identical output, so this is purely optional:
  ```bash
  pip install -r requirements.txt
  ```
  Without it you will see a one-line `[!] PyYAML not installed` notice on every run.
  It is harmless.
- **Obsidian (optional but recommended)** — the vault notes and the catalog output are
  plain markdown with wikilinks, so *any* editor works. Obsidian just makes the
  `[[wikilinks]]` clickable and the folders easy to browse.
- **An AI assistant (optional)** — Claude, ChatGPT, or a local model. Not required, but
  it turns note-authoring from a chore into a few paste-and-review minutes. See
  [`AI-PROMPTS.md`](AI-PROMPTS.md).

---

## 2. Mental model in 60 seconds

Four note types, one engine, one ranked catalog:

- **Actors** (`actors/`) — *who* might target you: their TTPs and how relevant they are.
- **Surfaces** (`surfaces/`) — *what* they can hit: an asset and its data sensitivity.
- **Recipes** (`recipes/`) — *one* single-step technique, tagged with a kill-chain
  `phase` and MITRE ATT&CK IDs.
- **Campaigns** (`campaigns/`) — a multi-step chain you have **already** authored,
  used only to dedup the engine's proposals.

The engine cross-links actors × recipes × surfaces, enumerates every plausible
`entry → … → impact` chain (including ones no human wired up), scores each 0–100, and
emits a ranked catalog of candidate campaigns. Full method: [`METHOD.md`](METHOD.md).

---

## 3. Install (2 min)

Clone or download the kit, then run it against the bundled fictional example vault to
confirm everything works:

```bash
git clone <repo-url> predictive-intel-kit
cd predictive-intel-kit
python3 engine/enumerate.py --vault vault-template --top 10
```

You should see progress lines on **stderr** like these:

```
[*] Loading vault: vault-template
[*] Loaded: 2 actors, 2 surfaces, 5 recipes, 1 campaigns
[*] 4 unique chains enumerated
[*] Emitting top 4 of 4 (filtered 0 overlaps)
```

…followed by a ranked markdown table printed to **stdout**, starting with:

```
## 🏆 Ranked Candidate Catalog

| Rank | ID | Actor | Score | Overlap | Priority | Emulation |
```

If you see that table, the engine runs. To see the full rendered catalog — detail
cards, chains, surfaces, and per-component score breakdowns — open
[`examples/sample-run-output.md`](../examples/sample-run-output.md).

---

## 4. Stand up YOUR vault (the scaffold copy)

Copy the `vault-template/` scaffold into (or next to) your Obsidian vault:

```bash
cp -r vault-template /path/to/your-obsidian-vault/predictive-intel
```

Keep the four folders — `actors/`, `surfaces/`, `recipes/`, `campaigns/`. Inside each
you will find two kinds of starter file:

- `_TEMPLATE.md` — **KEEP these.** They are your frontmatter cheat-sheet and the engine
  always skips any file whose name starts with `_TEMPLATE` or `README`.
- `EXAMPLE-*.md` — fictional sample notes. **Delete these when you are ready** to run on
  your own content, so the example data stops polluting your catalog.

**Already have folders with different names?** You do not have to rename anything. Point
the engine at your layout via `config/scoring.yaml`:

```yaml
vault:
  actors_dir: 03-actors
  surfaces_dir: 01-surfaces
  recipes_dir: 02-techniques   # searched recursively — phase subfolders are fine
  campaigns_dir: 04-campaigns
```

---

## 5. Author your first notes

Order matters. Build from the ground up so later notes have something to link to. For
every field list see [`DATA-CONTRACT.md`](DATA-CONTRACT.md); to have an AI draft these
from real sources, see [`AI-PROMPTS.md`](AI-PROMPTS.md).

### (a) 3–5 surfaces first — these ground everything

Surfaces are your real assets. Scoring leans on them (strategic relevance + sensitivity
exposure), so author them first.

```yaml
---
surface_id: SURF-001
interface_type: identity/SSO
state: confirmed              # "confirmed"/"validated" help emulation-readiness
owner_entity: IT
pir: [identity-compromise, initial-access]   # standing intel priorities this touches
data_sensitivity: [pii]       # PREFERRED over keyword guessing; see scoring.yaml
linked_recipes: []
linked_actors: []
---
```

### (b) 5–10 recipes — one technique each, with phase + MITRE

Each recipe is a single step. Two fields do the heavy lifting: **`phase`** places it in
the kill chain, and **`mitre_attck`** is what makes chains auto-assemble — an actor whose
TTPs overlap a recipe's IDs picks it up even if you never hand-linked them.

```yaml
---
recipe_id: REC-0001
recipe_name: SSO credential phishing
phase: entry                  # entry | establish | escalate | pivot | impact
mitre_attck: [T1566, T1078]   # <-- the auto-assembly key
opsec: medium                 # burn-on-use | low | low-to-medium | medium | medium-to-high | high
achieves: Valid SSO credentials / session for initial access
linked_surfaces: [SURF-001]
actor_uses: []                # optional explicit attribution
---
```

Author at least one **entry-phase** recipe — chains cannot start without one.

### (c) 2–3 actor cards — with tier, MITRE, and obvious links

```yaml
---
actor_id: APT-RAVEN
aliases: [Raven]
relevance_tier: tier-1        # tier-1..tier-4 | reference-only (drives probability)
priority: P1
mitre_attck: [T1566, T1078, T1098]   # overlap with recipe IDs = auto-attribution
linked_recipes: []            # optional explicit attribution
linked_surfaces: [SURF-001]
primary_tradecraft: Identity-first intrusion
---
```

### (d) Campaigns — only for chains you have ALREADY authored

Campaigns exist so the engine can flag its proposals as `DUPLICATE` or `EXTENDS`.
Only write one once you have actually hand-authored that chain.

```yaml
---
campaign_id: CAMP-2026-001
primary_actor: APT-RAVEN
recipes_orchestrated: [REC-0001, REC-0002]
surface_targets: [SURF-001]
---
```

---

## 6. Tune scoring to your org

Copy the example config and edit it — the engine merges it *over* the baked-in defaults:

```bash
cp config/scoring.example.yaml config/scoring.yaml
```

The few things most worth editing first:

- **Actor tiers** (`tier_probability`) — the multiplier each `relevance_tier` gets.
  tier-1 = names you expect to see; reference-only = tracked but not expected.
- **Sensitivity** — best to set `data_sensitivity:` *per surface* (step 5a). The
  `sensitive_data_indicators` / `high_value_indicators` keyword lists are only the
  fallback used when a surface omits that field — replace the examples with tokens that
  mean something in your environment.
- **`high_impact_actors`** — public names of data-theft / extortion actors that earn a
  sensitivity-score bump. The shipped list is a starter; edit to your threat model.

> **Weights must sum to 100.** If they don't, the engine prints a warning and scores
> stop being 0–100.

---

## 7. First real run

Point the engine at your vault and your config, and write a dated catalog into the vault:

```bash
python3 engine/enumerate.py \
    --vault /path/to/your-obsidian-vault/predictive-intel \
    --config config/scoring.yaml \
    --output /path/to/your-obsidian-vault/predictions/$(date +%F)-enumeration.md \
    --top 25
```

Useful flags:

- `--json` — emit JSON instead of markdown, for downstream tooling.
- `--include-overlaps` — keep chains that duplicate an existing campaign (normally filtered).
- `--min-score 40` — floor the emission so low-scoring noise is dropped.

Open the output `.md` in Obsidian: a ranked table up top, then a detail card per
candidate with the chain, target surfaces, and score breakdown — every actor/recipe/
surface is a working wikilink.

---

## 8. Read the catalog

Triage the catalog top-down; you are applying judgement to a ranked short-list, not
reading every row.

1. **Scan the ranked table.** Columns: `Score`, `Overlap`, `Priority`, `Emulation`.
2. **Focus on high-score `NEW` candidates first.** These are the un-authored chains the
   engine found for you — the whole point of the tool. A high-scoring `NEW` row is a
   plausible campaign nobody on your team sat down and wrote.
3. **`EXTENDS:<id>`** means the chain overlaps an existing campaign — decide whether it is
   worth *growing that campaign* to cover the new steps.
4. **Use the priority bucket + emulation-readiness columns to pick what to action.**
   `P1-FLAGSHIP`/`P1` with `READY` = front of the queue; `NEEDS-RECIPE` /
   `NEEDS-VALIDATION` tells you what is missing before you can emulate it.
5. **Promote a candidate** by authoring it as a campaign note (step 5d). On the next run
   the engine dedups it out — so your catalog always surfaces what is still *new*.

Keep dated catalogs (the `$(date +%F)` in step 7) so you can diff runs and watch the
long tail shrink as you work it.

---

## 9. Keep it fresh

- **Re-run quarterly**, and again within about a week of adding any new note — new
  actors, recipes, or surfaces open up chains that did not exist before.
- **Commit the vault to git.** Runs are idempotent (same vault + config ⇒ byte-identical
  output), so committed catalogs diff cleanly and show you exactly what changed cycle to
  cycle.

---

## 10. Troubleshooting

**"0 chains enumerated" / empty catalog.** A chain needs an actor with plausible recipes
and an entry point. Check that:
- actors have `mitre_attck` IDs **or** explicit `linked_recipes`,
- recipes have a `phase`,
- at least one `entry`-phase recipe is attributable to an actor (via MITRE overlap,
  `actor_uses`, or `linked_recipes`).

**Everything scores low.** Populate the signals scoring depends on: set `pir` and
`data_sensitivity` on surfaces, and give actors real `relevance_tier` values (an
untiered actor defaults to tier-3 = 0.40).

**A note is ignored.** It has missing or invalid YAML frontmatter, or its filename starts
with `README` or `_TEMPLATE` (both are skipped by design). Surfaces/recipes are also
skipped if they lack a `surface_id` / `recipe_id`.

**`[!] PyYAML not installed` warning.** Harmless — the bundled fallback parser produces
identical output. Install PyYAML (step 1) only if you want to silence it.
