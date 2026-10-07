---
title: "Predictive Intelligence Kit — Method"
tags: [🔮, method]
description: "How the enumeration engine cross-links actors, recipes, and surfaces to surface un-authored candidate attack chains, scores them, and ranks a triage catalog for a purple team to emulate."
---

# 🔮 Predictive Intelligence Kit — Method

## 1. Overview / BLUF

The Predictive Intelligence Kit performs **combinatorial state-space enumeration** over a markdown vault of threat-intel notes. It cross-links every **actor × recipe × surface** relationship implied by the vault and composes the plausible multi-step attack chains that follow from those links — including chains **no human ever hand-authored**. Each candidate chain is scored against a tunable 5-component rubric (weighted sum, 0–100), checked for overlap against campaigns you already wrote, filtered for diversity, and emitted as a ranked catalog. The point is to invert the operator's workload: instead of imagining attack paths from scratch, the operator does **triage over a ranked catalog** of machine-generated candidates — promoting the good ones to real campaigns or emulation drafts, and deferring the rest.

This is a **planning aid** in the spirit of MITRE CALDERA / Atomic Red Team adversary-emulation planning. It enumerates and ranks; it does **not** execute anything. All org-specific weighting lives in `config/scoring.yaml` or in your note frontmatter — the engine ships organisation-neutral.

> **Pipeline at a glance:** `load vault → attribute recipes to actors → compose chains → intersect surfaces → deduplicate → score → overlap-classify → diversity-filter → rank → emit`.

---

## 2. The four inputs

The engine parses YAML frontmatter from four note types. Field-level schemas live in [[DATA-CONTRACT|docs/DATA-CONTRACT.md]]; this is the short version.

| Note type | Folder (default) | Role in the method |
|---|---|---|
| **Actors** | `actors/` | Threat-actor cards: tier, aliases, MITRE TTP inventory, and any hand-wired links to recipes/surfaces. |
| **Surfaces** | `surfaces/` | Attack-surface / asset notes: interface type, confidence `state`, standing intel priorities (`pir`), explicit `data_sensitivity`. |
| **Recipes** | `recipes/` (recursive) | Single-step technique notes tagged with a kill-chain `phase`, MITRE IDs, `actor_uses`, `opsec`, and linked surfaces. |
| **Campaigns** | `campaigns/` | Already-authored multi-step campaigns. Used **only** for overlap dedup so the engine doesn't re-propose work you've done. |

A note with no parseable frontmatter is skipped, not fatal. Files named `README*` / `_TEMPLATE*` are ignored.

---

## 3. Step 1 — Recipe attribution

For each actor, the engine builds the actor's **plausible-recipe set** as the **UNION of three sources** (`candidate_recipes_for_actor`):

| Branch | Rule | What it captures |
|---|---|---|
| **(a)** | Recipe ID appears in the actor card's `linked_recipes` | Recipes you explicitly hand-wired to this actor. |
| **(b)** | Recipe's `actor_uses` names the actor **or any of its aliases** | Recipes that self-declare which actors run them. |
| **(c)** | Recipe's `mitre_attck` shares **≥1 technique** with the actor's `mitre_attck` | Recipes that merely *share tradecraft* with the actor. |

**Branch (c) is the engine's core value.** Branches (a) and (b) only re-surface links a human already authored. Branch (c) attributes a recipe to an actor purely because their MITRE technique inventories overlap — so it surfaces **non-obvious chains the operator never hand-wired**. If APT-RAVEN and a given recipe both reference `T1566`, the recipe becomes a candidate for RAVEN even if nobody ever linked them. This is how the kit proposes attack paths you haven't thought of yet.

The resulting recipe set is sorted deterministically by `recipe_id`.

---

## 4. Step 2 — Chain composition

Recipes are grouped by **phase**, over the ordered kill-chain DAG:

```
entry → establish → escalate → pivot → impact
```

Composition rules (`enumerate_chains`):

- **A chain MUST start with an entry-phase recipe.** Actors with no plausible entry recipe produce no chains.
- **One recipe per phase.** For each entry recipe, the engine extends it by taking the **single highest-affinity recipe** available in each later phase.
- **Affinity sort (deterministic):** within each phase, recipes where the actor (or an alias) appears in `actor_uses` sort **ahead of** MITRE-only (branch-c) matches; ties break by `recipe_id`. The engine then picks index `[0]`. Same vault + same config → byte-identical output.
- **Entry-only variant:** whenever a multi-phase chain is built, the engine *also* emits the entry recipe on its own. This lets a single-step high-impact actor survive into the catalog instead of being swallowed by its own longer chain.

> **Out of scope by design:** one recipe per phase means **no multi-branch / fan-out chains** (e.g. two parallel escalate paths). If a realistic attack needs branching, author it yourself as a scenario or campaign — the engine is a candidate generator, not a scenario compiler.

---

## 5. Step 3 — Surface intersection

Each chain is targeted at concrete surfaces:

```
target_surfaces = actor.linked_surfaces  ∩  (∪ linked_surfaces of the chain's recipes)
```

- If that **intersection is non-empty**, those surfaces are the targets (sorted).
- If the intersection is **empty**, the engine **falls back to the union** of the chain's recipe surfaces.
- If the actor has no `linked_surfaces` at all, the union is used directly.

The entry-only variant computes the same intersection using just the entry recipe's surfaces.

---

## 6. Step 4 — Deduplication

Enumeration can produce identical chains from different paths. The engine collapses any chains that match on the tuple:

```
(actor_id, sorted recipe-set, surface-set)
```

The first occurrence is kept; later identical chains are dropped (`deduplicate_chains`). The count after this step is the **total chains enumerated** reported in the catalog header.

---

## 7. Step 5 — Scoring

Each surviving chain is scored on **five components, each normalized to 0–1**, then multiplied by a weight. **Weights sum to 100**, so the composite is **0–100** (`score_chain`). If a custom config's weights don't sum to 100, the engine warns on stderr and the composite will fall outside 0–100.

Let `actor_tier_factor` = the tier → probability value (tier-1 `1.00`, tier-2 `0.70`, tier-3 `0.40`, tier-4 `0.10`, reference-only `0.05`; default `0.40` if the tier is unrecognised).

| # | Component | Weight | Definition (as implemented) |
|---|---|---|---|
| 1 | **strategic_relevance** | 30 | `avg(surface.priority_weight) × actor_tier_factor`. |
| 2 | **actor_probability** | 20 | `= actor_tier_factor`. |
| 3 | **detection_gap** | 20 | `min(1.0, phase_count / number_of_phases)`. |
| 4 | **sensitivity_exposure** | 20 | regulated + crown-jewel exposure, with a data-theft bump (below). |
| 5 | **operational_simplicity** | 10 | `clamp01((3.0 − avg_opsec_numeric) / 2.5)`. |

### Component detail

**1 · strategic_relevance (30)** — average surface `priority_weight` across the chain's target surfaces, scaled by the actor's tier factor. A surface's `priority_weight` is:

```
priority_weight = min(1.0, len(pir) * 0.2)                     # 5 PIRs → 1.0
               → fallback min(1.0, len(surface_layers) * 0.15) # only if pir is empty
```

So a surface touching more standing intel priorities (PIRs) weighs more. With no target surfaces, this component is 0.

**2 · actor_probability (20)** — simply the actor tier factor. A tier-1 actor contributes the full 20 points here; a reference-only actor contributes 1.

**3 · detection_gap (20)** — `min(1.0, phase_count / len(phases))`. The **rationale**: more phases means more handoff seams between kill-chain stages, and those seams are where detection coverage is typically thinnest. A 4-phase chain over a 5-phase model → `4/5 = 0.80`. (See Limitations — this is a crude proxy.)

**4 · sensitivity_exposure (20)** — counts how many target surfaces touch regulated/personal data (`sensitive`) vs crown-jewel/MNPI data (`high_value`):

```
exposure = (sensitive_count + 1.5 × high_value_count) / (num_surfaces × 2.5)
if actor ∈ high_impact_actors:  exposure = min(1.0, exposure × 1.3 + 0.1)
exposure = min(1.0, exposure)
```

A surface counts as sensitive / high-value **either** from its explicit `data_sensitivity` frontmatter list (preferred: classes like `pii`, `crown_jewel`, `mnpi`, `material`) **or**, as a fallback when that field is absent, by substring-matching the configured `sensitive_data_indicators` / `high_value_indicators` against the surface's interface type, id, owner, and filename.

**5 · operational_simplicity (10)** — `clamp01((3.0 − avg_opsec_numeric) / 2.5)`. Each recipe's `opsec` tier maps to a number (`burn-on-use 0.5, low 1, low-to-medium 1.5, medium 2, medium-to-high 2.5, high 3`); the chain averages them. **Lower opsec = louder / easier to run = higher real-world attacker uptake**, so a louder chain scores *higher* simplicity. An all-`medium` chain → `(3.0 − 2.0)/2.5 = 0.40`.

### Composite formula

```
composite = Σ ( component_raw[k] × weight[k] )   for k in the 5 components
```

### Worked example — catalog top candidate (APT-RAVEN full chain, 59.0)

From the example vault's `sample-run-output.md`, rank 1 is the APT-RAVEN 4-phase chain
(`entry → establish → escalate → impact`) targeting `SURF-001` (SSO portal) and
`SURF-002` (code repo). Tracing the numbers:

| Component | Raw (0–1) | Why | × Weight | Contribution |
|---|---|---|---|---|
| strategic_relevance | 0.30 | `avg priority_weight (0.30) × tier-1 factor (1.00)` | 30 | **9.0** |
| actor_probability | 1.00 | tier-1 → 1.00 | 20 | **20.0** |
| detection_gap | 0.80 | 4 phases / 5-phase model = 0.80 | 20 | **16.0** |
| sensitivity_exposure | 0.50 | both surfaces touch regulated + crown-jewel data | 20 | **10.0** |
| operational_simplicity | 0.40 | chain averages to `medium` opsec → 0.40 | 10 | **4.0** |
| **Composite** | — | `9.0 + 20.0 + 16.0 + 10.0 + 4.0` | **100** | **59.0** |

So the composite is **59.0 / 100**, which lands in the **P2** bucket.

---

## 8. Priority buckets

The composite maps to a next-cycle priority label (highest threshold first):

| Composite | Label | Meaning |
|---|---|---|
| ≥ 85 | **P1-FLAGSHIP** | Front-of-queue emulation candidate. |
| ≥ 70 | **P1** | High priority this cycle. |
| ≥ 55 | **P2** | Standard priority. |
| ≥ 40 | **P3** | Research / doc-only this cycle. |
| else | **DEFER** | Below the bar. |

(The 59.0 RAVEN chain → **P2**; thresholds are config, see Tuning.)

---

## 9. Step 6 — Overlap with existing campaigns

Each candidate's recipe-set is compared against every authored campaign's `recipes_orchestrated` via **Jaccard similarity** (`overlap_with_existing`):

```
jaccard = |chain_recipes ∩ campaign_recipes| / |chain_recipes ∪ campaign_recipes|
```

A campaign is only considered if it's **relevant** — its `primary_actor` matches the candidate's actor/aliases **OR** its recipe set intersects the candidate's. The best relevant match classifies the candidate:

| Jaccard | Status | Default handling |
|---|---|---|
| ≥ 0.8 | **DUPLICATE:`<id>`** | **Filtered out** by default; `--include-overlaps` keeps them. |
| 0.4 – 0.8 | **EXTENDS:`<id>`** | Kept, flagged with the campaign ID it extends. |
| < 0.4 | **NEW** | Kept, genuinely novel. |

**Why this exists:** the operator's attention is the scarce resource. DUPLICATE candidates are just re-proposals of campaigns you already authored — noise. EXTENDS candidates are near-misses worth a glance (a variant of existing work). NEW candidates are the real prize: chains the vault implies but that no one has written up. The overlap classifier steers triage toward novelty.

---

## 10. Step 7 — Diversity filter

Before emitting top-N, the engine enforces diversity so a single prolific actor or a flood of EXTENDS items can't dominate (`_apply_diversity`). Two controls:

- **`max_per_actor`** (default **3**): cap on candidates per actor in the top-N.
- **`quota`** (default **0.6**): at least **60%** of the emitted top-N must be **NEW** chains.

The selection is a **three-pass** algorithm over the score-sorted candidate list:

1. **Fill NEW slots** — walk candidates in score order, taking NEW ones until `target_new = floor(top_n × quota)` is reached, respecting the per-actor cap.
2. **Fill EXTENDS slots** — walk again, taking non-NEW (EXTENDS) candidates until `target_ext = top_n − target_new` is reached, respecting the cap.
3. **Top-up** — walk a final time taking anything not yet chosen (still respecting the cap) until top-N is full.

The chosen set is then re-sorted by `(−composite_score, actor_id)` for presentation.

---

## 11. Emulation readiness

Each emitted candidate gets a readiness label indicating how close it is to a runnable emulation (BAS) campaign (`emulation_readiness`):

| Label | Condition |
|---|---|
| **READY** | ≥ 2 phases **AND** every recipe has MITRE coverage **AND** ≥ 1 target surface in a `confirmed` / `validated` state. |
| **NEEDS-RECIPE** | Single-phase chain, **or** some recipe is missing `mitre_attck`. |
| **NEEDS-VALIDATION** | Full multi-phase chain with MITRE coverage, but **no** target surface is `confirmed` / `validated`. |

This tells the operator at a glance whether a candidate can go straight to emulation, needs better recipes, or needs surface validation first.

---

## 12. Tuning

**Everything org-specific is config, not code.** Edit `config/scoring.yaml`, re-run, get a re-ranked catalog — no code change. Tunable sections:

- `weights` — the 5-component weights (must sum to 100).
- `tier_probability` — tier → probability multiplier.
- `priority_buckets` — composite → label thresholds.
- `phases` — the kill-chain DAG (first phase is the required entry).
- `opsec_numeric` — opsec tier → number.
- `sensitive_data_indicators` / `high_value_indicators` — fallback substring lists.
- `high_impact_actors` — actors that get the sensitivity bump.
- `diversity` — `quota` and `max_per_actor`.

A config file is **merged OVER the baked-in defaults at the top level** (supply a whole section to override one — sections are replaced, not deep-merged). With no config, sensible defaults run against the bundled example vault.

### CLI flags

| Flag | Purpose |
|---|---|
| `--vault PATH` | Vault root (default: bundled `vault-template`). |
| `--config PATH` | Scoring/config YAML (default: baked-in defaults). |
| `--output PATH` | Output markdown file (default: stdout). |
| `--top N` | Emit top-N candidates (default 25). |
| `--min-score F` | Floor composite for emission (default 0). |
| `--include-overlaps` | Keep DUPLICATE chains instead of filtering them. |
| `--diversity-quota F` | Min fraction of top-N that must be NEW (default: config). |
| `--max-per-actor N` | Cap candidates per actor in top-N (default: config). |
| `--json` | Emit JSON instead of markdown. |
| `--run-date YYYY-MM-DD` | Override run-date (deterministic testing / stable IDs). |

---

## 13. Re-run cadence

- **Quarterly at minimum** — baseline refresh aligned to the intel cycle.
- **Within ~1 week of authoring any new actor, surface, or recipe** — a single new note can unlock a whole family of new chains via branch-(c) MITRE overlap. Re-running promptly is how you capture that.
- **Keep dated catalogs.** Output IDs are `PRED-<run_date>-NNN`; keep each run's file so you can **diff deltas over time** — what became NEW, what graduated to a campaign, what dropped out.

---

## 14. Honest limitations

- **`detection_gap` is a crude phase-count proxy.** "More phases = thinner detection" is a heuristic, not a measurement. Ideally replace it with real detection-coverage density (per-technique detection confidence from your SIEM/EDR mappings).
- **Scores are only as good as your frontmatter.** `pir` and `data_sensitivity` drive two of the five components. Vaults that leave those sparse will produce uniformly weak scores and the ranking loses discriminating power — populate them.
- **One recipe per phase.** No multi-branch / fan-out chains. Realistic branching attacks must be authored by hand as scenarios/campaigns.
- **Opsec matching is substring-on-first-token.** The `opsec` value is lowercased and split on `;`, then the first token is substring-matched against the opsec table; unusual opsec strings silently fall back to `medium` (2.0).
- **Overlap uses recipe-set Jaccard only.** Two chains with the same recipes but different surfaces/ordering look identical to the overlap classifier; surface targeting is not part of the similarity.

---

> **See also:** [[DATA-CONTRACT|docs/DATA-CONTRACT.md]] for frontmatter field schemas · `config/scoring.yaml` for the live rubric · `examples/sample-run-output.md` for a full worked catalog.
