# 🔮 Predictive Intelligence Kit

**Turn a plain-markdown knowledge base into a ranked catalog of the attack chains you haven't thought of yet.**

If you keep threat-intel notes in Obsidian (or any folder of markdown-with-frontmatter), this kit reads them, cross-links your **actors × techniques × attack-surfaces** into every *plausible* multi-step chain, scores each against priorities you define, and tells you which campaigns to emulate next — including the non-obvious chains you never hand-wired.

It is a ~700-line single-file Python engine with **no required dependencies** and **zero built-in content**. Everything organisation-specific lives in your notes and one config file. Point it at the bundled example vault and it runs in one command.

```bash
python3 engine/enumerate.py --vault vault-template --top 10
```

---

## The idea in one picture

```
   actor cards            recipe notes             surface notes
 (who targets you)   (one technique each)     (what they can hit)
        │                    │                        │
        └─────────┬──────────┴───────────┬────────────┘
                  ▼                       ▼
        attribute recipes to      intersect target
        actors 3 ways:            surfaces
        (a) hand-linked
        (b) actor_uses            ┌──────────────────────────┐
        (c) MITRE overlap  ──────▶│  enumerate phase chains   │
            (finds the                │  entry→…→impact       │
             non-obvious)             └───────────┬───────────┘
                                                  ▼
                           score (5 components) · dedup vs your
                           existing campaigns · diversity filter
                                                  ▼
                              ranked candidate catalog (.md)
                              NEW / EXTENDS / DUPLICATE · P1…DEFER
```

The payoff is branch **(c)**: a recipe whose MITRE-ATT&CK IDs overlap an actor's known TTPs gets attributed to that actor *even if you never linked them* — so the engine proposes chains that are plausible but that no human sat down and authored. Manual authoring finds the obvious chains; this finds the long tail.

---

## Why it exists

Once a threat-intel vault reaches a few dozen actors × techniques × surfaces, the number of *possible* attack chains explodes into the millions. Humans author the handful that are obvious. The valuable chains — the ones that get you ahead of real adversary behaviour — live in the combinatorial long tail no one has time to walk by hand. This engine walks it mechanically, every time, and hands you a ranked short-list to apply judgement to. Your job shifts from *blank-page authoring* to *triage over a ranked catalog*.

---

## Quickstart

```bash
# 1. (optional) better YAML fidelity — the engine works without it too
pip install -r requirements.txt

# 2. run against the bundled fictional example vault
python3 engine/enumerate.py --vault vault-template --top 10

# 3. point it at your own vault + your own priorities
cp config/scoring.example.yaml config/scoring.yaml   # then edit
python3 engine/enumerate.py \
    --vault /path/to/your-vault \
    --config config/scoring.yaml \
    --output /path/to/your-vault/predictions/$(date +%F)-enumeration.md \
    --top 25
```

Open the output `.md` in Obsidian: a ranked table up top, a detail card per candidate (chain + target surfaces + score breakdown) below. Every actor/recipe/surface is a working wikilink.

See [`examples/sample-run-output.md`](examples/sample-run-output.md) for exactly what a run produces against the example vault.

---

## What you need: a vault that follows the data contract

Four note types, each a markdown file with YAML frontmatter. The engine reads **only the frontmatter**; prose is for humans.

| Folder | Note type | What it is |
|---|---|---|
| `actors/` | **Actor card** | A threat actor — who might target you, their TTPs, relevance tier |
| `surfaces/` | **Surface** | An attack surface / asset — what they can hit, its data sensitivity |
| `recipes/` | **Recipe** | One single-step technique, tagged with its kill-chain phase + MITRE IDs |
| `campaigns/` | **Campaign** | A multi-step chain you've *already* authored (used to dedup candidates) |

Folder names are configurable. The [`vault-template/`](vault-template/) folder is a ready-to-copy scaffold with a `_TEMPLATE.md` and a runnable fictional example for each type. Full field-by-field spec: [`docs/DATA-CONTRACT.md`](docs/DATA-CONTRACT.md).

**Starting from nothing?** You don't have to hand-write these notes. [`docs/AI-PROMPTS.md`](docs/AI-PROMPTS.md) has copy-paste prompts that turn an AI assistant into a note-authoring factory, and [`docs/GETTING-STARTED.md`](docs/GETTING-STARTED.md) walks a bare Obsidian vault to a first enumeration run.

---

## How scoring works (tunable, no code changes)

Each chain gets a composite **0–100** from five weighted components — all editable in `config/scoring.yaml`:

| Component | Default weight | Measures |
|---|---:|---|
| `strategic_relevance` | 30 | surface priority-coverage × actor relevance tier |
| `actor_probability` | 20 | tier-based likelihood the actor targets you |
| `detection_gap` | 20 | phase-span proxy for thin detection seams |
| `sensitivity_exposure` | 20 | regulated / crown-jewel data in the blast radius |
| `operational_simplicity` | 10 | easier-to-run chains = higher attacker uptake |

Composite maps to a priority bucket (`P1-FLAGSHIP` ≥85 … `DEFER` <40), and each candidate is tagged **NEW**, **EXTENDS** an existing campaign, or **DUPLICATE** (filtered). Edit a weight, re-run, get a re-ranked catalog. The full method — enumeration, scoring, overlap dedup, diversity quota — is documented in [`docs/METHOD.md`](docs/METHOD.md).

---

## Repository layout

```
predictive-intel-kit/
├── engine/enumerate.py          # the whole engine — stdlib-only, config-driven
├── config/scoring.example.yaml  # copy to scoring.yaml and tune to your org
├── vault-template/              # drop-in scaffold: templates + runnable example
│   ├── actors/  surfaces/  recipes/  campaigns/
├── docs/
│   ├── METHOD.md                # the methodology in full
│   ├── DATA-CONTRACT.md         # frontmatter schema for every note type
│   ├── GETTING-STARTED.md       # bare vault + AI → first run
│   └── AI-PROMPTS.md            # prompts to seed notes with an AI assistant
├── examples/sample-run-output.md
├── requirements.txt  ·  LICENSE (MIT)
```

---

## Design guarantees

- **Stdlib-only** — PyYAML is optional; a bundled fallback parser produces identical output.
- **Idempotent** — same vault + same config ⇒ byte-identical output (all sorts deterministic). Safe to commit catalogs and diff them over time.
- **Defensive** — missing fields default sensibly; a note without frontmatter is skipped, never fatal.
- **Fast** — a few hundred milliseconds across dozens of actors/recipes/surfaces.
- **No content** — ships with fictional example data only. Nothing about any real organisation is baked in.

---

## Intended use

This is a **defensive** CTI / purple-team planning aid, in the spirit of MITRE CALDERA and Atomic Red Team: it helps a security team decide which adversary behaviours to emulate and validate detections against. It plans; it does not execute anything. Use it for authorised threat-informed defence.

## License

MIT — see [`LICENSE`](LICENSE).
