#!/usr/bin/env python3
"""
Predictive Intelligence Enumeration Engine
===========================================

Walks an Obsidian (or any plain-markdown) vault, parses YAML frontmatter from four
note types -- **actors**, **surfaces**, **recipes**, **campaigns** -- builds an
in-memory graph, and combinatorially enumerates *plausible* multi-step attack
chains that you have NOT yet manually authored as standalone campaigns.

Each enumerated chain is scored against a tunable 5-component rubric (weighted sum
0-100), checked for overlap with your existing campaigns, and emitted as a ranked
markdown catalog you can read directly in Obsidian -- or as JSON for downstream
tooling.

This is the open-source *method*. It ships with zero organisation-specific content:
every value that encodes "what matters to my org" lives in `config/scoring.yaml`,
or in the frontmatter of your own notes. Point it at a bare vault that follows the
data contract (see `docs/DATA-CONTRACT.md`) and it runs.

Design tenets
-------------
* **Stdlib-first**: the only optional dependency is PyYAML. A hand-rolled
  frontmatter parser is used as a fallback if PyYAML is missing.
* **Zero-config runnable**: sensible defaults are baked in; `scoring.yaml` only
  *overrides*. You can run against the bundled example vault with no setup.
* **Idempotent**: same vault state + same config -> byte-identical output
  (all sorts are deterministic).
* **Defensive**: missing frontmatter fields default sensibly; a note with no
  frontmatter is skipped, not fatal.
* **Operator-tunable**: scoring weights, tier probabilities, priority buckets and
  sensitivity indicators are all config, not code.

Usage
-----
    # run against the bundled example vault
    python3 engine/enumerate.py --vault vault-template --top 10

    # run against your own vault with your own config
    python3 engine/enumerate.py \
        --vault /path/to/my-vault \
        --config config/scoring.yaml \
        --output /path/to/my-vault/predictions/$(date +%F)-enumeration.md \
        --top 25

CLI flags
---------
    --vault PATH        Vault root (default: ./vault-template next to this script)
    --config PATH       Scoring/config YAML (default: baked-in defaults)
    --output PATH       Output markdown file (default: stdout)
    --top N             Emit top-N candidates (default: 25)
    --min-score F       Floor score for emission (default: 0)
    --include-overlaps  Keep chains that duplicate existing campaigns
    --diversity-quota F Min fraction of top-N that must be NEW (default: 0.6)
    --max-per-actor N   Cap candidates per actor in top-N (default: 3)
    --json              Emit JSON instead of markdown
    --run-date YYYY-MM-DD   Override run-date (deterministic testing)

License: MIT. See LICENSE.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

# -- Optional PyYAML, with stdlib fallback ----------------------------------
try:
    import yaml  # type: ignore
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False


# ===========================================================================
# DEFAULT CONFIG  (everything org-specific lives here or in scoring.yaml)
# ===========================================================================
# These defaults let the engine run against a bare vault with no config file.
# Copy config/scoring.example.yaml -> config/scoring.yaml and edit to make the
# scoring reflect *your* priorities. A config file merges OVER these defaults
# (top-level keys are replaced, not deep-merged -- supply a whole section).

DEFAULT_CONFIG: dict[str, Any] = {
    # Where each note type lives, relative to the vault root. Point these at
    # whatever folder structure your vault uses.
    "vault": {
        "actors_dir": "actors",
        "surfaces_dir": "surfaces",
        "recipes_dir": "recipes",       # searched recursively (phase subfolders OK)
        "campaigns_dir": "campaigns",
    },

    # 5-component rubric. Weights MUST sum to 100 so the composite is 0-100.
    "weights": {
        "strategic_relevance":    30,   # surface priority-coverage x actor tier
        "actor_probability":      20,   # tier-based likelihood actor targets you
        "detection_gap":          20,   # phase-span proxy for thin detection seams
        "sensitivity_exposure":   20,   # regulated/crown-jewel data exposure
        "operational_simplicity": 10,   # easier chain = higher attacker uptake
    },

    # Actor relevance tier -> probability multiplier (0-1).
    "tier_probability": {
        "tier-1": 1.00,
        "tier-2": 0.70,
        "tier-3": 0.40,
        "tier-4": 0.10,
        "reference-only": 0.05,
    },

    # Composite-score thresholds -> next-cycle priority label. Highest first.
    "priority_buckets": [
        [85, "P1-FLAGSHIP"],
        [70, "P1"],
        [55, "P2"],
        [40, "P3"],
        [0,  "DEFER"],
    ],

    # Ordered kill-chain phases. Chains respect this DAG; entry is required.
    "phases": ["entry", "establish", "escalate", "pivot", "impact"],

    # OPSEC tier -> numeric (lower = louder/easier-to-detect = easier-to-execute).
    "opsec_numeric": {
        "low": 1, "low-to-medium": 1.5, "medium": 2, "medium-to-high": 2.5,
        "high": 3, "burn-on-use": 0.5,
    },

    # --- Sensitivity model -------------------------------------------------
    # PREFERRED: declare sensitivity explicitly per surface via its frontmatter
    #   data_sensitivity: [pii, crown_jewel]
    # These substring lists are the FALLBACK when a surface omits that field:
    # if any token appears in the surface's interface_type / id / owner_entity /
    # filename, the surface is treated as touching that data class.
    # Replace the examples below with tokens that matter to YOUR environment.
    "sensitive_data_indicators": [     # regulated / personal data (PII-class)
        "customer", "participant", "employee", "hr", "payroll",
        "identity", "sso", "okta", "entra", "directory",
    ],
    "high_value_indicators": [         # crown-jewel / material-non-public-class
        "executive", "finance", "source-code", "repository", "secrets",
        "signing", "treasury", "board",
    ],

    # Actors known for data-theft / extortion get a sensitivity-score multiplier.
    # These are PUBLIC threat-actor names (starter list); edit freely.
    "high_impact_actors": [
        "UNC3944", "Scattered Spider", "ShinyHunters", "LAPSUS$",
        "FIN7", "Qilin", "RansomHub", "DragonForce",
    ],

    # Catalog diversity controls.
    "diversity": {
        "quota": 0.6,          # min fraction of top-N that must be NEW chains
        "max_per_actor": 3,    # cap candidates per actor in top-N
    },
}


def load_config(path: Path | None) -> dict[str, Any]:
    """Return DEFAULT_CONFIG with the user's YAML merged over it (top-level)."""
    cfg = {k: (v.copy() if isinstance(v, (dict, list)) else v)
           for k, v in DEFAULT_CONFIG.items()}
    if path is None:
        return cfg
    if not path.exists():
        print(f"[!] config not found: {path} -- using defaults", file=sys.stderr)
        return cfg
    text = path.read_text(encoding="utf-8")
    user = yaml.safe_load(text) if HAVE_YAML else _parse_config_yaml(text)
    if isinstance(user, dict):
        for k, v in user.items():
            cfg[k] = v
    # Validate weights sum
    wsum = sum(cfg["weights"].values())
    if wsum != 100:
        print(f"[!] weights sum to {wsum}, not 100 -- scores will not be 0-100",
              file=sys.stderr)
    return cfg


# ===========================================================================
# Data classes
# ===========================================================================

@dataclass
class Actor:
    actor_id: str
    aliases: list[str] = field(default_factory=list)
    relevance_tier: str = "tier-3"   # default mid-tier
    priority: str = "P3"
    mitre_attck: list[str] = field(default_factory=list)
    linked_recipes: list[str] = field(default_factory=list)
    linked_surfaces: list[str] = field(default_factory=list)
    primary_tradecraft: str = ""
    file_path: str = ""


@dataclass
class Surface:
    surface_id: str
    interface_type: str = ""
    state: str = ""
    owner_entity: str = ""
    surface_layers: list[str] = field(default_factory=list)
    pir: list[str] = field(default_factory=list)          # priority intel reqs
    data_sensitivity: list[str] = field(default_factory=list)  # explicit classes
    linked_recipes: list[str] = field(default_factory=list)
    linked_actors: list[str] = field(default_factory=list)
    file_path: str = ""

    def priority_weight(self) -> float:
        """Strategic weight proxy: more standing intel-priorities touched = higher.
        Falls back to surface-layer count if `pir` is unpopulated."""
        if self.pir:
            return min(1.0, len(self.pir) * 0.2)         # 5 PIRs = max
        return min(1.0, len(self.surface_layers) * 0.15)

    def _blob(self) -> str:
        return " ".join([
            self.interface_type, self.surface_id, self.owner_entity,
            (self.file_path or "").lower(),
        ]).lower()

    def touches_sensitive(self, indicators: list[str]) -> bool:
        if self.data_sensitivity:
            return any(c in ("pii", "sensitive", "personal", "regulated")
                       for c in (x.lower() for x in self.data_sensitivity))
        blob = self._blob()
        return any(ind.lower() in blob for ind in indicators)

    def touches_high_value(self, indicators: list[str]) -> bool:
        if self.data_sensitivity:
            return any(c in ("crown_jewel", "mnpi", "high_value", "material")
                       for c in (x.lower() for x in self.data_sensitivity))
        blob = self._blob()
        return any(ind.lower() in blob for ind in indicators)


@dataclass
class Recipe:
    recipe_id: str
    name: str = ""
    phase: str = "entry"
    mitre_attck: list[str] = field(default_factory=list)
    actor_uses: list[str] = field(default_factory=list)
    linked_surfaces: list[str] = field(default_factory=list)
    opsec: str = "medium"
    achieves: str = ""
    file_path: str = ""

    def opsec_numeric(self, table: dict[str, float]) -> float:
        tier_marker = (self.opsec or "medium").lower().split(";")[0].strip()
        for k, v in table.items():
            if k in tier_marker:
                return v
        return 2.0  # medium default


@dataclass
class Campaign:
    campaign_id: str
    primary_actor: str = ""
    recipes_orchestrated: list[str] = field(default_factory=list)
    surface_targets: list[str] = field(default_factory=list)


@dataclass
class CandidateChain:
    candidate_id: str
    actor: Actor
    recipes_by_phase: dict[str, Recipe]
    surfaces_targeted: list[str]
    score_components: dict[str, float]
    composite_score: float
    overlap_status: str
    priority_recommendation: str
    emulation_readiness: str

    def phases_used(self, phases: list[str]) -> list[str]:
        return [p for p in phases if p in self.recipes_by_phase]


# ===========================================================================
# Frontmatter parser
# ===========================================================================

FM_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


def parse_frontmatter(text: str) -> dict[str, Any]:
    """Extract the YAML frontmatter dict from markdown. Returns {} if absent."""
    m = FM_RE.match(text)
    if not m:
        return {}
    fm_text = m.group(1)
    if HAVE_YAML:
        try:
            data = yaml.safe_load(fm_text)
            return data if isinstance(data, dict) else {}
        except yaml.YAMLError:
            return _hand_parse_frontmatter(fm_text)
    return _hand_parse_frontmatter(fm_text)


def _hand_parse_frontmatter(text: str) -> dict[str, Any]:
    """Minimal YAML subset: scalar, inline-list, block-list. No nesting."""
    out: dict[str, Any] = {}
    cur_key: str | None = None
    cur_list: list[str] | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if line.lstrip().startswith("- ") and cur_list is not None:
            cur_list.append(_strip_yaml_value(line.lstrip()[2:]))
            continue
        if ":" in line and not line.startswith(" "):
            if cur_key is not None and cur_list is not None:
                out[cur_key] = cur_list
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if not val:
                cur_key = key
                cur_list = []
                continue
            if val.startswith("[") and val.endswith("]"):
                items = [_strip_yaml_value(x) for x in val[1:-1].split(",") if x.strip()]
                out[key] = items
                cur_key = None
                cur_list = None
                continue
            out[key] = _strip_yaml_value(val)
            cur_key = None
            cur_list = None
    if cur_key is not None and cur_list is not None:
        out[cur_key] = cur_list
    return out


def _strip_yaml_value(v: str) -> str:
    v = v.strip()
    if " #" in v:
        v = v.split(" #", 1)[0].rstrip()
    if v.startswith('"') and v.endswith('"'):
        v = v[1:-1]
    elif v.startswith("'") and v.endswith("'"):
        v = v[1:-1]
    return v


# ---------------------------------------------------------------------------
# Config YAML parser (stdlib fallback used only when PyYAML is unavailable).
# Handles exactly the shapes scoring.yaml uses: top-level scalars, inline lists,
# block lists (of scalars OR inline 2-element lists), and ONE level of nested
# maps. This keeps the kit's "zero required dependencies" promise honest so
# `--config` works even without PyYAML installed.
# ---------------------------------------------------------------------------

def _cfg_scalar(v: str) -> Any:
    v = v.strip()
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    if re.fullmatch(r"-?\d+", v):
        return int(v)
    if re.fullmatch(r"-?\d+\.\d+", v):
        return float(v)
    return v


def _cfg_scalar_or_list(v: str) -> Any:
    v = v.strip()
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        if not inner:
            return []
        return [_cfg_scalar(x) for x in inner.split(",") if x.strip()]
    return _cfg_scalar(v)


def _cfg_strip_comment(s: str) -> str:
    """Drop a comment: a '#' at the start of the (stripped) value or after
    whitespace. Config values never legitimately contain '#'."""
    out: list[str] = []
    prev = ""
    for ch in s:
        if ch == "#" and (prev == "" or prev.isspace()):
            break
        out.append(ch)
        prev = ch
    return "".join(out).rstrip()


def _parse_config_block(block: list[str]) -> Any:
    """A block is either a list (lines start with '- ') or a map (k: v lines)."""
    if any(l.strip().startswith("- ") for l in block):
        out_list: list[Any] = []
        for l in block:
            s = l.strip()
            if s.startswith("- "):
                out_list.append(_cfg_scalar_or_list(_cfg_strip_comment(s[2:])))
        return out_list
    out_map: dict[str, Any] = {}
    for l in block:
        s = l.strip()
        if ":" in s:
            k, _, v = s.partition(":")
            out_map[k.strip()] = _cfg_scalar_or_list(_cfg_strip_comment(v))
    return out_map


def _parse_config_yaml(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    lines = text.splitlines()
    i, n = 0, len(lines)
    while i < n:
        line = lines[i].rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or line.startswith((" ", "\t")):
            i += 1
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = _cfg_strip_comment(val.strip())
            if val:
                out[key] = _cfg_scalar_or_list(val)
                i += 1
                continue
            # block: gather following indented (non-blank, non-comment) lines
            block: list[str] = []
            j = i + 1
            while j < n:
                bl = lines[j]
                if not bl.strip() or bl.strip().startswith("#"):
                    j += 1
                    continue
                if not bl.startswith((" ", "\t")):
                    break
                block.append(bl)
                j += 1
            out[key] = _parse_config_block(block)
            i = j
            continue
        i += 1
    return out


# ===========================================================================
# Vault loader
# ===========================================================================

def load_vault(vault_root: Path, cfg: dict[str, Any]) -> tuple[
    dict[str, Actor], dict[str, Surface],
    dict[str, Recipe], dict[str, Campaign],
]:
    """Walk the vault, parse frontmatter, build typed registries keyed by ID."""
    actors: dict[str, Actor] = {}
    surfaces: dict[str, Surface] = {}
    recipes: dict[str, Recipe] = {}
    campaigns: dict[str, Campaign] = {}

    vcfg = cfg["vault"]
    phases = cfg["phases"]

    # -- Actors --------------------------------------------------------------
    actor_dir = vault_root / vcfg["actors_dir"]
    if actor_dir.exists():
        for p in sorted(actor_dir.rglob("*.md")):
            if p.name.startswith(("README", "_TEMPLATE")):
                continue
            fm = _read_fm(p)
            if not fm:
                continue
            aid = str(fm.get("actor_id") or p.stem)
            actor = Actor(
                actor_id=aid,
                aliases=_as_list(fm.get("aliases")),
                relevance_tier=_normalize_tier(
                    str(fm.get("relevance_tier", fm.get("voya_relevance", "tier-3")))),
                priority=str(fm.get("priority", fm.get("quarterly_priority", "P3"))),
                mitre_attck=_as_list(fm.get("mitre_attck")) or _as_list(fm.get("mitre_attack")),
                linked_recipes=_as_list(fm.get("linked_recipes")),
                linked_surfaces=_as_list(fm.get("linked_surfaces")),
                primary_tradecraft=str(fm.get("primary_tradecraft", "")),
                file_path=str(p),
            )
            actors[aid] = actor

    # -- Surfaces ------------------------------------------------------------
    surf_dir = vault_root / vcfg["surfaces_dir"]
    if surf_dir.exists():
        for p in sorted(surf_dir.rglob("*.md")):
            if p.name.startswith(("README", "_TEMPLATE")):
                continue
            fm = _read_fm(p)
            if not fm:
                continue
            sid = str(fm.get("surface_id") or "").strip()
            if not sid:
                continue
            surfaces[sid] = Surface(
                surface_id=sid,
                interface_type=str(fm.get("interface_type", "")),
                state=str(fm.get("state", "")),
                owner_entity=str(fm.get("owner_entity", "")),
                surface_layers=_as_list(fm.get("surface_layers")) or _as_list(fm.get("tpf_layers")),
                pir=_as_list(fm.get("pir")),
                data_sensitivity=_as_list(fm.get("data_sensitivity")),
                linked_recipes=_as_list(fm.get("linked_recipes")),
                linked_actors=_as_list(fm.get("linked_actors")),
                file_path=str(p),
            )

    # -- Recipes (recursive across phase subdirs) ----------------------------
    rec_dir = vault_root / vcfg["recipes_dir"]
    if rec_dir.exists():
        for p in sorted(rec_dir.rglob("*.md")):
            if p.name.startswith(("README", "_TEMPLATE")):
                continue
            fm = _read_fm(p)
            if not fm:
                continue
            rid = str(fm.get("recipe_id") or "").strip()
            if not rid:
                continue
            phase = str(fm.get("phase", "entry")).strip().lower()
            if phase not in phases:
                for candidate in phases:
                    if f"/{candidate}/" in str(p):
                        phase = candidate
                        break
                else:
                    phase = phases[0]
            recipes[rid] = Recipe(
                recipe_id=rid,
                name=str(fm.get("recipe_name", p.stem)),
                phase=phase,
                mitre_attck=_as_list(fm.get("mitre_attck")) or _as_list(fm.get("mitre_attack")),
                actor_uses=_as_list(fm.get("actor_uses")),
                linked_surfaces=_as_list(fm.get("linked_surfaces")),
                opsec=str(fm.get("opsec", "medium")),
                achieves=str(fm.get("achieves", "")),
                file_path=str(p),
            )

    # -- Campaigns -----------------------------------------------------------
    camp_dir = vault_root / vcfg["campaigns_dir"]
    if camp_dir.exists():
        for p in sorted(camp_dir.rglob("*.md")):
            if p.name.startswith(("README", "_TEMPLATE")):
                continue
            fm = _read_fm(p)
            if not fm:
                continue
            cid = str(fm.get("campaign_id") or p.stem).strip()
            campaigns[cid] = Campaign(
                campaign_id=cid,
                primary_actor=str(fm.get("primary_actor", "")),
                recipes_orchestrated=_as_list(fm.get("recipes_orchestrated")),
                surface_targets=_as_list(fm.get("surface_targets")),
            )

    return actors, surfaces, recipes, campaigns


def _read_fm(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    return parse_frontmatter(text)


def _as_list(val: Any) -> list[str]:
    if val is None:
        return []
    if isinstance(val, list):
        return [str(x).strip() for x in val if str(x).strip()]
    if isinstance(val, str):
        if "," in val:
            return [x.strip() for x in val.split(",") if x.strip()]
        return [val.strip()] if val.strip() else []
    return [str(val)]


def _normalize_tier(raw: str) -> str:
    """Accept freeform tier strings; normalise to the canonical five."""
    raw_l = (raw or "").lower()
    if "tier-1" in raw_l or "critical" in raw_l or "flagship" in raw_l:
        return "tier-1"
    if "tier-2" in raw_l:
        return "tier-2"
    if "tier-3" in raw_l:
        return "tier-3"
    if "tier-4" in raw_l:
        return "tier-4"
    if "reference" in raw_l:
        return "reference-only"
    return "tier-3"


# ===========================================================================
# Enumeration
# ===========================================================================

def candidate_recipes_for_actor(
    actor: Actor, recipes: dict[str, Recipe],
) -> list[Recipe]:
    """All recipes plausibly attributable to this actor, from three sources:
      (a) recipes the actor card explicitly lists in `linked_recipes`,
      (b) recipes whose `actor_uses` names this actor or an alias,
      (c) recipes whose `mitre_attck` overlaps the actor's TTP inventory.
    Branch (c) is what surfaces NEW (non-author-curated) chains."""
    out: dict[str, Recipe] = {}
    actor_names = {actor.actor_id} | set(actor.aliases)
    actor_ttps = set(actor.mitre_attck)
    for rid, r in recipes.items():
        if rid in actor.linked_recipes:
            out[rid] = r
            continue
        if any(name in r.actor_uses for name in actor_names):
            out[rid] = r
            continue
        if actor_ttps and (set(r.mitre_attck) & actor_ttps):
            out[rid] = r
    return sorted(out.values(), key=lambda x: x.recipe_id)


def enumerate_chains(
    actors: dict[str, Actor],
    recipes: dict[str, Recipe],
    phases: list[str],
) -> list[tuple[Actor, dict[str, Recipe], list[str]]]:
    """For each actor, build plausible cross-phase chains.

    For each actor we group plausible recipes by phase, require an entry-phase
    recipe, and extend it with the highest-affinity recipe per later phase
    (deterministic; actor-explicit recipes preferred over MITRE-only matches).
    Target surfaces = actor.linked_surfaces intersected with the union of the
    chain's recipe surfaces (falling back to the union if that is empty)."""
    chains: list[tuple[Actor, dict[str, Recipe], list[str]]] = []
    later_phases = phases[1:]

    for actor_id in sorted(actors):
        actor = actors[actor_id]
        plausible = candidate_recipes_for_actor(actor, recipes)
        if not plausible:
            continue
        by_phase: dict[str, list[Recipe]] = {p: [] for p in phases}
        for r in plausible:
            by_phase.setdefault(r.phase, []).append(r)

        for phase in by_phase:
            by_phase[phase].sort(key=lambda r: (
                0 if (actor.actor_id in r.actor_uses or
                      any(a in r.actor_uses for a in actor.aliases)) else 1,
                r.recipe_id,
            ))

        entries = by_phase.get(phases[0], [])
        if not entries:
            continue

        for entry in entries:
            chain: dict[str, Recipe] = {phases[0]: entry}
            for later in later_phases:
                if by_phase.get(later):
                    chain[later] = by_phase[later][0]

            chain_surfaces: set[str] = set()
            for r in chain.values():
                chain_surfaces.update(r.linked_surfaces)
            if actor.linked_surfaces:
                preferred = chain_surfaces & set(actor.linked_surfaces)
                target_surfaces = sorted(preferred) if preferred else sorted(chain_surfaces)
            else:
                target_surfaces = sorted(chain_surfaces)

            chains.append((actor, chain, target_surfaces))

            # entry-only variant so single-step high-impact actors survive
            if len(chain) > 1:
                solo: dict[str, Recipe] = {phases[0]: entry}
                solo_surfaces = sorted(set(entry.linked_surfaces) &
                                       set(actor.linked_surfaces or entry.linked_surfaces))
                if not solo_surfaces:
                    solo_surfaces = sorted(set(entry.linked_surfaces))
                chains.append((actor, solo, solo_surfaces))

    return chains


def deduplicate_chains(
    chains: list[tuple[Actor, dict[str, Recipe], list[str]]],
) -> list[tuple[Actor, dict[str, Recipe], list[str]]]:
    """Drop chains identical in (actor_id, recipe-set, surface-set)."""
    seen: set[tuple] = set()
    out = []
    for actor, chain, surfaces in chains:
        key = (
            actor.actor_id,
            tuple(sorted(r.recipe_id for r in chain.values())),
            tuple(surfaces),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append((actor, chain, surfaces))
    return out


# ===========================================================================
# Scoring
# ===========================================================================

def score_chain(
    actor: Actor,
    chain: dict[str, Recipe],
    surfaces_targeted: list[str],
    surfaces: dict[str, Surface],
    cfg: dict[str, Any],
) -> dict[str, float]:
    """Compute the 5 scoring components (each 0-1) and the weighted composite."""
    weights = cfg["weights"]
    tier_prob = cfg["tier_probability"]
    surf_objs = [surfaces[s] for s in surfaces_targeted if s in surfaces]
    actor_tier_factor = tier_prob.get(actor.relevance_tier, 0.4)

    # 1. Strategic relevance (surface priority-coverage x actor tier)
    if surf_objs:
        pr_avg = sum(s.priority_weight() for s in surf_objs) / len(surf_objs)
    else:
        pr_avg = 0.0
    strategic_relevance = pr_avg * actor_tier_factor

    # 2. Actor probability (tier-driven)
    actor_prob = actor_tier_factor

    # 3. Detection-gap exposure (phase-span proxy: more phases = more seams)
    detection_gap = min(1.0, len(chain) / max(1, len(cfg["phases"])))

    # 4. Sensitivity exposure (regulated + crown-jewel data; data-theft bump)
    sens = cfg["sensitive_data_indicators"]
    hv = cfg["high_value_indicators"]
    sens_count = sum(1 for s in surf_objs if s.touches_sensitive(sens))
    hv_count = sum(1 for s in surf_objs if s.touches_high_value(hv))
    data_theft = any(a in cfg["high_impact_actors"]
                     for a in [actor.actor_id, *actor.aliases])
    if surf_objs:
        exposure = (sens_count + 1.5 * hv_count) / (len(surf_objs) * 2.5)
    else:
        exposure = 0.0
    if data_theft:
        exposure = min(1.0, exposure * 1.3 + 0.1)
    exposure = min(1.0, exposure)

    # 5. Operational simplicity (inverse complexity; attacker prefers easy)
    if chain:
        avg_opsec = sum(r.opsec_numeric(cfg["opsec_numeric"]) for r in chain.values()) / len(chain)
        simplicity = max(0.0, min(1.0, (3.0 - avg_opsec) / 2.5))
    else:
        simplicity = 0.0

    components = {
        "strategic_relevance":    strategic_relevance,
        "actor_probability":      actor_prob,
        "detection_gap":          detection_gap,
        "sensitivity_exposure":   exposure,
        "operational_simplicity": simplicity,
    }
    composite = sum(components[k] * weights[k] for k in weights)
    components["composite"] = composite
    return components


def overlap_with_existing(
    chain: dict[str, Recipe], actor: Actor, campaigns: dict[str, Campaign],
) -> str:
    """NEW / EXTENDS:<id> / DUPLICATE:<id> via Jaccard on recipe sets.
    >=0.8 duplicate, 0.4-0.8 extends, <0.4 new."""
    chain_recipes = {r.recipe_id for r in chain.values()}
    actor_names = {actor.actor_id, *actor.aliases}
    best_match: tuple[float, str] | None = None
    for cid, camp in campaigns.items():
        camp_recipes = set(camp.recipes_orchestrated)
        if not camp_recipes:
            continue
        actor_match = (camp.primary_actor in actor_names or
                       any(name in camp.primary_actor for name in actor_names))
        if not actor_match and not (chain_recipes & camp_recipes):
            continue
        if chain_recipes:
            jacc = len(chain_recipes & camp_recipes) / len(chain_recipes | camp_recipes)
        else:
            jacc = 0.0
        if jacc >= 0.8:
            return f"DUPLICATE:{cid}"
        if jacc >= 0.4:
            if best_match is None or jacc > best_match[0]:
                best_match = (jacc, cid)
    if best_match:
        return f"EXTENDS:{best_match[1]}"
    return "NEW"


def priority_recommendation(score: float, buckets: list) -> str:
    for threshold, label in buckets:
        if score >= threshold:
            return label
    return "DEFER"


def emulation_readiness(
    chain: dict[str, Recipe], surfaces: dict[str, Surface],
    surfaces_targeted: list[str],
) -> str:
    """Heuristic readiness for conversion to a runnable emulation (BAS) campaign.
    READY = >=2 phases, every recipe has MITRE coverage, >=1 confirmed surface."""
    if len(chain) < 2:
        return "NEEDS-RECIPE"
    if any(not r.mitre_attck for r in chain.values()):
        return "NEEDS-RECIPE"
    if surfaces_targeted:
        states = [surfaces[s].state for s in surfaces_targeted if s in surfaces]
        if not any("confirmed" in (st or "") or "validated" in (st or "")
                   for st in states):
            return "NEEDS-VALIDATION"
    return "READY"


# ===========================================================================
# Diversity filter
# ===========================================================================

def _apply_diversity(
    candidates: list[CandidateChain],
    top_n: int, max_per_actor: int, new_quota: float,
) -> list[CandidateChain]:
    """Pick top-N respecting per-actor cap and a NEW-candidate quota."""
    target_new = int(top_n * new_quota)
    target_ext = top_n - target_new
    chosen: list[CandidateChain] = []
    actor_counts: dict[str, int] = {}
    new_count = 0
    ext_count = 0

    for c in candidates:
        if len(chosen) >= top_n:
            break
        if c.overlap_status != "NEW":
            continue
        if actor_counts.get(c.actor.actor_id, 0) >= max_per_actor:
            continue
        if new_count >= target_new:
            break
        chosen.append(c)
        actor_counts[c.actor.actor_id] = actor_counts.get(c.actor.actor_id, 0) + 1
        new_count += 1

    for c in candidates:
        if len(chosen) >= top_n:
            break
        if c.overlap_status == "NEW":
            continue
        if actor_counts.get(c.actor.actor_id, 0) >= max_per_actor:
            continue
        if ext_count >= target_ext:
            break
        chosen.append(c)
        actor_counts[c.actor.actor_id] = actor_counts.get(c.actor.actor_id, 0) + 1
        ext_count += 1

    for c in candidates:
        if len(chosen) >= top_n:
            break
        if c in chosen:
            continue
        if actor_counts.get(c.actor.actor_id, 0) >= max_per_actor:
            continue
        chosen.append(c)
        actor_counts[c.actor.actor_id] = actor_counts.get(c.actor.actor_id, 0) + 1

    chosen.sort(key=lambda c: (-c.composite_score, c.actor.actor_id))
    return chosen


# ===========================================================================
# Output formatting
# ===========================================================================

def make_candidate_id(seq: int, run_date: str) -> str:
    return f"PRED-{run_date}-{seq:03d}"


def _wikilink(file_path: str, label: str) -> str:
    """Emit an Obsidian wikilink by basename -- resolves anywhere in the vault."""
    stem = Path(file_path).stem if file_path else label
    return f"[[{stem}|{label}]]"


def render_markdown(
    candidates: list[CandidateChain], run_date: str,
    surfaces: dict[str, Surface], cfg: dict[str, Any],
    total_enumerated: int, overlap_filtered: int,
) -> str:
    weights = cfg["weights"]
    phases = cfg["phases"]
    out: list[str] = []
    out += [
        "---", "tags:", "  - 🔮", "aliases:",
        f"  - Predictive Intelligence Enumeration {run_date}",
        f"date_created: {run_date}", f"last_updated: {run_date}",
        "template_version: 1.0", "validation_status: draft",
        f"run_date: {run_date}", f"total_chains_enumerated: {total_enumerated}",
        f"overlap_filtered_count: {overlap_filtered}",
        f"emitted_count: {len(candidates)}", "engine_version: 1.0", "---", "",
        f"# 🔮 Predictive Intelligence Enumeration — {run_date}", "",
        f"**Engine v1.0** · **Run** {run_date} · **Top-N** {len(candidates)} "
        f"· **Total chains** {total_enumerated} · **Duplicates filtered** {overlap_filtered}",
        "",
        "> Combinatorially-enumerated plausible attack chains derived from "
        "cross-linking actors × recipes × surfaces. Each chain is a *candidate "
        "campaign* not yet manually authored. Scoring rubric: see `config/scoring.yaml`.",
        "",
        "> **How to use:** read the top-N. For each NEW high-score candidate, "
        "decide — promote to a standalone campaign, or convert directly to an "
        "emulation draft. Lower-score / EXTENDS items are backlog.",
        "", "---", "", "## 🏆 Ranked Candidate Catalog", "",
        "| Rank | ID | Actor | Score | Overlap | Priority | Emulation |",
        "|---|---|---|---|---|---|---|",
    ]
    for i, c in enumerate(candidates, 1):
        out.append(
            f"| {i} | {c.candidate_id} | {c.actor.actor_id} "
            f"({c.actor.relevance_tier}) | {c.composite_score:.1f} "
            f"| {c.overlap_status} | {c.priority_recommendation} "
            f"| {c.emulation_readiness} |"
        )
    out += ["", "---", ""]

    for i, c in enumerate(candidates, 1):
        out += [
            f"## {i}. {c.candidate_id} — {c.actor.actor_id}", "",
            f"**Actor:** {_wikilink(c.actor.file_path, c.actor.actor_id)} "
            f"({c.actor.relevance_tier}, priority {c.actor.priority})  ",
            f"**Composite score:** **{c.composite_score:.1f} / 100** "
            f"→ recommended priority: **{c.priority_recommendation}**  ",
            f"**Overlap with existing campaigns:** {c.overlap_status}  ",
            f"**Emulation-conversion readiness:** {c.emulation_readiness}", "",
            "### Generated chain", "",
        ]
        for phase in phases:
            if phase in c.recipes_by_phase:
                r = c.recipes_by_phase[phase]
                achieves = (r.achieves[:120] + "…") if len(r.achieves) > 120 else r.achieves
                out.append(f"- **{phase.upper():>9}** → {_wikilink(r.file_path, r.recipe_id)} "
                           f"*({r.name})* — {achieves}")
        out += ["", "### Target surfaces", ""]
        if c.surfaces_targeted:
            for s in c.surfaces_targeted:
                surf = surfaces.get(s)
                if surf:
                    out.append(f"- {_wikilink(surf.file_path, s)} — `{surf.interface_type}` "
                               f"(state: `{surf.state}`)")
                else:
                    out.append(f"- {s} *(surface not loaded)*")
        else:
            out.append("- *(no surface intersection — chain may need surface targeting)*")
        out += ["", "### Score breakdown", "",
                "| Component | Weight | Raw (0-1) | Contribution |", "|---|---|---|---|"]
        for k in weights:
            raw = c.score_components[k]
            out.append(f"| {k.replace('_', ' ')} | {weights[k]} | {raw:.2f} | {raw * weights[k]:.1f} |")
        out += [f"| **Composite** | **100** | — | **{c.composite_score:.1f}** |", "", "---", ""]

    out += [
        "## Methodology Summary", "",
        "Chains are enumerated from each actor's plausible-recipe set (union of: "
        "the actor card's `linked_recipes`, recipes naming the actor in "
        "`actor_uses`, and recipes whose MITRE-ATT&CK IDs overlap the actor's "
        "TTP inventory). Target surfaces intersect the actor's `linked_surfaces` "
        "with each recipe's `linked_surfaces`. See `docs/METHOD.md` for the full "
        "method and `config/scoring.yaml` for the rubric.", "",
    ]
    return "\n".join(out)


def render_json(candidates: list[CandidateChain], phases: list[str]) -> str:
    payload = []
    for c in candidates:
        payload.append({
            "candidate_id":    c.candidate_id,
            "actor_id":        c.actor.actor_id,
            "actor_tier":      c.actor.relevance_tier,
            "phases":          c.phases_used(phases),
            "recipes":         {p: r.recipe_id for p, r in c.recipes_by_phase.items()},
            "surfaces":        c.surfaces_targeted,
            "composite_score": round(c.composite_score, 2),
            "components":      {k: round(v, 3) for k, v in c.score_components.items()},
            "overlap":         c.overlap_status,
            "priority":        c.priority_recommendation,
            "emulation":       c.emulation_readiness,
        })
    return json.dumps(payload, indent=2)


# ===========================================================================
# Main
# ===========================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Predictive intelligence enumeration engine (open-source method)")
    parser.add_argument("--vault", type=Path,
                        default=Path(__file__).resolve().parent.parent / "vault-template",
                        help="Vault root (default: bundled vault-template)")
    parser.add_argument("--config", type=Path, default=None,
                        help="Scoring/config YAML (default: baked-in defaults)")
    parser.add_argument("--output", type=Path, default=None,
                        help="Output markdown file (default: stdout)")
    parser.add_argument("--top", type=int, default=25)
    parser.add_argument("--min-score", type=float, default=0.0)
    parser.add_argument("--include-overlaps", action="store_true")
    parser.add_argument("--diversity-quota", type=float, default=None,
                        help="Min fraction of top-N that must be NEW (default: config)")
    parser.add_argument("--max-per-actor", type=int, default=None,
                        help="Cap candidates per actor in top-N (default: config)")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--run-date", type=str, default=date.today().isoformat())
    args = parser.parse_args()

    cfg = load_config(args.config)
    phases = cfg["phases"]
    quota = args.diversity_quota if args.diversity_quota is not None else cfg["diversity"]["quota"]
    max_per_actor = args.max_per_actor if args.max_per_actor is not None else cfg["diversity"]["max_per_actor"]

    vault_root = args.vault
    if not vault_root.exists():
        print(f"[ERROR] Vault root does not exist: {vault_root}", file=sys.stderr)
        return 2

    print(f"[*] Loading vault: {vault_root}", file=sys.stderr)
    actors, surfaces, recipes, campaigns = load_vault(vault_root, cfg)
    print(f"[*] Loaded: {len(actors)} actors, {len(surfaces)} surfaces, "
          f"{len(recipes)} recipes, {len(campaigns)} campaigns", file=sys.stderr)
    if not HAVE_YAML:
        print("[!] PyYAML not installed; using built-in fallback parser "
              "(output is identical). `pip install pyyaml` is optional.",
              file=sys.stderr)
    if not actors:
        print(f"[!] No actor notes found under '{vault_root / cfg['vault']['actors_dir']}'. "
              "Author at least one actor card (with mitre_attck or linked_recipes) "
              "and one entry-phase recipe to generate chains. See docs/GETTING-STARTED.md.",
              file=sys.stderr)

    raw_chains = enumerate_chains(actors, recipes, phases)
    chains = deduplicate_chains(raw_chains)
    print(f"[*] {len(chains)} unique chains enumerated", file=sys.stderr)

    candidates: list[CandidateChain] = []
    overlap_filtered = 0
    for actor, chain, surfaces_targeted in chains:
        components = score_chain(actor, chain, surfaces_targeted, surfaces, cfg)
        composite = components["composite"]
        if composite < args.min_score:
            continue
        overlap = overlap_with_existing(chain, actor, campaigns)
        if overlap.startswith("DUPLICATE") and not args.include_overlaps:
            overlap_filtered += 1
            continue
        candidates.append(CandidateChain(
            candidate_id="",
            actor=actor,
            recipes_by_phase=chain,
            surfaces_targeted=surfaces_targeted,
            score_components=components,
            composite_score=composite,
            overlap_status=overlap,
            priority_recommendation=priority_recommendation(composite, cfg["priority_buckets"]),
            emulation_readiness=emulation_readiness(chain, surfaces, surfaces_targeted),
        ))

    candidates.sort(key=lambda c: (
        -c.composite_score, c.actor.actor_id,
        tuple(sorted(r.recipe_id for r in c.recipes_by_phase.values())),
    ))
    for i, c in enumerate(candidates, 1):
        c.candidate_id = make_candidate_id(i, args.run_date)

    emitted = _apply_diversity(candidates, top_n=args.top,
                               max_per_actor=max_per_actor, new_quota=quota)
    print(f"[*] Emitting top {len(emitted)} of {len(candidates)} "
          f"(filtered {overlap_filtered} overlaps)", file=sys.stderr)

    if args.json:
        rendered = render_json(emitted, phases)
    else:
        rendered = render_markdown(emitted, args.run_date, surfaces, cfg,
                                   total_enumerated=len(chains),
                                   overlap_filtered=overlap_filtered)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(f"[*] Wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
