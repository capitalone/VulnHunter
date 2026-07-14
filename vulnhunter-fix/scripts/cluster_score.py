"""Score clusters by risk-reduction weight.

The scoring rubric is defined in `prompts/parse_issues.md` Step 3(b).
This module is the authoritative implementation — when the prompt
emits `clusters.json`, the model assigns scores per the rubric, and
this script either (a) computes them from scratch given a
`(severity → count)` per cluster, or (b) re-checks the model's
arithmetic on an existing clusters.json. Either path beats trusting
the model to do hash-like math reliably.

Weights:
    Critical (and High+, which normalizes to Critical) = 8
    High                                                = 4
    Medium                                              = 2
    Low                                                 = 1
    Unknown                                             = 1

Sort: descending by total score, tiebreak by member count desc.
The top-scoring cluster gets `(Recommended)` in its `AskUserQuestion`
label (per parse_issues.md Step 3(c)).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


WEIGHTS = {
    "critical": 8,
    "high+": 8,   # High+ normalizes to Critical
    "high": 4,
    "medium": 2,
    "low": 1,
    "unknown": 1,
}


# Cluster names should be topic-derived (parse_issues.md Step 3(b):
# "short and concrete"). A degraded model run that falls back to
# `Cluster 1`, `Group 2`, etc. should fail loudly rather than slip
# through into the AskUserQuestion checkboxes — generic labels give
# the developer no signal about what's in the cluster.
#
# Allow the documented sentinel "Other clusters" (parse_issues.md
# Step 3(c) — used as the 4th slot when >4 clusters emerge).
_GENERIC_CLUSTER_NAME_RE = re.compile(
    r"^\s*(cluster|group|topic|category)\b\s*\d*\s*$",
    re.IGNORECASE,
)


def is_generic_cluster_name(name: str) -> bool:
    """True if `name` is a fallback placeholder rather than a topic."""
    return bool(_GENERIC_CLUSTER_NAME_RE.match(name or ""))


def weight_for(severity: str) -> int:
    """Map a severity label (case-insensitive) to its weight.

    Returns 1 (Unknown weight) for anything unrecognized — keeps the
    score finite rather than throwing, matching the prompt's "label
    as Unknown and sort it last" rule.
    """
    return WEIGHTS.get((severity or "").strip().lower(), 1)


def score_breakdown(breakdown: dict[str, int]) -> int:
    """Sum weighted severities. breakdown is `{severity: count}`."""
    total = 0
    for sev, count in (breakdown or {}).items():
        total += weight_for(sev) * int(count)
    return total


@dataclass
class Cluster:
    name: str
    members: list[dict]
    severity_breakdown: dict[str, int]

    @property
    def score(self) -> int:
        return score_breakdown(self.severity_breakdown)

    @property
    def member_count(self) -> int:
        return len(self.members)


def sort_clusters(clusters: list[Cluster]) -> list[Cluster]:
    """Sort by score desc, tiebreak by member count desc."""
    return sorted(
        clusters,
        key=lambda c: (-c.score, -c.member_count),
    )


def annotate_clusters_json(payload: dict[str, Any]) -> dict[str, Any]:
    """Take a clusters.json payload, compute `score` for every cluster,
    sort by the rubric, and return the new payload.

    Input shape (what parse_issues.md Step 3(b) instructs the model to write):
        {
          "clusters": [
            {"name": "...", "rationale": "...", "members": [...],
             "severity_breakdown": {"High": 7, "Medium": 1}}
          ]
        }

    Raises ValueError if any cluster carries a generic placeholder
    name (Cluster 1, Group 2, …). Names must be topic-derived per
    parse_issues.md Step 3(b).
    """
    raw = payload.get("clusters", []) or []
    generic = [c.get("name", "") for c in raw if is_generic_cluster_name(c.get("name", ""))]
    if generic:
        raise ValueError(
            "clusters.json carries generic placeholder name(s) "
            f"{generic!r} — names must be topic-derived per "
            "parse_issues.md Step 3(b). Re-invoke clustering and "
            "name each cluster after its subsystem or fix shape."
        )
    clusters = [
        Cluster(
            name=c.get("name", ""),
            members=c.get("members", []) or [],
            severity_breakdown=c.get("severity_breakdown", {}) or {},
        )
        for c in raw
    ]
    sorted_clusters = sort_clusters(clusters)
    out_clusters = []
    for i, c in enumerate(sorted_clusters):
        original = next(r for r in raw if r.get("name") == c.name)
        annotated = dict(original)
        annotated["score"] = c.score
        annotated["recommended"] = (i == 0)
        out_clusters.append(annotated)
    return {**payload, "clusters": out_clusters}


def main_with_argv(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "clusters_path",
        type=Path,
        help="Path to clusters.json. Annotated copy is written to stdout.",
    )
    args = parser.parse_args(argv)
    try:
        payload = json.loads(args.clusters_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: could not read {args.clusters_path}: {exc}", file=sys.stderr)
        return 1
    try:
        annotated = annotate_clusters_json(payload)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    json.dump(annotated, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def main() -> int:
    return main_with_argv(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
