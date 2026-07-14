"""Tests for scripts/cluster_score.py — risk-reduction scoring rubric.

The rubric lives in prompts/parse_issues.md Step 3(b); this test file
is the regression guard for the math.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from cluster_score import (  # noqa: E402
    Cluster,
    annotate_clusters_json,
    score_breakdown,
    sort_clusters,
    weight_for,
)


class TestWeightFor:
    @pytest.mark.parametrize(
        "severity,expected_weight",
        [
            ("Critical", 8),
            ("critical", 8),
            ("CRITICAL", 8),
            ("High+", 8),  # High+ normalizes to Critical
            ("high+", 8),
            ("High", 4),
            ("Medium", 2),
            ("Low", 1),
            ("Unknown", 1),
            ("", 1),  # missing severity gets Unknown weight
            ("Bogus", 1),  # unrecognized → Unknown weight
        ],
    )
    def test_rubric(self, severity, expected_weight):
        assert weight_for(severity) == expected_weight


class TestScoreBreakdown:
    def test_zero_breakdown(self):
        assert score_breakdown({}) == 0

    def test_single_severity(self):
        assert score_breakdown({"High": 5}) == 20

    def test_mixed_severities(self):
        # 7 High (28) + 1 Medium (2) = 30 — the rubric's worked example.
        assert score_breakdown({"High": 7, "Medium": 1}) == 30

    def test_high_plus_collapses_to_critical(self):
        assert score_breakdown({"High+": 1}) == 8
        assert score_breakdown({"High+": 2, "Critical": 1}) == 24


class TestSortClusters:
    def _c(self, name: str, breakdown: dict, members: int) -> Cluster:
        return Cluster(
            name=name,
            members=[{"vuln": f"VULN-{i}"} for i in range(members)],
            severity_breakdown=breakdown,
        )

    def test_descending_by_score(self):
        a = self._c("a", {"High": 3}, 3)   # 12
        b = self._c("b", {"Critical": 2}, 2)  # 16
        c = self._c("c", {"Medium": 4}, 4)  # 8
        result = sort_clusters([a, b, c])
        assert [x.name for x in result] == ["b", "a", "c"]

    def test_tiebreak_by_member_count_desc(self):
        # Both score 8 — Medium*4 (4 members) vs Critical (1 member).
        # Tie broken by member count desc — the 4-member cluster goes first.
        a = self._c("a", {"Critical": 1}, 1)  # 8, 1 member
        b = self._c("b", {"Medium": 4}, 4)    # 8, 4 members
        result = sort_clusters([a, b])
        assert [x.name for x in result] == ["b", "a"]

    def test_5_high_outranks_1_critical(self):
        """The user-facing rubric promise: a 5-High cluster (score 20)
        beats a 1-Critical cluster (score 8). Regression guard for the
        sorter."""
        high5 = self._c("high5", {"High": 5}, 5)
        crit1 = self._c("crit1", {"Critical": 1}, 1)
        result = sort_clusters([crit1, high5])
        assert result[0].name == "high5"


class TestAnnotateClustersJson:
    def test_writes_score_and_recommended(self):
        payload = {
            "clusters": [
                {"name": "Authn",
                 "rationale": "missing authz",
                 "members": [{"vuln": "VULN-001"}, {"vuln": "VULN-002"}],
                 "severity_breakdown": {"High": 7, "Medium": 1}},
                {"name": "TLS",
                 "rationale": "outbound TLS",
                 "members": [{"vuln": "VULN-005"}],
                 "severity_breakdown": {"High": 3, "Medium": 2}},
            ]
        }
        out = annotate_clusters_json(payload)
        names = [c["name"] for c in out["clusters"]]
        assert names == ["Authn", "TLS"]  # 30 > 16
        assert out["clusters"][0]["score"] == 30
        assert out["clusters"][0]["recommended"] is True
        assert out["clusters"][1]["score"] == 16
        assert out["clusters"][1]["recommended"] is False

    def test_preserves_unknown_fields(self):
        payload = {
            "clusters": [
                {"name": "x", "extra_field": "preserve me", "members": [],
                 "severity_breakdown": {"High": 1}}
            ],
            "top_level_extra": "also preserve",
        }
        out = annotate_clusters_json(payload)
        assert out["clusters"][0]["extra_field"] == "preserve me"
        assert out["top_level_extra"] == "also preserve"

    def test_empty_clusters_no_crash(self):
        assert annotate_clusters_json({"clusters": []}) == {"clusters": []}

    @pytest.mark.parametrize(
        "generic_name",
        ["Cluster 1", "Cluster 2", "cluster 3", "Group 1", "Topic 5", "Category", "Cluster"],
    )
    def test_rejects_generic_cluster_names(self, generic_name):
        payload = {
            "clusters": [
                {"name": generic_name, "members": [{}, {}], "severity_breakdown": {"High": 2}},
            ]
        }
        with pytest.raises(ValueError, match="generic placeholder"):
            annotate_clusters_json(payload)

    def test_allows_topic_derived_names(self):
        # Concrete topic-derived names pass straight through.
        payload = {
            "clusters": [
                {"name": "TLS hardening", "members": [{}], "severity_breakdown": {"High": 1}},
                {"name": "Auth boundaries", "members": [{}], "severity_breakdown": {"Medium": 1}},
                {"name": "Other clusters", "members": [{}], "severity_breakdown": {"Low": 1}},
            ]
        }
        out = annotate_clusters_json(payload)
        assert [c["name"] for c in out["clusters"]] == [
            "TLS hardening",
            "Auth boundaries",
            "Other clusters",
        ]


class TestCli:
    def test_round_trip_via_file(self, tmp_path):
        import subprocess
        script = Path(__file__).resolve().parents[1] / "scripts" / "cluster_score.py"
        clusters = tmp_path / "clusters.json"
        clusters.write_text(json.dumps({
            "clusters": [
                {"name": "a", "members": [], "severity_breakdown": {"Critical": 1}},
                {"name": "b", "members": [], "severity_breakdown": {"High": 5}},
            ]
        }))
        result = subprocess.run(
            [sys.executable, str(script), str(clusters)],
            capture_output=True, text=True, check=True,
        )
        out = json.loads(result.stdout)
        # b's 5-High (20) outranks a's 1-Critical (8); b is recommended.
        assert out["clusters"][0]["name"] == "b"
        assert out["clusters"][0]["recommended"] is True
