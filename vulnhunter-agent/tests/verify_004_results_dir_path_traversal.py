"""Security test: VULN-004 — results-dir marker must not carry path traversal.

CWE-22. The vulnhunt-results-dir marker flows into the scratch run-dir name
and mkdir(parents=True). Extraction must reject markers containing '/', '\\',
or '..', and the sink must refuse a run_dir that escapes scratch_root.
"""

from pathlib import Path

import pytest

from agent.verify import _contained_run_dir
from agent.verify_extract import MarkerExtractionError, extract_markers


def _body(results_dir: str) -> str:
    return (
        "<!-- vulnfix-key: 0123456789abcdef -->\n"
        "<!-- vulnhunt-finding-id: VULN-001 -->\n"
        f"<!-- vulnhunt-results-dir: {results_dir} -->\n"
    )


def test_canonical_results_dir_still_extracts():
    m = extract_markers(_body("vulnhunter-oss_VULNHUNT_RESULTS_2026-07-12-191114"))
    assert m.results_dir == "vulnhunter-oss_VULNHUNT_RESULTS_2026-07-12-191114"


@pytest.mark.parametrize(
    "malicious",
    [
        "sess_../../../../var/tmp/pwn",
        "x_VULNHUNT_RESULTS_../../evil",
        "..x_VULNHUNT_RESULTS_2026",
        "a/b_VULNHUNT_RESULTS_2026",
        "a\\b_VULNHUNT_RESULTS_2026",
    ],
)
def test_traversal_bearing_results_dir_is_rejected(malicious):
    with pytest.raises(MarkerExtractionError):
        extract_markers(_body(malicious))


def test_contained_run_dir_allows_in_tree(tmp_path: Path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    rd = _contained_run_dir(scratch, "repo-2026-ts")
    assert rd.resolve().is_relative_to(scratch.resolve())


def test_contained_run_dir_rejects_escape(tmp_path: Path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    with pytest.raises(ValueError):
        _contained_run_dir(scratch, "repo-../../../../../../etc/pwn-ts")
