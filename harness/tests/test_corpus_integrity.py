"""Integrity checks for the shipped benchmark corpus.

Validates that the real ground_truth/ files satisfy the constraints the
benchmark runner assumes: valid JSON arrays, required fields present, globally
unique finding_id values, and well-formed source_code URLs.

Runs in ~0.05s with no network, no model, and no cloning.
"""

import json
import os

import pytest

import local_harness.benchmark.run as run
from local_harness.benchmark.run import _validate_benchmarks

GROUND_TRUTH_DIR = os.path.join(
    os.path.dirname(__file__), "..", "local_harness", "benchmark", "ground_truth"
)


def _load_corpus():
    """Load all *.json files from ground_truth/ the same way the runner does."""
    results = []
    for name in sorted(os.listdir(GROUND_TRUTH_DIR)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(GROUND_TRUTH_DIR, name)
        with open(path) as f:
            results.append((name, json.load(f)))
    return results


def test_corpus_loads_without_errors():
    """The shipped corpus must pass _validate_benchmarks with zero errors."""
    benchmarks = _load_corpus()
    assert benchmarks, "No corpus files found in ground_truth/"
    errors = _validate_benchmarks(benchmarks)
    assert errors == [], "Corpus validation failed:\n" + "\n".join(errors)


def test_finding_ids_globally_unique():
    """finding_id must be unique across all corpus files."""
    benchmarks = _load_corpus()
    seen = {}
    duplicates = []
    for filename, findings in benchmarks:
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            fid = finding.get("finding_id")
            if fid is None:
                continue
            if fid in seen:
                duplicates.append(f"{fid} appears in both {seen[fid]} and {filename}")
            else:
                seen[fid] = filename
    assert duplicates == [], "Duplicate finding IDs found:\n" + "\n".join(duplicates)


def test_validate_benchmarks_rejects_non_dict_entry():
    """A JSON array containing a non-object entry should produce a clear error."""
    benchmarks = [("bad.json", ["not-a-dict"])]
    errors = _validate_benchmarks(benchmarks)
    assert any("JSON object" in e for e in errors)


def test_validate_benchmarks_rejects_non_list_file():
    """A corpus file whose top-level value is not an array should produce a clear error."""
    benchmarks = [("bad.json", {"finding_id": "X"})]
    errors = _validate_benchmarks(benchmarks)
    assert any("JSON array" in e for e in errors)


def test_validate_benchmarks_rejects_missing_fields():
    """A finding missing required fields should produce a clear error."""
    benchmarks = [("bad.json", [{"finding_id": "X", "type": "SQLi"}])]
    errors = _validate_benchmarks(benchmarks)
    assert any("missing required fields" in e for e in errors)


def test_validate_benchmarks_rejects_bad_source_url():
    """A finding with a malformed source_code URL should produce a clear error."""
    benchmarks = [("bad.json", [{
        "finding_id": "X-001",
        "type": "SQLi",
        "description": "test",
        "source_code": "https://github.com/org/repo/blob/abc123/file.py",
    }])]
    errors = _validate_benchmarks(benchmarks)
    assert any("source_code" in e for e in errors)


def _finding(**overrides):
    base = {
        "finding_id": "X-001",
        "type": "SQLi",
        "description": "test",
        "source_code": "https://github.com/org/repo/tree/abc123",
    }
    base.update(overrides)
    return base


def test_validate_benchmarks_rejects_non_string_source_code():
    """A null (or other non-string) source_code must not reach url.startswith()."""
    benchmarks = [("bad.json", [_finding(source_code=None)])]
    errors = _validate_benchmarks(benchmarks)
    assert any("source_code must be a string" in e for e in errors)


def test_validate_benchmarks_rejects_non_string_finding_id():
    """A non-hashable finding_id (e.g. a list) must not reach `fid in seen_ids`."""
    benchmarks = [("bad.json", [_finding(finding_id=["X"])])]
    errors = _validate_benchmarks(benchmarks)
    assert any("finding_id must be a string" in e for e in errors)


@pytest.mark.parametrize(
    "bad_url",
    [
        "https://github.com/org/repo/tree/",  # empty hash -> parses to hash "tree"
        "https://github.com/tree/x",  # no org/repo -> parses to repo "x"
        "https://github.com/o/r/tree/abc/sub/file.py",  # trailing path -> hash "file.py"
    ],
    ids=["empty-hash", "repo-named-tree", "trailing-path-segments"],
)
def test_validate_benchmarks_rejects_source_url_shapes_that_misparse(bad_url):
    """Each of these passes the old substring check but mis-parses in parse_source_url()."""
    benchmarks = [("bad.json", [_finding(source_code=bad_url)])]
    errors = _validate_benchmarks(benchmarks)
    assert any("source_code" in e for e in errors), f"expected rejection for {bad_url!r}"


def test_load_all_benchmarks_reports_invalid_json(monkeypatch, tmp_path):
    """A corpus file with malformed JSON must go through the validation-error path,
    not raise a raw json.JSONDecodeError traceback."""
    bdir = tmp_path / "gt"
    bdir.mkdir()
    (bdir / "broken.json").write_text("[{,}]")
    monkeypatch.setattr(run, "BENCHMARK_DIR", str(bdir))

    with pytest.raises(SystemExit):
        run.load_all_benchmarks()
