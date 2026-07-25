from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _module():
    path = (
        Path(__file__).resolve().parents[1]
        / "benchmarks"
        / "codex_grade_corpus.py"
    )
    spec = importlib.util.spec_from_file_location("codex_grade_corpus", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_benchmark_has_25_fixtures_and_100_labels(tmp_path: Path) -> None:
    module = _module()

    summary = module.materialize(tmp_path / "corpus")

    assert summary == {"fixtures": 25, "instances": 100}
    truth = json.loads(
        (tmp_path / "corpus" / "authz-01" / "ground_truth.json").read_text()
    )
    assert len(truth["instances"]) == 4
    assert {row["expect"] for row in truth["instances"]} == {
        "REPORTABLE",
        "DEFERRED",
        "SAFE",
    }


def test_benchmark_scorer_reports_false_clean_metrics(tmp_path: Path) -> None:
    module = _module()
    predictions = tmp_path / "predictions.jsonl"
    predictions.write_text(
        json.dumps(
            {
                "fixture_id": "authz-01",
                "instance_id": "authz-vulnerable",
                "prediction": "REPORTABLE",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    metrics = module.score(predictions)

    assert metrics["labels"] == 100
    assert metrics["true_positive"] == 1
    assert metrics["false_negative"] > 0
    assert metrics["high_critical_false_clean"] > 0
