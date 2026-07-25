"""Materialize and score the Codex-grade comparative security corpus.

The corpus is intentionally local and deterministic. Running either scanner is
kept separate because provider credentials and execution authorization belong to
the benchmark operator. Both engines export normalized JSONL predictions:

{"fixture_id":"authz-01","instance_id":"authz-vulnerable","prediction":"REPORTABLE"}
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
from typing import Any


TEMPLATES: dict[str, list[dict[str, str]]] = {
    "authz": [
        {
            "id": "authz-vulnerable",
            "expect": "REPORTABLE",
            "severity": "High",
            "file": "controllers/account.py",
            "content": "def get_account(account_id):\n    return db.find_by_id(account_id)\n",
        },
        {
            "id": "authz-safe",
            "expect": "SAFE",
            "severity": "High",
            "file": "controllers/safe_account.py",
            "content": "def get_account(account_id, tenant_id):\n    return db.find(account_id=account_id, tenant_id=tenant_id)\n",
        },
        {
            "id": "authz-external-rls",
            "expect": "DEFERRED",
            "severity": "High",
            "file": "services/supabase_account.py",
            "content": "def get_account(client, account_id):\n    return client.table('accounts').select('*').eq('id', account_id).execute()\n",
        },
        {
            "id": "authz-negative-control",
            "expect": "SAFE",
            "severity": "Medium",
            "file": "services/constant.py",
            "content": "PUBLIC_ACCOUNT_TYPE = 'demo'\n",
        },
    ],
    "injection": [
        {
            "id": "injection-eval",
            "expect": "REPORTABLE",
            "severity": "Critical",
            "file": "handlers/eval_handler.py",
            "content": "def run(request):\n    return eval(request.body)\n",
        },
        {
            "id": "injection-safe-parser",
            "expect": "SAFE",
            "severity": "High",
            "file": "handlers/safe_parser.py",
            "content": "import ast\ndef run(request):\n    return ast.literal_eval(request.body)\n",
        },
        {
            "id": "injection-shell",
            "expect": "REPORTABLE",
            "severity": "High",
            "file": "handlers/shell.py",
            "content": "import subprocess\ndef run(request):\n    subprocess.run(request.command, shell=True)\n",
        },
        {
            "id": "injection-argv-control",
            "expect": "SAFE",
            "severity": "High",
            "file": "handlers/argv.py",
            "content": "import subprocess\ndef run(name):\n    subprocess.run(['/usr/bin/id', '--user', name], shell=False)\n",
        },
    ],
    "file": [
        {
            "id": "file-archive-traversal",
            "expect": "REPORTABLE",
            "severity": "High",
            "file": "storage/archive.py",
            "content": "def unpack(upload, destination):\n    upload.extractall(destination)\n",
        },
        {
            "id": "file-contained",
            "expect": "SAFE",
            "severity": "High",
            "file": "storage/safe_archive.py",
            "content": "def safe_join(root, name):\n    path=(root/name).resolve()\n    path.relative_to(root.resolve())\n    return path\n",
        },
        {
            "id": "file-mobile-root",
            "expect": "REPORTABLE",
            "severity": "High",
            "file": "res/xml/file_paths.xml",
            "content": "<paths><root-path name=\"all\" path=\".\" /></paths>\n",
        },
        {
            "id": "file-mobile-safe",
            "expect": "SAFE",
            "severity": "Medium",
            "file": "res/xml/safe_paths.xml",
            "content": "<paths><files-path name=\"exports\" path=\"exports/\" /></paths>\n",
        },
    ],
    "supply_chain": [
        {
            "id": "supply-mutable-installer",
            "expect": "REPORTABLE",
            "severity": "High",
            "file": ".github/workflows/deploy.yml",
            "content": "steps:\n  - run: curl -fsSL https://example.invalid/install | bash\n  - run: deploy --token \"${{ secrets.DEPLOY_TOKEN }}\"\n",
        },
        {
            "id": "supply-pinned-action",
            "expect": "SAFE",
            "severity": "Medium",
            "file": ".github/workflows/pinned.yml",
            "content": "steps:\n  - uses: actions/checkout@0123456789012345678901234567890123456789\n",
        },
        {
            "id": "supply-mutable-action",
            "expect": "REPORTABLE",
            "severity": "Medium",
            "file": ".github/workflows/mutable.yml",
            "content": "steps:\n  - uses: vendor/deploy-action@v2\n",
        },
        {
            "id": "supply-same-origin-checksum",
            "expect": "DEFERRED",
            "severity": "High",
            "file": ".github/workflows/checksum.yml",
            "content": "steps:\n  - run: curl -O https://example.invalid/tool && curl -O https://example.invalid/tool.sha256 && sha256sum -c tool.sha256\n",
        },
    ],
    "network_parser_secret": [
        {
            "id": "network-ssrf",
            "expect": "REPORTABLE",
            "severity": "High",
            "file": "routes/fetch.py",
            "content": "import requests\ndef fetch(request):\n    return requests.get(request.args['url'])\n",
        },
        {
            "id": "network-allowlist",
            "expect": "SAFE",
            "severity": "High",
            "file": "routes/safe_fetch.py",
            "content": "ALLOWED={'api.example.com'}\ndef fetch(host):\n    if host not in ALLOWED: raise ValueError()\n",
        },
        {
            "id": "parser-pickle",
            "expect": "REPORTABLE",
            "severity": "High",
            "file": "routes/import_data.py",
            "content": "import pickle\ndef load(request):\n    return pickle.loads(request.body)\n",
        },
        {
            "id": "secret-env-control",
            "expect": "SAFE",
            "severity": "High",
            "file": "config/secrets.py",
            "content": "import os\nAPI_KEY = os.environ['API_KEY']\n",
        },
    ],
}


def corpus() -> list[dict[str, Any]]:
    fixtures: list[dict[str, Any]] = []
    for template, cases in TEMPLATES.items():
        for index in range(1, 6):
            fixtures.append(
                {
                    "fixture_id": f"{template}-{index:02d}",
                    "template": template,
                    "cases": cases,
                }
            )
    return fixtures


def materialize(destination: Path) -> dict[str, int]:
    destination.mkdir(parents=True, exist_ok=True)
    fixtures = corpus()
    for fixture in fixtures:
        root = destination / fixture["fixture_id"]
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True)
        for case in fixture["cases"]:
            path = root / case["file"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(case["content"], encoding="utf-8")
        (root / "ground_truth.json").write_text(
            json.dumps(
                {
                    "schema_version": "1",
                    "fixture_id": fixture["fixture_id"],
                    "instances": [
                        {
                            key: case[key]
                            for key in ("id", "expect", "severity", "file")
                        }
                        for case in fixture["cases"]
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    return {
        "fixtures": len(fixtures),
        "instances": sum(len(row["cases"]) for row in fixtures),
    }


def score(predictions: Path) -> dict[str, float | int]:
    expected = {
        (fixture["fixture_id"], case["id"]): case["expect"]
        for fixture in corpus()
        for case in fixture["cases"]
    }
    observed: dict[tuple[str, str], dict[str, Any]] = {}
    for line in predictions.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        observed[(row["fixture_id"], row["instance_id"])] = row
    reportable = {key for key, value in expected.items() if value == "REPORTABLE"}
    predicted = {
        key for key, value in observed.items()
        if value.get("prediction") == "REPORTABLE"
    }
    true_positive = len(reportable & predicted)
    false_positive = len(predicted - reportable)
    false_negative = len(reportable - predicted)
    precision = true_positive / max(1, true_positive + false_positive)
    recall = true_positive / max(1, true_positive + false_negative)
    high_critical_misses = sum(
        1
        for fixture in corpus()
        for case in fixture["cases"]
        if case["expect"] == "REPORTABLE"
        and case["severity"] in {"High", "Critical"}
        and (fixture["fixture_id"], case["id"]) not in predicted
    )
    deferred = {key for key, value in expected.items() if value == "DEFERRED"}
    deferred_correct = sum(
        observed.get(key, {}).get("prediction") == "DEFERRED"
        for key in deferred
    )
    safe = {key for key, value in expected.items() if value == "SAFE"}
    safe_correct = sum(
        observed.get(key, {}).get("prediction") in {"SAFE", "SUPPRESSED"}
        for key in safe
    )
    reviewed = [
        row for row in observed.values() if row.get("review_survived") is not None
    ]
    coverage = [
        bool(row["coverage_closed"])
        for row in observed.values()
        if row.get("coverage_closed") is not None
    ]
    return {
        "labels": len(expected),
        "predictions": len(observed),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "precision": precision,
        "recall": recall,
        "high_critical_false_clean": high_critical_misses,
        "deferred_accuracy": deferred_correct / max(1, len(deferred)),
        "safe_suppression_accuracy": safe_correct / max(1, len(safe)),
        "unique_model_discoveries": sum(
            len(row.get("discoverers", [])) == 1
            and row.get("prediction") == "REPORTABLE"
            for row in observed.values()
        ),
        "review_survival_rate": (
            sum(bool(row["review_survived"]) for row in reviewed) / len(reviewed)
            if reviewed
            else 0.0
        ),
        "coverage_closure_rate": (
            sum(coverage) / len(coverage) if coverage else 0.0
        ),
        "cost_usd": sum(float(row.get("cost_usd", 0.0)) for row in observed.values()),
        "tokens": sum(int(row.get("tokens", 0)) for row in observed.values()),
        "duration_seconds": sum(
            float(row.get("duration_seconds", 0.0))
            for row in observed.values()
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    materialize_parser = subparsers.add_parser("materialize")
    materialize_parser.add_argument("destination", type=Path)
    score_parser = subparsers.add_parser("score")
    score_parser.add_argument("predictions", type=Path)
    args = parser.parse_args()
    result = (
        materialize(args.destination)
        if args.command == "materialize"
        else score(args.predictions)
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
