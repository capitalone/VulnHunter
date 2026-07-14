"""Global per-finding detection history tracker.

Maintains local_harness/finding_history.json with detection/miss timestamps
for every benchmark finding across all runs.
"""

import json
import os
import time

from local_harness.config import HISTORY_FILE, atomic_write_json


def load_history():
    if not os.path.isfile(HISTORY_FILE):
        return {}
    try:
        with open(HISTORY_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        print(f"  WARNING: {HISTORY_FILE} is corrupt, starting fresh")
        return {}


def save_history(history):
    atomic_write_json(HISTORY_FILE, history, sort_keys=True)


def update_history(state, targets):
    """Append current run results to finding_history.json.

    Returns (recorded_count, skipped_count).
    """
    ts = int(time.time())
    history = load_history()

    in_scope = set()
    for target in targets.values():
        for finding in target["findings"]:
            in_scope.add(finding["finding_id"])

    recorded = 0
    skipped = 0

    for finding_id in sorted(in_scope):
        judgment = state.get("judgments", {}).get(finding_id)
        if judgment is None or judgment.get("detected") is None:
            skipped += 1
            continue

        if finding_id not in history:
            history[finding_id] = {"detected": [], "missed": []}

        if judgment["detected"]:
            history[finding_id]["detected"].append(ts)
        else:
            history[finding_id]["missed"].append(ts)
        recorded += 1

    save_history(history)
    return recorded, skipped


def get_stable_findings(threshold=3):
    """Return finding IDs that were detected in every one of the last `threshold` runs."""
    history = load_history()
    stable = set()

    for finding_id, data in history.items():
        entries = (
            [(ts, True) for ts in data.get("detected", [])]
            + [(ts, False) for ts in data.get("missed", [])]
        )
        # Secondary key makes ordering deterministic when a detected and a
        # missed entry share the same second-granularity timestamp.
        entries.sort(key=lambda x: (x[0], x[1]))

        if len(entries) < threshold:
            continue

        last_n = entries[-threshold:]
        if all(detected for _, detected in last_n):
            stable.add(finding_id)

    return stable
