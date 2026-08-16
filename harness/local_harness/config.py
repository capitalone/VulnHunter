"""Shared constants for the VulnHunter test harness."""

import json
import os
import tempfile

HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HARNESS_DIR)

BENCHMARK_DIR = os.path.join(HARNESS_DIR, "benchmark", "ground_truth")
CLONE_BASE_DIR = os.path.join(HARNESS_DIR, "benchmark_repos")
RESULTS_DIR = os.path.join(HARNESS_DIR, "benchmark_results")
STATE_FILE = os.path.join(RESULTS_DIR, "state.json")
TALLY_FILE = os.path.join(RESULTS_DIR, "tally.json")
TALLY_REPORT = os.path.join(RESULTS_DIR, "BENCHMARK_REPORT.md")

MAX_SCAN_WORKERS = 5
SCAN_TIMEOUT = 21600  # 6 hours
JUDGE_TIMEOUT = 600  # 10 minutes (batched judging can be larger)
CLONE_TIMEOUT = 300  # 5 minutes
MODEL = "claude-opus-4-8"

# --- Retry configuration for 429 rate limiting ---
SCAN_MAX_RETRIES = 3
SCAN_RETRY_INITIAL_BACKOFF = 60
SCAN_RETRY_BACKOFF_MULTIPLIER = 2.0
SCAN_RETRY_MAX_BACKOFF = 300

JUDGE_MAX_RETRIES = 3
JUDGE_RETRY_INITIAL_BACKOFF = 30
JUDGE_RETRY_BACKOFF_MULTIPLIER = 2.0
JUDGE_RETRY_MAX_BACKOFF = 180

SKILLS_DIR = os.path.expanduser("~/.claude/skills/vulnhunt")
PHASES_DIR = os.path.join(SKILLS_DIR, "phases")

# --- Scan/judge engine selection -----------------------------------------
# Which agent harness drives scans (and, separately, the judge). The skills
# must be installed for that harness (./install.sh --target <engine> from the
# repo root). Override via VULNHUNT_HARNESS_ENGINE / VULNHUNT_HARNESS_JUDGE_ENGINE.
# Judging with a DIFFERENT engine than the scanner avoids self-preference
# bias — e.g. scan with hermes, judge with claude-code.
ENGINE = os.environ.get("VULNHUNT_HARNESS_ENGINE", "claude-code")
JUDGE_ENGINE = os.environ.get("VULNHUNT_HARNESS_JUDGE_ENGINE", ENGINE)

ENGINES = {
    "claude-code": {
        "binary": "claude",
        "skills_dir": "~/.claude/skills/vulnhunt",
    },
    "hermes": {
        "binary": "hermes",
        "skills_dir": "~/.hermes/skills/vulnhunt",
    },
    "copilot": {
        "binary": "copilot",
        "skills_dir": "~/.copilot/skills/vulnhunt",
    },
    "codex": {
        "binary": "codex",
        "skills_dir": "~/.codex/skills/vulnhunt",
    },
}

for _name in (ENGINE, JUDGE_ENGINE):
    if _name not in ENGINES:
        raise ValueError(
            f"unknown harness engine {_name!r} (supported: {', '.join(sorted(ENGINES))})"
        )

# Engine-aware skills location (same value as SKILLS_DIR for claude-code).
ENGINE_SKILLS_DIR = os.path.expanduser(ENGINES[ENGINE]["skills_dir"])

# --- Batch scanning (ad-hoc URL list) ---
BATCH_CLONE_BASE_DIR = os.path.join(REPO_ROOT, "repos_being_scanned")
BATCH_REPO_LIST_FILE = os.path.join(HARNESS_DIR, "batch", "REPO_LIST.txt")
BATCH_UPLOAD_DIR = os.path.join(REPO_ROOT, "to_upload")
BATCH_LOG_FILENAME = "batch_scan.log"

# --- Finding history ---
HISTORY_FILE = os.path.join(HARNESS_DIR, "finding_history.json")


def atomic_write_json(path, obj, *, indent=2, sort_keys=False):
    """Write JSON to `path` atomically.

    A crash or SIGINT mid-write would otherwise leave a truncated file that
    later reads (state resume, history) can't parse. Writing to a temp file in
    the same directory and os.replace()-ing it in makes the swap atomic on
    POSIX, so readers always see either the old or the complete new content.
    """
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, indent=indent, sort_keys=sort_keys)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
