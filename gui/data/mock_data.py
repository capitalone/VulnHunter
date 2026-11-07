"""Mock data for the demo gui: a happy-path replay of a real VulnHunter run.

Modeled on the structure of a previous internal read-only scan: finding format,
severity mix, phase order and agent counts. Repository, file and field names are
generic placeholders. Statuses beyond Open/Verified, the extra history
rows and the log line wording are synthetic, so the table shows every status.
"""
from dataclasses import dataclass

REPO_URL = "https://github.com/sample-org/sample-backend"
ISSUES_URL = REPO_URL + "/issues"


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    location: str
    status: str
    cwe: str = ""
    issue: int = 0  # GitHub issue number in the scanned repo, 0 if none

    @property
    def issue_url(self):
        return f"{ISSUES_URL}/{self.issue}" if self.issue else ""


@dataclass
class ScanRecord:
    repo: str
    model: str
    mode: str
    date: str
    findings: list
    output: list
    tokens: str = "n/a"
    duration: str = "n/a"


# Model menu label -> model ID shown in the scan log. Matches vulnhunt.sh, where
# the DeepSeek option maps Opus to deepseek-v4-pro. OpenAI and Gemini stay disabled.
MODEL_IDS = {
    "Claude Opus": "claude-opus-5-5",
    "DeepSeek": "deepseek-v4-pro",
}
DISABLED_MODELS = ["OpenAI", "Gemini"]

# Severity tiers, highest first. This is the only place that sets the order:
# reverse this list to flip the table sort and the tracker rows. (The repo's
# GitHub issues list low to high, so reverse it to match that view.)
SEVERITY_ORDER = ["High+", "High", "Medium", "Low", "Informational"]

# Findings modeled on a previous scan: 0 High+, 3 High, 0 Medium, 4 Low, 0 Informational.
# Issue numbers are placeholders. Statuses are synthetic.
SAMPLE_FINDINGS = [
    Finding("VULN-003", "High", "OS command injection via label in fetch_clips.py",
            "scripts/dataset/fetch_clips.py:78", "PR open", "CWE-78", 1),
    Finding("VULN-005", "High", "OS command injection via url in trim_clips.py",
            "scripts/dataset/trim_clips.py:17", "Open", "CWE-78", 2),
    Finding("VULN-006", "High", "OS command injection via label in trim_clips.py",
            "scripts/dataset/trim_clips.py:17", "Open", "CWE-78", 3),
    Finding("VULN-002", "Low", "Unbounded request body on /infer",
            "server/app.py:147", "Verified", "CWE-400", 4),
    Finding("VULN-004", "Low", "Path traversal / arbitrary directory creation in fetch_clips.py",
            "scripts/dataset/fetch_clips.py:69", "Merged", "CWE-22", 5),
    Finding("VULN-007", "Low", "Path traversal of the output path in trim_clips.py",
            "scripts/dataset/trim_clips.py:15", "Open", "CWE-22", 6),
    Finding("VULN-008", "Low", "Cleartext, unverified dataset download",
            "tools/dataset_download.py:219", "Open", "CWE-494", 7),
]

# Replay of the real phase sequence: 1 recon, 9 trace agents + 1 sink-driven agent,
# verify, reproduce/test/fix, sweep, report.
SAMPLE_OUTPUT = [
    "[scan] target: " + REPO_URL,
    "[scan] branch main @ abc1234 | model {model_id} | mode read-only",
    "[scan] read-only: no dependencies installed, target source not modified",
    "",
    "[phase 1] recon: mapping entry points and sinks",
    "[phase 1] found 27 inputs across 12 entry points",
    "[phase 1] partitions: SG-1 inference server (4), SG-2 dataset scripts, SG-3 training and download tooling",
    "[phase 1] input #18 (train.py CLI args) was unassigned, added to SG-3",
    "",
    "[phase 2] wave 1: INJ, NAV, LOG trace agents on SG-1 and SG-2",
    "[phase 2] SG-1 INJ done: 0 candidates",
    "[phase 2] SG-2 NAV done: 0 candidates",
    "[phase 2] SG-1 NAV done: 0 candidates",
    "[phase 2] SG-1 LOG done: 2 candidates (/infer resource use)",
    "[phase 2] SG-2 LOG done: 0 candidates",
    "[phase 2] SG-2 INJ done: 5 candidates (3x CWE-78, 2x CWE-22)",
    "[phase 2] wave 2: INJ, NAV, LOG trace agents on SG-3",
    "[phase 2] SG-3 NAV done: 0 candidates",
    "[phase 2] SG-3 INJ done: 0 candidates (zip-slip blocked by CPython zipfile)",
    "[phase 2] SG-3 LOG done: 2 candidates (dataset download over plain HTTP)",
    "[phase 2] wave 3: sink-driven audit, tracing backward from dangerous sinks",
    "[phase 2] sink-driven audit done: 0 new candidates",
    "[phase 2] all 10 agents reported, 27 of 27 inputs covered",
    "[phase 2] aggregation: 9 candidates",
    "",
    "[phase 2b] adversarial verification: trying to disprove each candidate",
    "[phase 2b] VULN-001 rejected -> code quality (inference is the endpoint's intended function)",
    "[phase 2b] VULN-009 rejected -> false positive (downloader is dead code)",
    "[phase 2b] confirmed 7 of 9: 3 High, 4 Low",
    "",
    "[phase 3] writing PoCs and exploit tests (not executed in read-only mode)",
    "[phase 3] fix strategies: subprocess argv list (RC-1), path allow-list (RC-2), HTTPS + SHA-256 (RC-3), MAX_CONTENT_LENGTH (RC-4)",
    "[phase 3d] sweep for sibling instances of each root cause",
    "[phase 3d] no new instances; instance counts match for RC-1 to RC-4",
    "",
    "[phase 4] compiling report",
    "[+] VULN-003 High   fetch_clips.py:78      CWE-78",
    "[+] VULN-005 High   trim_clips.py:17         CWE-78",
    "[+] VULN-006 High   trim_clips.py:17         CWE-78",
    "[+] VULN-002 Low    server/app.py:147  CWE-400",
    "[+] VULN-004 Low    fetch_clips.py:69      CWE-22",
    "[+] VULN-007 Low    trim_clips.py:15         CWE-22",
    "[+] VULN-008 Low    dataset_download.py:219  CWE-494",
    "[done] 7 findings: 0 High+, 3 High, 0 Medium, 4 Low, 0 Informational",
]

def scan_output(model_label):
    """SAMPLE_OUTPUT with the model ID of the chosen menu entry filled in."""
    model_id = MODEL_IDS.get(model_label, model_label)
    return [line.replace("{model_id}", model_id) for line in SAMPLE_OUTPUT]


SCAN_TOKENS = "1.75M"
SCAN_DURATION = "19 min"

# Scans already in the history table when the app opens (newest first).
# Only the first row is the real run (Claude Opus); the others are invented.
SEED_HISTORY = [
    ScanRecord("sample-org/sample-backend", "Claude Opus", "Live", "Oct 23, 2026",
               list(SAMPLE_FINDINGS), scan_output("Claude Opus"), "1.75M", "19 min"),
    # Synthetic: same findings replayed as a DeepSeek run to exercise that menu entry.
    ScanRecord("sample-org/sample-backend", "DeepSeek", "Demo", "Oct 24, 2026",
               list(SAMPLE_FINDINGS), scan_output("DeepSeek"), "n/a", "n/a"),
    ScanRecord("sample-org/payments-api", "Claude Opus", "Demo", "Oct 20, 2026",
               [Finding("VULN-001", "High+", "Hardcoded API key (sample)",
                        "src/config/settings.py:12", "Verified", "CWE-798")],
               ["# invented sample scan", "[done] 1 finding"], "n/a", "n/a"),
    ScanRecord("sample-org/clean-service", "Claude Opus", "Demo", "Oct 18, 2026",
               [], ["# invented sample scan", "[done] 0 findings"], "n/a", "n/a"),
]
