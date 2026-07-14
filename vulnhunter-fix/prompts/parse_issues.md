# Phase 1 (in-place mode): Parse Issues

## When this prompt runs

Use this prompt instead of `parse.md` when the skill is invoked in **in-place mode** — i.e., the user runs `/vulnhunter-fix` from inside an already-checked-out target repo, without passing `TARGET_REPO`. See `SKILL.md` for mode dispatch.

**Two sub-shapes:**
- **Default:** no `RESULTS_PATH` — findings come from `vulnhunter`-labeled issues on `origin` (Steps 1–5 below).
- **`RESULTS_PATH` supplied:** findings come from a local scan-results directory or URL — skip the issue-harvest steps via **Step 0** below.

## Step 0: RESULTS_PATH short-circuit (skip when `$RESULTS_PATH` is unset)

If the mode-dispatch line from `detect_mode.sh` includes `results=<path>`, the operator supplied findings on disk. Skip Steps 1–4 (which harvest issues from GitHub) and jump directly to Step 5a's README-extraction path, sourced from `$RESULTS_PATH` instead of a cloned publish repo.

Set the following in `work.json` before proceeding:
```json
{
  "mode": "in_place",
  "no_source_issues": true,
  "results_path": "<absolute or resolved RESULTS_PATH>",
  ...
}
```

Downstream renderers (`deliver.md`, `templates/pr_body_cluster.md`) branch on `no_source_issues` to switch PR-body language from `Closes #N` to `Addresses VULN-N per <results_path>` — no changes to `deliver.md` are needed here.

**Resolving `RESULTS_PATH`:**
- If it points at a local directory containing a scan `README.md`, use it as-is.
- If it's a git URL (owner/repo or full https), clone shallow into `.vulnhunter-fix/results-clone/`:
  ```bash
  git clone --depth 1 "$RESULTS_PATH" .vulnhunter-fix/results-clone
  RESULTS_PATH=".vulnhunter-fix/results-clone"
  ```
- Verify a README.md is present; abort with a diagnostic if not.

Then continue at **Step 5a** with `RESULTS_PATH` as the results directory. Skip Step 5's "clone publish repo" preamble.

---

## Inputs (default path — no `RESULTS_PATH`)

- **CWD** = target repo root (already validated by mode dispatch + Step 1b auth check)
- **Optional positional args**: explicit issue URLs the user wants to process. If absent, discovery harvests all open `vulnhunter`-labeled issues on `origin`.
- **`vulnhunt-results-dir` marker** in each issue body identifies the corresponding scan results directory.

## Actions

> **Implementation principle: cheapest model that gets it right.**
>
> Several steps below are "transform JSON A into JSON B" — extract severity, walk a README, join by key, etc. Three tiers, pick by cost:
>
> 1. **Trivial extraction** (single field, simple filter): `jq -r .field file.json`. No escapes, no regex. Fine inline.
> 2. **Small transform you already have everything for** (filter by selected numbers, join two in-context JSONs by key, render a markdown table): the main agent does it directly using the `Write` tool. No subprocess, no extra LLM call.
> 3. **Large mechanical scan over a big blob** — delegate to a subagent via the `Agent` tool with `subagent_type: "general-purpose"`. Pick the model carefully:
>    - **`model: "haiku"`** for shape-stable transforms over well-defined input (e.g., the Step 3(a) severity annotation: every issue body has the same `**Severity** | <val>` row format).
>    - **`model: "sonnet"`** for shape-variable transforms where the input layout drifts run-to-run (e.g., the Step 5a README extraction: rollup-subsumed findings, multi-CWE rows, varying detail-section field labels — Haiku has dropped findings on real reports). Sonnet costs more per token but is order-of-magnitude more reliable when the input doesn't fit a single pattern.
>
> When in doubt between Haiku and Sonnet for a subagent transform, **prefer Sonnet** — a missed finding or wrong field value silently propagates through the whole pipeline (re-runs, manual injections, lost work). The Haiku cost saving rarely pays for that.
>
> Multi-line `jq` pipelines inside bash heredocs are a fourth option that **we don't use** — they keep biting us on shell quoting (`\!=`, `\\*\\*`, alternation order) and silently drop rows. Move that work up one tier.

### Step 1: Fetch issues from GitHub (via Bash)

All network calls happen in Bash blocks (Claude's Bash tool has the working TLS context that Python subprocesses don't). Discovery and explicit-URL paths both produce the same shape: a JSON array of issue objects with `number`, `url`, `title`, `body`.

> **Read the "`git` + `gh` failure policy" section of `SKILL.md` before continuing.** Any `gh` call below that fails with `tls: failed to verify certificate`, `OSStatus -…`, or other transport-level errors means **STOP and ask the user to run the single command in their own terminal**. Do not retry. Do not try `git ls-remote` or `curl` as a substitute. Do not call a different `gh` subcommand hoping it works. The same rule applies to `git` — including the `git clone` of the publish repo in Step 4. One command at a time, wait for the user to paste, then continue.

```bash
mkdir -p .vulnhunter-fix

# OWNER_REPO was computed in SKILL.md mode dispatch. Pass --repo to
# every gh call so the same command also works when the user pastes
# it into their own terminal (their gh may lack `gh repo set-default`).

# Discovery — no args, every open vulnhunter-labeled issue on origin
gh issue list \
    --repo "$OWNER_REPO" \
    --label vulnhunter \
    --state open \
    --limit 200 \
    --json number,url,title,body \
    > .vulnhunter-fix/raw_issues.json

# Or, when the user supplied explicit URLs: fetch each one and combine.
# Replace the loop with the URLs you were given.
# : > .vulnhunter-fix/raw_issues.json
# echo "[" > .vulnhunter-fix/raw_issues.json
# first=1
# for url in https://github.com/org/repo/issues/42 https://github.com/org/repo/issues/43; do
#     number="${url##*/}"
#     [ $first -eq 1 ] || echo "," >> .vulnhunter-fix/raw_issues.json
#     gh issue view "$number" --repo "$OWNER_REPO" \
#         --json number,url,title,body \
#         >> .vulnhunter-fix/raw_issues.json
#     first=0
# done
# echo "]" >> .vulnhunter-fix/raw_issues.json
```

If `gh issue list` exits non-zero, surface stderr and stop. Common failure shapes:

| Symptom | Cause | Action |
|---------|-------|--------|
| `no issues match your search` (empty array) | Repo has no findings yet, or all were closed | Stop and tell the user. |
| `HTTP 404` on `gh issue list` | `vulnhunter` label doesn't exist on origin | Stop; the user should run the scanner first so it creates the label and posts issues. |
| `gh: not authenticated` | `gh auth` not set | The Step 1b auth check should have caught this. Re-run `gh auth login`. |

### Step 2: Extract markers + enforce homogeneity (one `python3 -c` call)

Marker regexes and the homogeneity check live in `scripts/issue_intake.py` (small, well-tested). Call them from a `python3 -c` snippet — no separate wrapper script needed.

```bash
RESULTS_DIR_NAME_AND_OWNERS="$(python3 - <<'PY'
import json, os, sys
sys.path.insert(0, os.environ["SKILL_DIR"] + "/scripts")
from issue_intake import extract_markers, MarkerExtractionError, enforce_homogeneity, IssueRecord

raw = json.load(open(".vulnhunter-fix/raw_issues.json"))
records = []
for issue in raw:
    body = issue.get("body", "") or ""
    try:
        markers = extract_markers(body, source_label=f"issue #{issue['number']}")
    except MarkerExtractionError as e:
        print(f"warn: {e} — skipping", file=sys.stderr)
        continue
    # Parse owner/repo from the issue URL: https://<host>/<owner>/<repo>/issues/N
    parts = issue["url"].rstrip("/").split("/")
    owner, repo = parts[-4], parts[-3]
    records.append(IssueRecord(
        owner=owner, repo=repo, number=int(issue["number"]),
        url=issue["url"], title=issue.get("title", ""),
        body_tampered=False, original_body=body, markers=markers,
    ))

if not records:
    print("error: no usable issues — none carried valid vulnhunter markers", file=sys.stderr)
    sys.exit(1)

owner, repo, results_dir = enforce_homogeneity(records)

# Emit the canonical intake.json shape.
intake = {
    "owner": owner, "repo": repo, "results_dir": results_dir,
    "issues": [
        {
            "number": r.number, "url": r.url, "title": r.title,
            "body_tampered": r.body_tampered,
            "markers": {
                "vulnfix_key": r.markers.vulnfix_key,
                "finding_id": r.markers.finding_id,
                "results_dir": r.markers.results_dir,
            },
        }
        for r in records
    ],
}
json.dump(intake, open(".vulnhunter-fix/intake.json", "w"), indent=2)
print(f"{owner}/{repo}::{results_dir}")
PY
)"

# Determine the default branch — derive it locally from git refs
# (NO network call). Fallback chain:
#   1. origin/HEAD symref (set automatically on `git clone`)
#   2. main / master if they exist on the remote
#   3. currently-checked-out branch
# All three are git-local: no `gh` call, no TLS path, no user-paste.
DEFAULT_BRANCH="$(git symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null \
    | sed 's|^origin/||')"
if [ -z "$DEFAULT_BRANCH" ]; then
    for b in main master; do
        if git rev-parse --verify --quiet "refs/remotes/origin/$b" >/dev/null 2>&1; then
            DEFAULT_BRANCH="$b"
            break
        fi
    done
fi
[ -z "$DEFAULT_BRANCH" ] && DEFAULT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"

# Splice default_branch into intake.json. The python heredoc above
# already wrote the file; we add this one field via Python rather
# than a jq round-trip (in/out parse, temp file rename).
python3 - "$DEFAULT_BRANCH" <<'PY'
import json, sys
path = ".vulnhunter-fix/intake.json"
data = json.load(open(path))
data["default_branch"] = sys.argv[1]
json.dump(data, open(path, "w"), indent=2)
PY
```

After this step, `.vulnhunter-fix/intake.json` carries `owner`, `repo`, `results_dir`, `default_branch`, and an `issues` array — each entry has the three machine markers extracted from the body.

> **Edit-history reconstruction was dropped from v1.** If a developer edits the issue body and removes the markers, the issue is skipped (with a warning). This is acceptable for the common case where the scanner posts canonical issue bodies. To re-add reconstruction later, fetch `gh api graphql` for each issue's `userContentEdits` and feed them to `reconstruct_original` before `extract_markers`.

### Step 3: Present harvested issues and ask the user which to work on

**Always ask.** Three-part interaction: list, group, choose.

**(a) Annotate intake with severities + show the table.** Delegate this to a Haiku subagent so the main agent doesn't burn Opus/Sonnet tokens iterating over every issue body. Use the `Agent` tool with `subagent_type: "general-purpose"` and `model: "haiku"`.

The subagent's job (specify all of this in its `prompt`):

1. Read `.vulnhunter-fix/raw_issues.json` (full body of every harvested issue) AND `.vulnhunter-fix/intake.json` (the in-progress intake produced by Step 2).
2. For each issue, find the `**Severity** | <value>` row in the raw_issues.json `.body`. Recognize `Critical`, `High+`, `High`, `Medium`, `Low`. **Normalize `High+` → `Critical`**.
3. If no severity row, label that issue `Unknown` (don't drop it).
4. Sort `.issues` so Critical is first, then High, Medium, Low, Unknown.
5. Overwrite `.vulnhunter-fix/intake.json` with the annotated JSON via the `Write` tool. Schema = existing intake fields (number, url, title, body_tampered, markers) + a `severity` field on each issue. **Do NOT copy the `body` field over from raw_issues.json** — body lives in raw_issues.json only; intake.json stays small. Preserve the top-level `owner`, `repo`, `results_dir`, `default_branch` that Step 2 wrote.
6. **Reply with the markdown table** (and nothing else — no prose, no summary). Columns:
   - `# | Severity | VULN | Title | URL`
   - One row per issue, in the sorted order. VULN comes from `.markers.finding_id`.

Why Haiku and not the main agent: this is mechanical regex + JSON shuffling over a ~90KB blob. Sonnet/Opus would do the same work for ~5x the cost. The subagent has just enough tool access (`Read`, `Write`) to do its job and nothing more.

After the subagent returns, **display its response verbatim** — that's the table the user sees. The annotated `intake.json` is already on disk for step 3(b/c) and step 6.

Example issue entry after annotation:

```json
{
  "number": 17,
  "url": "...",
  "title": "...",
  "body_tampered": false,
  "severity": "Critical",
  "markers": {
    "vulnfix_key": "...",
    "finding_id": "VULN-017",
    "results_dir": "..."
  }
}
```

Do not include the `body` field — it lives in `raw_issues.json` and bloats `intake.json` unnecessarily. Sort `.issues` so Critical comes first, then High, Medium, Low, Unknown.

**(b) Cluster findings into logical PR-able groups (when `N > 4`).** Read each issue body in `raw_issues.json` and group findings by **topic**: same subsystem (auth, TLS, CORS, DB access, logging, …), or same fix shape (add input validation, set timeouts, scope CORS origins, …). Aim for **2–4 clusters**. Cluster names should be short (≤ 5 words) and concrete:

- Good: `CORS hardening`, `Authorization checks`, `Outbound TLS`, `Concurrency / races`
- Bad: `Security improvements`, `Code quality`, `Various`

Each cluster has: a `name`, a one-sentence rationale (e.g., *"Five findings all add missing authorization at HTTP handler boundaries"*), and a `members` list of issue numbers + VULN IDs.

**The cluster IS the delivery unit.** In interactive (in-place) mode, every cluster the developer picks lands as **one cohesive PR** on one branch — not one PR per finding. That's the whole point of clustering: a reviewer reads one PR that addresses a topic end-to-end. Per-finding TDD evidence (exploit demo + RED→GREEN test + fix) is preserved as separate commits within the cluster's branch. (Fork mode does the opposite — strict one-PR-per-finding — see `plan.md`.)

Heuristic for choosing cluster boundaries: if the same engineer would naturally land these as **one PR** touching the same general subsystem (even across a few files), they belong together. Don't fight it: a cluster with 8 findings across 4 files is fine if the topic is coherent. Severity is **not** the grouping criterion — topic is. (Severity bucketing is the fallback in part (c) only if clustering yields no useful groups.)

**Rank clusters by risk-reduction score** so the user sees the highest-impact remediation first. For each cluster, sum the severity weights of its members:

| Severity | Weight |
|----------|--------|
| Critical *(also: `High+` — treat as Critical)* | 8 |
| High | 4 |
| Medium | 2 |
| Low | 1 |
| Unknown | 1 |

`High+` from older reports is semantically equivalent to Critical — normalize it to Critical before scoring.

Sort clusters descending by total score. Tiebreak by member count descending (a tied cluster with more findings covers more surface and goes first). The top-scoring cluster gets `(Recommended)` appended to its label in part (c).

This rewards both severity AND breadth: a 5-High cluster (score 20) outranks a 1-Critical cluster (score 8), and a 4-Medium cluster (score 8) ties with the 1-Critical and breaks the tie on member count. That matches a "biggest risk reduction this run" heuristic better than the previous "highest peak severity present" rule, which couldn't distinguish a 1-Critical cluster from a 5-Critical one.

Write the clusters to `.vulnhunter-fix/clusters.json` in the sorted order, with each cluster's `score` and `severity_breakdown` included for transparency (normalize `High+` → `Critical` in the breakdown as well):

```json
{
  "clusters": [
    {
      "name": "Authorization checks",
      "rationale": "Eight findings close missing-authz gaps at HTTP handler boundaries.",
      "score": 30,
      "severity_breakdown": {"High": 7, "Medium": 1},
      "members": [
        {"number": 1, "vuln": "VULN-001"},
        {"number": 2, "vuln": "VULN-002"}
      ]
    }
  ]
}
```

If fewer than 2 plausible clusters emerge (everything is one big topic, or every finding is unrelated to every other), skip clustering and proceed to part (c) with severity buckets.

After writing `clusters.json`, run the canonical scorer to compute / normalize the rubric math deterministically — don't trust the model to do the arithmetic:

```bash
python3 "${SKILL_DIR}/scripts/cluster_score.py" .vulnhunter-fix/clusters.json \
    > .vulnhunter-fix/clusters.json.tmp \
    && mv .vulnhunter-fix/clusters.json.tmp .vulnhunter-fix/clusters.json
```

This rewrites `clusters.json` with the canonical `score` field per cluster and a `recommended: true` flag on the top-scoring cluster. The `(Recommended)` label in part (c) below comes from that flag.

**(c) Ask via `AskUserQuestion` (checkboxes preferred over typed input).** Adapt the question shape to the issue count `N` and whether clustering succeeded:

| Issue count | Clusters available? | Question shape |
|-------------|---------------------|----------------|
| `N == 1` | — | Skip the question — auto-proceed. Tell the user what's about to happen and that they can interrupt. |
| `N == 0` | — | Tell the user nothing was harvested and stop. |
| `2 ≤ N ≤ 4` | — | **One** `AskUserQuestion` with `multiSelect: true` and one option per issue. Label = `"#N — VULN-XXX — short title"`; description = `"severity, CWE, location"`. |
| `N > 4` | **yes** (≥ 2 clusters) | **One** `AskUserQuestion` with `multiSelect: true` over the clusters **in the risk-reduction order** computed in (b). Label = `"<cluster name> (N issues)"`; description = the rationale + the VULN IDs in the cluster (truncated if long). Up to 4 clusters; if more emerged, merge the smallest related ones or surface them in the 4th slot as `"Other clusters"`. The first cluster (highest risk-reduction score) gets `(Recommended)` appended to its label. |
| `N > 4` | **no** (clustering failed) | **One** `AskUserQuestion` with `multiSelect: true` over severity buckets that appear (Critical / High / Medium / Low, empty buckets omitted). Label = `"Critical (3 issues)"`; description lists the VULN IDs. |

In all `N > 4` cases the auto-included **Other** option lets the user type `42,55,71` for fine-grained selection.

**Parsing the answer.** Whatever shape was used, normalize down to a set of issue numbers:

- **Per-issue checkboxes**: each selected option's label starts with `#N` — extract every `#(\d+)` from the joined answers.
- **Cluster checkboxes**: look up each selected cluster name in `clusters.json` and union its `members[].number` values.
- **Severity buckets** (fallback): take every issue from `intake.json` whose `.severity` matches a selected bucket label.
- **"Other" custom text**: parse comma-separated `42,43`, `#42, #43`, or single numbers. Reject non-numeric tokens and re-ask.

Then narrow `intake.json` to the chosen subset (preserving the full harvest as `intake.full.json`):

After the user answers, build the filtered intake yourself — no jq. Steps:

1. Snapshot the full harvest:
   ```bash
   cp .vulnhunter-fix/intake.json .vulnhunter-fix/intake.full.json
   ```
2. From the `AskUserQuestion` response, determine the selected issue numbers (per the "Parsing the answer" rules above).
3. Use the `Write` tool to overwrite `.vulnhunter-fix/intake.json` with the same JSON shape minus the unselected issue entries. You already have the unfiltered object in context from Step 3(a). Sanity-check that the result still has `.owner`, `.repo`, `.results_dir`, `.default_branch`, and a non-empty `.issues` array.
4. If the user selected `none` (no issues), write an empty `.issues` array, tell the user nothing was done, and exit cleanly.

If the user selected nothing (no checkboxes ticked, no text in Other) treat it as `none` → exit cleanly with a message that nothing was done.

### Step 4: Stage the full report

Every vulnhunter-posted issue body carries a `Full report: <URL>` line that points at the README inside the publish repo. The URL format is:

```
<publish_repo_url>/blob/<branch>/<src_owner>/<src_name>/<timestamp>/<commit>/<results_dir>/README.md
```

So **both the publish repo URL and the exact nested path are derivable from any one issue body** — no `find` walk needed, no user prompt needed, no config alias lookup needed.

Parse it out, then clone:

```bash
RESULTS_DIR_NAME="$(jq -r .results_dir .vulnhunter-fix/intake.json)"

# Extract `Full report: <URL>` from any issue body that has it. Every
# vulnhunter-posted issue carries this line, but if the developer
# edited the first issue and stripped the marker, .[0] alone would
# fail. The `capture(...)?` swallows non-matches into the empty
# stream; the array collects only successful captures; `first //
# empty` returns the first one.
REPORT_URL="$(jq -r '
  [ .[].body
    | capture("Full report:[ \t]*(?<u>https?://[^ \r\n]+)")?
    | .u
  ] | first // empty
' .vulnhunter-fix/raw_issues.json 2>/dev/null)"

if [ -z "$REPORT_URL" ] || [ "$REPORT_URL" = "null" ]; then
    echo "ERROR: Could not extract 'Full report:' URL from raw_issues.json." >&2
    echo "Issue bodies should carry the URL per vulnhunter's template; if not, the issues weren't posted by the canonical agent." >&2
    exit 1
fi

# Split on /blob/ — left is the publish repo URL, right is
# <branch>/<src_owner>/<src_name>/<timestamp>/<commit>/<results_dir>/README.md
PUBLISH_REPO="${REPORT_URL%%/blob/*}"
NESTED_PATH="${REPORT_URL#*/blob/}"
NESTED_PATH="${NESTED_PATH#*/}"  # strip the branch segment

# Security: REPORT_URL was extracted from an issue body. An attacker
# who can apply the `vulnhunter` label to a crafted issue could
# otherwise inject `Full report: https://attacker.example/...` and
# we'd clone+trust their repo as the report source. Allowlist the
# publish host to github.com and GitHub Enterprise installations
# (github.<corp-domain>) — matches the detect_mode.sh host rule.
PUBLISH_HOST=""
case "$PUBLISH_REPO" in
    http://*|https://*|ssh://*)
        PUBLISH_HOST="${PUBLISH_REPO#*://}"
        PUBLISH_HOST="${PUBLISH_HOST%%/*}"
        PUBLISH_HOST="${PUBLISH_HOST#*@}"
        ;;
    git@*:*)
        PUBLISH_HOST="${PUBLISH_REPO#git@}"
        PUBLISH_HOST="${PUBLISH_HOST%%:*}"
        ;;
esac
case "$PUBLISH_HOST" in
    github.com|*.github.com|github.*) ;;
    *)
        echo "ERROR: publish repo host '$PUBLISH_HOST' (from $PUBLISH_REPO) is not on the allowlist." >&2
        echo "The 'Full report:' URL was extracted from an issue body; only github.com and GitHub Enterprise installations are trusted as report sources. Refusing to clone an unknown host." >&2
        exit 1
        ;;
esac

# The nested path's directory (without /README.md) is where the report
# files live INSIDE the publish repo.
REPORT_PATH_IN_REPO="${NESTED_PATH%/README.md}"

# Sandbox-friendly git clone (same incantation scripts/clone_repo.sh
# uses for fork mode): `-c init.templateDir= --template=` skips the
# hook-template copy that the macOS sandbox denies; `--depth 1` keeps
# it small; destination is INSIDE the project under `.vulnhunter-fix/`
# so no writes ever escape CWD.
mkdir -p .vulnhunter-fix/publish
PUBLISH_CLONE=".vulnhunter-fix/publish/repo"
rm -rf "$PUBLISH_CLONE" 2>/dev/null
git -c init.templateDir= -c core.hooksPath=/dev/null clone \
    --template= --depth 1 \
    "$PUBLISH_REPO" "$PUBLISH_CLONE"

# Use the path derived from the URL — no find walk.
REPORT_PATH="$PUBLISH_CLONE/$REPORT_PATH_IN_REPO"

# Sanity check: the directory should exist and contain README.md.
if [ ! -f "$REPORT_PATH/README.md" ]; then
    echo "ERROR: Expected $REPORT_PATH/README.md after clone but did not find it." >&2
    echo "Listing publish clone contents for debugging:" >&2
    find "$PUBLISH_CLONE" -maxdepth 6 -name README.md >&2
    exit 1
fi

# Record the path for Step 5 to read.
echo "$REPORT_PATH" > .vulnhunter-fix/.report_path

# Cache the publish repo URL in a user-writable location so future
# runs against the same results_dir can skip the parse step. We do
# NOT write back to ${SKILL_DIR}/config.json — the installer writes
# it 0644 and `install.sh` may overwrite on re-install, so persisting
# state there silently fails. Use the project's own
# .vulnhunter-fix/publish_repo_aliases.json instead.
python3 - "$RESULTS_DIR_NAME" "$PUBLISH_REPO" <<'PY' 2>/dev/null || true
import json, os, sys
key, url = sys.argv[1], sys.argv[2]
cache_path = ".vulnhunter-fix/publish_repo_aliases.json"
try:
    aliases = json.load(open(cache_path))
except (FileNotFoundError, json.JSONDecodeError):
    aliases = {}
if aliases.get(key) != url:
    aliases[key] = url
    json.dump(aliases, open(cache_path, "w"), indent=2)
PY
```

**If `git clone` fails (TLS cert error, sandbox denial that survived the flags above, anything else from the failure policy):** STOP — do NOT try `gh repo clone`, `--config http.sslVerify=false`, or any other workaround. Per the `git` + `gh` failure policy in `SKILL.md`, ask the user to clone it themselves **into the same in-project path** so nothing outside the project gets touched:

```
git clone failed in the sandbox. Please run this in your own terminal and tell me when it's done:

    rm -rf <project_root>/.vulnhunter-fix/publish/repo
    git clone --depth 1 <PUBLISH_REPO> <project_root>/.vulnhunter-fix/publish/repo

(Substitute the real project root and PUBLISH_REPO URL.) The clone goes into the project's own `.vulnhunter-fix/publish/repo/` so nothing leaks into your $HOME and no extra permission grants are needed when I resume.
```

When the user confirms, re-compute `REPORT_PATH` by re-deriving it from the URL the same way as the in-sandbox path: split `Full report:` on `/blob/<branch>/` and join the right-hand-side path-portion (minus `/README.md`) to `$PUBLISH_CLONE`. Write the result to `.vulnhunter-fix/.report_path`. No `find` walk — the URL still encodes the exact nested path. No further `git` calls. **Never** instruct the user to clone to `~/vulnfix-publish-clone`, `$TMPDIR`, or any other path outside the project — those paths require additional permission prompts every time the skill touches them, and leftover state in `$HOME` causes "destination already exists" failures on the next run.

If the publish repo can't be cloned even from the user's terminal (real permission denied, 404), report it cleanly and stop — they need access from the security team.

### Step 5: Extract findings from the report (model-driven)

The report path was recorded in `.vulnhunter-fix/.report_path` by Step 4. Read it back at the top of this step:

```bash
REPORT_PATH="$(cat .vulnhunter-fix/.report_path)"
```

**Read the report yourself, don't shell out.** `scripts/parse_results.py` exists for the fork path but its regex-based approach has repeatedly missed real-world variants — multi-CWE columns, rollup-subsumed findings that only appear in detail sections, drifted severity tiers. Doing the extraction in your own context handles drift naturally. Fork mode still uses the script as a deterministic fallback; in-place mode does not need it.

**Step 5a: Read the README and produce a draft findings list (Sonnet subagent).**

Delegate this to a **Sonnet** subagent via the `Agent` tool (`subagent_type: "general-purpose"`, `model: "sonnet"`). README extraction was originally Haiku-targeted (the upstream `issues_extract.py` uses Haiku for this), but Haiku has proven unreliable on the report layout we see in practice — it drops rollup-subsumed findings, misreads multi-CWE rows, and confuses detail-section field labels. Sonnet handles the same input correctly and the cost delta vs Haiku is small compared to the cost of an incorrect findings list propagating through the rest of the pipeline (re-runs, missed findings, manual injection of corrections).

**Important: the subagent has no shell context.** Before invoking `Agent`, the main agent must substitute the actual path of `REPORT_PATH` (read from `.vulnhunter-fix/.report_path`) into the subagent's `prompt` text. Do not pass the literal string `$REPORT_PATH` — the subagent will try to read a file called `$REPORT_PATH/README.md` and fail.

The subagent's job (specify all of this in its `prompt` *with the real absolute path already substituted*):

1. Read `<the absolute report path>/README.md` (e.g., `/Users/foo/proj/.vulnhunter-fix/publish/repo/.../<RESULTS_DIR_NAME>/README.md`).
2. Find every row in the summary table whose status is `Confirmed`.
3. **Also scan detail sections** (`## VULN-NNN: …` blocks) for any VULN-IDs that don't appear in the summary table — vulnhunter sometimes "rolls up" related findings under one umbrella VULN-ID where the rolled-up children appear only in the umbrella's detail block. Those count too.
4. For each finding, pull these fields from the table row + detail section:

   | Field | Source | Example |
   |-------|--------|---------|
   | `id` | summary table | `"VULN-008"` |
   | `title` | summary table | `"Tag-management URL injection"` |
   | `cwe` | summary table (verbatim, may be multi-CWE) | `"CWE-918 / CWE-74"` |
   | `primary_cwe` | first `CWE-\d+` substring of `cwe` | `"CWE-918"` |
   | `severity` | summary table (normalize `High+` → `Critical`) | `"Critical"` |
   | `status` | summary table | `"Confirmed"` |
   | `location` | detail section `**Location**` cell | `"internal/x.go:100-109"` |
   | `root_cause` | detail section `**Root Cause**` cell | (one sentence) |
   | `entry_point` | detail section `**Entry Point**` cell | (HTTP route or function) |
   | `data_flow` | detail section `**Data Flow**` cell | (source → sink description) |
   | `proposed_fix.strategy` | detail section `### Proposed Fix` → `**Strategy**` | (one sentence) |
   | `proposed_fix.files_to_change` | detail section `**Files to change**` | (paths) |
   | `proposed_fix.why` | detail section `**Why this works**` | (one sentence) |

   Empty string is fine for any field you can't find — never invent values.

5. Write the result to `.vulnhunter-fix/findings.draft.json` via the `Write` tool.
6. Reply with just a one-line confirmation including the count of confirmed findings extracted. Nothing else.

Schema to put on disk:

```json
{
  "findings": [
    {
      "id": "VULN-008",
      "title": "...",
      "cwe": "CWE-918 / CWE-74",
      "primary_cwe": "CWE-918",
      "severity": "High",
      "status": "Confirmed",
      "location": "internal/x.go:100-109",
      "root_cause": "...",
      "entry_point": "...",
      "data_flow": "...",
      "proposed_fix": {"strategy": "...", "files_to_change": "...", "why": "..."}
    }
  ]
}
```

**Step 5b: Deterministic post-processing — compute `vulnfix_key`, attach file paths.**

The cross-tool join key is `SHA-256(location|primary_cwe|root_cause)[:16]`. The model can't reliably compute SHA-256 of arbitrary strings, so this step shells back into Python (no network — pure hashing + file enumeration).

First, validate the subagent's output before doing any post-processing. A bad draft should fail fast with a directed message, not crash inside the hashing pass:

```bash
python3 "${SKILL_DIR}/scripts/validate_findings_draft.py" \
    .vulnhunter-fix/findings.draft.json
```

If validation fails, re-invoke the Step 5a Sonnet subagent with the validator's stderr appended to the subagent's prompt as guidance ("your prior output failed validation: <message> — produce a corrected one"). Do NOT proceed to hashing until validation passes.

```bash
REPORT_PATH="$(cat .vulnhunter-fix/.report_path)"

python3 - "$REPORT_PATH" <<'PY'
import json, os, re, sys
from pathlib import Path

sys.path.insert(0, os.environ["SKILL_DIR"] + "/scripts")
from issue_intake import compute_vulnfix_key

report = Path(sys.argv[1])

# Enumerate available PoC and exploit_test files by canonical VULN-NNN.
files_by_vuln: dict[str, dict[str, str]] = {}
for sub, key in [("poc", "poc"), ("exploit_tests", "exploit_test")]:
    d = report / sub
    if not d.exists():
        continue
    for fp in d.iterdir():
        m = re.search(r"VULN[-_](\d+)", fp.name, re.IGNORECASE)
        if not m:
            continue
        vid = f"VULN-{int(m.group(1)):03d}"
        files_by_vuln.setdefault(vid, {})[key] = str(fp)

try:
    with open(".vulnhunter-fix/findings.draft.json") as f:
        draft = json.load(f)
except json.JSONDecodeError as exc:
    print(
        f"error: findings.draft.json from Step 5a is not valid JSON ({exc}). "
        "Re-run Step 5a's Haiku/Sonnet subagent — its output is malformed.",
        file=sys.stderr,
    )
    sys.exit(2)
except FileNotFoundError:
    print(
        "error: findings.draft.json missing. Step 5a's subagent should "
        "have written it before this step runs.",
        file=sys.stderr,
    )
    sys.exit(2)
if not isinstance(draft, dict) or not isinstance(draft.get("findings"), list):
    print(
        "error: findings.draft.json must be an object with a 'findings' "
        "list. Re-run Step 5a — the subagent produced wrong-shape output.",
        file=sys.stderr,
    )
    sys.exit(2)

findings = []
for item in draft.get("findings", []):
    primary = (item.get("primary_cwe") or "").strip()
    if not primary:
        m = re.search(r"CWE-\d+", item.get("cwe") or "")
        primary = m.group(0) if m else ""
    item["primary_cwe"] = primary
    # Belt-and-suspenders: normalize High+ → Critical even if Step 5a
    # already did. The cluster scorer and severity sorter both rely on
    # this normalization.
    if (item.get("severity") or "").strip().lower() == "high+":
        item["severity"] = "Critical"
    item["vulnfix_key"] = compute_vulnfix_key(
        item.get("location", ""), primary, item.get("root_cause", "")
    )
    item["files"] = files_by_vuln.get(item["id"], {})
    findings.append(item)

out = {
    "results_dir": str(report),
    "readme_path": str(report / "README.md"),
    "total_findings": len(findings),
    "confirmed_findings": len(findings),
    "findings": findings,
    "vuln_files": files_by_vuln,
}
with open(".vulnhunter-fix/findings.json", "w") as f:
    json.dump(out, f, indent=2)
print(f"wrote {len(findings)} findings to .vulnhunter-fix/findings.json", file=sys.stderr)
PY
```

After this step `.vulnhunter-fix/findings.json` has the same shape `parse_results.py` produces in fork mode — downstream phases (`plan.md`, `implement.md`, `verify.md`) consume it unchanged.

**Validate the canonical findings before any downstream phase reads it** (REQ-SCH-006). `findings.json` must match `references/finding-schema.json`; a malformed finding would surface as a confusing traceback deep in `plan.md` rather than a directed error here:

```bash
python3 "${SKILL_DIR}/scripts/validate-finding.py" .vulnhunter-fix/findings.json
```

Failures route back to Step 5a (re-invoke the subagent with the validator's stderr as guidance) — do not proceed to clustering until it passes.

**Step 5c: Sanity-check coverage.**

Every issue in `intake.json` (after Step 3 filtering) should have a matching finding by `vulnfix_key`. Quick diff:

```bash
SCRATCH="$TMPDIR/vulnfix-check-$$"
mkdir -p "$SCRATCH"
jq -r '.issues[].markers.vulnfix_key' .vulnhunter-fix/intake.json | sort > "$SCRATCH/vf_issues"
jq -r '.findings[].vulnfix_key'         .vulnhunter-fix/findings.json | sort > "$SCRATCH/vf_findings"
comm -23 "$SCRATCH/vf_issues" "$SCRATCH/vf_findings" > "$SCRATCH/orphan_issues"

if [ -s "$SCRATCH/orphan_issues" ]; then
    echo "WARN: selected issue(s) with no matching finding (re-read README):" >&2
    cat "$SCRATCH/orphan_issues" >&2
fi
rm -rf "$SCRATCH"
```

If any selected issue has no matching finding, go back to Step 5a and **re-read the relevant sections of the README more carefully** — the umbrella/rollup pattern is the most common cause. Don't paper over it with a manual injection; fix the extraction.

### Step 6: Cross-reference selected issues to findings

Join `intake.json` and `findings.json` by `vulnfix_key`, then write `.vulnhunter-fix/work.json` via the `Write` tool. The shape:

```json
{
  "owner": "<from intake>",
  "repo": "<from intake>",
  "results_dir": "<from intake>",
  "default_branch": "<from intake>",
  "items": [
    {
      "finding": { /* the full finding object from findings.json */ },
      "issue": { "number": 17, "url": "...", "title": "...", "markers": {...} }
    }
  ]
}
```

For each finding in `findings.json`, look up the issue in `intake.json.issues` by `vulnfix_key`:

- **Match found**: emit a work item pairing both. The issue object should be the full entry from `intake.json` (preserving `body_tampered`, `markers`, `severity`, etc.).
- **Finding with no matching selected issue**: skip it — out of scope for this run (the user only chose a subset).
- **Selected issue with no matching finding**: warn on stderr (the scan was re-run since the issues were posted), but don't fail.

You have both JSON files in context. Doing this in your head + `Write` is more reliable than a multi-line `jq -n --slurpfile` invocation that has bitten us with shell-quoting.

### Step 7: Present + continue

Show the final work table inline (you composed `work.json` in Step 6 and have it in context — produce the markdown directly, no jq). Columns: `VULN | CWE | Severity | Location | Issue | Title`. Then continue to Phase 2 (`prompts/plan.md`). No second confirmation gate — the user already chose what to work on in Step 3.

## Output contract

Downstream phases must find:

- `.vulnhunter-fix/raw_issues.json` — the raw `gh issue list` output
- `.vulnhunter-fix/intake.json` — extracted markers, filtered to user-selected issues
- `.vulnhunter-fix/intake.full.json` — pre-filter snapshot
- `.vulnhunter-fix/publish/repo/` — shallow clone of the publish repo (contains the report dir at some nested path)
- `.vulnhunter-fix/.report_path` — absolute path to the specific results dir inside the publish clone
- `.vulnhunter-fix/findings.json` — parsed findings
- `.vulnhunter-fix/work.json` — finding↔issue join, canonical work list

## Error handling

- Every error stops the phase — never proceed with partial intake.
- Surface stderr from `gh` and `jq` calls verbatim.
- Keep `.vulnhunter-fix/` populated on failure so the user can inspect what was harvested before retrying.
- If the user picks `none` in Step 3, exit cleanly — no further artifacts created.
