# Phase 1: Parse VulnHunter Results

## Inputs Required

- `RESULTS_PATH`: Path to VulnHunter results (local directory or GHE repo URL)
- `TARGET_REPO`: GitHub repo URL to fix (e.g., `https://github.com/org/repo`)

> **Read the "`git` + `gh` failure policy" section of `SKILL.md` before continuing.** Every `gh` and `git` call below — `git clone` of the results repo, any later `gh` calls — must follow the same rule: on `tls: failed to verify certificate`, `OSStatus -…`, sandbox copy denials, or any unexpected non-zero exit, STOP and ask the user to run the command in their own terminal. Do not retry, do not substitute tools.

## Actions

**Step 1: Resolve results path.**

If `RESULTS_PATH` is a URL (starts with `https://`), clone it first:
```bash
git clone --depth 1 "$RESULTS_PATH" ".work/findings"
RESULTS_PATH=".work/findings"
```

If local, verify the path exists:
```bash
ls "$RESULTS_PATH/README.md"
```

**Step 2: Parse the results.**

Run the parser script:
```bash
python3 scripts/parse_results.py "$RESULTS_PATH"
```

This outputs JSON with all confirmed findings including: ID, title, CWE, severity, location, root cause, proposed fix strategy, and paths to PoC/exploit test files.

**Step 3: Validate findings are actionable.**

For each finding, verify:
- It has status "Confirmed"
- It has a non-empty proposed fix strategy
- The location field points to a real file in the target repo
- At least one of: PoC file or exploit test file exists

**Step 4: Read the detailed context.**

For each confirmed finding, read:
1. The PoC file (`poc/VULN-NNN_*.md`) — understand the data flow and payload
2. The exploit test (`exploit_tests/test_vuln_NNN_*.py` or in the repo's test directory) — understand what proves exploitability
3. The full finding detail section from README.md — understand the proposed fix

## Output

Present to the user:
- Number of confirmed findings found
- Table: ID | CWE | Severity | Location | Fix Strategy (short)
- Any findings that lack actionable fix info (warn but don't block)

## Error Conditions

- `README.md` not found → STOP: "Invalid results path. Expected VulnHunter output at: {path}"
- No confirmed findings → STOP: "No confirmed vulnerabilities to remediate."
- Parser fails → STOP: "Failed to parse {path}/README.md. The regex parser couldn't extract findings from the summary table. Inspect the report manually and re-run, or if you are in interactive (in-place) mode, use `prompts/parse_issues.md` Step 5a's validated Sonnet extraction instead — do NOT freelance findings from the README, since hallucinated findings would produce PRs for vulnerabilities that don't exist."
