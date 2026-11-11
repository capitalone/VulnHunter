# SG-3 — vulnhunter-fix gate scripts + library

Repo root (all paths below are relative to this): `/Users/srujankd/Temple_University/Senior Year/Capstone/workspace/code/VulnHunter`

**Entry point:** `preflight.py`, `check-scope.py`, `worktree-reset.py`, `run-gates.py` (dispatches to child scripts), `build_graph.py`, `sweep-root-causes.py`, `validate-*`
**Production reachability:** PRODUCTION (shipped gate scripts; no env gate found).

## Assigned inputs

| # | Source Type | Location | Variable | Entry Point | Trust |
|---|---|---|---|---|---|
| 36 | CLI flag | `vulnhunter-fix/scripts/*.py` | `--repo-root` (many scripts) | gate scripts | local |
| 37 | CLI flag | `vulnhunter-fix/scripts/check-body-completeness.py:147`, `vulnhunter-fix/scripts/pr-body-check.py:144`, `vulnhunter-fix/scripts/run-gates.py:247` | `--body` / `--pr-body` / `--issue-body` | body lints | external |
| 38 | CLI flag / stdin | `vulnhunter-fix/scripts/compute-completeness-tier.py:229`, `vulnhunter-fix/scripts/crypto-trust-chain-checkers.py:353` | `--diff` / stdin diff | tier/trust checks | external |
| 39 | CLI flag | `vulnhunter-fix/scripts/check-scope.py:84` | `--branch`, `--base-ref`, `--files-modified` | scope gate | external |
| 40 | CLI flag | `vulnhunter-fix/scripts/worktree-reset.py:144` | `--worktree`, `--branch-baseline`, `--vuln-id`, `--reason` | worktree reset | local |
| 41 | CLI flag | `vulnhunter-fix/scripts/run-gates.py:250`, `vulnhunter-fix/scripts/validate-verification.py:294` | `--sidecars-dir`, `--result`, `--plan` | gate inputs | local |

## File scope (app-specific — define your trace scope)

`vulnhunter-fix/scripts/*.py` (see the full script list under `vulnhunter-fix/scripts/`), `vulnhunter-fix/vulnhunter_fix/graph/*.py`, `vulnhunter-fix/vulnhunter_fix/delivery.py`.

## Shared infrastructure catalog

Self-contained; external dependencies are `jsonschema`, `graphifyy`, and the repo schema files. No application-shared nodes.

## Threat model

- App-layer auth enforcement: **NONE**
- Caller identity binding: **NONE**
- Per-resource authorization: **NONE**
- Attacker profile: local operator (for `--repo-root`/`--worktree`/`--reason`/`--sidecars-dir` flags) and any party supplying PR/issue bodies, diffs, branch names, or file-modified lists (CI/gate inputs — content not bound to a verified author identity).
- Attacker controls: repo-root path, body/PR-body/issue-body text, diffs, branch/base-ref/file-modified names, worktree path, vuln-id, reason, sidecars-dir/result/plan paths.
- Attacker does NOT control: schema files, trusted local environment.
- Existing attacker capabilities: baseline is "can reach the endpoint" only (all-NONE).
- Existing mitigations (input validation, NOT auth): CWE-88 option-injection rejection (`check-scope.py:24`); path/shape validation where present.
