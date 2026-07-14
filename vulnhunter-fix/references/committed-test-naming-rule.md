# Committed Test-Naming Rule (REQ-GAT-013)

**Consumed by:** `scripts/check-committed-test-naming.py` (Gate 7), routed via `scripts/run-gates.py` (`gate7_committed_test_naming`). The promotion it enforces is spelled out in `prompts/implement.md` (IP-Step H / Step H) and `prompts/worker_agent_common.md` (Step G).

## Rule

The security test is authored under a transient `verify_{VULN_ID}_*` scaffold name during the RED→GREEN cycle (the prefix keeps it out of the repo's default test collection while the agent iterates). Before commit it MUST be promoted to a discoverable, repo-convention name (see `references/repo-type-adapters.md`) and the scaffold deleted, so the repo's own runner collects it and it counts toward coverage.

The gate fails closed if that promotion did not happen: any file **added on the branch** whose basename matches the scaffold signature is a leak.

## Scaffold signature

```
^(?:verify|exploit)_VULN[-_]?
```

- Case-insensitive; matched against the **basename** only.
- Anchored on `VULN` so a target repo's own `verify_email.py` / `exploit_utils.go` is NOT flagged — only VulnHunter-Fix scaffolds are.

## Gate 7 behavior

`scripts/check-committed-test-naming.py`:
1. Resolves a base ref (`--base`, then `origin/<base>`, then `origin/HEAD`, then `main`/`master`) and diffs `base...HEAD --diff-filter=A` for files added across the branch.
2. If no base resolves, falls back to HEAD's added files and emits a loud warning (a HEAD-only scan can miss a scaffold committed in an earlier commit of a multi-finding cluster PR).
3. Flags any added file whose basename matches the scaffold signature.

Exit codes: `0` clean, `1` scaffold leak found, `2` usage / git error.

## Scope

Gate 7 enforces only the **negative** invariant (no scaffold committed). It does not confirm the **positive** — that the promoted name matches the repo's convention and is actually collected by the repo's runner. That guarantee belongs to the discrimination step (run via the repo's own test command) and is tracked separately.
