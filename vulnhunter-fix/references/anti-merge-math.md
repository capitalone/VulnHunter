# Anti-Merge Math (REQ-GAT-006)

**Consumed by:** `scripts/anti-merge-check.py` and Phase 3 of the
executor when deciding whether to group findings into one PR.

## Purpose

Prevent over-aggressive grouping. When a grouping's cost (in files
touched or test files affected) approaches the cost of splitting into
individual PRs, the group provides little review benefit and increases
review-drift risk. The 0.6 threshold is the mechanical fence.

## The check

For a proposed group `G` covering `n` findings:

```
group_allowed = (
    total_files_grouped(G)      <= 0.6 * total_files_split(G)
    OR
    total_test_files_grouped(G) <= 0.6 * total_test_files_split(G)
)
```

Where:
- `total_files_grouped(G)` — count of distinct source files touched
  when all n findings are combined into one PR.
- `total_files_split(G)` — count of distinct source files touched
  when each finding gets its own PR (sum across n individual PRs).
- Similarly for test files.

## Outcomes

| Ratio | Meaning | Action |
|-------|---------|--------|
| ≤ 0.6 | Grouping is efficient (files heavily overlap) | Allow the group |
| > 0.6 and < 1.0 | Grouping is inefficient (files diverge) | Split into individual PRs |
| ≥ 1.0 | Grouping costs MORE than splitting (should be impossible) | Split; log as diagnostic |

The **either/or** in the formula means the group is allowed if EITHER
the source-file ratio OR the test-file ratio is within budget. Findings
that touch the same source file but different test files can still
group (common for tests-mirror-tree conventions).

## Example

Three findings in the same file, each adds one test:

- `total_files_grouped` = 2 (source + one merged test file if colocated)
- `total_files_split` = 6 (3 × 2)
- Ratio = 2/6 = 0.33 → **group allowed**

Three findings in three different files, each adds one test:

- `total_files_grouped` = 6 (3 source + 3 test)
- `total_files_split` = 6 (3 × 2)
- Ratio = 6/6 = 1.0 → **split**

## Rationale

At small `n`, grouping benefits from shared context. At large `n`, the
reviewer's cognitive load per file review exceeds the savings, and any
one finding's regression can force the whole group back to the repair
loop. The 0.6 threshold is calibrated empirically from CASF's
production data.
