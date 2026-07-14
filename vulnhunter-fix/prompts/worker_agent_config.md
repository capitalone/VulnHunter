# Worker Agent — Configuration (IaC / IAM; no Python TDD)

**Extends:** `worker_agent_common.md` — BUT with two divergences:

1. **No Python TDD.** The discriminating "test" for configuration
   findings is a static-analysis tool assertion (`tfsec`, `checkov`,
   `cfn-lint`, `kube-linter`, `helm lint`), not a pytest file. Steps
   C/D/E of the common preamble are adjusted accordingly (see below).
2. **No `verify_` scaffold file.** The discriminating evidence is a
   `tfsec --format json <before/after>` diff captured in the plan
   artifact.

**Canonical fix pattern (per `references/cwe-fix-patterns.md` Class 5):**

1. Modify the declarative artifact (Terraform, CloudFormation, Kubernetes
   manifest, Helm values) — never a runtime workaround.
2. Restrict to least privilege: explicit deny of public/wildcard state;
   explicit allow of the required principals only.
3. Enable the C1-standard control at the source (encryption at rest,
   IMDSv2, VPC endpoints, WAF, MFA, TLS).

## Discrimination requirements (Step E.5)

- Pre-fix: `tfsec` (or equivalent) asserts the finding is present with
  its exact rule ID and severity.
- Post-fix: same tool asserts the finding is gone.

Record in `.work/<repo>/discrimination/<vuln>.json`:

```json
{
  "vuln_id": "VULN-NNN",
  "method": "static-analysis-diff",
  "tool": "tfsec" | "checkov" | "cfn-lint" | "kube-linter",
  "pre_fix_result": "fail",
  "post_fix_result": "pass",
  "assertion_target": "<file>:<line> — <tool_rule_id> no longer triggers"
}
```

## FULL-tier bar (REQ-HON-004)

Grant `completeness_tier: FULL` only when:

- The declarative artifact itself is modified (not a runtime drift
  corrector).
- No wildcard permission survives (`Resource: "*"` or `NotAction: "*"`).
- No drift-corrector loop or scheduled Lambda compensates.
- The static-analysis tool passes clean against the changed files.

## Anti-patterns

- Drift-corrector Lambda that re-applies the secure setting periodically
  → **WORKAROUND** (the artifact still declares the insecure state).
- Deny statement added but a permissive statement earlier in the
  document still grants access → **MITIGATION**.
- `Resource: "*"` narrowed to `"arn:aws:s3:::*"` (still all buckets) →
  **MITIGATION**.
- Config change without atomic apply (partial config edit that leaves
  intermediate state broken) → **CANNOT_AUTO_FIX**.

## Test-policy override

For config-only findings, `test_policy` from the manifest is IGNORED for
Step F (regression check). The regression check is:

```bash
tfsec --format compact <changed-tf-file>   # or checkov / cfn-lint per tool
```

Exit 0 = clean; exit non-zero = the finding (or a new one) still
triggers → treat as `REGRESSIONS_FOUND`.

## Residual template

```
config: <artifact> — <specific permissive path> (e.g., "S3 bucket policy still permits GetObject from Principal AWS: '*' when Referer header matches allowlist")
```
