# Security Policy

This policy covers vulnerabilities in the VulnHunter tooling itself (the skills and
the harness), not vulnerabilities in code you scan with it.

## Reporting a vulnerability

Please **do not open a public issue** for security reports.

Instead, use GitHub's private vulnerability reporting for this repository:
open the **Security** tab and choose **Report a vulnerability**. This opens a
private advisory visible only to the maintainers.

When reporting, please include:

- A description of the issue and its impact.
- Steps to reproduce (a minimal proof of concept if possible).
- The version or commit you tested against.
- Any suggested remediation.

We will acknowledge your report, keep you updated on remediation progress, and
coordinate disclosure timing with you.

## Scope

In scope — the VulnHunter tooling itself:

- The `/vulnhunt` (scanner), `/vulnhunt-fix-verify` (verifier), and
  `/vulnhunter-fix` (remediation) skill prompts and their orchestration.
- The `vulnhunter-agent/` headless runtime and the `harness/` (`local_harness`)
  developer tooling.

Out of scope:

- Findings the scanner produces about third-party code you point it at.
- Issues that require running the tool against code or model access you are not
  authorized to use.
