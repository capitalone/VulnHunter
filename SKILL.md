---
name: vulnhunter
description: Run provider-neutral, multi-model security scans over an authorized local Git checkout or repository URL.
---

# VulnHunter universal skill

Use the standalone `vulnhunter` command as the integration surface. Do not
reimplement the scan phases in the host coding agent.

1. Confirm that the target is a repository the user is authorized to scan.
2. Check `vulnhunter --version`. If it is unavailable, direct the user to the
   installation and provider setup in this repository's `README.md`. Do not
   silently install software or select a remote provider.
3. For an ordinary interactive scan, run:

   `vulnhunter scan <absolute-repository-path>`

   The CLI itself asks the only two operational questions: scan level and core
   model count. The second screen can open the provider model browser with `m`;
   model choices are retained for later scans. Do not ask duplicate questions
   in the coding tool.
4. For automation, use explicit values:

   `vulnhunter scan <path> --level standard --models 2 --yes --json`

5. Wait for the process to exit. Read `run_manifest.json` and `README.md` from
   the reported results directory.
6. Treat `COMPLETE_CLEAN` as clean only when coverage is complete. Report
   `COMPLETE_FINDINGS` and `COMPLETE_CONDITIONAL` distinctly. Never reinterpret
   `INCOMPLETE_LIMIT`, `INCOMPLETE_COVERAGE`, or `FAILED` as clean.

Remote providers receive selected repository content. The CLI must display the
exact roster and locality before dispatch. Never replace a local model with a
remote model or add a provider that was not displayed.
