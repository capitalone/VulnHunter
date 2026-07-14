# Contributing

Thanks for your interest in improving VulnHunter.

## Ground rules

- Be respectful and constructive.
- Only test the scanner against code you are authorized to scan.
- Do not include real, unpublished vulnerability data for third-party systems in
  the benchmark corpus you commit — use synthetic entries or public,
  deliberately-vulnerable apps (see
  `harness/local_harness/benchmark/ground_truth/README.md`).

## Development setup

Each Python component is a self-contained subtree with its own `pyproject.toml`;
there is no root package. Install and test whichever component you're changing:

```bash
git clone https://github.com/capitalone/vulnhunter.git
cd vulnhunter

# dev harness (batch + benchmark tooling)
cd harness          && python -m pip install -e ".[dev]" && python -m pytest tests/ --cov=local_harness
# the fix skill's helper package
cd vulnhunter-fix   && python -m pip install -e ".[dev]" && python -m pytest -q
# the headless runtime agent
cd vulnhunter-agent && python -m pip install -e ".[dev]" && python -m pytest -q
```

The `vulnhunt/`, `vulnhunt-fix-verify/`, and `vulnhunter-fix/` skills are
prompt-only (Markdown); install them locally with `./install.sh` from the repo
root to try changes with the `claude` CLI.

## Pull requests

1. Fork the repo and create a topic branch.
2. Make your change with a clear commit message describing the "why".
3. Keep the harness tests green and coverage steady.
4. Open a PR describing the change and how you validated it.

## Reporting bugs

Open a GitHub issue for functional bugs. For security issues in the tool itself,
follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
