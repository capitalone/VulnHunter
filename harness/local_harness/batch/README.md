# Batch Scanning

Scan arbitrary GitHub repos using the shared VulnHunter scan engine.

## Quick start

1. Edit `local_harness/batch/REPO_LIST.txt` — one GitHub URL per line
2. `python -m local_harness.batch.run scan`
3. `python -m local_harness.batch.run status` (check progress)
4. `python -m local_harness.batch.run collect` (gather results into `to_upload/`)

## Options

- `--re-clone` — remove and re-clone repos that already exist locally
- `--max-workers N` — parallel scan workers (default: 5)
- `--upload-dir DIR` — override destination for `collect` (default: `to_upload/`)
