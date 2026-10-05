#!/usr/bin/env python3
"""Batch vulnhunt runner: clones repos from REPO_LIST.txt and scans them in parallel.

Usage:
    python -m local_harness.batch.run scan [--re-clone] [--max-workers N]
    python -m local_harness.batch.run status
    python -m local_harness.batch.run collect [--upload-dir DIR]
"""

import argparse
import os
import re
import sys
import time
from urllib.parse import urlsplit

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from .utils import collect_results, parse_repo_list, scan_status
from local_harness.clone import shallow_clone
from local_harness.config import (
    BATCH_CLONE_BASE_DIR,
    BATCH_LOG_FILENAME,
    MAX_SCAN_WORKERS,
)
from local_harness.scan import clean_incomplete_results, has_valid_results, scan_targets, ts


_GITHUB_COMPONENT_RE = re.compile(r"[A-Za-z0-9._-]+")


def _repo_parts_from_url(url):
    """Return the owner and repository from a supported GitHub clone URL.

    Both URL-style remotes and the common git@github.com:owner/repo.git form
    are accepted.
    """
    value = url.strip()
    if "://" not in value:
        host, separator, path = value.partition(":")
        if not separator or host.rsplit("@", 1)[-1].casefold() != "github.com":
            raise ValueError("expected a github.com repository URL")
    else:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https", "ssh", "git"}:
            raise ValueError("expected an HTTP(S), SSH, or git GitHub URL")
        if (parsed.hostname or "").casefold() not in {"github.com", "www.github.com"}:
            raise ValueError("expected a github.com repository URL")
        path = parsed.path

    parts = [part for part in path.rstrip("/").split("/") if part]
    if len(parts) != 2:
        raise ValueError("expected a GitHub repository URL ending in OWNER/REPOSITORY")

    owner, repo = parts
    if repo.endswith(".git"):
        repo = repo[:-4]

    if any(
        component in {"", ".", ".."} or not _GITHUB_COMPONENT_RE.fullmatch(component)
        for component in (owner, repo)
    ):
        raise ValueError("repository path contains unsupported characters")
    return owner, repo


def repo_name_from_url(url):
    """Extract repo name from a GitHub URL."""
    _, repo = _repo_parts_from_url(url)
    return repo


def repo_target_name_from_url(url):
    """Return a stable, filesystem-safe batch target name for a GitHub URL."""
    owner, repo = _repo_parts_from_url(url)
    return f"{owner.casefold()}__{repo.casefold()}"


def cmd_scan(args):
    """Clone repos and scan them."""
    urls = parse_repo_list()
    if not urls:
        print("No URLs found in REPO_LIST.txt")
        sys.exit(1)

    repo_targets = {}
    clone_failures = []
    duplicate_count = 0
    for url in urls:
        try:
            target_name = repo_target_name_from_url(url)
        except ValueError as exc:
            clone_failures.append((url, f"invalid repository URL: {exc}"))
            continue
        if target_name in repo_targets:
            duplicate_count += 1
            continue
        repo_targets[target_name] = url

    print(f"[{ts()}] Found {len(urls)} repo list entries")
    for i, (target_name, url) in enumerate(repo_targets.items()):
        print(f"  [{i + 1}] {url} -> {target_name}")
    if duplicate_count:
        noun = "entry" if duplicate_count == 1 else "entries"
        print(f"  Ignoring {duplicate_count} duplicate repo {noun}")
    print(flush=True)

    # Phase 1: Clone
    print(f"[{ts()}] Cloning repos (depth=1) ...")
    folders = []

    for target_name, url in repo_targets.items():
        target_dir = os.path.join(BATCH_CLONE_BASE_DIR, target_name)
        target_dir, error = shallow_clone(url, target_dir, re_clone=args.re_clone)
        if error:
            print(f"  [{ts()}] CLONE FAILED: {url}\n           {error}", flush=True)
            clone_failures.append((url, error))
        else:
            folders.append(target_dir)

    if clone_failures:
        print(f"\n[{ts()}] {len(clone_failures)} clone(s) failed:")
        for url, err in clone_failures:
            print(f"    {url}: {err}")
        print(flush=True)

    if not folders:
        print("No repos were cloned successfully. Nothing to scan.")
        sys.exit(1)

    # Phase 2: Scan
    if args.resume:
        for f in folders:
            removed = clean_incomplete_results(f, log_filename=BATCH_LOG_FILENAME)
            if removed:
                print(f"  [{ts()}] Cleaned incomplete results in {os.path.basename(f)}: {removed}", flush=True)
        skipped = [f for f in folders if has_valid_results(f)]
        folders = [f for f in folders if not has_valid_results(f)]
        if skipped:
            print(f"[{ts()}] Skipping {len(skipped)} repo(s) with existing results (--resume):")
            for f in skipped:
                print(f"  {os.path.basename(f)}")
            print(flush=True)

    if not folders:
        print(f"[{ts()}] All repos already have results. Nothing to scan.")
        sys.exit(0)

    targets = [
        {"clone_dir": folder, "key": os.path.basename(folder)}
        for folder in folders
    ]

    start = time.time()
    results = scan_targets(targets, max_workers=args.max_workers, log_filename=BATCH_LOG_FILENAME,
                           readonly=args.readonly)
    elapsed = time.time() - start

    # Phase 3: Summary
    print(f"\n{'=' * 60}")
    print(f"[{ts()}] All scans complete in {elapsed:.0f}s")
    print(f"{'=' * 60}")

    successes = 0
    failures = 0
    total_cost = 0.0
    for target_key, r in results:
        ok = r.returncode == 0
        successes += ok
        failures += not ok
        status = "OK" if ok else f"FAIL(exit={r.returncode})"
        cost = r.cost_data.get("total_cost_usd", 0)
        total_cost += cost
        cost_str = f"${cost:.2f}" if cost else "-"
        print(f"  {status:12s} | {r.elapsed:5.0f}s | {cost_str:>7s} | {r.label}")

    print(f"\n  {successes} succeeded, {failures} failed, "
          f"{elapsed:.0f}s total, ${total_cost:.2f} total cost")
    if clone_failures:
        print(f"  {len(clone_failures)} repo(s) skipped due to clone failure")


def cmd_status(args):
    """Check scan progress."""
    scan_status()


def cmd_collect(args):
    """Collect results for upload."""
    collect_results(upload_dir=args.upload_dir)


def main():
    parser = argparse.ArgumentParser(description="VulnHunter Batch Scanner")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Clone and scan repos")
    scan_parser.add_argument("--re-clone", action="store_true",
                             help="Remove and re-clone repos that already exist")
    scan_parser.add_argument("--resume", action="store_true",
                             help="Skip repos that already have a completed scan report")
    scan_parser.add_argument("--max-workers", type=int, default=MAX_SCAN_WORKERS,
                             help=f"Parallel scan workers (default: {MAX_SCAN_WORKERS})")
    scan_parser.add_argument("--readonly", action="store_true",
                             help="Read-only scan: skip dependency installation and code execution")

    subparsers.add_parser("status", help="Check scan progress")

    collect_parser = subparsers.add_parser("collect", help="Collect results for upload")
    collect_parser.add_argument("--upload-dir", type=str, default=None,
                                help="Override upload destination directory")

    args = parser.parse_args()

    if not args.command:
        args.command = "scan"
        args.re_clone = False
        args.resume = False
        args.max_workers = MAX_SCAN_WORKERS
        args.readonly = False

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "collect":
        cmd_collect(args)


if __name__ == "__main__":
    main()
