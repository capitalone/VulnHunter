"""Run vulnhunt scans on cloned repos."""

import json
import os
import shutil
import stat
import subprocess
import threading
import time
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from . import config
from .config import (
    MAX_SCAN_WORKERS,
    MODEL,
    PHASES_DIR,
    SCAN_MAX_RETRIES,
    SCAN_RETRY_BACKOFF_MULTIPLIER,
    SCAN_RETRY_INITIAL_BACKOFF,
    SCAN_RETRY_MAX_BACKOFF,
    SCAN_TIMEOUT,
    SKILLS_DIR,
)

# The result of scanning one folder. A namedtuple (rather than a bare 7-tuple)
# so consumers can use attribute access and a field reorder can't silently
# corrupt positional unpacking.
ScanResult = namedtuple(
    "ScanResult",
    "folder_path label returncode event_count elapsed results_dir cost_data",
)


def ts():
    return datetime.now().strftime("%H:%M:%S")


# O_NOFOLLOW is POSIX-only; on Windows it is absent and we rely on the
# lstat/islink checks alone.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)


def _is_regular_file(path):
    """True only for a real regular file at `path` (no symlink, FIFO, device...).

    Scan logs live inside the untrusted clone, so a log path may be a planted
    symlink to a host file or a FIFO that would block a reader forever.
    """
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def _open_log_for_read(path):
    """Open a scan log for binary reading without following a final symlink.

    Returns None when the path is not a regular file (absent, symlink, FIFO...).
    """
    if not path or not _is_regular_file(path):
        return None
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_BINARY)
    except OSError:
        return None
    return os.fdopen(fd, "rb")


def _open_log_for_write(path):
    """Create a fresh scan log at `path` without writing through a planted link.

    The log lives inside the untrusted clone: a repo can commit
    `batch_scan.log -> ~/.zshrc` (or a dangling link to a not-yet-existing
    host path), and an agent with Bash can leave a hard link there before a
    retry. open(path, "w") would follow/truncate any of those. Remove whatever
    is at the path first (unlinking a link never touches its target), then
    create the file exclusively with O_NOFOLLOW so a link raced into place
    makes the open fail rather than redirect the write.
    """
    if os.path.lexists(path):
        _remove_results_entry(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW
    fd = os.open(path, flags, 0o644)
    return os.fdopen(fd, "w")


def _tail_lines(path, max_bytes=65536):
    """Return the last lines of a file without loading the whole thing.

    Scan logs are JSONL and can grow large over a multi-hour scan; callers only
    need the final `result` event, so reading the trailing window is enough.
    A log that is not a regular file (e.g. a planted symlink) reads as empty.
    """
    f = _open_log_for_read(path)
    if f is None:
        return []
    with f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - max_bytes))
        data = f.read()
    return data.decode("utf-8", errors="replace").splitlines()


RESULTS_MARKER = "_VULNHUNT_RESULTS_"


def _is_link(path):
    """True for a symlink, or (Windows, py3.12+) an NTFS junction.

    os.path.islink does not report junctions, so a junction planted in a clone
    on Windows would otherwise be treated as a real directory. On older Pythons
    without os.path.isjunction, junctions remain undetected (documented gap).
    """
    if os.path.islink(path):
        return True
    isjunction = getattr(os.path, "isjunction", None)
    return bool(isjunction and isjunction(path))


def _is_git_tracked(clone_dir, entry):
    """True if `entry` (relative to clone_dir) has files tracked by git.

    A clone only contains tracked content, so a *_VULNHUNT_RESULTS_* dir that
    git knows about was committed by the (untrusted) repo, not produced by our
    scan. If git is unavailable or clone_dir isn't a work tree, return False
    and fall back to the previous (untracked-assumed) behaviour.
    """
    try:
        proc = subprocess.run(
            ["git", "ls-files", "-z", "--", entry],
            cwd=clone_dir, capture_output=True, timeout=30,
        )
    except Exception:  # git missing, timeout, or a stubbed subprocess layer
        return False
    return proc.returncode == 0 and bool(proc.stdout.strip(b"\0"))


def _is_scan_results_dir(clone_dir, entry):
    """True if clone_dir/entry looks like results produced by our own scan.

    Rejects planted symlinks/junctions (isdir follows them, so a link to
    another dir would be judged/collected/trusted) and dirs the repo committed
    itself (which would make --resume skip the scan and ship a forged report).
    """
    if RESULTS_MARKER not in entry:
        return False
    full_path = os.path.join(clone_dir, entry)
    if _is_link(full_path) or not os.path.isdir(full_path):
        return False
    return not _is_git_tracked(clone_dir, entry)


def find_results_dir(clone_dir):
    """Find the *_VULNHUNT_RESULTS_* directory our scan produced in a cloned repo.

    Planted symlinks and repo-committed results dirs are skipped.
    """
    if not os.path.isdir(clone_dir):
        return None
    for entry in sorted(os.listdir(clone_dir)):
        if _is_scan_results_dir(clone_dir, entry):
            return os.path.join(clone_dir, entry)
    return None


def _is_valid_readme(results_dir):
    readme = os.path.join(results_dir, "README.md")
    # A symlinked README would have the judge/resume read an arbitrary host file.
    return _is_regular_file(readme) and os.lstat(readme).st_size > 100


def has_valid_results(clone_dir):
    """Check if a clone directory has valid scan results."""
    results_dir = find_results_dir(clone_dir)
    if not results_dir:
        return False
    return _is_valid_readme(results_dir)


def _remove_results_entry(path):
    """Remove a results entry safely.

    An untrusted cloned repo can plant a symlink named *_VULNHUNT_RESULTS_*
    pointing at a directory. os.path.isdir follows symlinks, so the old cleanup
    code reached shutil.rmtree(<symlink>), which raises
    "Cannot call rmtree on a symbolic link" — an unhandled OSError that aborts
    the entire scan/batch run (CANON-34, availability DoS). Unlink the planted
    symlink (never its target); only rmtree real directories.
    """
    if os.path.islink(path):
        os.unlink(path)
    elif _is_link(path):
        # NTFS junction (Windows): rmdir removes the junction, not its target.
        os.rmdir(path)
    elif os.path.isdir(path):
        shutil.rmtree(path)
    elif os.path.lexists(path):
        # Regular file, FIFO, socket, ... — just drop the name.
        os.remove(path)


def clean_incomplete_results(clone_dir, log_filename="benchmark_scan.log"):
    """Remove results dirs that lack a valid README.md so a resume will re-scan them.

    Returns list of removed directory names (empty if none removed).
    """
    removed = []
    if not os.path.isdir(clone_dir):
        return removed
    for entry in os.listdir(clone_dir):
        if "_VULNHUNT_RESULTS_" in entry:
            full_path = os.path.join(clone_dir, entry)
            is_link = _is_link(full_path)
            if not is_link and not os.path.isdir(full_path):
                continue
            # A planted symlink or a results dir committed in the repo is never
            # a valid results dir of ours; remove it (without following links)
            # so a resume re-scans cleanly.
            if (is_link or not _is_scan_results_dir(clone_dir, entry)
                    or not _is_valid_readme(full_path)):
                _remove_results_entry(full_path)
                removed.append(entry)
                log_file = os.path.join(clone_dir, log_filename)
                # lexists, not isfile: isfile misses a dangling planted link.
                if os.path.lexists(log_file):
                    _remove_results_entry(log_file)
    return removed


def clean_prior_results(clone_dir, log_filename="benchmark_scan.log"):
    """Remove all *_VULNHUNT_RESULTS_* directories and the scan log from a clone directory.

    Returns list of removed directory/file names (empty if none existed).
    """
    removed = []
    if not os.path.isdir(clone_dir):
        return removed
    for entry in os.listdir(clone_dir):
        if "_VULNHUNT_RESULTS_" in entry:
            full_path = os.path.join(clone_dir, entry)
            if _is_link(full_path) or os.path.isdir(full_path):
                _remove_results_entry(full_path)
                removed.append(entry)
    log_file = os.path.join(clone_dir, log_filename)
    # lexists, not isfile: isfile misses a dangling planted link.
    if os.path.lexists(log_file):
        _remove_results_entry(log_file)
        removed.append(log_filename)
    return removed


def is_rate_limit_failure(log_file_path):
    """Check if a scan failed due to 429 rate limiting by inspecting the final result event."""
    if not log_file_path or not _is_regular_file(log_file_path):
        return False
    try:
        lines = _tail_lines(log_file_path)
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if event.get("type") == "result":
                    return event.get("api_error_status") == 429
            except json.JSONDecodeError:
                continue
    except (IOError, OSError):
        pass
    return False


def extract_cost_from_log(log_file_path):
    """Extract cost and token usage from the final result event in a scan log.

    Returns dict with total_cost_usd, input_tokens, output_tokens,
    cache_read_tokens, cache_creation_tokens, duration_api_ms, num_turns,
    or empty dict if not found.
    """
    if not log_file_path or not _is_regular_file(log_file_path):
        return {}
    try:
        lines = _tail_lines(log_file_path)
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if event.get("type") == "result":
                    model_usage = event.get("modelUsage", {})
                    total_input = sum(m.get("inputTokens", 0) for m in model_usage.values())
                    total_output = sum(m.get("outputTokens", 0) for m in model_usage.values())
                    total_cache_read = sum(m.get("cacheReadInputTokens", 0) for m in model_usage.values())
                    total_cache_creation = sum(m.get("cacheCreationInputTokens", 0) for m in model_usage.values())
                    return {
                        "total_cost_usd": event.get("total_cost_usd", 0),
                        "input_tokens": total_input,
                        "output_tokens": total_output,
                        "cache_read_tokens": total_cache_read,
                        "cache_creation_tokens": total_cache_creation,
                        "duration_api_ms": event.get("duration_api_ms", 0),
                        "num_turns": event.get("num_turns", 0),
                    }
            except json.JSONDecodeError:
                continue
    except (IOError, OSError):
        pass
    return {}


def build_scan_command(folder_path, prompt, engine=None, readonly=False):
    """Build the scan subprocess argv for one engine.

    claude-code replicates the historical argv exactly (tests snapshot it).
    Other engines drive the same installed skill through their headless
    contract; success is still judged by the *_VULNHUNT_RESULTS_* dir.
    """
    engine = engine or config.ENGINE
    if engine == "claude-code":
        return [
            "claude", "-p", prompt,
            "--output-format", "stream-json",
            "--verbose",
            "--allowedTools", "Read", "Write", "Edit", "Bash", "Agent",
            "--permission-mode", "acceptEdits",
            "--model", MODEL,
            "--add-dir", folder_path,
            "--add-dir", os.path.dirname(folder_path),
            "--add-dir", SKILLS_DIR,
            "--add-dir", PHASES_DIR,
        ]
    if engine == "hermes":
        # terminal (shell) only when the run isn't read-only, mirroring the
        # Bash policy of the claude-code path.
        toolsets = "file,delegation" if readonly else "file,terminal,delegation"
        return [
            "hermes", "chat", "-Q",
            "-s", "vulnhunt",
            "-t", toolsets,
            "-m", MODEL,
            "-q", prompt,
        ]
    raise ValueError(f"unknown engine {engine!r}")


def scan_folder(folder_path, log_file=None, readonly=False, engine=None):
    """Run vulnhunt on one folder, stream events to a log file.

    Returns a ScanResult (folder_path, label, returncode, event_count,
    elapsed, results_dir, cost_data).
    """
    engine = engine or config.ENGINE
    label = os.path.basename(folder_path)

    if log_file is None:
        log_file = os.path.join(folder_path, "benchmark_scan.log")

    # Resolve the skills dir from the *effective* engine (not the import-time
    # default) so an engine= override or a mutated env is honored.
    skills_dir = config.skills_dir_for(engine) if engine != "claude-code" else SKILLS_DIR
    if not os.path.isdir(skills_dir):
        print(f"  [{ts()}] [{label}] Error: Skill not installed for engine "
              f"'{engine}'. Run install.sh --target {engine} first.")
        return ScanResult(folder_path, label, 1, 0, 0, None, {})

    prompt = (
        f"/vulnhunt {folder_path}\n\n"
        "IMPORTANT: This is running in non-interactive headless mode. "
        "Do NOT ask for approval or confirmation. Execute immediately."
    )
    if readonly:
        prompt += (
            "  Perform a read-only scan, skip instructions related to "
            "getting dependencies and executing code"
        )

    print(f"  [{ts()}] [{label}] STARTING scan", flush=True)
    start = time.time()

    proc = subprocess.Popen(
        build_scan_command(folder_path, prompt, engine=engine, readonly=readonly),
        stdout=subprocess.PIPE,
        # Merge stderr into stdout (which we drain below) rather than piping it
        # to its own buffer no one reads — an unread stderr pipe deadlocks the
        # child once it writes more than the pipe buffer (~64 KB).
        stderr=subprocess.STDOUT,
        text=True,
        cwd=folder_path,
    )

    event_count = 0
    timed_out = False

    def _kill_on_timeout():
        nonlocal timed_out
        timed_out = True
        print(f"  [{ts()}] [{label}] TIMEOUT after {SCAN_TIMEOUT}s — killing", flush=True)
        proc.kill()

    timer = threading.Timer(SCAN_TIMEOUT, _kill_on_timeout)
    timer.start()
    try:
        with _open_log_for_write(log_file) as log:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                log.write(line + "\n")
                log.flush()

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                event_count += 1
                if event_count % 50 == 0:
                    print(f"  [{ts()}] [{label}] ... {event_count} events", flush=True)
    finally:
        timer.cancel()

    proc.wait()
    elapsed = time.time() - start

    # A process that completed right as the timer fired can be flagged timed_out
    # even though it emitted a full result; don't discard a valid scan's data.
    if timed_out and has_valid_results(folder_path):
        timed_out = False

    if timed_out:
        print(f"  [{ts()}] [{label}] KILLED (timeout) after {elapsed:.0f}s", flush=True)
        cost_data = {}
    else:
        cost_data = extract_cost_from_log(log_file)
        cost_str = f", ${cost_data['total_cost_usd']:.2f}" if cost_data.get("total_cost_usd") else ""
        tokens_str = ""
        if cost_data.get("input_tokens") or cost_data.get("output_tokens"):
            total_tokens = (cost_data.get("input_tokens", 0) + cost_data.get("output_tokens", 0)
                           + cost_data.get("cache_read_tokens", 0) + cost_data.get("cache_creation_tokens", 0))
            tokens_str = f", {total_tokens:,} tokens"
        print(f"  [{ts()}] [{label}] FINISHED in {elapsed:.0f}s "
              f"(exit {proc.returncode}, {event_count} events{cost_str}{tokens_str})", flush=True)

    results_dir = find_results_dir(folder_path)
    return ScanResult(folder_path, label, proc.returncode, event_count, elapsed, results_dir, cost_data)


def scan_folder_with_retry(folder_path, log_filename=None, readonly=False, engine=None):
    """Wrap scan_folder with retry on 429 rate limit failures.

    Returns: Same ScanResult as scan_folder, with elapsed summed across attempts.
    """
    label = os.path.basename(folder_path)
    backoff = SCAN_RETRY_INITIAL_BACKOFF
    total_elapsed = 0
    log_file = os.path.join(folder_path, log_filename) if log_filename else None

    for attempt in range(SCAN_MAX_RETRIES + 1):
        if attempt > 0:
            print(f"  [{ts()}] [{label}] RETRY {attempt}/{SCAN_MAX_RETRIES} "
                  f"after {backoff:.0f}s backoff", flush=True)
            time.sleep(backoff)
            backoff = min(backoff * SCAN_RETRY_BACKOFF_MULTIPLIER, SCAN_RETRY_MAX_BACKOFF)

            removed = clean_prior_results(folder_path, log_filename or "benchmark_scan.log")
            if removed:
                print(f"  [{ts()}] [{label}] Cleaned {len(removed)} partial result(s)", flush=True)

        result = scan_folder(folder_path, log_file=log_file, readonly=readonly, engine=engine)
        total_elapsed += result.elapsed

        actual_log = os.path.join(folder_path, log_filename or "benchmark_scan.log")
        if result.returncode != 0 and is_rate_limit_failure(actual_log):
            if attempt < SCAN_MAX_RETRIES:
                print(f"  [{ts()}] [{label}] 429 rate limit detected "
                      f"(attempt {attempt + 1}/{SCAN_MAX_RETRIES + 1})", flush=True)
                continue
            else:
                print(f"  [{ts()}] [{label}] 429 rate limit — "
                      f"exhausted all {SCAN_MAX_RETRIES} retries", flush=True)

        return result._replace(elapsed=total_elapsed)


def scan_targets(targets, max_workers=None, status_interval=300, log_filename=None, readonly=False, engine=None):
    """Scan a list of benchmark targets in parallel with 429 retry.

    targets: list of dicts with at least 'clone_dir' and 'key' fields.
    status_interval: seconds between periodic status prints (default 5 min).
    log_filename: override log file name (default: benchmark_scan.log).
    Returns list of (target_key, ScanResult).
    """
    if max_workers is None:
        max_workers = MAX_SCAN_WORKERS

    print(f"\n[{ts()}] Starting scans for {len(targets)} targets "
          f"(engine {engine or config.ENGINE}, max {max_workers} parallel)", flush=True)

    results = []
    completed_keys = set()
    total = len(targets)
    last_status_time = time.time()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {
            executor.submit(scan_folder_with_retry, t["clone_dir"], log_filename=log_filename, readonly=readonly, engine=engine): t
            for t in targets
        }
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                result = future.result()
                results.append((target["key"], result))
                completed_keys.add(target["key"])
            except Exception as e:
                print(f"  [{ts()}] [{target['key']}] EXCEPTION: {e}", flush=True)
                results.append((target["key"],
                                ScanResult(target["clone_dir"], target["key"], -1, 0, 0, None, {})))
                completed_keys.add(target["key"])

            now = time.time()
            if now - last_status_time >= status_interval:
                last_status_time = now
                pending = [t["key"] for t in targets if t["key"] not in completed_keys]
                print(f"\n  [{ts()}] STATUS: {len(completed_keys)}/{total} complete, "
                      f"{len(pending)} still running:", flush=True)
                for k in pending:
                    print(f"    - {k}", flush=True)
                print(flush=True)

    return results
