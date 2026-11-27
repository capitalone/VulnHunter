"""Batch scanning utilities: repo list parsing, result collection, status reporting."""

import json
import os
import shutil
import stat

from local_harness.config import (
    BATCH_CLONE_BASE_DIR,
    BATCH_LOG_FILENAME,
    BATCH_REPO_LIST_FILE,
    BATCH_UPLOAD_DIR,
)
from local_harness.scan import (
    RESULTS_MARKER,
    _is_link,
    _is_scan_results_dir,
    _open_log_for_read,
    _remove_results_entry,
    extract_cost_from_log,
)


def _ignore_symlinks(dirpath, names):
    """copytree ignore callable: keep only real regular files and directories.

    Cloned repos are untrusted; a planted symlink (e.g. secret -> /etc/passwd)
    would otherwise have its target's contents copied into the published upload
    (CANON-18: arbitrary host-file read). FIFOs, sockets and device nodes are
    dropped as well: copytree either errors on them (aborting the collect) or,
    for a device, could block reading it. Uses lstat so nothing is followed.
    Called per-directory, so nested entries are handled too.
    """
    ignored = []
    for name in names:
        path = os.path.join(dirpath, name)
        try:
            mode = os.lstat(path).st_mode
        except OSError:
            ignored.append(name)
            continue
        if _is_link(path) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            ignored.append(name)
    return ignored


def _owns_results_dir(repo_entry, rdir):
    """True if results dir `rdir` was named for the repo clone `repo_entry`.

    The vulnhunt skill names its output `<basename(target)>_VULNHUNT_RESULTS_<...>`
    and the harness targets the clone dir itself (e.g. `owner__repo`), so a
    genuine results dir always starts with `<repo_entry>_VULNHUNT_RESULTS_`.
    Anything else (e.g. repoB shipping `repoA_VULNHUNT_RESULTS_1`) would be
    copied into the flat upload dir under another repo's name.
    """
    return rdir.startswith(repo_entry + RESULTS_MARKER)


def parse_repo_list(repo_list_file=None):
    """Read REPO_LIST.txt and return list of URLs.

    Skips blank lines and lines starting with #.
    """
    if repo_list_file is None:
        repo_list_file = BATCH_REPO_LIST_FILE

    urls = []
    with open(repo_list_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    return urls


def collect_results(clone_base=None, upload_dir=None):
    """Collect all VULNHUNT_RESULTS folders into upload_dir.

    Returns dict with 'copied' and 'missing' lists.
    """
    if clone_base is None:
        clone_base = BATCH_CLONE_BASE_DIR
    if upload_dir is None:
        upload_dir = BATCH_UPLOAD_DIR

    if not os.path.isdir(clone_base):
        print(f"No clone directory found: {clone_base}")
        return {"copied": [], "missing": []}

    os.makedirs(upload_dir, exist_ok=True)

    copied = []
    missing = []
    # dst name -> repo entry that produced it in this run; a later repo must
    # never replace an upload already produced from a different repo.
    produced_by = {}

    for entry in sorted(os.listdir(clone_base)):
        entry_path = os.path.join(clone_base, entry)
        # Skip symlinked repo entries: os.path.isdir follows symlinks, so a
        # symlinked entry could redirect enumeration outside clone_base
        # (CANON-18 defense-in-depth).
        if _is_link(entry_path) or not os.path.isdir(entry_path):
            continue
        if RESULTS_MARKER in entry:
            continue

        # Only collect results our scan produced for *this* repo:
        # - _is_scan_results_dir rejects a results root that is itself a
        #   symlink (copytree would copy the link target, e.g. ~/.ssh —
        #   CANON-18) and a results dir committed in the repo (a forged report);
        # - _owns_results_dir rejects dirs named for another repo, which would
        #   otherwise land in (and clobber) that repo's slot in the flat upload.
        results_dirs = []
        for d in sorted(os.listdir(entry_path)):
            if not _is_scan_results_dir(entry_path, d):
                continue
            if not _owns_results_dir(entry, d):
                print(f"  WARNING: skipping {entry}/{d}: name does not match repo {entry!r}")
                continue
            results_dirs.append(d)

        if not results_dirs:
            missing.append(entry)
            continue

        for rdir in results_dirs:
            src = os.path.join(entry_path, rdir)
            dst = os.path.join(upload_dir, rdir)
            key = os.path.normcase(rdir)
            owner = produced_by.get(key)
            if owner is not None and owner != entry:
                print(f"  WARNING: skipping {entry}/{rdir}: already collected from {owner}")
                continue
            if os.path.lexists(dst):
                _remove_results_entry(dst)
            shutil.copytree(src, dst, ignore=_ignore_symlinks)
            produced_by[key] = entry
            copied.append(rdir)

    print(f"{'=' * 60}")
    print("COLLECT RESULTS FOR UPLOAD")
    print(f"{'=' * 60}")
    print(f"Destination:        {upload_dir}")
    print(f"Copied:             {len(copied)}")
    print(f"Missing results:    {len(missing)}")
    print()

    if copied:
        print(f"--- COPIED ({len(copied)}) ---")
        for name in copied:
            print(f"  {name}")
        print()

    if missing:
        print(f"--- MISSING RESULTS ({len(missing)}) ---")
        for name in missing:
            print(f"  {name}")
        print()

    return {"copied": copied, "missing": missing}


def scan_status(clone_base=None, log_filename=None):
    """Check the status of a batch scan by reading log files.

    Returns dict with 'complete', 'errored', 'running', 'not_started' lists.
    """
    if clone_base is None:
        clone_base = BATCH_CLONE_BASE_DIR
    if log_filename is None:
        log_filename = BATCH_LOG_FILENAME

    if not os.path.isdir(clone_base):
        print(f"No clone directory found: {clone_base}")
        return {"complete": [], "errored": [], "running": [], "not_started": []}

    complete = []
    errored = []
    running = []
    not_started = []

    for entry in sorted(os.listdir(clone_base)):
        entry_path = os.path.join(clone_base, entry)
        if not os.path.isdir(entry_path):
            continue
        if "_VULNHUNT_RESULTS_" in entry:
            continue

        log_path = os.path.join(entry_path, log_filename)
        # The log lives in the untrusted clone: a planted symlink (or FIFO) at
        # this path is treated as absent rather than followed.
        f = _open_log_for_read(log_path)
        if f is None:
            not_started.append(entry)
            continue

        with f:
            lines = f.read().decode("utf-8", errors="replace").splitlines()

        if not lines:
            not_started.append(entry)
            continue

        last_line = lines[-1].strip()
        try:
            ev = json.loads(last_line)
        except json.JSONDecodeError:
            running.append((entry, "unparseable last line"))
            continue

        if ev.get("type") == "result":
            if ev.get("is_error"):
                status_code = ev.get("api_error_status", "unknown")
                errored.append((entry, f"api_error_status={status_code}"))
            else:
                duration_s = ev.get("duration_ms", 0) / 1000
                cost_data = extract_cost_from_log(log_path)
                complete.append((entry, duration_s, cost_data))
        else:
            subtype = ev.get("subtype", ev.get("type", "?"))
            running.append((entry, subtype))

    total_dirs = len(complete) + len(errored) + len(running) + len(not_started)

    print(f"{'=' * 60}")
    print("BATCH SCAN STATUS")
    print(f"{'=' * 60}")
    print(f"Cloned (dirs found):  {total_dirs}")
    print(f"Complete (success):   {len(complete)}")
    print(f"Errored:              {len(errored)}")
    print(f"Still running:        {len(running)}")
    print(f"Not started yet:      {len(not_started)}")
    print()

    if running:
        print(f"--- RUNNING ({len(running)}) ---")
        for name, status in running:
            print(f"  {name}  [{status}]")
        print()

    if errored:
        print(f"--- ERRORED ({len(errored)}) ---")
        for name, reason in errored:
            print(f"  {name}  [{reason}]")
        print()

    if complete:
        print(f"--- COMPLETE ({len(complete)}) ---")
        for name, duration_s, cost_data in complete:
            mins = duration_s / 60
            cost_str = f", ${cost_data['total_cost_usd']:.2f}" if cost_data.get("total_cost_usd") else ""
            print(f"  {name}  [{mins:.1f} min{cost_str}]")
        print()

    if not_started:
        print(f"--- NOT STARTED ({len(not_started)}) ---")
        for name in not_started[:10]:
            print(f"  {name}")
        if len(not_started) > 10:
            print(f"  ... and {len(not_started) - 10} more")
        print()

    return {"complete": complete, "errored": errored, "running": running, "not_started": not_started}
