#!/usr/bin/env python3
"""
VulnHunter Fix — Preflight Check

Verifies LOCAL system requirements before running the pipeline. Does
not make any network calls — auth + reachability are verified by the
prompt via Claude's Bash tool (which has the working network context
this Python process doesn't).

Run from CWD = the user's target repo for in-place mode, or any cwd
for fork mode.

Usage:
    python3 scripts/preflight.py
"""

import _skill_bootstrap  # noqa: F401  — adds bundled .venv site-packages to sys.path

import os
import shutil
import subprocess
import sys


REQUIRED_PYTHON = (3, 11)
REQUIRED_GIT = (2, 30)
CHECKS_PASSED = 0
CHECKS_FAILED = 0


def check(name: str, passed: bool, detail: str = "", optional: bool = False):
    global CHECKS_PASSED, CHECKS_FAILED
    if passed:
        CHECKS_PASSED += 1
        print(f"  [ok] {name}")
    else:
        if not optional:
            CHECKS_FAILED += 1
        msg = f"  [WARN] {name}" if optional else f"  [FAIL] {name}"
        if detail:
            msg += f" — {detail}"
        print(msg)


def parse_version(version_str: str) -> tuple:
    parts = []
    for p in version_str.strip().split("."):
        try:
            parts.append(int(p))
        except ValueError:
            break
    return tuple(parts)


def check_python():
    v = sys.version_info
    passed = (v.major, v.minor) >= REQUIRED_PYTHON
    check(
        f"Python {v.major}.{v.minor}.{v.micro}",
        passed,
        f"requires {REQUIRED_PYTHON[0]}.{REQUIRED_PYTHON[1]}+" if not passed else "",
    )


def check_git():
    git = shutil.which("git")
    if not git:
        check("git", False, "not found in PATH")
        return
    try:
        out = subprocess.check_output(["git", "--version"], text=True, timeout=5)
        version_str = out.strip().replace("git version ", "").split()[0]
        version = parse_version(version_str)
        passed = version[:2] >= REQUIRED_GIT
        check(
            f"git {version_str}",
            passed,
            f"requires {REQUIRED_GIT[0]}.{REQUIRED_GIT[1]}+" if not passed else "",
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        check("git", False, "cannot determine version")


def check_gh_cli():
    gh = shutil.which("gh")
    if not gh:
        check("gh CLI", False, "not found in PATH — install from https://cli.github.com")
        return
    try:
        out = subprocess.check_output(["gh", "--version"], text=True, timeout=5)
        version_str = out.strip().split("\n")[0].split()[-1].split("/")[-1]
        check(f"gh CLI {version_str}", True)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        check("gh CLI", False, "cannot determine version")


def check_claude_cli():
    claude = shutil.which("claude")
    if not claude:
        check("Claude CLI", False, "not found in PATH")
        return
    try:
        # `claude --version` may shell out through the CLI's own network path;
        # cap at 5s so a hung network call doesn't wedge preflight.
        out = subprocess.check_output(
            ["claude", "--version"], text=True, stderr=subprocess.DEVNULL, timeout=5,
        ).strip()
        check(f"Claude CLI ({out})" if out else "Claude CLI", True)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        check("Claude CLI", False, "cannot determine version")


def _free_disk_bytes(path: str) -> int:
    """Free disk space in bytes for the volume containing ``path``.

    os.statvfs doesn't exist on Windows — the CRT has no statvfs() for
    CPython to wrap — so this queries GetDiskFreeSpaceExW via ctypes there
    instead.
    """
    if os.name == "nt":
        import ctypes

        free_bytes = ctypes.c_ulonglong(0)
        if not ctypes.windll.kernel32.GetDiskFreeSpaceExW(
            ctypes.c_wchar_p(os.path.abspath(path)), None, None, ctypes.byref(free_bytes)
        ):
            raise OSError("GetDiskFreeSpaceExW failed")
        return free_bytes.value
    stat = os.statvfs(path)
    return stat.f_bavail * stat.f_frsize


def check_disk_space():
    try:
        free_gb = _free_disk_bytes(".") / (1024 ** 3)
    except (OSError, AttributeError):
        check("Disk space", True, "cannot determine — skipping check")
        return
    passed = free_gb >= 5.0
    check(
        f"Disk space ({free_gb:.1f} GB free)",
        passed,
        "recommend at least 5 GB free" if not passed else "",
    )


def _total_memory_bytes() -> int:
    """Total physical RAM in bytes. os.sysconf doesn't exist on Windows —
    the CRT has no sysconf() for CPython to wrap — so this queries
    GlobalMemoryStatusEx via ctypes there instead.
    """
    if os.name == "nt":
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            raise OSError("GlobalMemoryStatusEx failed")
        return stat.ullTotalPhys
    return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")


def check_memory():
    try:
        mem_gb = _total_memory_bytes() / (1024 ** 3)
        cpus = os.cpu_count() or 1
        slots = max(1, min(cpus, int(mem_gb // 4), 8))
        check(f"Memory ({mem_gb:.1f} GB, {cpus} CPUs → {slots} parallel slots)", True)
    except (ValueError, OSError, AttributeError):
        check("Memory", True, "cannot determine — will default to conservative settings")


def check_git_clone_writable():
    """Verify `git init` + a write into .git/config works under cwd.

    Some macOS sandbox profiles deny git's default hook-template copy
    under user paths, breaking every fresh `git clone`. The runner
    sets GIT_TEMPLATE_DIR= to skip that step; this preflight confirms
    that the workaround (or the absence of the restriction) leaves
    cwd actually writable for fresh repos.

    Fork-mode only — skipped in in-place mode since CWD is already a
    git repo.
    """
    import tempfile

    probe_dir = None
    try:
        probe_dir = tempfile.mkdtemp(prefix=".vulnfix-probe-", dir=".")
        env = os.environ.copy()
        env["GIT_TEMPLATE_DIR"] = ""
        result = subprocess.run(
            ["git", "-c", "init.templateDir=", "init", "-q", probe_dir],
            env=env, capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            check(
                "git init under cwd",
                False,
                f"failed even with GIT_TEMPLATE_DIR=: {result.stderr.strip()[:200]}",
            )
            return
        config = os.path.join(probe_dir, ".git", "config")
        if not os.path.isfile(config):
            check("git init under cwd", False, ".git/config was not created")
            return
        with open(config, "a") as f:
            f.write("# preflight write-probe\n")
        check("git clone-ready (cwd writable for fresh .git/)", True)
    except Exception as e:
        check("git clone-ready", False, str(e))
    finally:
        if probe_dir and os.path.isdir(probe_dir):
            shutil.rmtree(probe_dir, ignore_errors=True)


def _detect_in_place_root() -> str | None:
    """Return repo root if CWD is inside a git working tree with a
    GitHub origin; else None.

    Used to skip fork-mode-only filesystem probes when the user is
    running the skill against an already-cloned target repo.
    """
    if not shutil.which("git"):
        return None
    try:
        top = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except subprocess.CalledProcessError:
        return None
    if not top:
        return None
    try:
        origin = subprocess.check_output(
            ["git", "-C", top, "remote", "get-url", "origin"],
            text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except subprocess.CalledProcessError:
        return None
    if "github" not in origin.lower():
        return None
    return top


def check_in_place_mode(repo_root: str | None = None):
    """Run the in-place-mode-specific local checks.

    No network — `gh auth` and repo-access verification happen in the
    SKILL.md prompt via Claude's Bash tool (which has the working
    network context Python doesn't).

    ``repo_root`` may be passed in by the caller to avoid re-running
    detection; if omitted we detect it ourselves.
    """
    top = repo_root if repo_root is not None else _detect_in_place_root()
    if top is None:
        return

    print("\nIn-place mode:")

    # Working tree must be clean — otherwise our worktree branches
    # off an unknown commit state and confuses the user later.
    rc = subprocess.run(
        ["git", "-C", top, "diff", "--quiet"],
        capture_output=True,
    ).returncode
    rc_staged = subprocess.run(
        ["git", "-C", top, "diff", "--cached", "--quiet"],
        capture_output=True,
    ).returncode
    clean = rc == 0 and rc_staged == 0
    check(
        "Working tree is clean",
        clean,
        "uncommitted changes detected; commit or stash before running"
        if not clean else "",
    )

    # Prune any stale worktrees from prior crashed runs.
    try:
        subprocess.run(
            ["git", "-C", top, "worktree", "prune"],
            capture_output=True, check=True,
        )
        check("git worktree prune", True)
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        check("git worktree prune", False, str(exc))


CLOUD_LLM_ENV_VARS = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "DEEPSEEK_API_KEY",
    "MOONSHOT_API_KEY",
)


def check_graphifyy():
    """REQ-GRA-010: verify graphifyy is importable and version-pinned."""
    try:
        import graphify  # noqa: F401
    except ImportError as exc:
        check("graphifyy (module import)", False, f"cannot import 'graphify': {exc}")
        return
    try:
        from importlib.metadata import version, PackageNotFoundError
        version_str = version("graphifyy")
    except (ImportError, Exception) as exc:
        check("graphifyy version", False, f"cannot resolve distribution version: {exc}")
        return
    parts = parse_version(version_str)
    ok = (0, 8, 14) <= parts < (0, 9, 0)
    check(
        f"graphifyy {version_str}",
        ok,
        "requires >=0.8.14,<0.9.0 (REQ-GRA-001)" if not ok else "",
    )


def check_backend_isolation():
    """REQ-GRA-004: refuse to run when any cloud-LLM env var is set."""
    leaked = [name for name in CLOUD_LLM_ENV_VARS if os.environ.get(name)]
    if leaked:
        check(
            "graph backend isolation",
            False,
            f"cloud LLM env vars are set: {', '.join(leaked)}. "
            "AST-only isolation cannot be guaranteed until these are unset.",
        )
        return
    check("graph backend isolation (no cloud LLM env vars)", True)


def check_jsonschema():
    """REQ-SCH-001: verify jsonschema is importable and version-pinned."""
    try:
        import jsonschema  # noqa: F401
    except ImportError as exc:
        check("jsonschema (module import)", False, f"cannot import: {exc}")
        return
    try:
        from importlib.metadata import version as _version
        version_str = _version("jsonschema")
    except Exception as exc:
        check("jsonschema version", False, f"cannot resolve distribution version: {exc}")
        return
    parts = parse_version(version_str)
    ok = (4, 20) <= parts < (5, 0)
    check(
        f"jsonschema {version_str}",
        ok,
        "requires >=4.20,<5.0 (REQ-SCH-001)" if not ok else "",
    )


def main():
    print("VulnHunter Fix — Preflight Check")
    print("=" * 40)

    in_place_root = _detect_in_place_root()

    print("\nDependencies:")
    check_python()
    check_git()
    check_gh_cli()
    check_claude_cli()

    print("\nRemediation-rigor (Bundle 2 + 6):")
    check_graphifyy()
    check_backend_isolation()
    check_jsonschema()

    print("\nSystem Resources:")
    check_memory()
    check_disk_space()

    # The clone-writable probe is fork-mode-only: irrelevant when CWD
    # is already a git repo and would also leak `.vulnfix-probe-*`
    # tempdirs into it.
    if in_place_root is None:
        print("\nFilesystem:")
        check_git_clone_writable()

    check_in_place_mode(in_place_root)

    print(f"\n{'=' * 40}")
    print(f"Results: {CHECKS_PASSED} passed, {CHECKS_FAILED} failed")
    print(
        "Note: gh auth + GitHub reachability are checked separately "
        "via the prompt's Bash tool (Python subprocess can't talk to "
        "GitHub in this environment)."
    )

    if CHECKS_FAILED > 0:
        print("\nFix the failures above before running the pipeline.")
        _print_bootstrap_hint()
        sys.exit(1)
    else:
        print("\nAll local checks passed. Ready to run.")
        sys.exit(0)


def _print_bootstrap_hint():
    """When the failures look like a missing/broken bundled venv, print the
    exact one-command remediation. Avoids the "why is graphifyy missing?"
    dead-end where the user assumes a real dependency problem.
    """
    try:
        import graphify  # noqa: F401
        import jsonschema  # noqa: F401
    except ImportError:
        pass
    else:
        return  # Deps ARE importable — some other check is failing; no hint needed.

    skill_dir = os.path.expanduser("~/.claude/skills/vulnhunter-fix")
    skill_installed = os.path.isfile(os.path.join(skill_dir, "SKILL.md"))
    # install.sh/install.cmd live at the repo root and are never copied into
    # the installed skill dir by either installer, so the remediation hint
    # can only ever point back at the user's source checkout, not a path
    # under skill_dir — there is nothing there to run.
    if os.name == "nt":
        venv_python = os.path.join(skill_dir, ".venv", "Scripts", "python.exe")
        run_install_hint = "    install.cmd"
    else:
        venv_python = os.path.join(skill_dir, ".venv", "bin", "python3")
        run_install_hint = "    bash install.sh"

    print("\nBootstrap hint:")
    if os.path.isfile(venv_python):
        # Venv exists but the interpreter isn't running through the bootstrap.
        # Common cause: script was invoked with an incompatible Python
        # (see scripts/_skill_bootstrap.py re-exec logic).
        print(f"  A bundled venv exists at {venv_python}")
        print("  but this preflight isn't running through it. Ensure the")
        print("  installed skill's scripts import _skill_bootstrap (they do")
        print("  by default) and re-run preflight — the re-exec will")
        print("  transparently switch to the bundled Python 3.11.")
        print("  If that still fails, rebuild the venv from your")
        print("  vulnhunter-fix source checkout:")
        print(run_install_hint)
    elif skill_installed:
        # Skill dir exists (SKILL.md present) but no venv → installer never
        # ran, or ran with an older installer that predates venv bundling.
        print("  Skill is installed but the bundled venv is missing.")
        print("  From your vulnhunter-fix source checkout:")
        print(run_install_hint)
        print(f"  This creates {skill_dir}{os.sep}.venv{os.sep} and")
        print("  installs graphifyy + jsonschema into it.")
    else:
        # Not installed at all.
        print(f"  No installed skill at {skill_dir}.")
        print("  From your vulnhunter-fix source checkout:")
        print(run_install_hint)


if __name__ == "__main__":
    main()
