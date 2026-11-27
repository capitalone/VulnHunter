"""The agent README's example commands must satisfy the CLI contract.

Regression for #43: the quick start showed ``python -m agent <url>`` with
no ``--mode``. The CLI deliberately has no default mode, so new users
following the docs hit an argument error on their first command. This
test extracts every ``python -m agent`` line from the README's fenced
code blocks and runs it through the real parser, without loading config
or touching the network.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest

from agent.__main__ import _build_parser, main

README = Path(__file__).resolve().parents[1] / "README.md"
_FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)


def _readme_agent_commands() -> list[str]:
    commands = []
    for block in _FENCE_RE.findall(README.read_text(encoding="utf-8")):
        for line in block.splitlines():
            line = line.strip()
            if line.startswith("python -m agent "):
                commands.append(line)
    return commands


def test_readme_has_agent_commands() -> None:
    # Guard against the extractor silently matching nothing.
    assert _readme_agent_commands()


@pytest.mark.parametrize("command", _readme_agent_commands())
def test_readme_command_selects_a_valid_mode(command: str) -> None:
    argv = shlex.split(command, comments=True)[3:]  # drop "python -m agent"
    args = _build_parser().parse_args(argv)
    assert args.mode in ("scan", "verify"), command
    if args.mode == "scan":
        assert len(args.targets) == 1, command
    else:
        assert args.targets, command


def test_modeless_invocation_still_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    # The explicit-mode requirement is deliberate; fixing the docs must not
    # weaken it.
    with pytest.raises(SystemExit) as exc:
        main(["https://github.com/your-org/your-service"])
    assert exc.value.code == 2
    assert "--mode is required; choose scan or verify" in capsys.readouterr().err
