> **Harness adaptation note (Codex CLI).** This skill was authored for Claude
> Code; the methodology is unchanged. Two structural differences:
>
> 1. **You have no subagent-dispatch tool.** Where the skill says to launch a
>    subagent, execute that phase **yourself**, following the quoted block /
>    phase file exactly. For Phase 2, run the class-group trace passes
>    **sequentially** — one class group at a time — rather than dispatching
>    parallel agents; each pass still reads only its own class reference and
>    partition data. Keep your own context disciplined: after each pass,
>    record results to the results dir and do not carry candidate details
>    forward beyond what the phase files require.
> 2. **Tool vocabulary**: "Grep" → content search via shell (`rg` / `grep`);
>    "Glob" → filename search (`find`, `rg --files`, shell globs); "Read" →
>    file reads (`cat`/`sed -n` or your file-reading tool); "Bash" → the
>    sandboxed shell. Phase and skill files live under `~/.codex/skills/vulnhunt/`.
