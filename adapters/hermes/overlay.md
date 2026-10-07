> **Harness adaptation note (Hermes).** This skill was authored for Claude
> Code; the methodology is unchanged. Tool vocabulary mapping: "Grep" →
> `search_files` (content search) or `rg` via the terminal tool; "Glob" →
> filename/pattern search; "Read" → `read_file`; "Bash" → the `terminal`
> tool; "the Agent tool" / "launch a subagent" → `delegate_task` (children
> run with their own context and terminal session). Where a step says to
> launch a `general-purpose` subagent, dispatch via `delegate_task` with the
> quoted block as the goal. "Return message" limits ("under 20 words") apply
> to the delegate's final message. Web lookups (CVE/vendor advisories), where
> a phase calls for them, use the web toolset if enabled.
>
> **Delegation protocol (important).** Hermes runs every top-level
> `delegate_task` in the background: the call returns immediately with
> status "dispatched", and the child's result is delivered back to you only
> while your turn is still alive. After dispatching any subagent, do NOT
> conclude, error out, or produce a final answer while children are running.
> Keep the turn alive by periodically calling `delegate_task` with
> `action: "list"` until every child shows completed (its result then
> arrives as a follow-up message), and only then verify that phase's output
> files exist and continue the workflow.
