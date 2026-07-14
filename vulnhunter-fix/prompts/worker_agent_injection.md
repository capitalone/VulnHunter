# Worker Agent — Injection (CWE-22/78/79/89/94/352/434/502/601/611/918)

**Extends:** `worker_agent_common.md`. Read that file first.

**Canonical fix pattern (per `references/cwe-fix-patterns.md` Class 2):**

Replace ad-hoc concatenation with a **structural separator** appropriate
to the sink:

| Sink | Structural fix |
|------|----------------|
| SQL | Parameterized query / prepared statement (never string concat) |
| Shell | `subprocess.run([...], shell=False)` or argv list + allowlist |
| HTML | Context-aware auto-escape at render time |
| Path | Canonicalize + prefix-match against allowlist root |
| Deserialization | Schema-validated JSON / Pydantic — NEVER `pickle` on untrusted input |
| XML | Parser with `resolve_entities=False` |
| URL | Allowlist scheme+host, DNS re-resolve, block internal-network IPs |

**Reject at boundary; do not sanitize.** Sanitization is a MITIGATION
signal — the input is still reaching the sink after passing through a
filter, which is fragile.

## Discrimination requirements (Step E.5)

The security test MUST use the scan's exact PoC payload:

- Pre-fix: Payload from the finding's `poc_payload` field executes /
  exfiltrates / redirects.
- Post-fix: Same payload is rejected at the boundary with a structured
  error (400 with validation details, or exception).

Record this shape in `.work/<repo>/discrimination/<vuln>.json`.

## FULL-tier bar (REQ-HON-004)

Grant `completeness_tier: FULL` only when:

- The unsafe API is removed or private-scoped (verified by grep against
  the changed diff — no callers to the unsafe form remain).
- Every caller routes through the safe API (superset match against
  `graph.callers_of(sink_symbol)`).
- Discrimination test uses the scan's PoC payload verbatim.

## Anti-patterns (auto-downgrade)

- Regex-based sanitizer for a structural language (SQL, HTML, URL) →
  **MITIGATION** (regexes miss escape variants).
- Blocklist of known-bad payloads → **MITIGATION** (allowlists are FULL).
- Post-hoc log of suspicious input without rejection → **WORKAROUND**.
- Length limit as sole defense → **MITIGATION**.
- Comment-based fix ("added TODO to sanitize") → refuse; mark
  `CANNOT_AUTO_FIX`.

## Residual template

```
injection: <sink> — <specific pattern still accepted> (e.g., "path traversal via `//` normalized differently on Windows")
```
