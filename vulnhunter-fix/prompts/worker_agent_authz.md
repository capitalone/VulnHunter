# Worker Agent — Authorization (CWE-287/290/306/639/862/863/915)

**Extends:** `worker_agent_common.md`. Read that file first.

**Canonical fix pattern (per `references/cwe-fix-patterns.md` Class 1):**

1. Move the authorization check to the earliest deterministic path
   (middleware, route decorator, method entry).
2. Fail closed: default `deny`; explicit `allow` only after identity +
   role check.
3. Verify server-side; never trust client-supplied identity headers
   (`X-User-Id`) as sole signal.
4. Route every caller through the authorized entry path — no fallback
   `if is_admin or legacy_flag:` branches.

## Discrimination requirements (Step E.5)

The security test MUST use two distinct user contexts:

- User A owns resource R; user B does not.
- Pre-fix: B's request to `GET /resource/R` returns R's data (or a
  privileged mutation succeeds).
- Post-fix: B's request returns 403 (or 404 if enumeration is a concern).

Record this shape in `.work/<repo>/discrimination/<vuln>.json`.

## FULL-tier bar (REQ-HON-004)

Grant `completeness_tier: FULL` only when:

- Sink is invoked via one authorized path only (verified via
  `graph.callers_of(sink_symbol)`).
- No fallback branch exists in the fix diff (`grep -E "legacy_|bypass_|
  skip_auth_"` returns nothing under the changed files).
- Discrimination test uses two contexts (pre-fix / post-fix asymmetry).

If any condition fails → `MITIGATION` with a residual entry naming the
open fallback path (e.g., `"legacy_admin_endpoint remains bypassable"`).

## Anti-patterns (auto-downgrade to MITIGATION or WORKAROUND)

- Client-side authorization only (JavaScript in browser) → **WORKAROUND**.
- Header-based identity without cryptographic verification (unsigned
  `X-User-Id`) → **WORKAROUND**.
- "Deny by default" implemented as `if not allowed: log_warning()` (no
  raise/return) → **WORKAROUND** (log-only).
- Role check inside the handler after side-effect executes →
  **MITIGATION** (check present but ordered after damage).

## Residual template

For any non-FULL fix, emit residual vectors in this shape:

```
authz: <path> — <specific reason unclosed> (e.g., "GET /admin/legacy — pre-fix middleware not applied to legacy router")
```
