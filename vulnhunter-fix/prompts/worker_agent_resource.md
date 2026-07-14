# Worker Agent — Resource (CWE-117/200/362/400/532)

**Extends:** `worker_agent_common.md`. Read that file first.

**Canonical fix pattern (per `references/cwe-fix-patterns.md` Class 4):**

Class 4 covers resource consumption, race conditions, and information
disclosure — grouped because they share the "bounded/safe use of a
resource" theme.

| CWE | Fix pattern |
|-----|-------------|
| CWE-117 (Log injection) | PII masking at log call site; structured logging fields (never `%s` interpolation of raw input) |
| CWE-200 (Info exposure) | Remove sensitive field from response; do not obfuscate |
| CWE-362 (Race / TOCTOU) | Atomic operation: CAS, DB unique constraint, file-lock, transactional insert |
| CWE-400 (Resource consumption) | Bounded limit: timeout, semaphore, connection cap; error on breach |
| CWE-532 (Sensitive in logs) | Mask at the log call site; enumerate the masked field names |

## Discrimination requirements (Step E.5)

- Pre-fix: resource-exhaustion payload succeeds within scan bounds, OR
  the sensitive field appears in log/response.
- Post-fix: payload is rejected with bounded error, OR the field is
  absent.

## FULL-tier bar (REQ-HON-004)

Grant `completeness_tier: FULL` only when:

- The bound/mask is at the correct layer (sink, not upstream).
- No unbounded fallback exists ("if limit fails, allow through" is
  automatic MITIGATION).
- Discrimination test asserts the exhaustion or leak was actually
  observed pre-fix (not just theoretically possible).

## Anti-patterns

- Semaphore/limit around the entire service, not the specific sink →
  **MITIGATION**.
- Log field renamed but full record still emitted → **WORKAROUND**.
- CWE-362 fix that catches the race exception without correcting the
  ordering → **MITIGATION** (masks the symptom, race still exists).
- CWE-400 fix that logs but does not throttle → **WORKAROUND**.

## Residual template

```
resource: <resource-name> — <specific unbounded path> (e.g., "no timeout on /api/report/generate; a subsequent multipart upload still consumes memory unbounded")
```
