# Sweep Patterns

**Referenced by:** REQ-SWP-002. Consumed by `scripts/sweep-root-causes.py`
Pass 2 (pattern pass, per CWE-class regex over files not covered by
graph-anchored Pass 1).

## Purpose

Sweep patterns catch sibling defects that Pass 1 misses because they are
not directly reachable via `graph.callers_of()` — e.g., copy-pasted
patterns in files the graph does not connect, or callers only reachable
via string-based dispatch. Pass 2 is regex-only; false positives are
expected and reviewed before amendment.

## Pattern table

Each row is a CWE class + a compiled regex. The sweep script iterates
through the ROOT cause's CWE class, then applies the matching row(s) to
every source file in the target repo.

### Authorization

```
class: authz
cwes: [287, 290, 306, 639, 862, 863, 915]
patterns:
  # Flags a Flask route whose decorator block (between @app.route and def)
  # contains NO *_required guard. The negative lookahead is scoped to each
  # decorator line so an already-protected route (@login_required etc.)
  # does NOT match. `.` never crosses newlines (no DOTALL), so decorator
  # lines are enumerated explicitly. NOTE: only inspects decorators BELOW
  # the route line; a guard placed above @app.route is not seen (accepted
  # limitation for this low-confidence Pass-2 fallback).
  - '@app\.route\([^)]*\)[^\n]*\n(?:[ \t]*@(?!\w*_required\b)[^\n]*\n)*[ \t]*def\s+\w+'
  - 'is_admin\s*or\s+\w+'          # fallback branches
  - '(?<!\.)request\.headers\.get\([\"\']X-User-Id'  # header-based identity without server verify
```

### Injection

```
class: injection
cwes: [22, 78, 79, 89, 94, 352, 434, 502, 601, 611, 918]
patterns:
  - 'execute\([\"\'].*?\%s'         # SQL string interpolation
  - 'os\.system\('                    # shell injection
  - 'subprocess\.\w+\([^)]*shell\s*=\s*True'
  - 'pickle\.loads\('                 # untrusted deserialization
  - '\.innerHTML\s*='                 # DOM XSS
  - '<!ENTITY\s'                      # XXE
```

### Crypto

```
class: crypto
cwes: [295, 326, 327, 328, 330, 345, 347]
patterns:
  - 'AES\.MODE_(?:ECB|CBC)'
  - '\bMD5\b'
  - '\bSHA-?1\b'
  - 'verify\s*=\s*False'
  - 'insecure_skip_verify'
  - 'DES\.new\('
```

### Resource

```
class: resource
cwes: [117, 200, 362, 400, 532]
patterns:
  - 'while\s+True\s*:.*?read\('
  - 'logger?\.\w+\([^)]*(password|secret|api_key|ssn|credit_card)'
  - '\.readlines\(\)'                 # unbounded read
```

### Config (regex on declarative artifacts)

```
class: config
cwes: []   # config findings tagged with cwe: "config"
patterns:
  - 'Resource\s*:\s*[\"\']\*[\"\']'   # IAM wildcard
  - 'publicly_accessible\s*:\s*true'
  - '"cidr":\s*"0\.0\.0\.0/0"'
```

## Confidence semantics

Pass 2 matches are always low-confidence (regex, not AST-anchored).
Sweep records `Captured (regex-only)` per REQ-SWP-007 when the graph
backend was in fallback mode; a mixed run (Pass 1 AST + Pass 2 regex)
records `Captured` without the annotation.
