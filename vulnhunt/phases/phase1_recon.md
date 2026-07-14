# Phase 1: Reconnaissance

> **Context**: You have completed the Mandatory First Actions (results directory,
> dependencies). The orchestrator's Operating Principles and
> Investigation Discipline are in effect throughout this phase.

Your goal is to map the complete attack surface before looking for specific
vulnerabilities.

### Step 1: Structural Overview

Use the **Glob tool** to discover all production source files by language. Run
multiple Glob calls **in parallel** for each language extension present:

- `**/*.js`, `**/*.ts`, `**/*.tsx`, `**/*.go`, `**/*.java`, `**/*.scala`, `**/*.kt`,
  `**/*.py`, `**/*.c`, `**/*.cpp`, `**/*.rs`, `**/*.lua`, `**/*.m`

Exclude results in test, vendor, generated, and third-party directories (see
Operating Principle #5 for the full exclusion list). Review the file list to identify:
- What languages are used
- What frameworks are in use (web frameworks, ORMs, crypto libraries)
- What the module/package structure looks like

### Step 1a: Sink Enumeration Pre-Pass

Before building the input inventory, grep for ALL dangerous sink patterns from
the Phase 2 Sink Reference — adapted to the detected frameworks — including
template-level sinks (e.g., `[href]`, `v-html`). Record each sink's file:line
to create a **sink inventory** for cross-referencing with the input inventory.
Exclude test/spec files from results. If results are truncated, run additional
scoped greps per app/lib directory to ensure full coverage.

**Completeness cross-check (MANDATORY)**: Grep results are often truncated.
After building the sink inventory, list every app/module from Step 1 and confirm
each has at least one sink entry. For EACH app/module with zero sinks, run a
**separate** targeted grep within that app's source directory (and its associated
libs/) for the same sink patterns. Do not skip this step — a missing app in the
sink inventory cascades to a missing partition and a total blind spot.
Include shared libraries that serve a specific app (e.g., `libs/auth/step-up/`
serves `apps/step-up/`) in the coverage check for that app.

**URL-path-concatenation sink sweep (MANDATORY)**: In addition to navigation
sinks, grep ALL production source files (including shared libraries) for
string concatenation/interpolation into HTTP client URL arguments — patterns
like `${baseUrl}${param}`, `url + param`, template literals passed to
`http.get()`/`fetch()`/`request()`. These are SSRF/path-traversal sinks
even when the base URL is hardcoded. Record each in the sink inventory. When
a shared library contains such a sink, include that file in the app-specific
file list of every partition whose inputs reach it.

### Step 1b: Input Inventory (CRITICAL — this drives the entire audit)

After reading the file tree and identifying the tech stack, **enumerate every
point where external data enters the codebase.** This inventory is the
completeness guarantee — every input gets traced to a disposition, and the audit
is not done until the inventory is fully resolved.

Use the **Grep tool** to find all user-controllable inputs, adapting patterns to
the detected frameworks. Do NOT use the examples below verbatim — build patterns
from what you actually found in Step 1.

**Where to look for inputs** — search for the detected framework's input-parsing
APIs to find every entry point, then read each entry point to enumerate its inputs.
Adapt to ALL entry point types present in the codebase, not just HTTP:
- **HTTP** — Express/Koa/Fastify: `req.params`, `req.query`, `req.body`, `req.headers`, `req.cookies`; Spring: `@RequestParam`, `@PathVariable`, `@RequestBody`; Go net/http: `r.URL.Query()`, `r.FormValue()`, `r.Header.Get()`; Flask/Django: `request.args`, `request.form`, `request.json`; Rails: `params[]`, `request.headers[]`
- **gRPC / RPC**: protobuf message fields in service method signatures, Thrift struct fields
- **CLI**: `cobra.Command` flag definitions, `argparse` arguments, `process.argv`, `flag.Parse`
- **Message queues**: Kafka/SQS/RabbitMQ consumer message bodies, message headers/attributes
- **Serverless**: `event` object fields (API Gateway, SQS trigger, SNS trigger, S3 event, etc.)
- **WebSocket**: message handler payloads, connection upgrade parameters
- **File processors**: file content, file names, MIME types from watched directories or upload endpoints
- **Scheduled jobs / cron**: if a job reads from a store that an attacker can write to, the store values are inputs
- **HTTP interceptor / middleware response handlers**: interceptors that read
  fields from response or error bodies (`err.error.*`, `event.body.*`) and
  pass them to navigation sinks, storage, or further processing. Search for
  `HttpInterceptor` (Angular), error-handling middleware (Express/Koa),
  `ResponseBodyAdvice`/`@ExceptionHandler` (Spring)
- **Filters/interceptors with direct response sinks**: filters and middleware
  that respond directly (redirect, error page) WITHOUT delegating to a controller.
  Search for: servlet Filter with `sendRedirect`/`setStatus`, Spring
  `HandlerInterceptor` returning false, Express middleware calling `res.redirect()`
  without `next()`. These are independent entry points — inventory the request
  fields they consume (URI, query string, headers, path components).
- **Framework infrastructure endpoints**: many frameworks start additional network
  listeners beyond the application's explicit route definitions — cluster
  management APIs, health/readiness probes on separate ports, cluster
  communication/remoting, debug/profiling endpoints. Search for these in the
  application's main/bootstrap class and configuration files. For each, verify:
  (a) what port/interface it binds to, (b) whether authentication is configured,
  (c) whether TLS is enabled, (d) what operations it exposes. An unauthenticated
  management endpoint that allows cluster manipulation or an unencrypted remoting
  port that accepts serialized messages are findings — even though they are not
  part of the application's API routes.
- Adapt further for any other entry point types you detect.

The examples above are starting points, not exhaustive. After identifying the
codebase's frameworks and libraries, add any additional input-parsing APIs,
middleware, or data-binding patterns you recognize — including project-specific
wrappers, custom request parsers, or framework plugins not listed here.

**What to enumerate** — every place an attacker can influence a value:

- **HTTP inputs**: route parameters, query strings, request bodies, headers,
  cookies. Search for the detected framework's request-parsing APIs.
- **File uploads**: multipart form data, file names, file content, MIME types.
- **URL/path components**: path segments used in routing or downstream logic.
- **WebSocket messages**: message handlers, event listeners.
- **CLI arguments**: command-line flags, positional arguments, stdin.
- **Environment variables and config**: values read at runtime from env or config
  files that a deployment-adjacent attacker could influence.
- **Message queue / event consumers**: messages received from queues, topics,
  event buses (Kafka, SQS, RabbitMQ, etc.).
- **Incoming gRPC / RPC fields**: protobuf message fields, Thrift struct fields.
- **Database reads**: values read from a store that an attacker could have written
  to via another endpoint (second-order inputs).
- **Third-party API responses**: data returned from external services that the
  attacker could influence (e.g., by controlling what's stored in that service).
- Adapt further for any other input vectors present in the detected stack.
- **Server variables promoted by infrastructure config**: variables normally
  trusted (e.g., remote_addr, client IP, server_name) that become attacker-
  controllable due to config directives in the repo. Grep for: `set_real_ip_from`,
  `trust proxy`, `ForwardedHeaders`, `x-forwarded-for` trust settings. For each
  directive that trusts a broad CIDR (0.0.0.0/0, any, true), add the promoted
  variable as an attacker-controlled input in the inventory.

The categories above are starting points. Add any additional input vectors you
recognize from the codebase's specific libraries, custom abstractions, or
domain patterns — even if not listed here.

**For each input, record:**
1. **Location**: file:line where the input enters the codebase
2. **Source type**: HTTP param / header / body field / cookie / CLI arg / env var /
   queue message / file upload / etc.
3. **Variable name**: what the input is assigned to in code
4. **Entry point**: which route, CLI command, queue consumer, gRPC method, or
   other entry point receives it
5. **Trust level**: unauthenticated / authenticated / internal / privileged —
   based on what auth/authz is required to reach this entry point

**Output format** — produce a numbered inventory table:

| # | Source Type | Location | Variable | Entry Point | Trust Level |
|---|---|---|---|---|---|
| 1 | HTTP query param | src/handlers/search.js:14 | `q` | GET /api/search | unauth |
| 2 | HTTP header | src/middleware/auth.js:8 | `x-correlation-id` | all HTTP routes | unauth |
| 3 | CLI argument | cmd/import.go:22 | `--file` | `import` command | local |
| 4 | SQS message body | src/consumers/notify.js:9 | `event.body` | notify-queue consumer | internal |
| ... | ... | ... | ... | ... | ... |

**Prioritization**: When working through the inventory in Phase 2, start with
inputs at the lowest trust level (unauthenticated first, then authenticated, then
internal, then privileged). Inputs reachable without authentication have the
highest attacker accessibility and should be traced first.

**Completeness check**: After building the inventory, compare it against the entry
points found in Step 1. Every entry point (HTTP route, CLI command, queue consumer,
gRPC method, cron job, etc.) should have at least one input. If an entry point
appears in the scan but has zero inputs in the inventory, either you missed inputs
— go back and read that entry point's code — OR the endpoint genuinely accepts no
user input. In the latter case, add a synthetic inventory entry with source type
'no-input endpoint', variable 'N/A', and trust level based on what authentication
the endpoint requires. Zero-input endpoints are critical for the NAV agent: an
endpoint that performs a sensitive operation without requiring authentication is an
auth bypass candidate (CWE-306) regardless of whether it processes user data.

**Sibling input rule**: When an extraction point (destructuring, query param
parser, DTO binding) yields N inputs, enumerate ALL N in the inventory — not
just the dangerous-looking ones. Also grep for each parameter name across ALL
entry points — the same name at different routes is a separate input.
Phase 2 determines safety, not Phase 1.

### Step 1c: Indirect Dispatch Detection

Search for patterns where functions are stored in objects, maps, or arrays and
called dynamically at runtime. These create hidden call edges that static forward
tracing will miss:

- **Function/method maps**: `handlers[type](req)`, `strategies[key].execute(data)`,
  `bundleConfig.dataFetcher(params)`
- **Callback registration**: functions passed as arguments and invoked later
  (event listeners, middleware chains, promise callbacks)
- **Factory/builder patterns**: functions that return other functions selected
  by configuration or input
- **Re-export/wrapper modules**: utility modules that import a function and
  re-export it (or wrap it), creating an indirect path from callers of the
  wrapper to the original function

For each dispatch pattern found:
1. Enumerate every function in the dispatch table / callback registry
2. Add each as a separate entry point in the input inventory (the dispatched
   function receives the same user-controlled data the dispatcher received)
3. Flag these in the inventory as "indirect dispatch" so Phase 2 traces them
   with extra care

This step is critical for codebases with plugin architectures, middleware chains,
data fetcher layers, or strategy patterns where user-controlled data flows through
a dispatcher to one of several target functions.

- **Actor/message framework dispatch**: For actor-based or message-routing
  frameworks, the message routing and entity identity layer is security-critical.
  Audit:
  - *Entity ID / shard key construction*: How are entity IDs derived from request
    data? If entity IDs are formed by concatenating user-controlled fields without
    unambiguous delimiters, different inputs can produce the same entity ID,
    causing one principal's cached state (credentials, sessions, authorization
    decisions) to be served to another. Search for entity ID extraction, shard
    key derivation, and equivalent dispatch-identity patterns in the detected
    framework.
  - *Cached state reuse*: If actors/handlers cache authorization decisions or
    credentials across requests (e.g., tokens with a TTL), verify that the cache
    key is collision-resistant across all security-relevant dimensions. Two
    requests with different authorization contexts MUST map to different
    entity/cache IDs.
  - *Companion objects and factory methods*: Dispatch identity functions are
    often defined separately from the message handler itself — in companion
    objects, factory classes, or configuration modules. Always read them.

### Step 1d: Adjacency Map & Subgraph Partitioning

Phase 2 dispatches parallel trace agents, each responsible for a self-contained
slice of the codebase. This step builds the map that determines how to partition
the work. The goal is to group inputs whose data flows pass through shared
application-specific code, so each agent gets a coherent context with no
cross-contamination from unrelated traces.

#### 1. Build the Application Call Graph

For each entry point in the input inventory, identify which application functions
it calls. Use **Grep** to follow imports and function calls **two levels deep**
from each handler:

- **Level 1**: Read the handler/controller function. List every function it calls
  that is defined in this codebase (not framework/library calls). Record the file
  each function lives in.
- **Level 2**: For each Level 1 function, read its body and list the functions IT
  calls (same criteria — codebase-defined, not framework). Record files.

Also record which **dangerous sinks** (from the Phase 2 sink reference) each
call chain reaches. You do not need to trace data flow here — just identify which
sink APIs appear in the functions along each chain.

Output the **Application Call Graph** table:

| Entry Point | Inputs | App Functions Called | Sinks Reached | Files Touched |
|---|---|---|---|---|
| POST /api/search | #1, #2 | buildQuery, execSearch | sql.query | handlers/search.js, db/search.js |
| GET /api/users/:id | #3, #4 | fetchUser, formatResponse | sql.query, http.redirect | handlers/users.js, db/users.js |

Budget: 2-4 Grep/Read calls per entry point. Do NOT deep-dive into data flow —
that is Phase 2's job. This step only needs call-level connectivity.

#### 2. Build the Shared Infrastructure Catalog

Identify modules that are **cross-cutting infrastructure** — used by many entry
points but not creating meaningful data flow coupling between them. Factor these
OUT of the connectivity analysis so they don't collapse everything into one giant
component.

**Auto-detect**: Any module imported by more than 50% of entry points is shared
infrastructure.

**Also explicitly include** (if present):
- Authentication/authorization middleware
- Logging and observability utilities
- ORM base classes, database drivers, connection pools
- Sanitization and validation utilities
- Error handling middleware
- Configuration and environment readers
- HTTP client wrappers (base clients, interceptors)
- Serialization/deserialization utilities

Output the **Shared Infrastructure Catalog**:

| Module | Role | Files |
|---|---|---|
| auth middleware | authentication | src/middleware/auth.js |
| ORM base | data access | src/db/base.js, src/db/connection.js |
| sanitizer | input sanitization | src/utils/sanitize.js |

Trace agents receive this catalog as reference context — they can read these
files when investigating defenses, but these modules do not define the agent's
trace scope.

**Exception**: Config modules that export functions accepting parameters and
interpolating them into URLs, queries, or commands are **application-specific
sinks**, not shared infrastructure. Include them in the app-specific file list
for the subgraph(s) that call them.

#### 3. Compute Subgraph Partitions

Two entry points belong to the **same subgraph** if they share any application-
specific function NOT in the shared infrastructure catalog. Use union-find logic:

1. Start with each entry point in its own set.
2. For each application function in the call graph table, find all entry points
   that call it (directly or transitively within the 2 levels traced).
3. Merge those entry points' sets.
4. Each resulting set is a subgraph partition.

Output the **Subgraph Partition Table**:

| Partition | Inputs | Entry Points | App-Specific Files | Shared Nodes Used |
|---|---|---|---|---|
| SG-1 | #1, #2 | POST /api/search | handlers/search.js, db/search.js | ORM, logging |
| SG-2 | #3, #4 | GET /api/users/:id | handlers/users.js, db/users.js | ORM, auth |
| SG-3 | #5, #6, #7 | POST /api/upload | handlers/upload.js, storage/files.js | auth, logging |

#### 4. Check for Pathological Partitions

After computing partitions, check for degenerate cases:

- **Oversized partition (>20 inputs or >15 app-specific files)**: Sub-partition
  by entry-point file or route prefix. For example, split `/api/admin/*` routes
  from `/api/public/*` routes within the same component.
- **Single function connecting everything**: If one application function (not in
  the shared catalog) connects all entry points into one component, promote that
  function to the shared infrastructure catalog and recompute partitions.
- **Truly monolithic (cannot split below 20 inputs)**: Mark the partition with
  `SEQUENTIAL-FALLBACK`. Phase 2 will process this partition sequentially with
  entry-point-level checkpointing instead of spawning a single overwhelmed agent.
- **Undersized partitions (≤2 inputs AND 1 app-specific file)**: Merge with the
  most closely related partition rather than creating a standalone partition.

#### 5. Production Reachability Annotation

For EACH partition, verify whether its entry points are production-reachable:
1. Read the route-mounting code (e.g., `app.use()`, router registration in
   the main app file). Check if the route is behind an environment gate
   (e.g., `if (env === 'dev')`, `if (process.env.NODE_ENV !== 'production')`).
2. Annotate each partition as `PRODUCTION` or `DEV-ONLY`.
3. The determination must be based on actual code (file:line), not naming
   conventions or comments.

`DEV-ONLY` partitions are NOT dispatched to trace agents. Instead, record:
`"SG-N: SKIPPED — entry point gated by [file:line], only reachable in [env]"`
and mark all inputs as `SAFE (not production-reachable)`.

**Partition coverage check (MANDATORY)**: List every production app from Step 1.
For each, confirm it appears in at least one partition. Any app with zero
coverage is a gap — go back to Steps 1a/1b, enumerate sinks and inputs for
that app (including its associated libs/), then create or merge a partition.
This check must produce an explicit per-app pass/fail list in the output.

### Step 1e: Authorization & Classification Gate Audit

Grep for `.contains(`, `includes(`, `indexOf(`, `has(` in authorization helpers
and access-control modules identified during Steps 1b-1c. For each hit, check:

| Check | CANDIDATE if |
|---|---|
| Receiver type | `.contains()` called on a `String` (substring match, not membership) rather than `Set`/`List`/`Array` |
| Allowlist loading | List loaded via `getString`/`getProperty` without `split()` — a comma-delimited string, not a collection |
| Comparison direction | `input.contains(allowlistValue)` — reversed; any input containing the value as a substring passes |
| Ambiguous classification | Unanchored substring/regex match on attacker-controlled input classifies it into a security-relevant category (tenant, sensitivity tier, resource bucket) — attacker can embed multiple markers to satisfy different classifiers differently |

Any match is a CANDIDATE even if no inventoried input currently reaches it —
these are latent authorization bypasses. Add them to the inventory as "gate logic"
entries with source type "authorization gate".

**Classification consistency check**: When the codebase derives the same security-
relevant dimension (tenant, category, access tier, resource scope) from the same
user-controlled input in multiple places, grep for all sites that determine that
dimension. If any two sites use different logic (e.g., substring match vs. prefix
match vs. regex), flag as CANDIDATE — the attacker can craft an input that passes
one classifier but gets routed by another.

### Step 1f: Authentication Path Enumeration

For each entry point that returns credentials or authorization decisions,
enumerate every authentication branch (the dispatch on which token/credential
type is present). For each branch, record what credential is required, whether
it is cryptographically verified, and where the identity value comes from.

Flag any branch where identity is accepted without cryptographic verification.
Add these to the inventory as "auth bypass path" entries for Phase 2 tracing.

Also grep for comments containing `bypass`, `skip auth`, `without auth`,
`no token` — evaluate each as a candidate.

### Step 2: Threat Model

Derive the threat model from audited-code evidence; Phase 2b reads these
fields directly. Prose about upstream protection, network placement, or
"intentional" trust delegation is not admissible — if you only have prose,
the field is `NONE`.

Phase 1 is intentionally pessimistic. Record what the audited code itself
does at face value; do not credit upstream signals or known-library
shortcuts here. Downgrades for verified upstream delegation are
`phase2b_verify.md §8`'s job, not this phase's. False-positive candidates
get re-verified there; false-clean candidates do not.

Record one row per entry-point group. Use a single "all" row only when every
entry point shares the same enforcement, binding, and authorization.

**Output Step 2 as the table in Recon Output below — not as prose bullets.**
The bullets that follow define field semantics only.

For each row:

- **App-layer auth enforcement** — `<file:line>` of audited code that
  *rejects* requests lacking a credential, OR `NONE`.
- **Caller identity binding** — `<file:line>` of audited code that
  *cryptographically verifies* an inbound credential (signature, certificate,
  HMAC, signed assertion) and produces a verified caller identity, OR `NONE`.
  A principal constructed from an unverified header does not qualify.
- **Per-resource authorization** — `<file:line>` of audited code that
  authorizes the bound caller for *this* resource/operation (allow-list,
  ownership lookup, claim-to-resource binding), OR `NONE`. Only meaningful
  when the two fields above are non-`NONE`.
- **Attacker profile (derived)**:
  - All three `NONE` → any party that can reach this entry point.
  - Enforcement + binding present, authorization `NONE` → any caller the
    binding accepts; authorization is missing.
  - All three present → a specific caller authorized for the resource.
- **Attacker controls** — input rows from Step 1b reachable from this group.
- **Attacker does NOT control** — values established server-side or before
  this entry point.
- **Existing attacker capabilities** — what a binding-accepted caller can
  already do via the documented contract. Phase 2/2b reads this as the Gate 3
  baseline (`phase2_shared.md` Gate 3).
  **All-NONE constraint:** When all three fields are NONE, the baseline is
  "can reach the endpoint" — nothing more. Do NOT derive baseline capabilities
  from the absence of auth (e.g., "can already read/write any resource because
  there is no ownership check"). That reasoning is circular — missing auth
  cannot pre-authorize the operations it fails to protect. Each endpoint's
  operations remain subject to CWE-306/639 evaluation in Phase 2 NAV.

For non-network entry points (CLI, scheduled job, library API, queue
consumer), substitute the relevant execution boundary for "reach this entry
point"; field semantics are unchanged.

#### Anti-patterns

None of the following is admissible evidence; if it is the only basis for a
non-`NONE` value, the field is `NONE`:

- Path or route naming (prefixes such as "internal," "private," "protected,"
  "admin," or tenant/org IDs in the URL).
- Comments, doc-strings, or string-constant values asserting upstream
  protection ("auth handled by gateway," "internal only," "pre-authenticated
  traffic").
- Config that opts the entry point out of authentication (skip-auth flags,
  allow-anonymous routes, missing auth decorator/middleware, public-by-default
  handler annotations). This is the *absence* of enforcement.
- Transport-layer settings that *request* but do not *require* a client
  credential (e.g., `client-auth=want`, `ssl_verify_client optional`,
  `VerifyClientCertIfGiven`). These accept connections without a credential.
- Deployment-context inference (VPC, network topology, mesh, cluster, env name).
- Upstream proxy/gateway/LB claims (header, principal, routing decision) that
  the audited code does not cryptographically bind to a known issuer.
- Type, format, or shape validators on identifiers — they constrain shape,
  not ownership.

If your justification reduces to "the gateway/proxy/mesh handles it," cite
the verifying code or record `NONE`. When delegation is genuine, the
downgrade path is `phase2b_verify.md §8` — do not pre-resolve it here.

### Step 3: Trust Boundary Identification

From the structural overview and entry points, identify trust boundaries:
- Where does user input enter the system?
- Where does the system interact with external services (DB, filesystem, network)?
- Where are authentication/authorization checks performed?
- What data crosses privilege boundaries?

### Step 4: Build-Time Code Swapping Detection

Many projects swap code at build time — e.g., a build script copies files from
a production source directory or a mock directory into a build output directory
depending on the environment. If this pattern exists, your analysis MUST target
the production variant.

Check for this pattern:
- Look at the build system (Makefile, scripts/, bundler config, Dockerfile) for
  `cp`, `ln -s`, `rsync`, or similar commands that populate a directory from
  multiple sources
- Look for parallel directory structures with similar file names (e.g.,
  `prod-impl/foo.js` alongside `mock-impl/foo.js`)
- If found, **record which directory contains production code** and always read
  from that directory when investigating annotations or sinks in the build output

**Example**: If the build copies `prod-impl/*` into `build/` and you find
`build/service.js:218` has a dangerous sink, you MUST read `prod-impl/service.js:218` — the
build output may be stale or overwritten by a mock variant during test runs.

### Recon Output

Produce a compact Attack Surface Report (not the raw tool output):

**Languages**: [detected languages]
**Frameworks**: [detected frameworks and versions if visible]
**Input Inventory**: [total count] inputs across [count] entry points
  (include the full inventory table from Step 1b)

#### Threat Model

Use one row per entry-point group. Collapse to a single "all" row only after
confirming every entry point shares the three fields.

| Entry-point group | App-layer auth enforcement | Caller identity binding | Per-resource authorization |
|---|---|---|---|
| [e.g. `POST /accounts/*`] | [`<file:line>` or `NONE`] | [`<file:line>` or `NONE`] | [`<file:line>` or `NONE`] |

- **Attacker profile (per row):** [derived from the three fields]
- **Attacker controls:** [input rows from Step 1b]
- **Attacker does NOT control:** [server-side values, secrets, peer identity not exposed as input]
- **Existing attacker capabilities (per row):** [what the binding-accepted caller can already do via the documented contract — Gate 3 baseline]

#### Trust Boundaries
| Boundary | Location | Input Source | Validation |
|---|---|---|---|

#### Shared Infrastructure Catalog
(table from Step 1d — modules, roles, files)

#### Subgraph Partitions
(table from Step 1d — partition ID, inputs, entry points, app-specific files,
shared nodes used, any markers: DEPTH-SPLIT, SEQUENTIAL-FALLBACK)
