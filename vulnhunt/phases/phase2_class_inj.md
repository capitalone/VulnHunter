# Class Group: Injection (INJ)

## Dangerous Sink Reference

- **SQL/query execution**: raw query methods, query builders accepting string
  interpolation, template literals containing SQL keywords
- **OS command execution**: process spawning, shell invocation, process builders
  (especially shell=True or `sh -c` wrappers)
- **File system operations**: open, read, write, create, delete — especially
  where the path includes a user-controlled component. **Include network
  filesystem clients** as equivalent sinks: SMB/CIFS, SFTP, FTP, NFS, cloud
  storage clients where the key/path is user-controlled. Path traversal applies
  identically via `../` or `..\` sequences across network boundaries.
- **Outbound HTTP / URL construction**: fetch, request, HTTP client calls —
  especially where the URL path or query string is built from user input.
  Also flag as **CROSS-CLASS (NAV)** when user input is placed into outbound
  request headers — especially identity, attribution, or security-signal headers
  (e.g., X-User-Id, Source-Eid, X-Forwarded-For, X-On-Behalf-Of). When tracing
  a request body to an outbound HTTP call, check whether sub-fields are extracted
  and set as request headers on that call.
- **HTML / template rendering**: raw HTML insertion, unescaped template output,
  `dangerouslySetInnerHTML`, `| safe`, `v-html`, `{!! !!}`
- **Navigation / redirect sinks**: HTTP redirect APIs, Location header
  construction, `window.location.*`, `window.open()`, `<a href>` binding.
  **Dual-context**: `https:` → redirect (CWE-601); `javascript:`/`data:` → code
  execution (CWE-79, DOM-based XSS). If user input reaches a navigation sink
  without scheme validation (`http:`/`https:` allowlist), classify as CWE-79, not
  CWE-601 — the XSS subsumes the redirect
- **Email construction**: HTML email bodies, email headers (Subject, From, To)
- **Code evaluation**: `eval()`, `Function()`, `vm.runInNewContext()` (JS);
  `exec()`, `compile()` (Python); template `.compile()`/`.render()` with
  user-controlled template strings. CWE-94
- **File upload receivers**: multipart handlers where filename, extension,
  content-type, or storage path is user-controlled
- **Query language construction**: JQL, Elasticsearch DSL, GraphQL query building,
  LDAP filter construction, XPath

Adapt the specific API names to the detected language/framework. Add any additional
dangerous operations you recognize from the codebase's libraries or custom
abstractions.

## Vulnerability Classes

For each injection class, construct grep patterns appropriate to the languages and
frameworks identified during recon. Adapt function names, APIs, and file extensions
to the detected stack.

- **SQL Injection**: Trace string concatenation or format strings into SQL queries.
  Look for raw query methods and non-parameterized query builders.
  Parameterized/prepared statements are safe.
- **Command Injection**: Trace user input into OS command execution APIs.
  Pay special attention to shell invocations (`shell=True`, `sh -c`) vs. direct exec.
- **Path Traversal**: Trace user input into file path construction.
  Check whether `..` sequences are stripped or the path is resolved against
  an allowed base directory.
  **Client-side config/asset traversal**: In SPAs, user input interpolated into
  fetch URLs for config files (e.g., `/${exp}.json`) — `../` changes which file loads.
- **SSRF / URL Path Injection**: Trace user input into URL construction — especially
  internal APIs. Check whether the sanitizer encodes URL-significant characters
  (`/`, `..`, `?`, `&`, `=`, `#`, `%`). HTML sanitizers (like `xss()`) do NOT.
  Search for outbound HTTP client calls and fetch/request APIs.
- **API Query Language Injection**: Trace user input into non-SQL query language
  construction — JQL (Jira), ServiceNow encoded queries (`sysparm_query`),
  Elasticsearch DSL/query_string, GraphQL query building, XPath.
  Transport-safe URL encoding does NOT protect against query-language-level
  injection; the query parser interprets encoded characters after decoding.
  Search for API client calls that build query strings or filter expressions
  from user input. (For LDAP filter injection, see the dedicated LDAP Injection
  class below.)
- **XML/XXE Injection**: Trace user input into XML parsers. Check for dangerous
  defaults: `DocumentBuilderFactory` without `DISALLOW_DOCTYPE_DECL`,
  `SAXParserFactory` without entity resolver, `lxml.etree.parse` with
  `resolve_entities=True`, `XMLReader` without disabled external entities.
  CWE-611.
- **Unrestricted File Upload**: Check upload handlers for: extension allowlist
  (not blocklist), content-type validation against actual content, storage
  outside webroot with no-execute permissions, filename sanitization (null
  bytes, path separators). CWE-434.
- **XSS (Cross-Site Scripting)**: Trace user input into HTML output without
  escaping. Check these output contexts:
  - **Reflected/Stored XSS**: raw-output constructs or concatenation into HTML. CWE-79.
  - **Navigation-sink XSS**: See Sink Reference dual-context note. CWE-79, not CWE-601.
    **Per-file sink sweep:** When a file has ANY navigation sink, grep for ALL nav APIs
    (`location.href`, `location.assign`, `location.replace`, `window.open`,
    `sendRedirect`, `redirect`) and trace each independently.
    **Encoding/decoding transforms are NOT sanitizers:** `atob`/`btoa`, `decodeURIComponent`,
    `JSON.parse` do not validate schemes. Base64-decoded input → `window.location.href`
    without scheme validation is CWE-79.
  - **Email body XSS**: User input in HTML email bodies — email clients render HTML. CWE-79.
  - **Third-party markup injection**: User input in Jira wiki markup, Confluence,
    Slack mrkdwn, or rich-text formats supporting link/script injection.
  - **Email header injection (CRLF)**: User input in email headers without CRLF
    stripping — allows adding arbitrary headers. CWE-93.
- **Open Redirect**: Trace user input into redirect targets. Look for parameters
  named `returnTo`, `next`, `redirect_uri`, `redirect`, `return_url`, `continue`,
  `dest`, `destination`, `redir`, `url`, `target`, `forward`. Verify the redirect
  target is validated against an allowlist of domains/paths — not just checked for
  a prefix (attackers bypass `startsWith("https://example.com")` with
  `https://example.com.evil.com`).
  **Protocol-relative path trap:** "Path-only" values are NOT inherently safe — if
  the path can start with `//` (e.g., `//evil.com/`), browsers interpret it as
  protocol-relative. Verify the code rejects paths starting with `//`.
  Before classifying as CWE-601, verify the sink rejects `javascript:`/`data:`
  schemes per the Sink Reference dual-context note — if not, reclassify as CWE-79.
  Search for HTTP redirect APIs and `Location` header construction. CWE-601.
- **LDAP Injection**: Trace user input into LDAP filter or DN construction.
  Search for LDAP APIs (`InitialDirContext.search`, `javax.naming`,
  `LdapCtxFactory`, `ldap.search`, `ldap_search`, `SearchRequest`). Check whether
  the filter is built via interpolation/concatenation (vulnerable) or parameterized
  API (safe). LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) alter filter semantics.
  Even authenticated identity values (e.g., JWT `sub` claim) are tainted in LDAP
  context if used in query construction. CWE-90.
- **Code Injection / SSTI**: User input in code evaluation sinks or as the
  template string (not data) in template engine compile/render calls. CWE-94.

## Gate 2b: Sanitizer Verification Methodology (INJ-specific)

For injection-class findings, apply this expanded procedure in addition to the
generic Gate 2b in the shared file:

- **Empirically verify what the sanitizer does.** For EVERY sanitizer in the
  data flow, you MUST do one of:

  **(a) Read the sanitizer's source code** (in node_modules, vendor, stdlib, or
  the project's own code) and list the exact characters/patterns it transforms.
  If the source is minified or unavailable, use option (b).

  **(b) Construct a test expression** that proves the sanitizer's behavior on
  attack-relevant characters for the sink context. For URL sinks, test: `&`, `=`,
  `?`, `/`, `..`, `#`, `%`. For SQL sinks, test: `'`, `"`, `;`, `--`. For command
  sinks, test: `;`, `|`, `&`, `` ` ``, `$()`. For HTML sinks, test: `<`, `>`,
  `"`, `'`, `&`. Write the test as a runnable one-liner, e.g.:
  `node -e "const xss = require('xss'); console.log(xss('X&injected=true'))"`

  **(c) If you cannot read the source or construct a test** (e.g., the dependency
  isn't installed, or the language has no REPL), state this explicitly and
  **treat the sanitizer as ineffective** — do NOT assume it works. Proceed to
  Gate 3 with the finding intact.

- **Verify the sanitizer matches the sink context.** A sanitizer that encodes `<`
  and `>` (HTML context) does NOT protect a URL sink — it won't encode `&`, `=`,
  `/`, `..`. A URL encoder does NOT protect a SQL sink. The sanitizer must
  neutralize the specific characters that are dangerous in the specific sink
  context. See the "Do NOT eliminate" list in Gate 3 below for examples.

## Gate 3: Do NOT Eliminate (INJ-specific)

These ARE new capabilities even if they look similar to existing functionality:

- URL path injection on internal API gateways: "same host" ≠ "same capability."
  Traversing `../../other-service/admin` reaches different services/endpoints.
- Query parameter injection via sanitizer scope mismatch: injecting `&admin=true`
  into internal API calls can bypass authorization.
- Any finding where the only defense is a scope-mismatched sanitizer (e.g., `xss()`
  protecting a URL path — HTML sanitizer doesn't encode `/`, `..`, `&`, `=`, `#`, `%`).
- **Any attacker-controlled unsanitized value that propagates to a backend system**
  (internal API, database, message queue, cache, downstream service). Unsanitized
  data crossing a tier boundary is a confirmed finding — the backend may use it for
  routing, access control, cache keying, or query construction. Default: CANDIDATE.
  Downgrade only by citing specific file:line where the downstream validates.

## Severity Floor (INJ-specific)

Confirmed injection reaching a backend system with service credentials: **High**
— attacker-controlled data crossing a trust boundary with elevated credentials
is inherently dangerous. Do NOT downgrade to Medium based on "uncertain
downstream impact" or "read-only" or "base URL is hardcoded." The backend's
behavior with injected parameters is unknown and must be assumed hostile.
