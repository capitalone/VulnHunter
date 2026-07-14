# Repo-Type Adapters

**Referenced by:** REQ-CWE-004, REQ-CWE-005. Consumed by the executor's
Phase 2 (Plan) — the executor detects the target repo's primary language
and injects the matching adapter section into the worker prompt.

Each adapter names the language-specific commands, dependency conventions, and framework specifics needed for a worker to operate without guessing. Discrimination-test shape follows `references/test-quality-rubric.md` R1-R5 — no per-language scaffold needed. When adding a new language, add a section here plus
routing in `scripts/language-detect.py`.

---

## Go

**Detection signals:** `go.mod` at repo root; predominant `.go` files.

**Test command:** `go test ./... -race`
- `-race` is mandatory; concurrency findings depend on it.
- Test file naming: `*_test.go` in same package as source.

**Dependency management:** `go mod tidy` after every dep change.
- Reject wildcards in `go.mod`. Pin to specific versions.
- Vendoring only if repo already uses `vendor/`; do not introduce.

**Framework specifics:**
- Standard `net/http` + `context` is idiomatic.
- Auth: `cosp-go-tools` JWT validator (C1 default, 16+ repos).
- API: `ogen` code-gen from OpenAPI (35/46 API repos); manual routes discouraged.
- Logging: `slog` (Go 1.21+) or `zap` — `fmt.Println` is a C1 standard violation.


---

## Java

**Detection signals:** `pom.xml`, `build.gradle`, or `build.gradle.kts` at repo root; predominant `.java` files.

**Test command:** `mvn test` (Maven) or `./gradlew test` (Gradle).
- JUnit 5 preferred over JUnit 4.
- Mockito for mocking.
- Test file naming: `<Class>Test.java` under `src/test/java/`.

**Dependency management:**
- Maven: `<version>` element must not be a `LATEST` or `RELEASE` alias.
- Gradle: prefer version catalogs (`libs.versions.toml`).

**Framework specifics:**
- Spring Boot idioms: `@RestController`, `@Service`, constructor injection.
- Auth: Spring Security preferred over custom filters.
- Logging: SLF4J with a Logback backend. Never `System.out.println`.
- Secrets: `@Value` from configuration, sourced from Chamber of Secrets.


---

## TypeScript / JavaScript

**Detection signals:** `package.json`, `tsconfig.json`; predominant `.ts` / `.tsx` / `.js` / `.jsx` files.

**Test command:** Detect from `package.json` scripts:
- `npm test`, `pnpm test`, or `yarn test`.
- Vitest (24/31 frontend repos) preferred over Jest for new tests.
- E2E: Playwright (22/31 frontend repos).

**Dependency management:**
- Use the repo's package manager (do not switch npm↔pnpm↔yarn).
- Pin exact versions for direct security deps (`^` for indirect).
- Never introduce `--legacy-peer-deps` as a workaround.

**Framework specifics:**
- React 18+: Function components, hooks, no class components in new code.
- Routing: React Router (26/31) or TanStack Router (rising).
- CSS: Tailwind (14/31) or C1S tokens; do not introduce Emotion in a
  Tailwind repo.
- Logging: `console.log` is a C1 standard violation; use `pino` or the
  configured OTel logger.


---

## Python

**Detection signals:** `pyproject.toml`, `Pipfile`, `setup.py`, or `requirements.txt`; predominant `.py` files.

**Test command:** `pytest -x` (fail fast on first regression).
- `pipenv run pytest` if `Pipfile` exists.
- `pytest --tb=short` to keep tracebacks scoped.
- Coverage target: 80% (C1 minimum).

**Dependency management:**
- Prefer `Pipfile` + `Pipfile.lock` (this repo's convention).
- Never mix `requirements.txt` and `Pipfile`.
- Every new dep must resolve on the project's configured package index.

**Framework specifics:**
- Web: FastAPI or Flask; no bare `http.server` for production.
- Auth: `PyJWT` for JWT validation.
- Logging: stdlib `logging` module with structured formatter, never
  `print()`.
- Secrets: `chamber` client or `boto3` KMS — never env vars for the raw
  secret material.


---
