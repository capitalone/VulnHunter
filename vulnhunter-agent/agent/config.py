"""Configuration loader for the vulnhunter agent.

Sources every URL/credential/trust-store value from a TOML file and/or
environment variables. Env vars take precedence over the TOML file so
the same image can be deployed across environments without rebuilding.

Env-var convention: ``VULNHUNT_<SECTION>_<KEY>`` (uppercase). Examples:

    VULNHUNT_OAUTH_CLIENT_ID
    VULNHUNT_OAUTH_CLIENT_SECRET
    VULNHUNT_ANTHROPIC_MODEL
    VULNHUNT_GITHUB_SCAN_TOKEN
    VULNHUNT_GITHUB_REPORTS_TOKEN
    VULNHUNT_GITHUB_BROKER_TOKEN_DIR
    VULNHUNT_TLS_SSL_CERT_PATH

The TOML file path is resolved from --config, then ``$VULNHUNT_AGENT_CONFIG``,
then ``agent/config.toml`` next to this module. The file is optional when
every required value is supplied via env vars.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AnthropicConfig:
    # auth_mode selects how the agent authenticates to Claude:
    #   "api_key"       — direct Anthropic API using an API key (the default;
    #                     read from [anthropic].api_key or the ANTHROPIC_API_KEY
    #                     env var). bedrock_base_url / [oauth] are unused.
    #   "bedrock_oauth" — route through an AWS Bedrock proxy fronted by an
    #                     OAuth2 client-credentials token endpoint. Requires
    #                     bedrock_base_url and the [oauth] block.
    model: str
    auth_mode: str = "api_key"
    api_key: str = ""
    bedrock_base_url: str = ""
    aws_region: str = "us-east-1"


@dataclass(frozen=True)
class OAuthConfig:
    token_endpoint: str
    client_id: str
    client_secret: str
    expiry_safety_factor: float
    default_lifetime_seconds: int
    http_timeout_seconds: int


@dataclass(frozen=True)
class TLSConfig:
    ssl_cert_path: str


@dataclass(frozen=True)
class SandboxConfig:
    enabled: bool
    fail_if_unavailable: bool
    allow_unsandboxed_commands: bool


@dataclass(frozen=True)
class TelemetryConfig:
    enabled: bool
    otel_exporter_otlp_endpoint: str
    # Optional OTEL resource attributes (comma-separated key=value pairs).
    # Leave empty for a neutral default (service.name + type). Set to tag
    # exported telemetry with your own org/owner identifiers.
    resource_attributes: str = ""


@dataclass(frozen=True)
class ScanConfig:
    clone_base_dir: str
    clone_timeout_seconds: int
    allowed_tools: list[str]
    permission_mode: str
    # ``None`` means "derive from the model": 90 for 1M-context variants,
    # 85 for standard 200K-context. Set explicitly to override.
    autocompact_pct_override: int | None
    # Forwarded to the bundled CLI as ``CLAUDE_ASYNC_AGENT_STALL_TIMEOUT_MS``.
    # Caps how long an async subagent (Task tool) can go without forward
    # progress before the CLI surfaces a "Request timed out" tool result
    # to the orchestrator. The CLI's own default has been observed at
    # ~60 min, which is far too long when a subagent wedges. 20 min
    # gives Phase 2/3 reasoning steps headroom but catches genuine
    # stalls. Set to 0 to use the CLI's built-in default.
    async_agent_stall_timeout_ms: int
    # Comma-separated NO_PROXY value written into the scan subprocess env so
    # the bundled CLI bypasses any inherited HTTP proxy for these hosts/CIDRs.
    # Default covers loopback + private ranges; add your own internal zones.
    no_proxy: str = "localhost,127.0.0.1,169.254.169.254,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"


@dataclass(frozen=True)
class GitHubConfig:
    """Dual-identity credentials for GitHub-touching operations.

    Two distinct tokens, each scoped to what it touches:
      - ``scan_token``    — clone the target repo + post issues on it
                            (clone.py, issues.py, issues_fetch.py).
      - ``reports_token`` — push results + read the prior report from the
                            publish destination (publish.py,
                            issues_remote_report.py).

    Tokens are injected into URLs only when the parsed host matches
    ``host`` (case-insensitive), so a token never leaks across hosts.

    When ``broker_token_dir`` is set, both tokens are read on demand from
    ``{broker_token_dir}/scan.json`` and ``{broker_token_dir}/reports.json``
    (a file-based token broker: an external parent process owns token
    minting/refresh and writes them to disk, and the agent is a pure file
    consumer). The literal ``scan_token`` / ``reports_token`` fields are then
    ignored. Standalone deployments leave ``broker_token_dir`` empty and
    supply tokens via config or env.
    """

    host: str
    scan_token: str
    reports_token: str
    broker_token_dir: str = ""


@dataclass(frozen=True)
class PublishConfig:
    """Push the *_VULNHUNT_RESULTS_* directory to a remote git repo."""

    enabled: bool
    destination_repo: str
    branch: str
    commit_author_name: str
    commit_author_email: str


@dataclass(frozen=True)
class AuditConfig:
    """JSONL audit + findings-event emission for downstream ingest.

    Two output streams — audit lifecycle events and per-finding
    observations — appended to local JSONL files. The invoking harness
    ships the files onward to your ingest pipeline; this agent only
    writes locally.

    Field-level notes:

    - ``events_path`` / ``findings_path`` are always resolved through
      ``Path.expanduser().resolve()`` at load time, so ``~/`` works.
    - ``app_id`` is an application/service identifier for the *target* of
      the scan; it changes per invocation and is expected to come in
      via CLI (``--app-id``) or env for each run. ``"NA"`` matches
      the raw-findings schema's documented placeholder.
    - ``actor`` identifies the emitting worker in the audit record.
    - ``strict`` flips write-failure behavior: default is log-and-
      continue (a full disk shouldn't kill a 20-minute scan); strict
      raises immediately, for CI runs that want to fail loud.
    """

    enabled: bool
    events_path: str
    findings_path: str
    stdout: bool
    app_id: str
    actor: str
    strict: bool


@dataclass(frozen=True)
class LoggingConfig:
    """Optional verbose logging toggles, off by default.

    Both flags are independent so callers can enable just the slice they
    need without paying the noise cost of the other.
    """

    # Print SDK token usage and per-agent wall-clock duration for every
    # assistant turn in the scan loop. Tagged with parent_tool_use_id so
    # subagent turns are distinguishable from the orchestrator's.
    per_turn_usage: bool
    # Emit an INFO log each time a transient-error retry kicks in
    # (issues POST, issues GET pagination). The ``call_json_with_fallback``
    # primary→fallback warning is unconditional and is *not* governed by
    # this flag — it never duplicates output.
    retries: bool


@dataclass(frozen=True)
class IssuesConfig:
    """Post a GitHub issue per confirmed VulnHunter finding.

    The dedup pool is open issues on ``target_repo`` carrying ``dedup_label``.
    Findings extraction and semantic dedup use the configured Bedrock proxy
    via the existing OAuth token manager — no separate credentials.
    """

    enabled: bool
    target_repo: str  # empty → falls back to the scanned repo at runtime
    labels: list[str]  # labels applied to every posted issue
    dedup_label: str  # label used to scope the open-issue dedup pool
    haiku_model: str
    sonnet_model: str
    semantic_dedup: bool
    request_timeout_seconds: int
    max_open_issues: int
    # Token budget for LLM-based dedup, expressed as a fraction of the
    # model's context window. We never let a single batched dedup request
    # exceed this fraction; if the candidate set is too large we chunk.
    token_budget_fraction: float
    # Used in the chunking math; the haiku and sonnet models here are 200K-context.
    model_context_tokens: int
    # Post a closed "clean scan" receipt issue when a scan finds nothing.
    # See docs/clean-scan-notifications-design.md. Default true; the knob
    # exists so operators can suppress notifications pipeline-wide without
    # a code change.
    notify_clean_scan: bool
    # Label applied to (and used to look up) clean-scan issues. Different
    # from ``labels`` so findings and clean-scan receipts are visually and
    # programmatically distinguishable.
    clean_scan_label: str


@dataclass(frozen=True)
class VerifyConfig:
    """Inputs for the ``--mode=verify`` orchestrator.

    See ``docs/vulnhunt-fix-verify-agent-design.md`` for the full
    contract. The verify path reuses ``oauth``, ``github``, ``publish``,
    and ``tls`` from the rest of the config; this block holds only
    verify-specific knobs.
    """

    # Per-run scratch dirs land under this base. One subdirectory per
    # invocation (named ``<repo>-<scan-id-short>-<utc-ts>``). Left in
    # place after the run for forensics; ephemeral infrastructure is
    # expected to clean up.
    scratch_base_dir: str
    # Passed to ``shallow_clone`` for the target repo and every
    # additional_repos checkout.
    clone_timeout_seconds: int
    # Map from a free-form ``repo_hint`` string (as emitted by the
    # pre-flight cross-repo extractor) to a clonable git URL. The
    # agent never infers URLs; resolution is full-URL-or-alias only
    # (design §8.3). Loaded from TOML directly — not overridable via
    # env vars because alias tables are a team-level concern.
    repo_aliases: dict[str, str]
    # Extra hostnames (beyond ``github.host``) on which a URL-shaped
    # ``repo_hint`` may be resolved as a clone target. A URL hint whose
    # host is not ``github.host`` nor in this set resolves to ``None``
    # (CWE-918 SSRF guard). Operator-authored ``repo_aliases`` bypass
    # this check — they are trusted config. Empty by default.
    allowed_clone_hosts: tuple[str, ...] = ()
    # Explicit operator-authored ``owner`` / ``owner/repo`` path prefixes on
    # which an additional-repo clone may carry the operator scan token
    # (confused-deputy guard, CWE-441). This EXTENDS the prefixes derived
    # automatically from ``repo_aliases``; use it to authorize token-bearing
    # clones of paths not already referenced by an alias. Empty by default.
    token_path_prefixes: tuple[str, ...] = ()
    # CWE-400 verify-path resource bounds. Cap pagination and cumulative body
    # size so attacker comment/event/edit volume can't drive unbounded work.
    max_comment_pages: int = 20
    max_timeline_bytes: int = 5_000_000
    max_event_pages: int = 20
    max_edit_diff_bytes: int = 200_000
    max_edit_total_bytes: int = 5_000_000


@dataclass(frozen=True)
class RepoPropertiesConfig:
    """Optional operator-defined metadata tags stamped onto findings records.

    ``github_property_map`` maps a GitHub custom-property name (as returned
    by ``GET /repos/{owner}/{repo}/properties/values``) to the field name
    emitted on the findings stream. Empty by default — nothing is fetched
    or emitted unless an operator opts in by declaring their own mapping in
    ``[repo_properties]``. Loaded from TOML only (a table isn't expressible
    as a scalar env var); the CLI ``--repo-property NAME=VALUE`` flag
    supplies per-run overrides keyed by the emitted field name.
    """

    github_property_map: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentConfig:
    anthropic: AnthropicConfig
    oauth: OAuthConfig
    tls: TLSConfig
    sandbox: SandboxConfig
    telemetry: TelemetryConfig
    scan: ScanConfig
    github: GitHubConfig
    publish: PublishConfig
    issues: IssuesConfig
    verify: VerifyConfig
    logging: LoggingConfig
    audit: AuditConfig
    repo_properties: RepoPropertiesConfig = field(
        default_factory=RepoPropertiesConfig
    )
    source_path: Path | None = field(repr=False, default=None)


_DEFAULT_CONFIG_FILENAME = "config.toml"


def _resolve_config_path(explicit: str | os.PathLike[str] | None) -> Path | None:
    """Locate the TOML config file. Returns None if no file is found.

    A missing file is only fatal if env vars don't supply every required
    value — that check happens in load_config().
    """
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Config file not found: {path}")
        return path

    env = os.environ.get("VULNHUNT_AGENT_CONFIG")
    if env:
        path = Path(env).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"VULNHUNT_AGENT_CONFIG points to missing file: {path}")
        return path

    candidate = Path(__file__).resolve().parent / _DEFAULT_CONFIG_FILENAME
    if candidate.is_file():
        return candidate

    return None


def _env_name(section: str, key: str) -> str:
    return f"VULNHUNT_{section.upper()}_{key.upper()}"


def _coerce(value: str, kind: type) -> Any:
    """Convert a string env-var value into the expected scalar type."""
    if kind is bool:
        return value.strip().lower() in ("1", "true", "yes", "on")
    if kind is int:
        return int(value)
    if kind is float:
        return float(value)
    if kind is list:
        # Comma-separated for env vars.
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


def _resolve(
    raw: dict,
    section: str,
    key: str,
    *,
    kind: type = str,
    default: Any = None,
    required: bool = False,
) -> Any:
    """Resolve a single value: env var > TOML > default.

    When ``required=True`` we also reject empty strings — a TOML entry
    like ``client_id = ""`` would otherwise satisfy ``key in raw`` and
    silently return ``""``.
    """
    env_val = os.environ.get(_env_name(section, key))
    if env_val is not None:
        value = _coerce(env_val, kind)
    elif key in raw:
        value = raw[key]
    elif required and default is None:
        raise ValueError(
            f"Missing required value '{section}.{key}'. "
            f"Set in config.toml or via {_env_name(section, key)}."
        )
    else:
        return default

    if required and isinstance(value, str) and not value.strip():
        raise ValueError(
            f"Required value '{section}.{key}' must not be empty. "
            f"Set in config.toml or via {_env_name(section, key)}."
        )
    return value


def load_config(path: str | os.PathLike[str] | None = None) -> AgentConfig:
    """Load and validate the agent's configuration.

    Reads from the TOML file (if found) and overlays environment variables.
    Either source can supply every required field on its own.
    """
    config_path = _resolve_config_path(path)
    raw: dict[str, dict] = {}
    if config_path is not None:
        with config_path.open("rb") as fh:
            raw = tomllib.load(fh)

    anthropic_raw = raw.get("anthropic", {})
    oauth_raw = raw.get("oauth", {})
    tls_raw = raw.get("tls", {})
    sandbox_raw = raw.get("sandbox", {})
    telemetry_raw = raw.get("telemetry", {})
    scan_raw = raw.get("scan", {})
    github_raw = raw.get("github", {})

    auth_mode = (
        str(_resolve(anthropic_raw, "anthropic", "auth_mode", default="api_key"))
        .strip()
        .lower()
    )
    if auth_mode not in ("api_key", "bedrock_oauth"):
        raise ValueError(
            "anthropic.auth_mode must be 'api_key' or 'bedrock_oauth', "
            f"got '{auth_mode}'"
        )
    # api_key resolves from [anthropic].api_key / VULNHUNT_ANTHROPIC_API_KEY,
    # falling back to the standard ANTHROPIC_API_KEY env var.
    api_key = str(
        _resolve(anthropic_raw, "anthropic", "api_key", default="")
    ) or os.environ.get("ANTHROPIC_API_KEY", "")
    anthropic = AnthropicConfig(
        model=str(_resolve(anthropic_raw, "anthropic", "model", required=True)),
        auth_mode=auth_mode,
        api_key=api_key,
        bedrock_base_url=str(
            _resolve(anthropic_raw, "anthropic", "bedrock_base_url", default="")
        ).strip(),
        aws_region=str(
            _resolve(anthropic_raw, "anthropic", "aws_region", default="us-east-1")
        ),
    )
    if auth_mode == "bedrock_oauth" and not anthropic.bedrock_base_url:
        raise ValueError(
            "anthropic.auth_mode='bedrock_oauth' requires anthropic.bedrock_base_url"
        )

    oauth = OAuthConfig(
        token_endpoint=str(
            _resolve(oauth_raw, "oauth", "token_endpoint", default="")
        ),
        client_id=str(_resolve(oauth_raw, "oauth", "client_id", default="")),
        client_secret=str(_resolve(oauth_raw, "oauth", "client_secret", default="")),
        expiry_safety_factor=float(
            _resolve(oauth_raw, "oauth", "expiry_safety_factor", kind=float, default=0.9)
        ),
        default_lifetime_seconds=int(
            _resolve(
                oauth_raw, "oauth", "default_lifetime_seconds", kind=int, default=3600
            )
        ),
        http_timeout_seconds=int(
            _resolve(oauth_raw, "oauth", "http_timeout_seconds", kind=int, default=30)
        ),
    )
    if auth_mode == "bedrock_oauth" and (
        not oauth.token_endpoint or not oauth.client_id or not oauth.client_secret
    ):
        raise ValueError(
            "anthropic.auth_mode='bedrock_oauth' requires oauth.token_endpoint, "
            "oauth.client_id, and oauth.client_secret"
        )

    tls = TLSConfig(
        ssl_cert_path=str(
            _resolve(tls_raw, "tls", "ssl_cert_path", default="")
        )
    )

    sandbox = SandboxConfig(
        enabled=bool(
            _resolve(sandbox_raw, "sandbox", "enabled", kind=bool, default=True)
        ),
        fail_if_unavailable=bool(
            _resolve(
                sandbox_raw, "sandbox", "fail_if_unavailable", kind=bool, default=True
            )
        ),
        allow_unsandboxed_commands=bool(
            _resolve(
                sandbox_raw,
                "sandbox",
                "allow_unsandboxed_commands",
                kind=bool,
                default=False,
            )
        ),
    )

    telemetry = TelemetryConfig(
        enabled=bool(
            _resolve(telemetry_raw, "telemetry", "enabled", kind=bool, default=False)
        ),
        otel_exporter_otlp_endpoint=str(
            _resolve(
                telemetry_raw,
                "telemetry",
                "otel_exporter_otlp_endpoint",
                default="",
            )
        ),
        resource_attributes=str(
            _resolve(
                telemetry_raw,
                "telemetry",
                "resource_attributes",
                default="",
            )
        ),
    )

    scan = ScanConfig(
        clone_base_dir=str(
            _resolve(scan_raw, "scan", "clone_base_dir", default="./clones")
        ),
        clone_timeout_seconds=int(
            _resolve(scan_raw, "scan", "clone_timeout_seconds", kind=int, default=300)
        ),
        allowed_tools=list(
            _resolve(
                scan_raw,
                "scan",
                "allowed_tools",
                kind=list,
                # Minimal default — the bare set the skill needs to read
                # the codebase, dispatch its phase subagents, and write
                # its report. See config.example.toml for what to add
                # when phases need forward tracing (Grep) or the skill
                # is producing in-place edits (Edit).
                #
                # ``Bash`` is intentionally absent: read-only scans never
                # need it (the runner pre-stages everything the skill's
                # old Mandatory First Actions block used to gather via
                # shell), and non-read-only scans must opt in via the
                # CLI flag ``--enable-bash``. The agent layer appends
                # ``Bash`` only when that flag is passed; setting it in
                # this list (or a TOML override) is silently stripped.
                default=["Agent", "Glob", "Read", "Write"],
            )
        ),
        permission_mode=str(
            _resolve(scan_raw, "scan", "permission_mode", default="acceptEdits")
        ),
        autocompact_pct_override=(
            int(env_value)
            if (env_value := _resolve(
                scan_raw,
                "scan",
                "autocompact_pct_override",
                kind=int,
                default=None,
            )) is not None
            else None
        ),
        async_agent_stall_timeout_ms=int(
            _resolve(
                scan_raw,
                "scan",
                "async_agent_stall_timeout_ms",
                kind=int,
                default=1_200_000,  # 20 minutes
            )
        ),
        no_proxy=str(
            _resolve(
                scan_raw,
                "scan",
                "no_proxy",
                default="localhost,127.0.0.1,169.254.169.254,"
                "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
            )
        ),
    )

    github = GitHubConfig(
        host=str(_resolve(github_raw, "github", "host", default="github.com")),
        scan_token=str(_resolve(github_raw, "github", "scan_token", default="")),
        reports_token=str(_resolve(github_raw, "github", "reports_token", default="")),
        broker_token_dir=str(
            _resolve(github_raw, "github", "broker_token_dir", default="")
        ),
    )

    publish_raw = raw.get("publish", {})
    publish = PublishConfig(
        enabled=bool(
            _resolve(publish_raw, "publish", "enabled", kind=bool, default=False)
        ),
        destination_repo=str(
            _resolve(publish_raw, "publish", "destination_repo", default="")
        ),
        branch=str(_resolve(publish_raw, "publish", "branch", default="main")),
        commit_author_name=str(
            _resolve(
                publish_raw,
                "publish",
                "commit_author_name",
                default="VulnHunter Agent",
            )
        ),
        commit_author_email=str(
            _resolve(
                publish_raw,
                "publish",
                "commit_author_email",
                default="vulnhunter-agent@users.noreply.github.com",
            )
        ),
    )
    if publish.enabled and not publish.destination_repo:
        raise ValueError(
            "publish.enabled=true but publish.destination_repo is empty"
        )

    issues_raw = raw.get("issues", {})
    issues = IssuesConfig(
        enabled=bool(
            _resolve(issues_raw, "issues", "enabled", kind=bool, default=True)
        ),
        target_repo=str(
            _resolve(issues_raw, "issues", "target_repo", default="")
        ),
        labels=list(
            _resolve(
                issues_raw,
                "issues",
                "labels",
                kind=list,
                default=["security", "vulnhunter"],
            )
        ),
        dedup_label=str(
            _resolve(issues_raw, "issues", "dedup_label", default="vulnhunter")
        ),
        haiku_model=str(
            _resolve(
                issues_raw,
                "issues",
                "haiku_model",
                default="claude-haiku-4-5",
            )
        ),
        sonnet_model=str(
            _resolve(
                issues_raw, "issues", "sonnet_model", default="claude-sonnet-5"
            )
        ),
        semantic_dedup=bool(
            _resolve(
                issues_raw, "issues", "semantic_dedup", kind=bool, default=True
            )
        ),
        request_timeout_seconds=int(
            _resolve(
                issues_raw,
                "issues",
                "request_timeout_seconds",
                kind=int,
                default=60,
            )
        ),
        max_open_issues=int(
            _resolve(
                issues_raw,
                "issues",
                "max_open_issues",
                kind=int,
                default=1000,
            )
        ),
        token_budget_fraction=float(
            _resolve(
                issues_raw,
                "issues",
                "token_budget_fraction",
                kind=float,
                default=0.7,
            )
        ),
        model_context_tokens=int(
            _resolve(
                issues_raw,
                "issues",
                "model_context_tokens",
                kind=int,
                default=200_000,
            )
        ),
        notify_clean_scan=bool(
            _resolve(
                issues_raw,
                "issues",
                "notify_clean_scan",
                kind=bool,
                default=True,
            )
        ),
        clean_scan_label=str(
            _resolve(
                issues_raw,
                "issues",
                "clean_scan_label",
                default="VulnHunter: clean-scan",
            )
        ),
    )

    logging_raw = raw.get("logging", {})
    logging_cfg = LoggingConfig(
        per_turn_usage=bool(
            _resolve(
                logging_raw,
                "logging",
                "per_turn_usage",
                kind=bool,
                default=False,
            )
        ),
        retries=bool(
            _resolve(
                logging_raw,
                "logging",
                "retries",
                kind=bool,
                default=False,
            )
        ),
    )

    verify_raw = raw.get("verify", {})
    # repo_aliases is a TOML table; pull it straight from raw without
    # going through ``_resolve`` (which doesn't model dict-valued env
    # overrides). Anything non-dict in the TOML is ignored with a
    # well-shaped empty default.
    aliases_raw = verify_raw.get("repo_aliases", {})
    if not isinstance(aliases_raw, dict):
        aliases_raw = {}
    verify = VerifyConfig(
        scratch_base_dir=str(
            _resolve(
                verify_raw,
                "verify",
                "scratch_base_dir",
                default="./verify_runs",
            )
        ),
        clone_timeout_seconds=int(
            _resolve(
                verify_raw,
                "verify",
                "clone_timeout_seconds",
                kind=int,
                default=300,
            )
        ),
        repo_aliases={
            str(k): str(v)
            for k, v in aliases_raw.items()
            if isinstance(v, str) and v.strip()
        },
        allowed_clone_hosts=tuple(
            str(h).strip()
            for h in (
                verify_raw.get("allowed_clone_hosts", [])
                if isinstance(verify_raw.get("allowed_clone_hosts"), list)
                else []
            )
            if str(h).strip()
        ),
        token_path_prefixes=tuple(
            str(p).strip()
            for p in (
                verify_raw.get("token_path_prefixes", [])
                if isinstance(verify_raw.get("token_path_prefixes"), list)
                else []
            )
            if str(p).strip()
        max_comment_pages=int(
            _resolve(verify_raw, "verify", "max_comment_pages", kind=int, default=20)
        ),
        max_timeline_bytes=int(
            _resolve(
                verify_raw, "verify", "max_timeline_bytes", kind=int, default=5_000_000
            )
        ),
        max_event_pages=int(
            _resolve(verify_raw, "verify", "max_event_pages", kind=int, default=20)
        ),
        max_edit_diff_bytes=int(
            _resolve(
                verify_raw, "verify", "max_edit_diff_bytes", kind=int, default=200_000
            )
        ),
        max_edit_total_bytes=int(
            _resolve(
                verify_raw, "verify", "max_edit_total_bytes", kind=int, default=5_000_000
            )
        ),
    )

    audit_raw = raw.get("audit", {})
    audit = AuditConfig(
        enabled=bool(
            _resolve(audit_raw, "audit", "enabled", kind=bool, default=True)
        ),
        events_path=str(
            _resolve(
                audit_raw,
                "audit",
                "events_path",
                default="~/.vulnhunter/audit_events.jsonl",
            )
        ),
        findings_path=str(
            _resolve(
                audit_raw,
                "audit",
                "findings_path",
                default="~/.vulnhunter/findings_events.jsonl",
            )
        ),
        stdout=bool(
            _resolve(audit_raw, "audit", "stdout", kind=bool, default=False)
        ),
        app_id=str(
            _resolve(audit_raw, "audit", "app_id", default="NA")
        ),
        actor=str(
            _resolve(audit_raw, "audit", "actor", default="vulnhunter-agent")
        ),
        strict=bool(
            _resolve(audit_raw, "audit", "strict", kind=bool, default=False)
        ),
    )

    # repo_properties.github_property_map is a TOML table (GitHub
    # custom-property name → emitted findings field name). Like
    # verify.repo_aliases, it has no env-var form; pull it straight from
    # raw and coerce to a str→str dict, dropping blank/non-string values.
    repo_props_raw = raw.get("repo_properties", {})
    prop_map_raw = repo_props_raw.get("github_property_map", {})
    if not isinstance(prop_map_raw, dict):
        prop_map_raw = {}
    repo_properties_cfg = RepoPropertiesConfig(
        github_property_map={
            str(k): str(v)
            for k, v in prop_map_raw.items()
            if isinstance(v, str) and v.strip()
        },
    )

    return AgentConfig(
        anthropic=anthropic,
        oauth=oauth,
        tls=tls,
        sandbox=sandbox,
        telemetry=telemetry,
        scan=scan,
        github=github,
        publish=publish,
        issues=issues,
        verify=verify,
        logging=logging_cfg,
        audit=audit,
        repo_properties=repo_properties_cfg,
        source_path=config_path,
    )
