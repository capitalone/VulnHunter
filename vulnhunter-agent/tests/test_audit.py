"""Tests for agent.audit: ULID, writer, event builders, config overrides."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from agent.audit import (
    AuditPaths,
    AuditWriteError,
    AuditWriter,
    ULIDGenerator,
    build_clean_scan_notified,
    build_finding_event,
    build_finding_opened,
    build_scan_completed,
    build_scan_started,
    build_verify_completed,
    build_verify_decision,
    build_verify_started,
    event_id,
    event_time_now,
    finding_id_for,
    new_ulid,
    report_id_from,
    writer_from_config,
)
from agent.config import AuditConfig


# ---------------------------------------------------------------------------
# ULID
# ---------------------------------------------------------------------------


class TestULID:
    def test_new_ulid_is_26_char_crockford(self) -> None:
        u = new_ulid()
        assert len(u) == 26
        assert re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", u), u

    def test_generator_monotonic_within_ms(self) -> None:
        gen = ULIDGenerator()
        ulids = [gen.new() for _ in range(50)]
        assert sorted(ulids) == ulids
        assert len(set(ulids)) == 50

    def test_module_generator_unique(self) -> None:
        # Cheap smoke: 100 rapid mints under the module-level generator
        # should be unique and sorted (monotonic).
        vals = [new_ulid() for _ in range(100)]
        assert len(set(vals)) == 100
        assert sorted(vals) == vals

    def test_event_id_carries_descriptor(self) -> None:
        eid = event_id("scan_started")
        assert eid.endswith(":scan_started")
        assert len(eid.split(":", 1)[0]) == 26


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_event_time_now_is_iso_ms_z(self) -> None:
        t = event_time_now()
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", t), t

    def test_report_id_from_dir(self, tmp_path: Path) -> None:
        d = tmp_path / "myrepo_VULNHUNT_RESULTS_opus47_2026-07-01-120000"
        d.mkdir()
        assert report_id_from(d) == d.name

    def test_finding_id_format(self) -> None:
        assert finding_id_for("REPORT-A", "VULN-001") == "REPORT-A:VULN-001"


# ---------------------------------------------------------------------------
# AuditPaths
# ---------------------------------------------------------------------------


class TestAuditPaths:
    def test_from_config_expands_home(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        p = AuditPaths.from_config("~/a.jsonl", "~/b.jsonl")
        assert p.events == (tmp_path / "a.jsonl").resolve()
        assert p.findings == (tmp_path / "b.jsonl").resolve()


# ---------------------------------------------------------------------------
# AuditWriter
# ---------------------------------------------------------------------------


class TestAuditWriter:
    def test_emit_audit_writes_jsonl(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        w.emit_audit({"event_id": "1", "event_type": "scan_started"})
        w.emit_audit({"event_id": "2", "event_type": "scan_completed"})
        w.close()
        lines = (tmp_path / "audit.jsonl").read_text().splitlines()
        assert [json.loads(l)["event_id"] for l in lines] == ["1", "2"]

    def test_emit_finding_goes_to_findings_file(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        w.emit_finding({"id": "R:VULN-001"})
        w.close()
        lines = (tmp_path / "findings.jsonl").read_text().splitlines()
        assert json.loads(lines[0])["id"] == "R:VULN-001"

    def test_parent_dirs_auto_created(self, tmp_path: Path) -> None:
        w = AuditWriter(
            paths=AuditPaths(
                events=tmp_path / "sub" / "audit.jsonl",
                findings=tmp_path / "sub" / "findings.jsonl",
            ),
            stdout=False,
            strict=False,
        )
        w.emit_audit({"event_id": "x"})
        w.close()
        assert (tmp_path / "sub" / "audit.jsonl").is_file()

    def test_none_keys_dropped_on_serialize(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        w.emit_audit({"a": "keep", "b": None, "c": {"nested_none": None, "kept": 1}})
        w.close()
        line = (tmp_path / "audit.jsonl").read_text().strip()
        obj = json.loads(line)
        assert obj == {"a": "keep", "c": {"kept": 1}}

    def test_string_redaction(self, tmp_path: Path) -> None:
        w = _writer(tmp_path)
        w.emit_audit(
            {
                "event_id": "x",
                "notes": "cloned from https://user:secret-token@github.com/o/r",
            }
        )
        w.close()
        line = (tmp_path / "audit.jsonl").read_text()
        assert "secret-token" not in line
        assert "***" in line

    def test_stdout_mirror(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        w = AuditWriter(
            paths=AuditPaths(
                events=tmp_path / "audit.jsonl",
                findings=tmp_path / "findings.jsonl",
            ),
            stdout=True,
            strict=False,
        )
        w.emit_audit({"event_id": "abc"})
        w.close()
        captured = capsys.readouterr()
        assert "abc" in captured.out

    def test_strict_raises_on_write_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Force the open() call inside AuditWriter to fail.
        from agent import audit as audit_mod

        def _boom(path: Path) -> Any:  # noqa: ARG001
            raise OSError("disk full")

        monkeypatch.setattr(audit_mod, "_open_append", _boom)
        w = AuditWriter(
            paths=AuditPaths(
                events=tmp_path / "audit.jsonl",
                findings=tmp_path / "findings.jsonl",
            ),
            stdout=False,
            strict=True,
        )
        with pytest.raises(AuditWriteError):
            w.emit_audit({"event_id": "x"})

    def test_non_strict_logs_and_continues(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        from agent import audit as audit_mod

        def _boom(path: Path) -> Any:  # noqa: ARG001
            raise OSError("disk full")

        monkeypatch.setattr(audit_mod, "_open_append", _boom)
        w = AuditWriter(
            paths=AuditPaths(
                events=tmp_path / "audit.jsonl",
                findings=tmp_path / "findings.jsonl",
            ),
            stdout=False,
            strict=False,
        )
        with caplog.at_level("ERROR", logger="agent.audit"):
            w.emit_audit({"event_id": "x"})
            w.emit_audit({"event_id": "y"})
        error_records = [r for r in caplog.records if r.levelname == "ERROR"]
        # First error logs; second is silenced to avoid a jammed-disk spam.
        assert len(error_records) == 1


def _writer(tmp: Path) -> AuditWriter:
    return AuditWriter(
        paths=AuditPaths(
            events=tmp / "audit.jsonl",
            findings=tmp / "findings.jsonl",
        ),
        stdout=False,
        strict=False,
    )


# ---------------------------------------------------------------------------
# Event builders
# ---------------------------------------------------------------------------


class TestScanEvents:
    def test_scan_started_shape(self) -> None:
        e = build_scan_started(
            app_id="my-app",
            actor="tester",
            repo_slug="org/repo",
            report_id="report-123",
            model_version="claude-opus-4-8",
            target_sha="abcdef1",
        )
        for key in ("event_id", "event_time", "event_type", "repo_slug", "app_id", "report_id"):
            assert e.get(key), f"missing {key}"
        assert e["event_type"] == "scan_started"
        assert e["app_id"] == "my-app"
        assert e["repo_slug"] == "org/repo"
        assert e["report_id"] == "report-123"

    def test_scan_completed_populates_metrics(self) -> None:
        e = build_scan_completed(
            app_id="my-app",
            actor="tester",
            repo_slug="org/repo",
            report_id="report-123",
            model_version="claude-opus-4-8",
            target_sha="abcdef1",
            findings_count=5,
            scan_cost_usd=0.42,
            scan_duration_seconds=180,
        )
        assert e["event_type"] == "scan_completed"
        assert e["findings_count"] == 5
        assert e["scan_cost_usd"] == 0.42
        assert e["scan_duration_seconds"] == 180

    def test_scan_completed_failure_notes(self) -> None:
        e = build_scan_completed(
            app_id="my-app",
            actor="tester",
            repo_slug="org/repo",
            report_id="report-123",
            model_version="claude-opus-4-8",
            target_sha="abcdef1",
            findings_count=None,
            scan_cost_usd=None,
            scan_duration_seconds=None,
            notes="failed: RateLimitError: too many requests",
        )
        assert e["notes"] == "failed: RateLimitError: too many requests"
        assert e.get("findings_count") is None


class TestVerifyEvents:
    def test_verify_started_shape(self) -> None:
        e = build_verify_started(
            app_id="my-app",
            actor="tester",
            repo_slug="org/repo",
            report_id="report-123",
            model_version="m",
            target_sha="abc",
        )
        assert e["event_type"] == "verify_started"

    def test_verify_decision_maps_verdict(self) -> None:
        e = build_verify_decision(
            app_id="my-app",
            actor="tester",
            repo_slug="org/repo",
            report_id="report-123",
            finding_id="report-123:VULN-001",
            verdict="PASS",
            to_status="RESOLVED",
            from_status="OPEN",
            evidence_text="fix confirmed at foo.py:12",
        )
        assert e["event_type"] == "verify_decision"
        assert e["verdict"] == "PASS"
        assert e["to_status"] == "RESOLVED"
        assert "VULN-001" in e["event_id"]

    def test_verify_completed_shape(self) -> None:
        e = build_verify_completed(
            app_id="my-app",
            actor="tester",
            repo_slug="org/repo",
            report_id="report-123",
            model_version="m",
            target_sha="abc",
            findings_count=3,
            scan_duration_seconds=45,
        )
        assert e["event_type"] == "verify_completed"
        assert e["findings_count"] == 3


class TestFindingEvents:
    def test_finding_opened_carries_url(self) -> None:
        e = build_finding_opened(
            app_id="my-app",
            actor="tester",
            repo_slug="org/repo",
            report_id="report-123",
            finding_id="report-123:VULN-001",
            github_issue_url="https://github.com/o/r/issues/42",
        )
        assert e["event_type"] == "finding_opened"
        assert e["github_issue_url"] == "https://github.com/o/r/issues/42"
        assert e["to_status"] == "OPEN"

    def test_finding_event_open_populates_opened_at(self) -> None:
        e = build_finding_event(
            app_id="my-app",
            repo_slug="org/repo",
            report_id="report-123",
            finding_id="report-123:VULN-001",
            vuln_id="VULN-001",
            title="SQL Injection",
            cwe="CWE-89",
            severity="Critical",
            status="OPEN",
            location="src/db.py:42",
            root_cause="unparameterized query",
            opened=True,
        )
        assert e["opened_at"] == e["transitioned_at"]
        assert e["severity"] == "critical"

    def test_finding_event_transition_omits_opened_at(self) -> None:
        e = build_finding_event(
            app_id="my-app",
            repo_slug="org/repo",
            report_id="report-123",
            finding_id="report-123:VULN-001",
            vuln_id="VULN-001",
            title="",
            cwe="CWE-89",
            severity="critical",
            status="RESOLVED",
            location="",
            root_cause="fix confirmed",
            opened=False,
        )
        # opened_at is dropped during serialization (None value).
        assert "opened_at" not in json.loads(json.dumps({k: v for k, v in e.items() if v is not None}))
        assert e["status"] == "RESOLVED"

    def test_finding_event_defaults_cwe_when_missing(self) -> None:
        e = build_finding_event(
            app_id="my-app",
            repo_slug="org/repo",
            report_id="report-123",
            finding_id="report-123:VULN-001",
            vuln_id="VULN-001",
            title="thing",
            cwe="",
            severity="",
            status="OPEN",
            location="",
            root_cause="",
        )
        assert e["cwe"] == "CWE-UNKNOWN"
        assert e["severity"] == "informational"


class TestCleanScanEvent:
    def _base_kwargs(self) -> dict[str, str]:
        return {
            "app_id": "my-app",
            "actor": "tester",
            "repo_slug": "org/repo",
            "report_id": "report-123",
            "model_version": "claude-opus-4-8",
            "target_sha": "deadbeef",
        }

    def test_happy_path_defaults(self) -> None:
        e = build_clean_scan_notified(
            github_issue_url="https://github.com/o/r/issues/1",
            **self._base_kwargs(),
        )
        assert e["event_type"] == "clean_scan_notified"
        assert e["event_id"].endswith(":clean_scan_notified")
        assert e["to_status"] == "CLOSED"
        assert e["github_issue_url"] == "https://github.com/o/r/issues/1"
        assert e["target_sha"] == "deadbeef"
        assert e["notes"] is None

    def test_close_back_failure_flags_open_state(self) -> None:
        e = build_clean_scan_notified(
            github_issue_url="https://github.com/o/r/issues/2",
            to_status="OPEN",
            notes="close-back failed: 500 boom",
            **self._base_kwargs(),
        )
        assert e["to_status"] == "OPEN"
        assert "close-back failed" in e["notes"]

    def test_append_mode_notes_carry_existing_url(self) -> None:
        existing = "https://github.com/o/r/issues/7"
        e = build_clean_scan_notified(
            github_issue_url=existing,
            notes=f"append: {existing}",
            **self._base_kwargs(),
        )
        # to_status stays CLOSED even on append: the existing issue's
        # state isn't modified when we just comment on it.
        assert e["to_status"] == "CLOSED"
        assert e["notes"] == f"append: {existing}"


# ---------------------------------------------------------------------------
# writer_from_config
# ---------------------------------------------------------------------------


class TestWriterFromConfig:
    def test_disabled_returns_none(self) -> None:
        cfg = AuditConfig(
            enabled=False,
            events_path="/tmp/a.jsonl",
            findings_path="/tmp/b.jsonl",
            stdout=False,
            app_id="NA",
            actor="agent",
            strict=False,
        )
        assert writer_from_config(cfg) is None

    def test_enabled_returns_writer(self, tmp_path: Path) -> None:
        cfg = AuditConfig(
            enabled=True,
            events_path=str(tmp_path / "a.jsonl"),
            findings_path=str(tmp_path / "b.jsonl"),
            stdout=False,
            app_id="NA",
            actor="agent",
            strict=False,
        )
        w = writer_from_config(cfg)
        assert isinstance(w, AuditWriter)
        w.emit_audit({"event_id": "x"})
        w.close()
        assert (tmp_path / "a.jsonl").is_file()

    def test_default_config_has_audit_enabled(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Regression for #24 — audit is on by default in every deployment."""
        from agent.config import load_config

        # Build a minimal TOML that satisfies the required fields; the
        # [audit] section is intentionally absent so the loader falls
        # through to defaults.
        toml = tmp_path / "cfg.toml"
        toml.write_text(
            '[anthropic]\n'
            'bedrock_base_url = "https://bedrock.example.com"\n'
            'model = "claude-opus-4-8"\n'
            '[oauth]\n'
            'token_endpoint = "https://oauth.example.com/token"\n'
            'client_id = "cid"\n'
            'client_secret = "csecret"\n'
        )
        cfg = load_config(str(toml))
        assert cfg.audit.enabled is True
        assert cfg.audit.app_id == "NA"
        assert cfg.audit.actor == "vulnhunter-agent"


# ---------------------------------------------------------------------------
# vuln_id sanitization (Fix #20)
# ---------------------------------------------------------------------------


class TestVulnIdSanitization:
    def test_finding_event_rejects_malformed_vuln_id(self) -> None:
        # Attacker-controlled vuln_id containing a newline + fake field
        # must not propagate into event_id.
        e = build_finding_event(
            app_id="my-app",
            repo_slug="org/repo",
            report_id="report-123",
            finding_id="report-123:VULN-001",
            vuln_id="VULN-001\nfake: injected",
            title="",
            cwe="",
            severity="",
            status="OPEN",
            location="",
            root_cause="",
        )
        # event_id descriptor falls back to the finding_id tail — which
        # IS a valid VULN-NNN, so it's preserved.
        assert "\n" not in e["event_id"]
        assert e["event_id"].endswith(":VULN-001")

    def test_finding_opened_event_id_rejects_malformed_finding_id(self) -> None:
        # When finding_id itself is malformed (no VULN-NNN tail),
        # descriptor collapses to "unknown".
        e = build_finding_opened(
            app_id="my-app",
            actor="tester",
            repo_slug="org/repo",
            report_id="report-123",
            finding_id="report-123:BOGUS\ninjection",
            github_issue_url="https://github.com/o/r/issues/1",
        )
        assert "\n" not in e["event_id"]
        assert e["event_id"].endswith(":unknown")


# ---------------------------------------------------------------------------
# Verdict mapping (Fix #3 + #11)
# ---------------------------------------------------------------------------


class TestVerdictMapping:
    @pytest.mark.parametrize(
        "verdict,expected",
        [
            ("FIXED", ("PASS", "RESOLVED")),
            ("NOT_FIXED", ("FAIL", "REOPENED")),
            ("PARTIAL", ("FAIL", "REOPENED")),
            ("INCONCLUSIVE", ("FAIL", "REOPENED")),
            ("INVALID_INPUT", ("FAIL", "")),
            ("", ("FAIL", "")),
            ("SOMETHING_UNKNOWN", ("FAIL", "")),
        ],
    )
    def test_map_verdict(self, verdict: str, expected: tuple[str, str]) -> None:
        from agent.verify import _map_verify_verdict

        assert _map_verify_verdict(verdict) == expected


# ---------------------------------------------------------------------------
# Strict-mode propagation (Fix #12)
# ---------------------------------------------------------------------------


class TestStrictModePropagation:
    def test_strict_mode_write_failure_raises_on_close(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A strict writer must surface AuditWriteError on any emit failure.

        This is the guarantee runner.py depends on: if the scan
        succeeded and audit is strict, an audit failure must NOT be
        silently swallowed inside the emit-completion wrapper.
        """
        from agent import audit as audit_mod

        def _boom(path: Path) -> Any:  # noqa: ARG001
            raise OSError("disk full")

        monkeypatch.setattr(audit_mod, "_open_append", _boom)
        w = AuditWriter(
            paths=AuditPaths(
                events=tmp_path / "audit.jsonl",
                findings=tmp_path / "findings.jsonl",
            ),
            stdout=False,
            strict=True,
        )
        with pytest.raises(AuditWriteError):
            w.emit_audit({"event_id": "x"})


# ---------------------------------------------------------------------------
# Second-round review fixes
# ---------------------------------------------------------------------------


class TestPostCloseEmit:
    def test_emit_after_close_is_refused_in_strict(self, tmp_path: Path) -> None:
        w = AuditWriter(
            paths=AuditPaths(
                events=tmp_path / "a.jsonl",
                findings=tmp_path / "b.jsonl",
            ),
            stdout=False,
            strict=True,
        )
        w.emit_audit({"event_id": "1"})
        w.close()
        with pytest.raises(AuditWriteError):
            w.emit_audit({"event_id": "2"})

    def test_close_is_idempotent(self, tmp_path: Path) -> None:
        w = AuditWriter(
            paths=AuditPaths(
                events=tmp_path / "a.jsonl",
                findings=tmp_path / "b.jsonl",
            ),
            stdout=False,
            strict=False,
        )
        w.emit_audit({"event_id": "1"})
        w.close()
        w.close()  # must not raise


class TestFsyncFailureIsolation:
    def test_fsync_failure_does_not_silence_stream(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """fsync failure logs once but keeps writing subsequent events."""
        from agent import audit as audit_mod

        calls: list[int] = []

        def _fake_fsync(fd: int) -> None:
            calls.append(fd)
            raise OSError("fsync unavailable")

        monkeypatch.setattr(audit_mod.os, "fsync", _fake_fsync)
        w = AuditWriter(
            paths=AuditPaths(
                events=tmp_path / "audit.jsonl",
                findings=tmp_path / "findings.jsonl",
            ),
            stdout=False,
            strict=False,
        )
        with caplog.at_level("WARNING", logger="agent.audit"):
            w.emit_audit({"event_id": "1"})
            w.emit_audit({"event_id": "2"})
            w.emit_audit({"event_id": "3"})
        w.close()
        # All three events are on disk — fsync failure ≠ write failure.
        lines = (tmp_path / "audit.jsonl").read_text().splitlines()
        assert len(lines) == 3
        # fsync ran on each write (3 times), but the WARN log only fires once.
        assert len(calls) == 3
        fsync_warnings = [r for r in caplog.records if "fsync" in r.message]
        assert len(fsync_warnings) == 1

    def test_fsync_failure_raises_in_strict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from agent import audit as audit_mod

        def _fake_fsync(fd: int) -> None:  # noqa: ARG001
            raise OSError("fsync unavailable")

        monkeypatch.setattr(audit_mod.os, "fsync", _fake_fsync)
        w = AuditWriter(
            paths=AuditPaths(
                events=tmp_path / "audit.jsonl",
                findings=tmp_path / "findings.jsonl",
            ),
            stdout=False,
            strict=True,
        )
        with pytest.raises(AuditWriteError):
            w.emit_audit({"event_id": "1"})


class TestFindingIdCoercion:
    def test_empty_vuln_id_coerced_to_unknown(self) -> None:
        from agent.audit import finding_id_for

        assert finding_id_for("report-x", "") == "report-x:unknown"

    def test_malformed_vuln_id_coerced_to_unknown(self) -> None:
        from agent.audit import finding_id_for

        # Any string that doesn't match ^VULN-\d+$
        assert finding_id_for("report-x", "vuln-1") == "report-x:unknown"
        assert finding_id_for("report-x", "VULN-001\nfake") == "report-x:unknown"
        assert finding_id_for("report-x", "VULN-XYZ") == "report-x:unknown"

    def test_valid_vuln_id_passes_through(self) -> None:
        from agent.audit import finding_id_for

        assert finding_id_for("report-x", "VULN-001") == "report-x:VULN-001"
        assert finding_id_for("report-x", "VULN-9999") == "report-x:VULN-9999"


class TestDispositionEmissionSkipsWhenNoTransition:
    def test_invalid_input_does_not_emit_finding_event(self, tmp_path: Path) -> None:
        """INVALID_INPUT verdicts must NOT emit a finding-state event."""
        import types

        from agent import verify as verify_module
        from agent.audit import (
            AuditPaths,
            AuditWriter,
        )
        from agent.config import AuditConfig
        from agent.repo_properties import RepoProperties

        cfg = types.SimpleNamespace(
            audit=AuditConfig(
                enabled=True,
                events_path=str(tmp_path / "audit.jsonl"),
                findings_path=str(tmp_path / "findings.jsonl"),
                stdout=False,
                app_id="my-app",
                actor="tester",
                strict=False,
            )
        )
        writer = AuditWriter(
            paths=AuditPaths(
                events=tmp_path / "audit.jsonl",
                findings=tmp_path / "findings.jsonl",
            ),
            stdout=False,
            strict=False,
        )
        dispositions = [
            {
                "finding_id": "VULN-001",
                "verdict": "FIXED",
                "rationale": "fixed at foo.py:12",
            },
            {
                "finding_id": "VULN-999",
                "verdict": "INVALID_INPUT",
                "rationale": "no such finding in report",
            },
        ]
        verify_module._emit_verify_dispositions(
            audit_writer=writer,
            config=cfg,
            dispositions=dispositions,
            report_id="report-x",
            repo_slug="org/repo",
            model="claude-opus-4-8",
            target_sha="abc",
            repo_properties=RepoProperties(),
        )
        writer.close()

        audit_lines = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines()]
        finding_lines = [
            json.loads(l)
            for l in (tmp_path / "findings.jsonl").read_text().splitlines()
        ]
        # Two verify_decision audit events (one per disposition).
        assert len(audit_lines) == 2
        assert all(x["event_type"] == "verify_decision" for x in audit_lines)
        # Only ONE finding event — the FIXED one. INVALID_INPUT was skipped
        # because it has no state transition to record.
        assert len(finding_lines) == 1
        assert finding_lines[0]["status"] == "RESOLVED"

    def test_strict_mode_dispositions_propagate_write_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_emit_dispositions must propagate AuditWriteError, not swallow it."""
        import types

        from agent import audit as audit_mod
        from agent import verify as verify_module
        from agent.audit import (
            AuditPaths,
            AuditWriter,
            AuditWriteError,
        )
        from agent.config import AuditConfig
        from agent.repo_properties import RepoProperties

        def _boom(path: Path) -> Any:  # noqa: ARG001
            raise OSError("disk full")

        monkeypatch.setattr(audit_mod, "_open_append", _boom)
        cfg = types.SimpleNamespace(
            audit=AuditConfig(
                enabled=True,
                events_path=str(tmp_path / "audit.jsonl"),
                findings_path=str(tmp_path / "findings.jsonl"),
                stdout=False,
                app_id="my-app",
                actor="tester",
                strict=True,
            )
        )
        writer = AuditWriter(
            paths=AuditPaths(
                events=tmp_path / "audit.jsonl",
                findings=tmp_path / "findings.jsonl",
            ),
            stdout=False,
            strict=True,
        )
        dispositions = [
            {"finding_id": "VULN-001", "verdict": "FIXED", "rationale": "ok"},
        ]
        with pytest.raises(AuditWriteError):
            verify_module._emit_verify_dispositions(
                audit_writer=writer,
                config=cfg,
                dispositions=dispositions,
                report_id="report-x",
                repo_slug="org/repo",
                model="m",
                target_sha="s",
                repo_properties=RepoProperties(),
            )


class TestNoScanRepoSlugSSH:
    def test_ssh_url_normalized_before_slug(self, tmp_path: Path) -> None:
        """--no-scan + SSH-form URL must not produce a garbage slug."""
        import argparse

        from agent.__main__ import _repo_slug_for_audit

        results_dir = tmp_path / "myapp_VULNHUNT_RESULTS_opus47_2026-07-01-120000"
        results_dir.mkdir()
        args = argparse.Namespace(targets=["git@github.com:org/repo.git"])
        slug = _repo_slug_for_audit(results_dir, args, scan=False)
        assert slug == "org/repo"


# ---------------------------------------------------------------------------
# Third-round review fixes
# ---------------------------------------------------------------------------


class TestVulnIdPadding:
    """R3-#10 — VULN-N should be zero-padded to VULN-NNN on emit."""

    def test_single_digit_padded(self) -> None:
        from agent.audit import finding_id_for

        assert finding_id_for("R", "VULN-1") == "R:VULN-001"

    def test_already_padded_unchanged(self) -> None:
        from agent.audit import finding_id_for

        assert finding_id_for("R", "VULN-001") == "R:VULN-001"

    def test_four_digit_preserved(self) -> None:
        from agent.audit import finding_id_for

        assert finding_id_for("R", "VULN-1234") == "R:VULN-1234"

    def test_malformed_still_coerced_to_unknown(self) -> None:
        from agent.audit import finding_id_for

        assert finding_id_for("R", "VULN-abc") == "R:unknown"


class TestFreetextTruncation:
    """R3-#8 — notes / evidence_text must be capped for downstream ingest."""

    def test_long_notes_truncated(self) -> None:
        e = build_scan_completed(
            app_id="my-app",
            actor="tester",
            repo_slug="org/repo",
            report_id="R",
            model_version="m",
            target_sha="s",
            findings_count=None,
            scan_cost_usd=None,
            scan_duration_seconds=None,
            notes="A" * 5000,
        )
        assert e["notes"].endswith("...<truncated>")
        assert len(e["notes"]) <= 1000

    def test_short_notes_pass_through(self) -> None:
        e = build_scan_completed(
            app_id="my-app",
            actor="tester",
            repo_slug="org/repo",
            report_id="R",
            model_version="m",
            target_sha="s",
            findings_count=None,
            scan_cost_usd=None,
            scan_duration_seconds=None,
            notes="short and sweet",
        )
        assert e["notes"] == "short and sweet"

    def test_long_evidence_text_truncated(self) -> None:
        e = build_verify_decision(
            app_id="my-app",
            actor="tester",
            repo_slug="org/repo",
            report_id="R",
            finding_id="R:VULN-001",
            verdict="FAIL",
            to_status="REOPENED",
            evidence_text="B" * 5000,
        )
        assert e["evidence_text"].endswith("...<truncated>")
        assert len(e["evidence_text"]) <= 1000


class TestPreScanAuditTrail:
    """R3-#1 — pre-scan failures must still produce a full audit trail."""

    @pytest.mark.asyncio
    async def test_prior_results_error_emits_start_and_completed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        """PriorResultsError before the retry loop must still emit
        both scan_started and a scan_completed(failed:...) so downstream
        has a record of the attempt."""
        import dataclasses

        from agent import runner as runner_mod
        from agent.audit import AuditPaths, AuditWriter
        from agent.config import AuditConfig

        clone = tmp_path / "clone"
        clone.mkdir()
        # Pre-existing results dir triggers PriorResultsError.
        (clone / "myrepo_VULNHUNT_RESULTS_opus47_2026-01-01-000000").mkdir()

        class _FakeMgr:
            def __init__(self, *a: object, **k: object) -> None:
                pass

            def get_valid_token(self) -> str:
                return "fake"

        monkeypatch.setattr(runner_mod, "make_token_manager", lambda *a, **k: _FakeMgr())
        monkeypatch.setattr(runner_mod, "_vulnhunt_skill_path", lambda: tmp_path / "skill")

        writer = AuditWriter(
            paths=AuditPaths(
                events=tmp_path / "audit.jsonl",
                findings=tmp_path / "findings.jsonl",
            ),
            stdout=False,
            strict=False,
        )
        cfg = dataclasses.replace(
            populated_agent_config,
            audit=AuditConfig(
                enabled=True,
                events_path=str(tmp_path / "audit.jsonl"),
                findings_path=str(tmp_path / "findings.jsonl"),
                stdout=False,
                app_id="my-app",
                actor="tester",
                strict=False,
            ),
        )
        with pytest.raises(runner_mod.PriorResultsError):
            await runner_mod.run_vulnhunt(clone, cfg, audit_writer=writer)
        writer.close()

        events = [
            json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines()
        ]
        # Both scan_started and scan_completed must exist.
        types = [e["event_type"] for e in events]
        assert "scan_started" in types
        assert "scan_completed" in types
        completed = next(e for e in events if e["event_type"] == "scan_completed")
        assert "PriorResultsError" in completed["notes"]
        # scan_duration_seconds is populated even on pre-flight failure.
        assert isinstance(completed.get("scan_duration_seconds"), int)
