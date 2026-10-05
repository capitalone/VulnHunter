"""Tests for the ``--mode=orcarouter`` CLI surface.

Both authentication entries must be discoverable and independently usable:
``store-api-key`` (paste an existing key) and ``login`` (OAuth 2.0 + PKCE),
plus ``status`` / ``clear`` / ``models``.
"""

from __future__ import annotations

import json

import pytest

from agent.__main__ import main


@pytest.fixture
def creds(tmp_path, monkeypatch):
    path = tmp_path / "orca.json"
    monkeypatch.setenv("ORCA_CREDENTIALS_FILE", str(path))
    # Keep discovery off the network: point the API base at an unroutable
    # loopback port so the catalog falls back to the verified seed.
    monkeypatch.setenv("ORCA_API_BASE_URL", "http://127.0.0.1:1/v1")
    return path


def test_status_without_credential_is_reported(creds, capsys) -> None:
    rc = main(["--mode=orcarouter", "--orcarouter-action=status"])
    assert rc == 0
    assert "No usable OrcaRouter credential" in capsys.readouterr().out


def test_store_api_key_then_status_masks_secret(creds, capsys) -> None:
    rc = main(
        ["--mode=orcarouter", "--orcarouter-action=store-api-key",
         "--api-key", "sk-orca-CLIKEY000000000000000000"]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "sk-orca-CLIKEY000000000000000000" not in out
    assert "sk-orca-...0000" in out

    main(["--mode=orcarouter", "--orcarouter-action=status"])
    status = capsys.readouterr().out
    assert "sk-orca-CLIKEY000000000000000000" not in status
    assert "method: api_key" in status


def test_status_json_is_machine_readable(creds, capsys) -> None:
    main(["--mode=orcarouter", "--orcarouter-action=store-api-key",
          "--api-key", "sk-orca-JSON00000000000000000000"])
    capsys.readouterr()
    main(["--mode=orcarouter", "--orcarouter-action=status", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "ok"
    assert payload["method"] == "api_key"
    assert payload["generation"] == 1
    assert "api_key" not in payload  # only the masked form is emitted


def test_clear_removes_credential(creds, capsys) -> None:
    main(["--mode=orcarouter", "--orcarouter-action=store-api-key",
          "--api-key", "sk-orca-CLEARME0000000000000000"])
    capsys.readouterr()
    assert main(["--mode=orcarouter", "--orcarouter-action=clear"]) == 0
    assert "Removed" in capsys.readouterr().out
    assert creds.exists() is False


def test_models_falls_back_to_seed_when_offline(creds, capsys) -> None:
    rc = main(["--mode=orcarouter", "--orcarouter-action=models",
               "--capability", "chat", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["degraded"] is True
    assert payload["source"] == "seed"
    assert payload["count"] >= 5
    ids = {m["id"] for m in payload["models"]}
    assert "openai/gpt-5.5" in ids


def test_models_live_uses_catalog_api(creds, capsys, monkeypatch) -> None:
    import agent.orcarouter as orca

    def fake_discover(config, api_key, *, capability="chat", http_client=None):
        return orca.ModelCatalog(
            models=(
                orca.ModelInfo(id="vendor/live-model",
                               endpoint_types=("openai",),
                               input_modalities=("text",)),
            ),
            source="live",
        )

    monkeypatch.setattr(orca, "discover_catalog", fake_discover)
    rc = main(["--mode=orcarouter", "--orcarouter-action=models", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["source"] == "live"
    assert payload["degraded"] is False
    assert [m["id"] for m in payload["models"]] == ["vendor/live-model"]


def test_login_uses_the_oauth_adapter(creds, capsys, monkeypatch) -> None:
    import agent.orcarouter as orca

    used: dict = {}

    class _FakeProvider:
        def __init__(self, *a, **k):
            pass

        def connect_oauth(self):
            used["called"] = True
            return orca.CredentialResult(
                api_key="sk-orca-FROMOAUTH00000000000000",
                method=orca.ConnectMethod.OAUTH,
                scope="api",
                source="oauth",
            )

    monkeypatch.setattr(orca, "ConnectCredentialProvider", _FakeProvider)
    rc = main(["--mode=orcarouter", "--orcarouter-action=login"])
    assert rc == 0
    assert used.get("called") is True
    out = capsys.readouterr().out
    assert "login complete" in out
    assert "sk-orca-FROMOAUTH00000000000000" not in out


def test_orcarouter_mode_rejects_positional(creds) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--mode=orcarouter", "https://github.com/o/r"])
    assert excinfo.value.code == 2


def test_help_lists_both_entries(capsys) -> None:
    with pytest.raises(SystemExit):
        main(["--help"])
    text = capsys.readouterr().out
    assert "--orcarouter-action" in text
    assert "login" in text
    assert "store-api-key" in text


def test_models_rejects_incompatible_selected_model(creds, capsys, monkeypatch) -> None:
    """A selected model not in the capability-filtered set fails loudly."""
    import agent.orcarouter as orca

    monkeypatch.setattr(
        orca, "discover_catalog",
        lambda config, key, capability="chat", http_client=None: orca.ModelCatalog(
            models=(orca.ModelInfo(id="vendor/text-only",
                                   endpoint_types=("openai",),
                                   input_modalities=("text",)),),
            source="live",
        ),
    )
    rc = main(["--mode=orcarouter", "--orcarouter-action=models",
               "--capability", "image_input", "--model", "vendor/text-only"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "not available for capability" in err
    assert "vendor/text-only" in err
