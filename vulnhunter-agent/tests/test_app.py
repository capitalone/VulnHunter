import runpy
from vulnhunter import app


def test_main_help(capsys):
    try:
        app.main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
    captured = capsys.readouterr()
    assert "Provider-neutral, multi-model security scanner" in captured.out


def test_main_execution(monkeypatch):
    monkeypatch.setattr("sys.argv", ["vulnhunter", "--help"])
    try:
        runpy.run_module("vulnhunter.app", run_name="__main__")
    except SystemExit as exc:
        assert exc.code == 0
