"""CLI : sorties, seuil CI, codes de retour."""

from __future__ import annotations

import json

from app import cli


def test_cli_json_output_and_threshold(tmp_path, vulnerable_server, capsys):
    output = tmp_path / "report.json"
    code = cli.main(
        [
            "scan",
            vulnerable_server.url,
            "--no-save",
            "--quiet",
            "--format",
            "json",
            "--output",
            str(output),
            "--fail-under",
            "99",
        ]
    )
    assert code == cli.EXIT_THRESHOLD
    payload = json.loads(output.read_text())
    assert payload["score"] < 99
    assert payload["findings"]


def test_cli_passes_when_threshold_is_low(tmp_path, vulnerable_server):
    output = tmp_path / "report.json"
    code = cli.main(
        ["scan", vulnerable_server.url, "--no-save", "--quiet", "--format", "json", "--output", str(output)]
    )
    assert code == cli.EXIT_OK


def test_cli_text_output(vulnerable_server, capsys):
    code = cli.main(["scan", vulnerable_server.url, "--no-save", "--quiet"])
    assert code == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "Score" in out
    assert "Dépôt Git exposé" in out


def test_cli_sarif_output(tmp_path, vulnerable_server):
    output = tmp_path / "report.sarif.json"
    cli.main(
        ["scan", vulnerable_server.url, "--no-save", "--quiet", "--format", "sarif", "--output", str(output)]
    )
    payload = json.loads(output.read_text())
    assert payload["version"] == "2.1.0"


def test_cli_bad_target_returns_error(capsys):
    code = cli.main(["scan", "ftp://exemple.fr", "--no-save", "--quiet"])
    assert code == cli.EXIT_ERROR
    assert "Analyse impossible" in capsys.readouterr().err
