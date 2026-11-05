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


def test_cli_verify_reports_success(monkeypatch, capsys):
    from app import cli, verify

    async def fake_status(host: str) -> dict:
        return {
            "host": host,
            "token": "jeton123",
            "verified": False,
            "verified_at": None,
            "method": None,
            "instructions": {
                "record_name": f"_vulnlens.{host}",
                "record_value": "vulnlens-verification=jeton123",
                "file_url": f"https://{host}/.well-known/vulnlens.txt",
            },
        }

    async def fake_verify(host: str) -> dict:
        return {"verified": True, "method": "dns", "detail": "TXT trouvé"}

    monkeypatch.setattr(verify, "status", fake_status)
    monkeypatch.setattr(verify, "verify", fake_verify)

    assert cli.main(["verify", "cible.test"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "_vulnlens.cible.test" in out
    assert "Propriété confirmée" in out


def test_cli_verify_fails_without_proof(monkeypatch):
    from app import cli, verify

    async def fake_status(host: str) -> dict:
        return {
            "host": host,
            "token": "jeton123",
            "verified": False,
            "verified_at": None,
            "method": None,
            "instructions": {
                "record_name": f"_vulnlens.{host}",
                "record_value": "vulnlens-verification=jeton123",
                "file_url": f"https://{host}/.well-known/vulnlens.txt",
            },
        }

    async def fake_verify(_host: str) -> dict:
        return {"verified": False, "method": None, "detail": "Aucune preuve détectée."}

    monkeypatch.setattr(verify, "status", fake_status)
    monkeypatch.setattr(verify, "verify", fake_verify)

    assert cli.main(["verify", "cible.test"]) == cli.EXIT_THRESHOLD


def test_cli_default_profile_is_standard():
    from app import cli

    args = cli.build_parser().parse_args(["scan", "exemple.fr"])
    assert args.profile == "standard"


def test_cli_plan_format(capsys):
    from app import cli

    report = {
        "target": "https://cible.test/",
        "final_url": "https://cible.test/",
        "score": 50,
        "grade": "D",
        "findings": [
            {
                "id": "exposure.git",
                "title": "Dépôt Git exposé",
                "severity": "critical",
                "severity_label": "Critique",
                "category": "Exposition",
                "remediation": "Bloquez .git/",
            }
        ],
    }
    output = cli._render(report, "plan")
    assert "Bloquez .git/" in output
    assert "Score actuel" in output
