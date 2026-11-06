"""Analyse de bout en bout contre un serveur local volontairement vulnérable."""

from __future__ import annotations

import asyncio

import pytest

from app import config
from app.models import ScanReport
from app.safety import ScanError
from app.scanner.engine import run_scan


def test_full_scan_detects_expected_issues(vulnerable_server):
    events: list[dict] = []

    async def emit(payload: dict) -> None:
        events.append(payload)

    report: ScanReport = asyncio.run(run_scan(vulnerable_server.url, emit))

    ids = {finding.id for finding in report.findings}
    assert "transport.no-https" in ids
    assert "cookies.flags" in ids
    assert "exposure.git" in ids
    assert "exposure.dotenv" in ids
    assert "robots.disclosure" in ids
    assert "errors.stack-trace" in ids
    # Le serveur de test est en HTTP : le contenu mixte n'est pas pertinent,
    # en revanche le formulaire mot de passe non chiffré doit remonter.
    assert "content.insecure-password-form" in ids
    assert "content.iframe-no-sandbox" in ids
    assert "headers.csp-unsafe" in ids
    assert "headers.csp-wildcard" in ids
    assert "cookies.prefix-violation" in ids
    assert "exposure.directory-listing" in ids
    # Nouveaux contrôles : état Terraform, clé SSH, profiler, bibliothèque obsolète.
    assert "exposure.terraform-state" in ids
    assert "exposure.ssh-private-key" in ids
    assert "headers.debug-token" in ids
    assert "libs.jquery" in ids
    # Contrôle d'accès passif : le mode rapide lit les liens sans les ouvrir.
    assert "access.idor-object-id" in ids
    assert "access.sensitive-endpoint" in ids

    assert report.score < 60
    assert report.grade in {"D", "E", "F"}
    assert report.counts["critical"] >= 2
    assert report.duration_ms > 0
    assert report.scan_id
    # Le score est borné à 0 : la somme des pénalités peut dépasser 100.
    penalty = sum(report.score_breakdown.values())
    assert report.score_breakdown
    assert report.score == max(0, min(100, 100 - penalty))
    assert 1 <= len(report.priorities) <= 3

    # Chaque constat dit ce qu'il donne accès ; la synthèse liste les actifs joignables.
    idor = next(finding for finding in report.findings if finding.id == "access.idor-object-id")
    assert idor.grants and "Comptes utilisateurs" in idor.grants
    assert idor.grants_text
    assert idor.confidence == "a-confirmer"
    for finding in report.findings:
        assert finding.grants, finding.id
    assert report.executive["reachable"]
    assert "Comptes utilisateurs" in report.executive["reachable"]

    kinds = [event["type"] for event in events]
    assert kinds[0] in {"progress", "accepted"}
    assert "progress" in kinds
    assert kinds[-1] == "result"
    assert events[-1]["report"]["target"].startswith("http://127.0.0.1")


def test_progress_is_monotonic(vulnerable_server):
    percents: list[int] = []

    async def emit(payload: dict) -> None:
        if payload.get("type") == "progress":
            percents.append(payload["percent"])

    asyncio.run(run_scan(vulnerable_server.url, emit))
    assert percents == sorted(percents)
    assert percents[-1] >= 90


def test_findings_are_deduplicated(vulnerable_server):
    async def emit(_payload: dict) -> None:
        return None

    report = asyncio.run(run_scan(vulnerable_server.url, emit))
    ids = [finding.id for finding in report.findings]
    assert len(ids) == len(set(ids))


def test_unreachable_target_reports_error(monkeypatch):
    monkeypatch.setattr(config, "ALLOW_PRIVATE_TARGETS", True)

    async def emit(_payload: dict) -> None:
        return None

    with pytest.raises(ScanError) as excinfo:
        asyncio.run(run_scan("http://127.0.0.1:1/", emit))
    assert excinfo.value.code == "unreachable"


def test_standard_profile_aggregates_pages(vulnerable_server):
    """Le profil standard explore les pages internes et agrège les constats."""
    events: list[dict] = []

    async def emit(payload: dict) -> None:
        events.append(payload)

    report = asyncio.run(run_scan(vulnerable_server.url, emit, profile="standard"))

    assert report.profile == "standard"
    assert len(report.pages) >= 2
    urls = " ".join(page["url"] for page in report.pages)
    assert "/about" in urls and "/contact" in urls
    # Les pages ouvertes révèlent en plus le champ caché et le paramètre reflété.
    ids = {finding.id for finding in report.findings}
    assert "access.hidden-object-id" in ids
    assert "access.reflected-parameter" in ids
    # Une même famille de problème devient un seul constat enrichi.
    aggregated = next(f for f in report.findings if f.id == "headers.missing.referrer-policy")
    assert "pages analysées" in aggregated.evidence.lower()
    assert "http://127.0.0.1" in aggregated.evidence


def test_quick_profile_stays_single_page(vulnerable_server):
    async def emit(_payload: dict) -> None:
        return None

    report = asyncio.run(run_scan(vulnerable_server.url, emit, profile="quick"))
    assert report.profile == "quick"
    assert len(report.pages) == 1


def test_standard_profile_finds_secrets_and_third_parties(vulnerable_server):
    async def emit(_payload: dict) -> None:
        return None

    report = asyncio.run(run_scan(vulnerable_server.url, emit, profile="standard"))
    ids = {finding.id for finding in report.findings}

    assert "secrets.aws-access-key" in ids
    assert "secrets.source-map" in ids
    secret = next(f for f in report.findings if f.id == "secrets.aws-access-key")
    assert "AKIAZ7Q2XK4M9PLW3TRV" not in secret.evidence

    hosts = {item["host"] for item in report.third_parties}
    assert "cdn.insecure.test" in hosts
    assert "video.test" in hosts
    assert all(item["role"] for item in report.third_parties)


def test_foreign_form_finding_is_not_duplicated(vulnerable_server):
    async def emit(_payload: dict) -> None:
        return None

    report = asyncio.run(run_scan(vulnerable_server.url, emit, profile="standard"))
    ids = {finding.id for finding in report.findings}
    assert "surface.foreign-form-action" in ids
    assert "content.external-form-action" not in ids


def test_findings_carry_situation_and_danger(vulnerable_server):
    events: list[dict] = []

    async def emit(payload: dict) -> None:
        events.append(payload)

    asyncio.run(run_scan(vulnerable_server.url, emit, profile="standard"))
    payload = next(event for event in events if event.get("type") == "result")["report"]
    critical = next(f for f in payload["findings"] if f["id"] == "exposure.git")

    assert 1 <= critical["danger"] <= 10
    assert critical["danger"] >= 9
    assert critical["access"] and all(isinstance(step, str) for step in critical["access"])
    assert critical["reveals"]
    assert critical["danger_label"]
    assert payload["executive"]["danger_max"] >= 9
    assert all(finding.get("danger") for finding in payload["findings"])


def test_vulnerable_library_carries_version_and_reference(vulnerable_server):
    async def emit(_payload: dict) -> None:
        return None

    report = asyncio.run(run_scan(vulnerable_server.url, emit, profile="standard"))
    finding = next(f for f in report.findings if f.id == "libs.jquery")

    assert "3.4.1" in finding.title
    assert "3.5.0" in finding.evidence
    assert finding.reference.startswith("https://")
    assert finding.danger >= 7
    assert finding.access and finding.reveals
    # La bibliothèque est aussi visible dans l'empreinte technique.
    assert "jQuery" in report.fingerprint.get("bibliotheques", "")


def test_new_checks_are_reported_in_check_list(vulnerable_server):
    async def emit(_payload: dict) -> None:
        return None

    report = asyncio.run(run_scan(vulnerable_server.url, emit, profile="standard"))
    keys = {check.key: check for check in report.checks}

    assert "libs" in keys
    assert keys["libs"].status == "ok"
    assert keys["libs"].findings
    assert "exposure" in keys and keys["exposure"].status == "ok"
