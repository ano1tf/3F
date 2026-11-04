"""Analyse de bout en bout contre un serveur local volontairement vulnérable."""

from __future__ import annotations

import asyncio

import pytest

from app import config
from app.models import ScanReport
from app.scanner.engine import run_scan
from tests.fixtures.bad_server import FixtureServer


@pytest.fixture()
def vulnerable_server(monkeypatch):
    monkeypatch.setattr(config, "ALLOW_PRIVATE_TARGETS", True)
    with FixtureServer() as server:
        yield server


def test_full_scan_detects_expected_issues(vulnerable_server):
    events: list[dict] = []

    async def emit(payload: dict) -> None:
        events.append(payload)

    report: ScanReport = asyncio.run(run_scan(vulnerable_server.url, emit))

    ids = {finding.id for finding in report.findings}
    assert "transport.no-https" in ids
    assert "headers.missing.content-security-policy" in ids
    assert "cookies.flags" in ids
    assert "exposure.git" in ids
    assert "exposure.dotenv" in ids
    assert "robots.disclosure" in ids
    assert "errors.stack-trace" in ids
    # Le serveur de test est en HTTP : le contenu mixte n'est pas pertinent,
    # en revanche le formulaire mot de passe non chiffré doit remonter.
    assert "content.insecure-password-form" in ids
    assert "exposure.directory-listing" in ids

    assert report.score < 60
    assert report.grade in {"D", "E", "F"}
    assert report.counts["critical"] >= 2
    assert report.duration_ms > 0

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


def test_unreachable_target_reports_error():
    async def emit(_payload: dict) -> None:
        return None

    with pytest.raises(Exception):
        asyncio.run(run_scan("http://127.0.0.1:1/", emit))
