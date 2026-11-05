"""Agrégation multi-pages des constats."""

from __future__ import annotations

from app.models import Finding, Severity
from app.scanner.aggregate import aggregate, coverage_note


def finding(fid: str = "x", evidence: str = "preuve") -> Finding:
    return Finding(
        id=fid,
        title="Titre",
        severity=Severity.HIGH,
        category="Cat",
        description="Desc",
        evidence=evidence,
    )


def test_single_page_keeps_finding_untouched():
    result = aggregate([("https://a/", [finding()])], 1)
    assert len(result) == 1
    assert result[0].evidence == "preuve"


def test_multiple_pages_are_merged_with_urls():
    result = aggregate(
        [("https://a/1", [finding()]), ("https://a/2", [finding()]), ("https://a/3", [])],
        3,
    )
    assert len(result) == 1
    assert "2 des 3 pages" in result[0].evidence
    assert "https://a/1" in result[0].evidence
    assert "https://a/2" in result[0].evidence


def test_distinct_findings_are_kept_separate():
    result = aggregate(
        [("https://a/1", [finding("x"), finding("y")]), ("https://a/2", [finding("x")])],
        2,
    )
    by_id = {item.id: item for item in result}
    assert set(by_id) == {"x", "y"}
    assert "2 des 2 pages" in by_id["x"].evidence
    assert by_id["y"].evidence == "preuve"


def test_coverage_note():
    assert "une seule page" in coverage_note(1, 0)
    assert "6 pages" in coverage_note(6, 12)
    assert "12 URL" in coverage_note(6, 12)
