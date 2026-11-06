"""Référentiels de pentest : CWE, WSTG et score CVSS 3.1 calculé."""

from __future__ import annotations

import pytest

from app import standards

# --------------------------------------------------------------------------
# Calculateur CVSS 3.1 (valeurs de référence FIRST)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1),
        ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 4.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss_reference_values(vector, expected):
    assert standards.cvss_base(vector) == expected


def test_invalid_vector_raises():
    with pytest.raises(ValueError):
        standards.cvss_base("CVSS:3.1/AV:N/AC:X/PR:N/UI:N/S:U/C:H/I:H/A:H")


def test_vector_is_parsed():
    parts = standards.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert parts["AV"] == "N"
    assert parts["S"] == "U"


# --------------------------------------------------------------------------
# Table de correspondance
# --------------------------------------------------------------------------


def test_every_rule_is_reachable():
    """Aucune règle ne doit être masquée par un préfixe plus court placé avant."""
    for prefix, standard in standards.RULES:
        assert standards.for_finding(f"{prefix}exemple") is standard, prefix


def test_rule_format_is_consistent():
    for prefix, standard in standards.RULES:
        assert standard.cwe.startswith("CWE-"), prefix
        assert standard.cwe_name, prefix
        assert standard.wstg.startswith("WSTG-"), prefix
        assert standard.vector.startswith("CVSS:3.1/"), prefix
        assert 0.0 <= standard.cvss <= 10.0, prefix


def test_most_specific_rule_wins():
    specific = standards.for_finding("secrets.jwt-alg-none")
    generic = standards.for_finding("secrets.inconnu")
    assert specific.cwe == "CWE-347"
    assert generic.cwe == "CWE-798"


def test_known_families_are_mapped():
    idor = standards.for_finding("access.idor-object-id")
    assert idor.cwe == "CWE-639"
    assert idor.wstg == "WSTG-ATHZ-04"
    assert idor.cvss == 8.1

    git = standards.for_finding("exposure.git")
    assert git.cwe == "CWE-527"

    assert standards.for_finding("mystere.inconnu") is None


def test_describe_is_serialisable():
    data = standards.describe("access.idor-object-id")
    assert data["cwe"] == "CWE-639"
    assert isinstance(data["cvss"], float)
    assert data["cvss_vector"].startswith("CVSS:3.1/")
    assert standards.describe("mystere.inconnu") == {}


def test_scores_stay_coherent_with_common_severities():
    """Un constat critique ne peut pas afficher un CVSS de 3."""
    critical = ["secrets.jwt-alg-none", "secrets.", "exposure.ssh-private-key"]
    for finding_id in critical:
        assert standards.for_finding(finding_id).cvss >= 9.0, finding_id
    low = ["headers.hsts", "transport.", "content.sensitive-page-cacheable"]
    for finding_id in low:
        assert standards.for_finding(finding_id).cvss <= 4.0, finding_id
