"""Contrôle d'accès passif : IDOR, champs cachés, paramètres, surface d'admin."""

from __future__ import annotations

from app.models import Severity
from app.scanner.checks_access import inspect


def ids_in(pages=None, scripts=None):
    return {finding.id: finding for finding in inspect(pages or [], scripts or [])}


PAGE = "<html><body>page</body></html>"


def test_object_ids_in_path_are_flagged_as_idor():
    found = ids_in(
        pages=[
            ("https://site.test/users/42", PAGE),
            ("https://site.test/users/43", PAGE),
            ("https://site.test/factures/1024", PAGE),
        ]
    )
    finding = found["access.idor-object-id"]
    assert finding.severity is Severity.HIGH
    assert finding.confidence == "a-confirmer"
    assert "/users/{id}" in finding.evidence
    assert "42" in finding.evidence
    assert "BOLA" in finding.description or "IDOR" in finding.description


def test_object_id_in_query_is_flagged():
    found = ids_in(pages=[("https://site.test/facture?id=1024", PAGE)])
    assert "access.idor-object-id" in found
    assert "id=1024" in found["access.idor-object-id"].evidence


def test_uuid_identifiers_are_also_objects():
    found = ids_in(
        pages=[("https://site.test/comptes/3f2b1c9e-8f4a-4d5b-9c6e-1a2b3c4d5e6f", PAGE)]
    )
    assert "access.idor-object-id" in found


def test_non_identifiers_are_ignored():
    found = ids_in(
        pages=[
            ("https://site.test/users/dupont", PAGE),
            ("https://site.test/blog/article", PAGE),
            ("https://site.test/produits?couleur=rouge", PAGE),
        ]
    )
    assert "access.idor-object-id" not in found


def test_hidden_object_field_is_reported():
    html = (
        "<form method='post' action='/profil'>"
        "<input type='hidden' name='user_id' value='42'>"
        "<input name='email'></form>"
    )
    found = ids_in(pages=[("https://site.test/profil", html)])
    finding = found["access.hidden-object-id"]
    assert finding.severity is Severity.MEDIUM
    assert "user_id" in finding.evidence


def test_privilege_parameters_are_high():
    found = ids_in(
        pages=[
            ("https://site.test/espace?admin=1", PAGE),
            ("https://site.test/espace?role=admin", PAGE),
        ]
    )
    finding = found["access.parameter-control"]
    assert finding.severity is Severity.HIGH
    assert "admin=1" in finding.evidence


def test_path_parameters_are_medium():
    found = ids_in(pages=[("https://site.test/export?file=rapport.pdf", PAGE)])
    assert found["access.path-parameter"].severity is Severity.MEDIUM


def test_reflected_parameter_is_detected_without_payload():
    html = "<html><body>Résultats pour vulnlens</body></html>"
    found = ids_in(pages=[("https://site.test/recherche?q=vulnlens", html)])
    finding = found["access.reflected-parameter"]
    assert finding.confidence == "a-confirmer"
    assert "q" in finding.evidence
    assert "aucune charge" in finding.evidence.lower()


def test_absent_reflection_is_not_reported():
    html = "<html><body>Résultats pour autre chose</body></html>"
    found = ids_in(pages=[("https://site.test/recherche?q=vulnlens", html)])
    assert "access.reflected-parameter" not in found


def test_admin_endpoints_in_scripts_are_listed():
    found = ids_in(
        pages=[("https://site.test/", PAGE)],
        scripts=[("https://site.test/app.js", 'fetch("/admin/users"); go("/backoffice/")')],
    )
    finding = found["access.sensitive-endpoint"]
    assert finding.severity is Severity.LOW
    assert "/admin/users" in finding.evidence
    assert "/backoffice/" in finding.evidence


def test_clean_pages_produce_no_finding():
    found = ids_in(
        pages=[
            ("https://site.test/", "<html><body><a href='/blog'>Blog</a></body></html>"),
            ("https://site.test/blog", PAGE),
            ("https://site.test/contact", PAGE),
        ],
        scripts=[("https://site.test/app.js", "console.log('ok')")],
    )
    assert found == {}
