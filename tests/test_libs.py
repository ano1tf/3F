"""Bibliothèques front-end obsolètes : versions à vulnérabilités connues."""

from __future__ import annotations

from app.models import Severity
from app.scanner.checks_libs import detect_libraries, parse_version


def findings(pages=None, scripts=None):
    result, meta = detect_libraries(pages or [], scripts or [])
    return {finding.id: finding for finding in result}, meta


def test_parse_version_pads_and_truncates():
    assert parse_version("3.4.1") == (3, 4, 1)
    assert parse_version("1.12") == (1, 12, 0)
    assert parse_version("4.17.21.1") == (4, 17, 21, 1)


def test_outdated_jquery_is_high():
    found, meta = findings(scripts=[("https://site.test/js/jquery-3.4.1.min.js", "")])
    finding = found["libs.jquery"]
    assert finding.severity is Severity.HIGH
    assert "3.4.1" in finding.title
    assert "3.5.0" in finding.evidence
    assert "CVE-2019-11358" in finding.evidence
    assert finding.confidence == "certain"
    assert "jQuery 3.4.1" in meta["bibliotheques"]


def test_recent_jquery_is_not_flagged():
    found, meta = findings(scripts=[("https://site.test/js/jquery-3.7.1.min.js", "")])
    assert "libs.jquery" not in found
    assert "jQuery 3.7.1" in meta["bibliotheques"]


def test_jquery_ui_does_not_look_like_jquery():
    found, _meta = findings(scripts=[("https://site.test/js/jquery-ui-1.12.1.min.js", "")])
    assert "libs.jquery" not in found
    assert "libs.jquery-ui" in found
    assert found["libs.jquery-ui"].severity is Severity.MEDIUM


def test_bootstrap_3_and_4_have_distinct_severities():
    old3, _ = findings(scripts=[("https://site.test/css/bootstrap-3.3.7.min.css", "")])
    old4, _ = findings(scripts=[("https://site.test/css/bootstrap.min.css?v=4.2.0", "")])
    recent, _ = findings(scripts=[("https://site.test/css/bootstrap-5.3.3.min.css", "")])

    assert old3["libs.bootstrap3"].severity is Severity.HIGH
    assert old4["libs.bootstrap3"].severity is Severity.MEDIUM
    assert "libs.bootstrap3" not in recent


def test_handlebars_is_critical():
    found, _ = findings(scripts=[("https://site.test/js/handlebars-4.7.2.min.js", "")])
    assert found["libs.handlebars"].severity is Severity.CRITICAL
    assert "CVE-2021-23369" in found["libs.handlebars"].evidence


def test_angularjs_eol_and_xss():
    old, _ = findings(scripts=[("https://site.test/js/angular-1.7.9.min.js", "")])
    last, _ = findings(scripts=[("https://site.test/js/angular.min.js?v=1.8.3", "")])

    assert old["libs.angularjs"].severity is Severity.HIGH
    assert last["libs.angularjs"].severity is Severity.LOW


def test_lodash_and_axios_and_moment():
    found, _ = findings(
        scripts=[
            ("https://site.test/js/lodash-4.17.15.min.js", ""),
            ("https://site.test/js/axios@0.21.1.min.js", ""),
            ("https://site.test/js/moment-2.24.0.min.js", ""),
        ]
    )
    assert found["libs.lodash"].severity is Severity.HIGH
    assert found["libs.axios"].severity is Severity.MEDIUM
    assert found["libs.moment"].severity is Severity.MEDIUM


def test_version_in_html_is_probable():
    html = '<script src="https://cdn.test/jquery-2.2.4.min.js"></script>'
    found, _ = findings(pages=[("https://site.test/", html)])
    assert found["libs.jquery"].confidence == "probable"


def test_safe_versions_produce_no_finding():
    found, meta = findings(
        scripts=[
            ("https://site.test/js/jquery-3.7.1.min.js", ""),
            ("https://site.test/js/lodash-4.17.21.min.js", ""),
            ("https://site.test/js/vue-3.4.0.min.js", ""),
        ]
    )
    assert found == {}
    assert "jQuery 3.7.1" in meta["bibliotheques"]


def test_unversioned_scripts_are_ignored():
    found, meta = findings(scripts=[("https://site.test/js/app.min.js", "console.log('ok')")])
    assert found == {}
    assert meta == {}


def test_detection_is_case_insensitive():
    found, _ = findings(scripts=[("https://site.test/js/JQuery-1.12.4.min.js", "")])
    assert "libs.jquery" in found
