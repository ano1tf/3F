"""Cartographie des dépendances tierces."""

from __future__ import annotations

from app.scanner.checks_thirdparty import build_findings, role_for, summarize
from app.scanner.crawl import CrawlPage
from app.scanner.fetcher import HttpResponse

HTML = """
<html><head>
  <script src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>
  <script src="/local.js"></script>
  <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Inter">
  <script src="https://js.stripe.com/v3/"></script>
</head><body>
  <img src="https://cdn.autre.test/hero.png">
  <iframe src="https://www.youtube.com/embed/abc"></iframe>
  <form action="https://forms.crm.test/submit" method="post"><input name="email"></form>
  <form action="/contact" method="post"><input name="message"></form>
</body></html>
"""


def page(url: str = "https://cible.test/", body: str = HTML) -> CrawlPage:
    return CrawlPage(
        url=url,
        response=HttpResponse(url=url, status=200, body=body.encode(), headers=None),
        title="Accueil",
    )


def test_roles_are_identified():
    assert role_for("www.googletagmanager.com") == "Analytique & mesure"
    assert role_for("fonts.googleapis.com") == "CDN & polices"
    assert role_for("js.stripe.com") == "Paiement"
    assert role_for("www.youtube.com") == "Vidéo & médias"
    assert role_for("inconnu.test") == "Autre service"


def test_summarize_groups_third_parties_excluding_own_host():
    hosts = {item["host"]: item for item in summarize([page()])}
    assert "cible.test" not in hosts  # /local.js et /contact sont internes
    assert hosts["www.googletagmanager.com"]["role"] == "Analytique & mesure"
    assert hosts["fonts.googleapis.com"]["resources"] == ["style"]
    assert hosts["forms.crm.test"]["resources"] == ["formulaire"]
    assert hosts["cdn.autre.test"]["resources"] == ["image"]


def test_summarize_is_deterministic_across_pages():
    hosts = [item["host"] for item in summarize([page(), page(url="https://cible.test/contact")])]
    assert hosts == sorted(hosts)


def test_findings_report_sensitive_and_foreign_forms():
    summary = summarize([page()])
    findings = build_findings(summary, pages_count=1)
    ids = {finding.id for finding in findings}
    assert "surface.third-parties" in ids
    assert "surface.foreign-form-action" in ids

    info = next(f for f in findings if f.id == "surface.third-parties")
    assert "domain" in info.evidence.lower() or "domaine" in info.evidence.lower()
    assert "js.stripe.com" in info.evidence

    form = next(f for f in findings if f.id == "surface.foreign-form-action")
    assert "forms.crm.test" in form.evidence
    assert "cible.test" not in form.evidence.split("Formulaire(s) pointant vers : ")[1]


def test_no_third_party_no_finding():
    clean = page(body="<html><body><a href='/x'>x</a></body></html>")
    assert summarize([clean]) == []
    assert build_findings([], pages_count=1) == []
