"""Analyse statique de la page HTML : contenu mixte, formulaires, fuites dans le code."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from ..models import Finding, Severity
from .fetcher import HttpResponse

CATEGORY = "Contenu & formulaires"

SENSITIVE_COMMENT = re.compile(
    r"password|passwd|secret|api[_-]?key|token|todo|fixme|hack|debug|internal only|"
    r"ne pas supprimer|mot de passe|clé privée",
    re.I,
)


@dataclass
class PageInfo:
    scripts: list[str] = field(default_factory=list)
    scripts_with_integrity: set[int] = field(default_factory=set)
    styles: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    images: list[str] = field(default_factory=list)
    iframes: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    inline_handlers: list[str] = field(default_factory=list)
    blank_targets: list[str] = field(default_factory=list)
    generator: str = ""
    has_meta_csp: bool = False


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.info = PageInfo()
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script":
            src = a.get("src", "")
            if src:
                self.info.scripts.append(src)
                if a.get("integrity"):
                    self.info.scripts_with_integrity.add(len(self.info.scripts) - 1)
        elif tag == "link":
            rel = a.get("rel", "").lower()
            href = a.get("href", "")
            if "stylesheet" in rel and href:
                self.info.styles.append(href)
            if href:
                self.info.links.append(href)
        elif tag == "img" and a.get("src"):
            self.info.images.append(a["src"])
        elif tag == "iframe" and a.get("src"):
            self.info.iframes.append(a["src"])
        elif tag == "meta":
            if a.get("http-equiv", "").lower() == "content-security-policy":
                self.info.has_meta_csp = True
            if a.get("name", "").lower() == "generator":
                self.info.generator = a.get("content", "")
        elif tag == "form":
            self._form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "get").lower(),
                "has_password": False,
                "autocomplete": a.get("autocomplete", ""),
            }
        elif tag == "input" and self._form is not None:
            input_type = a.get("type", "text").lower()
            if input_type == "password":
                self._form["has_password"] = True
        elif tag == "a":
            if a.get("target", "").lower() == "_blank" and "noopener" not in a.get("rel", "").lower():
                self.info.blank_targets.append(a.get("href", "")[:120])
        elif tag == "body":
            for key, value in a.items():
                if key.startswith("on"):
                    self.info.inline_handlers.append(f"{key}={value[:60]}")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.info.forms.append(self._form)
            self._form = None

    def handle_comment(self, data: str) -> None:
        if data.strip():
            self.info.comments.append(data.strip()[:400])


def parse_page(html: str) -> PageInfo:
    parser = _PageParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # pragma: no cover - HTML exotique
        pass
    if parser._form is not None:
        parser.info.forms.append(parser._form)
    return parser.info


def _is_insecure(url: str) -> bool:
    return url.strip().lower().startswith("http://")


def check_page(response: HttpResponse) -> tuple[list[Finding], PageInfo]:
    findings: list[Finding] = []
    html = response.text
    info = parse_page(html)
    page_url = response.url
    is_https = urlsplit(page_url).scheme == "https"

    # Le contenu mixte n'a de sens que sur une page HTTPS.
    mixed = sorted(
        {
            u
            for u in (*info.scripts, *info.styles, *info.images, *info.iframes)
            if _is_insecure(u)
        }
    ) if is_https else []
    if mixed:
        findings.append(
            Finding(
                id="content.mixed-content",
                title="Contenu mixte (ressources HTTP sur page HTTPS)",
                severity=Severity.HIGH,
                category=CATEGORY,
                description="Des ressources sont chargées en HTTP clair sur une page HTTPS. Elles "
                "peuvent être modifiées par un attaquant réseau (injection de script), et les "
                "navigateurs modernes les bloquent.",
                evidence="\n".join(mixed[:10]),
                remediation="Servez toutes les ressources en HTTPS (ou en URL relatives) et activez "
                "`upgrade-insecure-requests` dans la CSP.",
                reference="https://developer.mozilla.org/fr/docs/Web/Security/Mixed_content",
            )
        )

    # Sur une page HTTP, le transport est déjà signalé globalement : on ne
    # remonte ici que les formulaires qui pointent explicitement vers du HTTP.
    insecure_forms = [
        f
        for f in info.forms
        if f["has_password"] and (_is_insecure(f["action"]) or (is_https and not f["action"]))
    ]
    if insecure_forms:
        findings.append(
            Finding(
                id="content.insecure-password-form",
                title="Formulaire de mot de passe à destination non chiffrée",
                severity=Severity.HIGH,
                category=CATEGORY,
                description="Un formulaire contenant un champ mot de passe poste vers une URL HTTP "
                "(ou hérite d'une page non chiffrée) : les identifiants circulent en clair.",
                evidence="\n".join(
                    f"action={f['action'] or '(page courante)'} method={f['method']}"
                    for f in insecure_forms[:5]
                ),
                remediation="Pointez tous les formulaires d'authentification vers une URL HTTPS "
                "absolue et vérifiez la redirection du site.",
                reference="https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            )
        )

    form_actions = sorted({urljoin(page_url, f["action"]) for f in info.forms if f["action"]})
    external_actions = [a for a in form_actions if urlsplit(a).hostname != urlsplit(page_url).hostname]
    if external_actions:
        findings.append(
            Finding(
                id="content.external-form-action",
                title="Formulaire envoyé vers un domaine tiers",
                severity=Severity.INFO,
                category=CATEGORY,
                description="Les données saisies partent vers un autre domaine. À vérifier : est-ce "
                "voulu (paiement, CRM) et couvert par la politique de confidentialité ?",
                evidence="\n".join(external_actions[:5]),
                remediation="Documentez et validez les domaines destinataires des formulaires.",
            )
        )

    suspicious_comments = [
        c for c in info.comments if SENSITIVE_COMMENT.search(c) and len(c) > 8
    ]
    if suspicious_comments:
        findings.append(
            Finding(
                id="content.comments-leak",
                title="Commentaires HTML potentiellement sensibles",
                severity=Severity.LOW,
                category="Fuite d'information",
                description="Des commentaires laissés dans le code source évoquent des secrets, des "
                "URL internes ou des points de debug.",
                evidence="\n---\n".join(c[:200] for c in suspicious_comments[:5]),
                remediation="Retirez les commentaires sensibles du HTML livré (nettoyage de build).",
                reference="https://owasp.org/www-project-web-security-testing-guide/",
            )
        )

    external_scripts = [
        s
        for i, s in enumerate(info.scripts)
        if i not in info.scripts_with_integrity
        and urlsplit(urljoin(page_url, s)).hostname not in {None, urlsplit(page_url).hostname}
    ]
    if external_scripts:
        findings.append(
            Finding(
                id="content.script-integrity",
                title="Scripts tiers sans Subresource Integrity (SRI)",
                severity=Severity.LOW,
                category=CATEGORY,
                description="Un script chargé depuis un domaine tiers sans attribut `integrity` peut "
                "être modifié (compromission du CDN) et s'exécuter avec les droits de la page.",
                evidence="\n".join(external_scripts[:8]),
                remediation="Ajoutez `integrity=\"sha384-…\"` et `crossorigin=\"anonymous\"` aux "
                "scripts tiers, ou hébergez-les vous-même.",
                reference="https://developer.mozilla.org/fr/docs/Web/Security/Subresource_Integrity",
            )
        )

    if info.blank_targets:
        findings.append(
            Finding(
                id="content.blank-noopener",
                title="Liens target=_blank sans rel=noopener",
                severity=Severity.LOW,
                category=CATEGORY,
                description="La page ouverte peut accéder à `window.opener` et rediriger l'onglet "
                "d'origine (tabnabbing).",
                evidence="\n".join(info.blank_targets[:8]),
                remediation="Ajoutez `rel=\"noopener noreferrer\"` à tous les liens `target=_blank`.",
                reference="https://developer.mozilla.org/fr/docs/Web/HTML/Element/a",
            )
        )

    if info.inline_handlers:
        findings.append(
            Finding(
                id="content.inline-handlers",
                title="Gestionnaires d'événements inline détectés",
                severity=Severity.INFO,
                category=CATEGORY,
                description="Les attributs `onclick`, `onload`… sont des cibles XSS privilégiées et "
                "empêchent l'usage d'une CSP stricte sans `unsafe-inline`.",
                evidence="\n".join(info.inline_handlers[:8]),
                remediation="Déplacez la logique vers des fichiers JS et utilisez addEventListener.",
                reference="https://developer.mozilla.org/fr/docs/Web/HTTP/CSP",
            )
        )

    if info.generator and re.search(r"\d+\.\d+", info.generator):
        findings.append(
            Finding(
                id="content.generator-version",
                title="Version du CMS divulguée",
                severity=Severity.LOW,
                category="Fuite d'information",
                description="La balise `generator` expose la version exacte du CMS, ce qui permet "
                "d'identifier les CVE applicables.",
                evidence=f'<meta name="generator" content="{info.generator}">',
                remediation="Supprimez la balise generator et maintenez le CMS à jour.",
                reference="https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
            )
        )

    return findings, info
