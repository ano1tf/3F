"""Cartographie des dépendances tierces : qui le site charge-t-il, et pour quoi faire ?"""

from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlsplit

from ..models import Finding, Severity
from .checks_content import parse_page
from .crawl import CrawlPage
from .fetcher import same_origin

CATEGORY = "Surface tierce"

ROLES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("CDN & polices", ("fonts.googleapis", "fonts.gstatic", "cdnjs", "jsdelivr", "unpkg",
                       "bootstrapcdn", "jquery.com", "typekit", "fontawesome")),
    ("Analytique & mesure", ("google-analytics", "googletagmanager", "hotjar", "matomo",
                             "segment.com", "mixpanel", "clarity.ms", "amplitude", "heap.io",
                             "plausible.io", "vercel-insights")),
    ("Publicité & réseaux sociaux", ("doubleclick", "googlesyndication", "facebook", "twitter",
                                     "linkedin", "tiktok", "instagram", "pinterest", "criteo",
                                     "taboola", "outbrain")),
    ("Paiement", ("stripe", "paypal", "adyen", "checkout.com", "braintree", "mollie", "klarna")),
    ("Vidéo & médias", ("youtube", "vimeo", "wistia", "jwplayer", "brightcove", "dailymotion",
                        "cloudinary", "imgix")),
    ("Support & chat", ("zendesk", "intercom", "crisp.chat", "tidio", "drift.com", "livechat",
                        "freshchat", "helpscout")),
    ("Sécurité & anti-bot", ("recaptcha", "hcaptcha", "cloudflare", "akamai", "datadome",
                             "turnstile", "imperva", "sucuri")),
    ("E-mail & marketing", ("mailchimp", "sendgrid", "hubspot", "marketo", "brevo", "sendinblue",
                            "mailjet", "klaviyo")),
)

MAX_HOSTS = 40


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def role_for(host: str) -> str:
    for label, markers in ROLES:
        if any(marker in host for marker in markers):
            return label
    return "Autre service"


def summarize(pages: list[CrawlPage]) -> list[dict]:
    """Regroupe par domaine tiers les ressources chargées depuis chaque page explorée."""
    own_host = host_of(pages[0].url) if pages else ""
    hosts: dict[str, dict] = defaultdict(lambda: {"host": "", "resources": [], "pages": set(), "example": ""})

    def register(raw: str, page_url: str, kind: str) -> None:
        absolute = raw if raw.startswith(("http://", "https://")) else ""
        if not absolute:
            from urllib.parse import urljoin

            absolute = urljoin(page_url, raw)
        host = host_of(absolute)
        if not host or host == own_host:
            return
        if same_origin(page_url, absolute):
            return
        entry = hosts[host]
        entry["host"] = host
        if kind not in entry["resources"]:
            entry["resources"].append(kind)
        entry["pages"].add(page_url)
        if not entry["example"]:
            entry["example"] = absolute

    for page in pages:
        if not page.ok:
            continue
        info = parse_page(page.response.text)
        for script in info.scripts:
            register(script, page.url, "script")
        for style in info.styles:
            register(style, page.url, "style")
        for image in info.images:
            register(image, page.url, "image")
        for iframe in info.iframes:
            register(iframe, page.url, "iframe")
        for form in info.forms:
            if form.get("action"):
                register(form["action"], page.url, "formulaire")

    summary = []
    for entry in hosts.values():
        summary.append(
            {
                "host": entry["host"],
                "role": role_for(entry["host"]),
                "resources": sorted(entry["resources"]),
                "pages": len(entry["pages"]),
                "example": entry["example"],
            }
        )
    summary.sort(key=lambda item: (-len(item["resources"]), -item["pages"], item["host"]))
    return summary[:MAX_HOSTS]


def build_findings(third_parties: list[dict], pages_count: int) -> list[Finding]:
    if not third_parties:
        return []

    lines = []
    for item in third_parties[:12]:
        resources = ", ".join(item["resources"])
        lines.append(f"  · {item['host']} [{item['role']}] — {resources}")
    if len(third_parties) > 12:
        lines.append(f"  … et {len(third_parties) - 12} autre(s) domaine(s)")

    sensitive = [item for item in third_parties if item["role"] in
                 ("Paiement", "Support & chat", "Analytique & mesure", "Publicité & réseaux sociaux")]
    risky_forms = [item for item in third_parties if "formulaire" in item["resources"]]

    findings = [
        Finding(
            id="surface.third-parties",
            title=f"{len(third_parties)} domaine(s) tiers chargés par le site",
            severity=Severity.INFO,
            category=CATEGORY,
            description="Chaque domaine tiers contacté par le navigateur du visiteur voit son "
            "adresse IP, son référent et parfois ses données de formulaire. C'est une surface de "
            "dépendance : une compromission chez le fournisseur devient une compromission du site "
            "(Magecart, supply-chain JavaScript).",
            evidence=(
                f"Domaines tiers détectés sur {pages_count} page(s) analysée(s) :\n"
                + "\n".join(lines)
                + (
                    "\n\nDomaines à surveiller en priorité : "
                    + ", ".join(sorted({item['host'] for item in sensitive}))
                    if sensitive
                    else ""
                )
            ),
            remediation="Documentez chaque domaine tiers (contrat, DPA, politique de sécurité), "
            "limitez-le au strict nécessaire et imposez `integrity`/CSP sur les ressources "
            "exécutables.",
            reference="https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities",
        )
    ]

    if risky_forms:
        hosts = ", ".join(item["host"] for item in risky_forms[:5])
        findings.append(
            Finding(
                id="surface.foreign-form-action",
                title="Données de formulaire envoyées à un domaine tiers",
                severity=Severity.MEDIUM,
                category=CATEGORY,
                description="Un formulaire poste vers un domaine qui n'appartient pas au site. "
                "Si ce n'est pas un prestataire identifié (paiement, CRM), les données saisies "
                "partent chez un tiers inconnu — problème de confidentialité et de conformité.",
                evidence=f"Formulaire(s) pointant vers : {hosts}",
                remediation="Vérifiez chaque destination : prestataire documenté (DPA signé) ou "
                "suppression du champ `action`. Privilégiez une soumission vers votre propre "
                "backend, qui relaie ensuite au prestataire.",
                reference="https://www.cnil.fr/fr/sous-traitant",
            )
        )

    return findings
