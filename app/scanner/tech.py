"""Empreinte technique enrichie : WAF, CDN, CMS, frameworks, bibliothèques, analytique.

Déductions à partir de ce que le serveur envoie déjà à chaque visiteur (en-têtes + HTML).
Aucune requête supplémentaire, aucun sondage actif.
"""

from __future__ import annotations

import re

WAF_SIGNATURES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Cloudflare", ("cf-ray", "cf-cache-status", "__cf_bm")),
    ("Akamai", ("akamai-grn", "x-akamai-request-id", "akamai-cache-status")),
    ("AWS CloudFront / WAF", ("x-amz-cf-id", "x-amz-cf-pop", "cloudfront")),
    ("Fastly", ("x-fastly-request-id", "x-served-by", "fastly-io")),
    ("Sucuri", ("x-sucuri-id", "x-sucuri-cache")),
    ("Imperva / Incapsula", ("x-iinfo", "incap_ses", "visid_incap")),
    ("F5 BIG-IP", ("x-wa-info", "bigipserver")),
    ("Azure Front Door", ("x-azure-ref", "x-fd-int-roxy-purgeid")),
    ("Vercel", ("x-vercel-id", "x-vercel-cache", "server: vercel")),
    ("Netlify", ("x-nf-request-id", "server: netlify")),
    ("GitHub Pages", ("x-github-request-id", "server: github.com")),
    ("ModSecurity", ("x-mod-security", "mod_security")),
    ("Wordfence", ("wordfence",)),
)

CMS_SIGNATURES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("WordPress", ("wp-content", "wp-includes", "wp-json")),
    ("Drupal", ("sites/default/files", "drupal-settings-json", "x-generator: drupal")),
    ("Joomla", ("/media/jui/", "com_content", "joomla")),
    ("PrestaShop", ("prestashop", "/modules/ps_", "var prestashop")),
    ("Shopify", ("cdn.shopify.com", "shopify-section", "myshopify")),
    ("Magento", ("mage/cookies", "static/version", "magento")),
    ("Ghost", ("ghost-url", "content=\"ghost")),
    ("Webflow", ("webflow.js", "data-wf-page")),
    ("Wix", ("wixstatic", "wix-image")),
    ("HubSpot CMS", ("hs-scripts.com", "hubspotusercontent")),
    ("Next.js", ("__next_data__", "/_next/static")),
    ("Nuxt", ("__nuxt", "/_nuxt/")),
    ("Astro", ("astro-island", "/_astro/")),
    ("Squarespace", ("squarespace.com", "static1.squarespace")),
)

FRAMEWORK_SIGNATURES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("React", ("data-reactroot", "react-dom", "__react")),
    ("Vue.js", ("data-v-", "vue.js", "__vue__")),
    ("Angular", ("ng-version", "angular.min.js")),
    ("Svelte", ("svelte-", "__svelte")),
    ("Alpine.js", ("x-data=", "alpinejs")),
    ("jQuery", ("jquery",)),
    ("Bootstrap", ("bootstrap.min.", "bootstrap.css")),
    ("Tailwind CSS", ("tailwind",)),
)

ANALYTICS_SIGNATURES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Google Tag Manager", ("googletagmanager.com/gtm.js", "gtm-")),
    ("Google Analytics 4", ("gtag/js?id=g-", "/g/collect")),
    ("Matomo", ("matomo.js", "piwik.js")),
    ("Plausible", ("plausible.io/js",)),
    ("Hotjar", ("hotjar",)),
    ("Microsoft Clarity", ("clarity.ms",)),
    ("Meta Pixel", ("connect.facebook.net", "fbq(")),
    ("LinkedIn Insight", ("snap.licdn.com",)),
    ("Sendinblue / Brevo", ("sibautomation", "brevo")),
    ("Intercom", ("intercom",)),
    ("Crisp", ("crisp.chat",)),
    ("reCAPTCHA", ("recaptcha", "gstatic.com/recaptcha")),
    ("hCaptcha", ("hcaptcha.com",)),
)

LANG_SIGNATURES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("PHP", ("x-powered-by: php", "phpsessid")),
    ("ASP.NET", ("x-aspnet-version", "asp.net", "__viewstate")),
    ("Java / Spring", ("jsessionid", "x-application-context")),
    ("Ruby on Rails", ("x-runtime", "_rails_session")),
    ("Django", ("csrftoken", "django")),
    ("Laravel", ("laravel_session", "x-powered-by: laravel")),
    ("Node.js / Express", ("x-powered-by: express",)),
)

_JQUERY = re.compile(r"jquery[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
_BOOTSTRAP = re.compile(r"bootstrap(?:\.min)?[-.](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
_VIEWPORT = re.compile(r"<meta[^>]+name=[\"']viewport", re.IGNORECASE)


def _haystack(headers: dict[str, str], html: str, scripts: list[str]) -> str:
    header_text = " ".join(f"{key}: {value}" for key, value in headers.items()).lower()
    return f"{header_text} {html.lower()[:200_000]} {' '.join(scripts).lower()}"


def _match(signatures, haystack: str) -> list[str]:
    found = []
    for label, markers in signatures:
        if any(marker in haystack for marker in markers):
            found.append(label)
    return found


def detect(headers: dict[str, str], html: str, scripts: list[str]) -> dict[str, str]:
    """:returns: empreinte normalisée, prête à être fusionnée dans le rapport."""
    haystack = _haystack(headers, html, scripts)
    fingerprint: dict[str, str] = {}

    waf = _match(WAF_SIGNATURES, haystack)
    if waf:
        fingerprint["waf"] = ", ".join(waf[:3])

    cdn = [name for name in ("Cloudflare", "AWS CloudFront / WAF", "Fastly", "Akamai", "Vercel", "Netlify")
           if name in waf]
    if cdn:
        fingerprint["cdn"] = ", ".join(cdn[:3])

    cms = _match(CMS_SIGNATURES, haystack)
    if cms:
        fingerprint["cms"] = ", ".join(cms[:3])

    frameworks = _match(FRAMEWORK_SIGNATURES, haystack)
    if frameworks:
        fingerprint["frameworks"] = ", ".join(frameworks[:4])

    libraries = []
    for regex, label in ((_JQUERY, "jQuery"), (_BOOTSTRAP, "Bootstrap")):
        match = regex.search(haystack)
        if match:
            libraries.append(f"{label} {match.group(1)}")
    if libraries:
        fingerprint["bibliotheques"] = ", ".join(libraries)

    analytics = _match(ANALYTICS_SIGNATURES, haystack)
    if analytics:
        fingerprint["analytique"] = ", ".join(analytics[:4])

    languages = _match(LANG_SIGNATURES, haystack)
    if languages:
        fingerprint["langage"] = ", ".join(languages[:2])

    if _VIEWPORT.search(html):
        fingerprint["responsive"] = "oui"

    return fingerprint
