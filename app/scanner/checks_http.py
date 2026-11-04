"""Contrôles HTTP : transport, en-têtes de sécurité, cookies, CORS, méthodes."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..models import Finding, Severity
from .fetcher import Fetcher, HttpResponse

CATEGORY = "Configuration HTTP"

SECURITY_HEADERS = {
    "strict-transport-security": (
        Severity.HIGH,
        "HSTS absent",
        "Sans HSTS, un attaquant sur le réseau peut forcer une première connexion en HTTP "
        "clair et intercepter les cookies de session (SSL-stripping).",
        "Ajoutez `Strict-Transport-Security: max-age=31536000; includeSubDomains` sur toutes "
        "les réponses HTTPS.",
        "https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Strict-Transport-Security",
    ),
    "content-security-policy": (
        Severity.HIGH,
        "Content-Security-Policy absent",
        "Aucune CSP : le navigateur exécutera n'importe quel script injecté. C'est le vecteur "
        "principal des failles XSS.",
        "Déployez une CSP restrictive (ex. `default-src 'self'; object-src 'none'; "
        "base-uri 'self'`), puis affinez-la en report-only avant de l'appliquer.",
        "https://developer.mozilla.org/fr/docs/Web/HTTP/CSP",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "X-Content-Type-Options absent",
        "Sans `nosniff`, un navigateur peut interpréter un fichier texte comme du HTML ou du "
        "JavaScript (MIME sniffing).",
        "Ajoutez `X-Content-Type-Options: nosniff`.",
        "https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/X-Content-Type-Options",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Referrer-Policy absent",
        "Les URL complètes (parfois avec des jetons) peuvent fuiter vers des sites tiers via "
        "l'en-tête Referer.",
        "Ajoutez `Referrer-Policy: strict-origin-when-cross-origin` (ou `no-referrer`).",
        "https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Referrer-Policy",
    ),
    "permissions-policy": (
        Severity.INFO,
        "Permissions-Policy absent",
        "Les API puissantes (caméra, micro, géolocalisation) ne sont pas restreintes pour les "
        "iframes et ressources tierces.",
        "Ajoutez par exemple `Permissions-Policy: camera=(), microphone=(), geolocation=()`.",
        "https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Permissions-Policy",
    ),
    "cross-origin-opener-policy": (
        Severity.INFO,
        "Cross-Origin-Opener-Policy absent",
        "L'isolation cross-origin est incomplète, ce qui laisse la porte ouverte à certaines "
        "attaques de type XS-Leak.",
        "Ajoutez `Cross-Origin-Opener-Policy: same-origin`.",
        "https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
    ),
}


def check_transport(target_url: str, response: HttpResponse, http_response: HttpResponse | None) -> list[Finding]:
    """HTTPS obligatoire, redirections et chaîne de redirection."""
    findings: list[Finding] = []
    scheme = urlsplit(target_url).scheme

    if scheme == "http":
        findings.append(
            Finding(
                id="transport.no-https",
                title="Site servi en HTTP clair",
                severity=Severity.HIGH,
                category="Transport",
                description="Le trafic circule sans chiffrement : identifiants, cookies et "
                "contenus peuvent être lus ou modifiés par un tiers sur le réseau.",
                evidence=f"URL analysée : {target_url}",
                remediation="Servez systématiquement en HTTPS et redirigez tout le HTTP (301) "
                "vers l'équivalent HTTPS.",
                reference="https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
            )
        )
    elif http_response is not None:
        final = http_response.url or ""
        if http_response.error:
            pass
        elif urlsplit(final).scheme == "http":
            findings.append(
                Finding(
                    id="transport.no-redirect",
                    title="Le HTTP n'est pas redirigé vers HTTPS",
                    severity=Severity.HIGH,
                    category="Transport",
                    description="La version HTTP du site répond du contenu au lieu de rediriger "
                    "vers HTTPS. Un attaquant peut exploiter cette version en clair.",
                    evidence=f"http://{urlsplit(target_url).netloc} → {http_response.status} sans redirection",
                    remediation="Configurez une redirection 301 permanente de http:// vers https:// "
                    "pour tout le domaine.",
                    reference="https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                )
            )

    if response.history:
        chain = " → ".join([f"{url} [{status}]" for url, status in response.history])
        findings.append(
            Finding(
                id="transport.redirect-chain",
                title="Chaîne de redirection",
                severity=Severity.INFO,
                category="Transport",
                description="Redirections suivies avant d'atteindre la page finale.",
                evidence=f"{chain} → {response.url} [{response.status}]",
            )
        )
    return findings


def check_headers(response: HttpResponse, is_https: bool) -> list[Finding]:
    findings: list[Finding] = []
    if response.error:
        return findings

    present = {k.lower(): v for k, v in response.headers.items()}

    for name, (severity, title, description, remediation, reference) in SECURITY_HEADERS.items():
        if name == "strict-transport-security" and not is_https:
            continue
        value = present.get(name, "").strip()
        if not value:
            findings.append(
                Finding(
                    id=f"headers.missing.{name}",
                    title=title,
                    severity=severity,
                    category=CATEGORY,
                    description=description,
                    evidence=f"En-tête `{name}` absent de la réponse {response.status}.",
                    remediation=remediation,
                    reference=reference,
                )
            )

    hsts = present.get("strict-transport-security", "")
    if hsts:
        match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        max_age = int(match.group(1)) if match else 0
        if max_age and max_age < 15_552_000:
            findings.append(
                Finding(
                    id="headers.hsts-short",
                    title="HSTS : durée trop courte",
                    severity=Severity.LOW,
                    category=CATEGORY,
                    description="Une durée inférieure à 180 jours réduit l'efficacité de HSTS.",
                    evidence=f"Strict-Transport-Security: {hsts}",
                    remediation="Passez `max-age` à 31536000 (1 an) et ajoutez `includeSubDomains`.",
                    reference="https://hstspreload.org/",
                )
            )
        if max_age == 0:
            findings.append(
                Finding(
                    id="headers.hsts-disabled",
                    title="HSTS désactivé (max-age=0)",
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    description="`max-age=0` demande aux navigateurs d'oublier HSTS : la protection "
                    "contre le SSL-stripping est annulée.",
                    evidence=f"Strict-Transport-Security: {hsts}",
                    remediation="Supprimez `max-age=0` et publiez une politique HSTS durable.",
                    reference="https://hstspreload.org/",
                )
            )

    csp = present.get("content-security-policy", "")
    if csp:
        low = csp.lower()
        if "unsafe-inline" in low or "unsafe-eval" in low:
            findings.append(
                Finding(
                    id="headers.csp-unsafe",
                    title="CSP permissive : unsafe-inline / unsafe-eval",
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    description="Ces directives autorisent l'injection de scripts inline, ce qui "
                    "annule une grande partie de la protection XSS.",
                    evidence=_truncate(csp, 320),
                    remediation="Supprimez `unsafe-inline`/`unsafe-eval` et utilisez des nonces ou "
                    "des hashes pour les scripts légitimes.",
                    reference="https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                )
            )
        if "*" in low and "default-src" in low:
            findings.append(
                Finding(
                    id="headers.csp-wildcard",
                    title="CSP avec joker `*`",
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    description="Un joker autorise le chargement de ressources depuis n'importe "
                    "quel domaine, y compris ceux contrôlés par un attaquant.",
                    evidence=_truncate(csp, 320),
                    remediation="Remplacez `*` par la liste explicite des sources de confiance.",
                    reference="https://developer.mozilla.org/fr/docs/Web/HTTP/CSP",
                )
            )
        if "default-src" not in low and "script-src" not in low:
            findings.append(
                Finding(
                    id="headers.csp-incomplete",
                    title="CSP sans directive de script",
                    severity=Severity.LOW,
                    category=CATEGORY,
                    description="Sans `default-src` ni `script-src`, la CSP ne restreint pas les "
                    "scripts et n'apporte donc pas de protection XSS.",
                    evidence=_truncate(csp, 320),
                    remediation="Définissez au minimum `default-src 'self'; script-src 'self'`.",
                    reference="https://developer.mozilla.org/fr/docs/Web/HTTP/CSP",
                )
            )

    if not present.get("x-frame-options") and "frame-ancestors" not in present.get(
        "content-security-policy", ""
    ).lower():
        findings.append(
            Finding(
                id="headers.clickjacking",
                title="Protection contre le clickjacking absente",
                severity=Severity.MEDIUM,
                category=CATEGORY,
                description="Ni `X-Frame-Options` ni `frame-ancestors` : la page peut être "
                "intégrée dans une iframe piégée et servir de clickjacking.",
                evidence="X-Frame-Options absent, CSP sans `frame-ancestors`.",
                remediation="Ajoutez `X-Frame-Options: DENY` (ou SAMEORIGIN) et "
                "`frame-ancestors 'none'` dans la CSP.",
                reference="https://owasp.org/www-community/attacks/Clickjacking",
            )
        )

    leaked = []
    for header in ("server", "x-powered-by", "x-aspnet-version", "x-generator", "x-drupal-cache", "x-runtime"):
        if header in present:
            leaked.append(f"{header}: {present[header]}")
    if leaked:
        has_version = any(re.search(r"\d+\.\d+", value) for value in leaked)
        findings.append(
            Finding(
                id="headers.version-disclosure",
                title="Divulgation de technologie / version",
                severity=Severity.LOW if has_version else Severity.INFO,
                category=CATEGORY,
                description="Le serveur expose sa technologie et parfois sa version exacte, ce qui "
                "facilite le ciblage de CVE connues.",
                evidence="\n".join(leaked[:6]),
                remediation="Masquez ces en-têtes (`ServerTokens Prod`, `expose_php = Off`, "
                "suppression de `X-Powered-By`) et évitez les numéros de version.",
                reference="https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
            )
        )
    return findings


def check_cookies(response: HttpResponse) -> list[Finding]:
    findings: list[Finding] = []
    raw_cookies = response.headers.get_list("set-cookie") if response.headers else []
    if not raw_cookies:
        return findings

    issues: list[str] = []
    for raw in raw_cookies:
        name = raw.split("=", 1)[0].strip() or "?"
        lower = raw.lower()
        missing = []
        if "secure" not in lower:
            missing.append("Secure")
        if "httponly" not in lower:
            missing.append("HttpOnly")
        if "samesite" not in lower:
            missing.append("SameSite")
        if "samesite=none" in lower and "secure" not in lower:
            missing.append("Secure (obligatoire avec SameSite=None)")
        if missing:
            issues.append(f"{name} → manque {', '.join(missing)}")

    if issues:
        findings.append(
            Finding(
                id="cookies.flags",
                title="Cookies sans attributs de sécurité",
                severity=Severity.MEDIUM,
                category="Cookies & session",
                description="Sans `Secure`, `HttpOnly` et `SameSite`, un cookie de session peut "
                "être intercepté en clair, lu par un script (XSS) ou envoyé en cross-site (CSRF).",
                evidence="\n".join(issues[:12]),
                remediation="Émettez les cookies avec `Secure; HttpOnly; SameSite=Lax` (ou "
                "`Strict`) et un préfixe `__Host-` pour les cookies critiques.",
                reference="https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
            )
        )
    return findings


async def check_cors(fetcher: Fetcher, url: str) -> list[Finding]:
    findings: list[Finding] = []
    probe_origin = "https://vulnlens-probe.example"
    response = await fetcher.get(url, headers={"Origin": probe_origin}, max_bytes=4096)
    if response.error:
        return findings

    allow_origin = response.header("access-control-allow-origin").strip()
    allow_credentials = response.header("access-control-allow-credentials").strip().lower()

    if allow_origin in {"*", probe_origin}:
        if allow_origin == probe_origin and allow_credentials == "true":
            findings.append(
                Finding(
                    id="cors.reflected-credentials",
                    title="CORS : origine arbitraire reflétée avec credentials",
                    severity=Severity.CRITICAL,
                    category="CORS",
                    description="Le serveur renvoie l'origine de l'attaquant et autorise les "
                    "cookies. N'importe quel site peut alors lire des données authentifiées "
                    "de la victime.",
                    evidence=f"Origin: {probe_origin}\nAccess-Control-Allow-Origin: {allow_origin}\n"
                    f"Access-Control-Allow-Credentials: {allow_credentials}",
                    remediation="Validez l'origine contre une liste blanche stricte et n'utilisez "
                    "jamais `Access-Control-Allow-Credentials: true` avec une origine reflétée.",
                    reference="https://portswigger.net/web-security/cors",
                )
            )
        elif allow_origin == probe_origin:
            findings.append(
                Finding(
                    id="cors.reflected",
                    title="CORS : origine arbitraire acceptée",
                    severity=Severity.MEDIUM,
                    category="CORS",
                    description="Toute origine est acceptée. Si des données sensibles sont "
                    "exposées par cet endpoint, elles sont lisibles par n'importe quel site.",
                    evidence=f"Origin: {probe_origin}\nAccess-Control-Allow-Origin: {allow_origin}",
                    remediation="Restreignez `Access-Control-Allow-Origin` aux domaines de confiance.",
                    reference="https://portswigger.net/web-security/cors",
                )
            )
        elif allow_credentials == "true":
            findings.append(
                Finding(
                    id="cors.wildcard-credentials",
                    title="CORS : joker avec credentials",
                    severity=Severity.HIGH,
                    category="CORS",
                    description="`Access-Control-Allow-Origin: *` combiné aux credentials est "
                    "refusé par les navigateurs, mais révèle une configuration dangereuse.",
                    evidence="Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                    remediation="Retirez les credentials ou listez explicitement les origines.",
                    reference="https://portswigger.net/web-security/cors",
                )
            )
        else:
            findings.append(
                Finding(
                    id="cors.wildcard",
                    title="CORS ouvert à toutes les origines",
                    severity=Severity.LOW,
                    category="CORS",
                    description="`Access-Control-Allow-Origin: *` autorise la lecture publique de "
                    "la ressource depuis n'importe quel site.",
                    evidence=f"Access-Control-Allow-Origin: {allow_origin}",
                    remediation="Si la ressource n'est pas publique, restreignez les origines.",
                    reference="https://developer.mozilla.org/fr/docs/Web/HTTP/CORS",
                )
            )
    return findings


async def check_methods(fetcher: Fetcher, url: str) -> list[Finding]:
    findings: list[Finding] = []
    options = await fetcher.request("OPTIONS", url, max_bytes=1024)
    allow = options.header("allow") or options.header("access-control-allow-methods")
    risky = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH") if m in allow.upper()]

    if risky:
        findings.append(
            Finding(
                id="methods.enabled",
                title="Méthodes HTTP sensibles annoncées",
                severity=Severity.LOW,
                category="Configuration HTTP",
                description="Le serveur annonce des méthodes qui permettent de modifier ou "
                "tracer des ressources. À vérifier : sont-elles réellement protégées ?",
                evidence=f"Allow: {allow}",
                remediation="Désactivez les méthodes inutilisées au niveau du serveur ou du "
                "reverse-proxy.",
                reference="https://owasp.org/www-project-web-security-testing-guide/",
            )
        )

    trace = await fetcher.request("TRACE", url, max_bytes=2048)
    if trace.status == 200 and "TRACE" in trace.text[:2000].upper():
        findings.append(
            Finding(
                id="methods.trace",
                title="Méthode TRACE activée",
                severity=Severity.MEDIUM,
                category="Configuration HTTP",
                description="TRACE renvoie la requête telle quelle et peut faciliter le vol de "
                "cookies via Cross-Site Tracing (XST).",
                evidence=f"TRACE {url} → {trace.status}",
                remediation="Désactivez TRACE (`TraceEnable off` sur Apache).",
                reference="https://owasp.org/www-community/attacks/Cross_Site_Tracing",
            )
        )
    return findings


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"
