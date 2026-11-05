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
    "cross-origin-embedder-policy": (
        Severity.INFO,
        "Cross-Origin-Embedder-Policy absent",
        "Sans COEP, les ressources cross-origin ne sont pas isolées : certaines attaques "
        "par canal auxiliaire (Spectre) restent envisageables.",
        "Ajoutez `Cross-Origin-Embedder-Policy: require-corp` si vos ressources le permettent.",
        "https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy",
    ),
    "cross-origin-resource-policy": (
        Severity.INFO,
        "Cross-Origin-Resource-Policy absent",
        "Le navigateur ne sait pas si cette ressource peut être chargée par un autre site.",
        "Ajoutez `Cross-Origin-Resource-Policy: same-origin` sur les ressources sensibles.",
        "https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
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
        findings.extend(analyse_csp(csp, is_https))

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

    # En-têtes de débogage : présents quand le profiler de développement tourne en production.
    debug_headers = [
        f"{name}: {present[name]}"
        for name in ("x-debug-token", "x-debug-token-link", "x-symfony-cache", "x-php-debug")
        if present.get(name)
    ]
    if debug_headers:
        findings.append(
            Finding(
                id="headers.debug-token",
                title="En-têtes de débogage exposés",
                severity=Severity.HIGH,
                category=CATEGORY,
                description=(
                    "Le serveur annonce un jeton de profiler : l'interface de débogage du "
                    "framework est active. Elle expose les requêtes SQL, les variables "
                    "d'environnement, les sessions et les e-mails envoyés — une fuite interne "
                    "complète, sans authentification."
                ),
                evidence="\n".join(debug_headers[:4]),
                remediation=(
                    "Désactivez le mode debug et le profiler en production (`APP_ENV=prod`, "
                    "`APP_DEBUG=false`), puis redémarrez l'application."
                ),
                reference="https://symfony.com/doc/current/profiler.html",
            )
        )
    return findings


def check_cookies(response: HttpResponse) -> list[Finding]:
    findings: list[Finding] = []
    raw_cookies = response.headers.get_list("set-cookie") if response.headers else []
    if not raw_cookies:
        return findings

    issues: list[str] = []
    prefix_issues: list[str] = []
    for raw in raw_cookies:
        chunks = raw.split(";")
        name = chunks[0].split("=", 1)[0].strip() or "?"
        # Les attributs se lisent après le premier « ; » : le nom du cookie ne doit
        # surtout pas être confondu avec l'attribut Secure (ex. ``__Secure-token``).
        attributes = ";".join(chunks[1:]).strip().lower()

        missing = []
        if "secure" not in attributes:
            missing.append("Secure")
        if "httponly" not in attributes:
            missing.append("HttpOnly")
        if "samesite" not in attributes:
            missing.append("SameSite")
        if "samesite=none" in attributes and "secure" not in attributes:
            missing.append("Secure (obligatoire avec SameSite=None)")
        if missing:
            issues.append(f"{name} → manque {', '.join(missing)}")

        # Préfixes normalisés : __Host- impose Secure + Path=/ + aucun Domain ;
        # __Secure- impose Secure.
        if name.startswith("__Host-"):
            if (
                "secure" not in attributes
                or "domain=" in attributes
                or not re.search(r"path\s*=\s*/\s*(;|$)", attributes)
            ):
                prefix_issues.append(
                    f"{name} → préfixe __Host- violé (Secure, Path=/, sans Domain)"
                )
        elif name.startswith("__Secure-") and "secure" not in attributes:
            prefix_issues.append(f"{name} → préfixe __Secure- sans attribut Secure")

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

    if prefix_issues:
        findings.append(
            Finding(
                id="cookies.prefix-violation",
                title="Préfixe de cookie de sécurité contourné",
                severity=Severity.MEDIUM,
                category="Cookies & session",
                description="Les préfixes `__Host-` et `__Secure-` sont des garanties imposées par "
                "le navigateur : les utiliser sans respecter leurs contraintes casse la protection "
                "attendue, voire fait rejeter le cookie.",
                evidence="\n".join(prefix_issues[:8]),
                remediation="Pour `__Host-` : `Secure; Path=/;` et surtout aucun attribut `Domain`. "
                "Pour `__Secure-` : `Secure` obligatoire.",
                reference="https://developer.mozilla.org/fr/docs/Web/HTTP/Cookies#cookie_prefixes",
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


def parse_csp(csp: str) -> dict[str, list[str]]:
    """Découpe une CSP en directives normalisées."""
    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        directives[tokens[0].lower()] = [token.lower() for token in tokens[1:]]
    return directives


def analyse_csp(csp: str, is_https: bool) -> list[Finding]:
    """Analyse directive par directive : c'est là que se joue la vraie protection XSS."""
    findings: list[Finding] = []
    directives = parse_csp(csp)
    evidence = _truncate(csp, 320)
    reference = "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"

    script_sources = directives.get("script-src") or directives.get("default-src") or []

    if not script_sources:
        findings.append(
            Finding(
                id="headers.csp-incomplete",
                title="CSP sans directive de script",
                severity=Severity.LOW,
                category=CATEGORY,
                description="Sans `default-src` ni `script-src`, la CSP ne restreint pas les "
                "scripts et n'apporte donc aucune protection XSS.",
                evidence=evidence,
                remediation="Définissez au minimum `default-src 'self'; script-src 'self'`.",
                reference=reference,
            )
        )
    else:
        if {"'unsafe-inline'", "'unsafe-eval'"} & set(script_sources):
            findings.append(
                Finding(
                    id="headers.csp-unsafe",
                    title="CSP permissive : unsafe-inline / unsafe-eval",
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    description="Ces mots-clés autorisent l'exécution de scripts injectés : la "
                    "protection XSS de la CSP est largement annulée.",
                    evidence=evidence,
                    remediation="Retirez `unsafe-inline`/`unsafe-eval` et utilisez des nonces "
                    "(`script-src 'nonce-…'`) ou des hashes pour les scripts légitimes.",
                    reference=reference,
                )
            )
        if "*" in script_sources:
            findings.append(
                Finding(
                    id="headers.csp-wildcard",
                    title="CSP avec joker `*` sur les scripts",
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    description="Un joker autorise le chargement de scripts depuis n'importe quel "
                    "domaine, y compris ceux qu'un attaquant peut contrôler.",
                    evidence=evidence,
                    remediation="Remplacez `*` par la liste explicite des sources de confiance.",
                    reference=reference,
                )
            )
        if any(source.startswith("http:") for source in script_sources):
            findings.append(
                Finding(
                    id="headers.csp-http-scheme",
                    title="CSP autorisant des scripts en HTTP",
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    description="Le schéma `http:` permet à un attaquant sur le réseau de remplacer "
                    "le script par le sien.",
                    evidence=evidence,
                    remediation="Utilisez uniquement `https:` et `'self'` dans `script-src`.",
                    reference=reference,
                )
            )
        if any(source.startswith("data:") for source in script_sources):
            findings.append(
                Finding(
                    id="headers.csp-data-scripts",
                    title="CSP autorisant les scripts `data:`",
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    description="`data:` dans `script-src` permet d'exécuter du code encodé "
                    "directement dans la page, ce qui contourne la politique.",
                    evidence=evidence,
                    remediation="Retirez `data:` de `script-src`.",
                    reference=reference,
                )
            )

    if "object-src" not in directives and "'none'" not in directives.get("default-src", []):
        findings.append(
            Finding(
                id="headers.csp-object-src",
                title="CSP sans `object-src 'none'`",
                severity=Severity.LOW,
                category=CATEGORY,
                description="Sans cette directive, des plugins historiques (Flash, Java) peuvent "
                "être chargés et servir de vecteur d'exécution.",
                evidence=evidence,
                remediation="Ajoutez `object-src 'none'` à la politique.",
                reference=reference,
            )
        )

    if "base-uri" not in directives:
        findings.append(
            Finding(
                id="headers.csp-base-uri",
                title="CSP sans `base-uri`",
                severity=Severity.LOW,
                category=CATEGORY,
                description="Une balise `<base>` injectée peut détourner toutes les URL relatives "
                "de la page vers un domaine attaquant.",
                evidence=evidence,
                remediation="Ajoutez `base-uri 'self'` (ou `'none'`).",
                reference=reference,
            )
        )

    if "frame-ancestors" not in directives:
        findings.append(
            Finding(
                id="headers.csp-frame-ancestors",
                title="CSP sans `frame-ancestors`",
                severity=Severity.INFO,
                category=CATEGORY,
                description="`frame-ancestors` est la seule protection anti-clickjacking qui "
                "s'applique aussi aux iframes imbriquées.",
                evidence=evidence,
                remediation="Ajoutez `frame-ancestors 'none'` (ou `'self'`).",
                reference="https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors",
            )
        )

    if is_https and "upgrade-insecure-requests" not in directives:
        findings.append(
            Finding(
                id="headers.csp-upgrade",
                title="CSP sans `upgrade-insecure-requests`",
                severity=Severity.INFO,
                category=CATEGORY,
                description="Cette directive réécrit automatiquement les ressources HTTP en HTTPS "
                "et évite les blocages de contenu mixte.",
                evidence=evidence,
                remediation="Ajoutez `upgrade-insecure-requests`.",
                reference="https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Content-Security-Policy/upgrade-insecure-requests",
            )
        )

    if "report-uri" not in directives and "report-to" not in directives:
        findings.append(
            Finding(
                id="headers.csp-reporting",
                title="CSP sans collecte de rapports",
                severity=Severity.INFO,
                category=CATEGORY,
                description="Sans `report-uri`/`report-to`, les tentatives d'injection bloquées "
                "passent inaperçues.",
                evidence=evidence,
                remediation="Ajoutez `report-to` vers un collecteur (ou `report-uri` en secours).",
                reference="https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Content-Security-Policy/report-to",
            )
        )

    return findings


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"
