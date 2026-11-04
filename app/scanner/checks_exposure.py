"""Détection de fichiers exposés, listages de répertoires et fuites d'information."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urljoin, urlparse

from ..models import Finding, Severity
from .fetcher import Fetcher, HttpResponse

CATEGORY = "Exposition de fichiers"


def _text(resp: HttpResponse, limit: int = 4000) -> str:
    return resp.body[:limit].decode("utf-8", errors="replace")


def _is_html(resp: HttpResponse) -> bool:
    ctype = resp.header("content-type").lower()
    return "text/html" in ctype or _text(resp, 400).lstrip().lower().startswith("<!doctype html")


def _body_startswith(*prefixes: bytes) -> Callable[[HttpResponse], str | None]:
    def validator(resp: HttpResponse) -> str | None:
        head = resp.body[:64]
        return f"Contenu commence par {head[:32]!r}" if head.startswith(prefixes) else None

    return validator


def _regex(pattern: str, label: str, flags: int = 0) -> Callable[[HttpResponse], str | None]:
    compiled = re.compile(pattern, flags)

    def validator(resp: HttpResponse) -> str | None:
        match = compiled.search(_text(resp))
        return f"{label} : {match.group(0)[:120]!r}" if match else None

    return validator


def _contains(*needles: str, ignore_html: bool = False) -> Callable[[HttpResponse], str | None]:
    def validator(resp: HttpResponse) -> str | None:
        if resp.status != 200:
            return None
        if ignore_html and _is_html(resp):
            return None
        body = _text(resp, 20000)
        for needle in needles:
            if needle.lower() in body.lower():
                return f"Marqueur détecté : {needle!r}"
        return None

    return validator


@dataclass
class Probe:
    path: str
    title: str
    severity: Severity
    description: str
    remediation: str
    reference: str
    validate: Callable[[HttpResponse], str | None]
    id: str


PROBES: list[Probe] = [
    Probe(
        "/.git/HEAD",
        "Dépôt Git exposé",
        Severity.CRITICAL,
        "Le dossier `.git` est accessible publiquement : tout le code source, l'historique et "
        "parfois des secrets (mots de passe, clés API) peuvent être reconstitués.",
        "Bloquez l'accès à `.git/` au niveau du serveur ou du reverse-proxy, puis révoquez tous "
        "les secrets présents dans l'historique.",
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",
        _body_startswith(b"ref:", b"DIRC"),
        "exposure.git",
    ),
    Probe(
        "/.git/config",
        "Configuration Git exposée",
        Severity.CRITICAL,
        "Le fichier de configuration Git révèle les remotes (souvent internes) et la structure du "
        "projet.",
        "Interdisez l'accès à `.git/` et révoquez les identifiants présents dans les URLs de remote.",
        "https://owasp.org/www-project-web-security-testing-guide/",
        _regex(r"\[core\]|\[remote", "Section de configuration"),
        "exposure.git-config",
    ),
    Probe(
        "/.env",
        "Fichier .env exposé",
        Severity.CRITICAL,
        "Le fichier d'environnement contient les secrets de l'application (base de données, clés "
        "d'API, jetons).",
        "Supprimez le fichier de la racine web, bloquez-le et faites tourner tous les secrets exposés.",
        "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
        _regex(r"(?m)^\s*[A-Z0-9_]{3,}\s*=", "Variable d'environnement"),
        "exposure.dotenv",
    ),
    Probe(
        "/.env.local",
        "Fichier .env.local exposé",
        Severity.CRITICAL,
        "Variante du fichier d'environnement, généralement chargée en production localement.",
        "Bloquez tous les fichiers `.env*` et révoquez les secrets.",
        "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
        _regex(r"(?m)^\s*[A-Z0-9_]{3,}\s*=", "Variable d'environnement"),
        "exposure.dotenv-local",
    ),
    Probe(
        "/.htaccess",
        "Fichier .htaccess lisible",
        Severity.MEDIUM,
        "Les règles de réécriture et de protection du serveur sont visibles, ce qui facilite la "
        "recherche de contournements.",
        "Désactivez la lecture directe des fichiers de configuration Apache.",
        "https://httpd.apache.org/docs/2.4/howto/htaccess.html",
        _contains("RewriteEngine", "Order ", "AuthType", ignore_html=True),
        "exposure.htaccess",
    ),
    Probe(
        "/web.config",
        "web.config exposé",
        Severity.HIGH,
        "Le fichier de configuration IIS/.NET peut contenir des chaînes de connexion et des clés.",
        "Bloquez l'accès aux fichiers de configuration et déplacez les secrets hors du répertoire web.",
        "https://learn.microsoft.com/fr-fr/aspnet/core/host-and-deploy/iis/",
        _contains("<configuration", "<connectionStrings", ignore_html=True),
        "exposure.web-config",
    ),
    Probe(
        "/Dockerfile",
        "Dockerfile exposé",
        Severity.MEDIUM,
        "Le Dockerfile révèle la stack, les dépendances et parfois des identifiants de build.",
        "Excluez les fichiers de build du déploiement public.",
        "https://owasp.org/www-project-web-security-testing-guide/",
        _regex(r"(?m)^\s*FROM\s+\S+", "Instruction Dockerfile"),
        "exposure.dockerfile",
    ),
    Probe(
        "/docker-compose.yml",
        "docker-compose.yml exposé",
        Severity.HIGH,
        "Le fichier peut contenir des mots de passe de bases, des ports internes et la topologie "
        "de l'infrastructure.",
        "Retirez ce fichier du répertoire servi et faites tourner les secrets.",
        "https://owasp.org/www-project-web-security-testing-guide/",
        _regex(r"^\s*services\s*:|^\s*image\s*:\s*\S+", "Clé compose", re.M),
        "exposure.compose",
    ),
    Probe(
        "/phpinfo.php",
        "Page phpinfo() exposée",
        Severity.HIGH,
        "phpinfo divulgue la configuration PHP, les chemins serveur, les modules et les variables "
        "d'environnement.",
        "Supprimez le fichier et désactivez phpinfo en production.",
        "https://www.php.net/manual/fr/function.phpinfo.php",
        _regex(r"PHP Version\s*[0-9.]+|phpinfo\(\)", "Version PHP"),
        "exposure.phpinfo",
    ),
    Probe(
        "/server-status",
        "Statut Apache exposé",
        Severity.HIGH,
        "Le module mod_status divulgue les URL en cours de traitement (parfois avec des jetons) et "
        "les adresses IP clientes.",
        "Restreignez `/server-status` aux adresses d'administration.",
        "https://httpd.apache.org/docs/2.4/mod/mod_status.html",
        _contains("Apache Server Status", "Server Status"),
        "exposure.server-status",
    ),
    Probe(
        "/actuator/env",
        "Actuator Spring Boot exposé",
        Severity.CRITICAL,
        "L'endpoint `env` expose les propriétés de l'application, souvent avec des secrets et des "
        "identifiants de base de données.",
        "Restreignez les endpoints Actuator (`management.endpoints.web.exposure.include`) et "
        "protégez-les par authentification.",
        "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html",
        _regex(r'"propertySources"|"activeProfiles"', "Charge utile Actuator", re.I),
        "exposure.actuator",
    ),
    Probe(
        "/actuator/health",
        "Endpoint de santé Spring Boot exposé",
        Severity.LOW,
        "L'endpoint de santé confirme la stack et peut divulguer l'état des dépendances.",
        "Limitez l'exposition des endpoints Actuator.",
        "https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html",
        _regex(r'"status"\s*:\s*"(UP|DOWN)"', "Statut applicatif", re.I),
        "exposure.actuator-health",
    ),
    Probe(
        "/.DS_Store",
        "Fichier .DS_Store exposé",
        Severity.LOW,
        "Ce fichier macOS liste l'arborescence du répertoire et aide à découvrir des fichiers "
        "non référencés.",
        "Supprimez les fichiers `.DS_Store` du déploiement et ajoutez-les à `.gitignore`.",
        "https://owasp.org/www-project-web-security-testing-guide/",
        _body_startswith(b"\x00\x00\x00\x01Bud1"),
        "exposure.ds-store",
    ),
    Probe(
        "/backup.zip",
        "Archive de sauvegarde téléchargeable",
        Severity.HIGH,
        "Une archive de sauvegarde accessible permet de récupérer le code source ou la base de "
        "données complète.",
        "Supprimez les archives du répertoire public et stockez les sauvegardes hors du serveur web.",
        "https://owasp.org/www-project-web-security-testing-guide/",
        lambda r: f"HTTP {r.status}, {r.header('content-type') or 'type inconnu'}"
        if r.status == 200 and "html" not in r.header("content-type").lower()
        else None,
        "exposure.backup-zip",
    ),
    Probe(
        "/backup.sql",
        "Dump SQL téléchargeable",
        Severity.CRITICAL,
        "Un export de base de données accessible expose l'intégralité des données utilisateurs.",
        "Supprimez le fichier, bloquez les extensions `.sql`, et faites une analyse d'impact RGPD.",
        "https://owasp.org/www-project-web-security-testing-guide/",
        _regex(r"CREATE TABLE|INSERT INTO|-- MySQL dump", "Instruction SQL", re.I),
        "exposure.sql-dump",
    ),
    Probe(
        "/composer.json",
        "Manifeste Composer exposé",
        Severity.LOW,
        "Les dépendances PHP et leurs contraintes de version sont visibles, ce qui oriente la "
        "recherche de CVE.",
        "Empêchez l'accès aux fichiers de dépendances en production.",
        "https://getcomposer.org/doc/",
        _regex(r'"require"\s*:', "Section require"),
        "exposure.composer",
    ),
    Probe(
        "/package.json",
        "Manifeste npm exposé",
        Severity.LOW,
        "Les dépendances JavaScript et versions sont visibles.",
        "Empêchez l'accès à `package.json` en production.",
        "https://docs.npmjs.com/cli/configuring-npm/package-json",
        _regex(r'"dependencies"\s*:', "Section dependencies"),
        "exposure.package-json",
    ),
    Probe(
        "/swagger-ui.html",
        "Interface Swagger/OpenAPI exposée",
        Severity.MEDIUM,
        "La documentation interactive de l'API révèle tous les endpoints, y compris ceux qui ne "
        "devraient pas être publics.",
        "Protégez la documentation par authentification ou désactivez-la en production.",
        "https://swagger.io/tools/swagger-ui/",
        _contains("swagger-ui", "Swagger UI", ignore_html=False),
        "exposure.swagger",
    ),
    Probe(
        "/graphql",
        "Endpoint GraphQL détecté",
        Severity.INFO,
        "Un endpoint GraphQL est exposé. Vérifiez que l'introspection est désactivée et que les "
        "requêtes sont limitées en profondeur.",
        "Désactivez l'introspection en production, ajoutez une limitation de profondeur et de débit.",
        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
        _regex(r'"errors"\s*:|"data"\s*:\s*\{|GraphQL', "Réponse GraphQL", re.I),
        "exposure.graphql",
    ),
    Probe(
        "/.well-known/security.txt",
        "security.txt absent",
        Severity.INFO,
        "Aucun canal de signalement de vulnérabilités n'est publié : les chercheurs ne savent pas "
        "à qui s'adresser.",
        "Publiez `/.well-known/security.txt` avec un contact et une politique de divulgation.",
        "https://www.rfc-editor.org/rfc/rfc9116",
        lambda r: None,
        "exposure.security-txt",
    ),
]


async def check_exposed_files(fetcher: Fetcher, base_url: str) -> tuple[list[Finding], dict[str, str]]:
    findings: list[Finding] = []
    meta: dict[str, str] = {}

    async def probe_one(probe: Probe):
        url = urljoin(base_url, probe.path.lstrip("/"))
        resp = await fetcher.get(url, max_bytes=48_000, timeout=min(8.0, 20))
        return probe, resp

    results = await fetcher.parallel([probe_one(p) for p in PROBES])

    for probe, resp in results:
        if resp.error:
            continue
        if probe.id == "exposure.security-txt":
            if resp.status == 200 and "contact:" in resp.text.lower():
                meta["security.txt"] = "présent"
            else:
                findings.append(
                    Finding(
                        id=probe.id,
                        title=probe.title,
                        severity=probe.severity,
                        category=CATEGORY,
                        description=probe.description,
                        evidence="GET /.well-known/security.txt → 404 / contenu sans contact",
                        remediation=probe.remediation,
                        reference=probe.reference,
                    )
                )
            continue

        evidence = probe.validate(resp)
        if evidence:
            findings.append(
                Finding(
                    id=probe.id,
                    title=probe.title,
                    severity=probe.severity,
                    category=CATEGORY,
                    description=probe.description,
                    evidence=f"GET {probe.path} → HTTP {resp.status}\n{evidence}",
                    remediation=probe.remediation,
                    reference=probe.reference,
                )
            )
    return findings, meta


async def check_robots(fetcher: Fetcher, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    resp = await fetcher.get(urljoin(base_url, "robots.txt"), max_bytes=64_000)
    if resp.error or resp.status != 200:
        return findings

    text = resp.text
    disallow = [
        line.split(":", 1)[1].strip()
        for line in text.splitlines()
        if line.lower().lstrip().startswith("disallow:")
    ]
    disallow = [d for d in disallow if d and d != "/"]
    sensitive = [
        d
        for d in disallow
        if re.search(r"admin|backup|private|config|db|secret|staging|dev|test|api|internal|\.env", d, re.I)
    ]
    if sensitive:
        findings.append(
            Finding(
                id="robots.disclosure",
                title="robots.txt révèle des chemins sensibles",
                severity=Severity.LOW,
                category="Reconnaissance",
                description="Les entrées `Disallow` indiquent précisément les zones que "
                "l'administrateur souhaite cacher. Elles sont publiques et servent de feuille de "
                "route aux attaquants.",
                evidence="\n".join(sensitive[:10]),
                remediation="N'utilisez pas robots.txt comme contrôle d'accès. Protégez réellement "
                "ces chemins (authentification, restriction IP).",
                reference="https://www.rfc-editor.org/rfc/rfc9309",
            )
        )
    if "sitemap" not in text.lower():
        pass
    return findings


async def check_error_pages(fetcher: Fetcher, base_url: str) -> list[Finding]:
    """Provoque une 404 et cherche des traces techniques dans la réponse."""
    findings: list[Finding] = []
    marker = "vulnlens-404-probe-8f3a1c"
    resp = await fetcher.get(urljoin(base_url, marker), max_bytes=64_000)
    if resp.error or resp.status not in (404, 500):
        return findings

    body = resp.text[:20000]
    patterns = {
        "Traceback (most recent call last)": "traceback Python",
        "at System.": "stack trace .NET",
        "SQLSTATE": "erreur SQL",
        "Warning: mysql": "erreur MySQL",
        "You have an error in your SQL syntax": "erreur SQL",
        "org.springframework": "stack trace Spring",
        "Notice: Undefined": "notice PHP",
        "Fatal error:": "erreur fatale PHP",
        "Whitelabel Error Page": "page d'erreur Spring par défaut",
        "Stack trace:": "stack trace",
    }
    hits = [label for needle, label in patterns.items() if needle.lower() in body.lower()]
    if hits:
        findings.append(
            Finding(
                id="errors.stack-trace",
                title="Traces techniques dans les pages d'erreur",
                severity=Severity.MEDIUM,
                category="Fuite d'information",
                description="Les erreurs détaillées révèlent les chemins, frameworks et requêtes "
                "internes : une aide précieuse pour préparer une attaque.",
                evidence=f"HTTP {resp.status} sur /{marker} → {', '.join(sorted(set(hits)))}",
                remediation="Désactivez l'affichage des erreurs en production et renvoyez une page "
                "d'erreur générique.",
                reference="https://owasp.org/www-community/Improper_Error_Handling",
            )
        )
    return findings


async def check_directory_listing(fetcher: Fetcher, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    for path in ("", "uploads/", "images/", "static/"):
        url = base_url if not path else urljoin(base_url, path)
        resp = await fetcher.get(url, max_bytes=32_000)
        if resp.error or resp.status != 200:
            continue
        body = resp.text[:8000].lower()
        if "<title>index of /" in body or "directory listing for" in body:
            findings.append(
                Finding(
                    id="exposure.directory-listing",
                    title="Listage de répertoire activé",
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    description="Le serveur liste le contenu des répertoires, ce qui expose les "
                    "fichiers non référencés (sauvegardes, documents internes).",
                    evidence=f"GET {url} → listage automatique",
                    remediation="Désactivez `Options -Indexes` (Apache) ou `autoindex off` (Nginx).",
                    reference="https://owasp.org/www-project-web-security-testing-guide/",
                )
            )
            break
    return findings


def detect_fingerprint(headers: dict[str, str], html: str) -> dict[str, str]:
    """Empreinte technique : utile pour le rapport, pas une vulnérabilité en soi."""
    blob = html[:200_000].lower()
    fingerprint: dict[str, str] = {}

    server = headers.get("server", "")
    if server:
        fingerprint["serveur"] = server
    powered = headers.get("x-powered-by", "")
    if powered:
        fingerprint["technologie"] = powered

    signatures = {
        "wordpress": "WordPress",
        "wp-content": "WordPress",
        "drupal": "Drupal",
        "joomla": "Joomla",
        "shopify": "Shopify",
        "next.js": "Next.js",
        "__next_data__": "Next.js",
        "react": "React",
        "vue.js": "Vue.js",
        "angular": "Angular",
        "laravel": "Laravel",
        "django": "Django",
        "spring": "Spring",
        "cloudflare": "Cloudflare",
    }
    detected = sorted({name for needle, name in signatures.items() if needle in blob})
    if detected:
        fingerprint["frameworks"] = ", ".join(detected)

    generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.I)
    if generator:
        fingerprint["generateur"] = generator.group(1)

    host = urlparse(headers.get("__url__", "")).hostname or ""
    if host:
        fingerprint["hote"] = host
    return fingerprint
