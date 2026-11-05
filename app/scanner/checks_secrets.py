"""Recherche de secrets dans les scripts exposés — 100 % passif.

On ne fait que télécharger les fichiers JavaScript déjà servis publiquement par le site
(comme le ferait un navigateur) et on y cherche des identifiants codés en dur. Les valeurs
sont **masquées** dans le rapport : la preuve suffit, inutile de recopier le secret.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from ..models import Finding, Severity
from .fetcher import Fetcher, same_origin

CATEGORY = "Secrets exposés"
MAX_SCRIPT_BYTES = 512_000
MAX_SCRIPTS = 10

_REF_OWASP = "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"
_REF_SECRETS = "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"


@dataclass(frozen=True)
class SecretPattern:
    id: str
    title: str
    severity: Severity
    regex: re.Pattern[str]
    description: str
    remediation: str
    reference: str = _REF_SECRETS


PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "secrets.aws-access-key",
        "Clé d'accès AWS exposée",
        Severity.CRITICAL,
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}\b"),
        "Une clé d'accès AWS est présente dans un fichier public. Couplée à la clé secrète, "
        "elle permet de piloter des ressources cloud (S3, EC2) aux frais et au nom du propriétaire.",
        "Révoquez la clé dans IAM, générez-en une nouvelle, et servez-vous d'un coffre "
        "(Secrets Manager, Vault) ou de rôles IAM au lieu de constantes dans le code.",
    ),
    SecretPattern(
        "secrets.private-key",
        "Clé privée exposée",
        Severity.CRITICAL,
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        "Un bloc de clé privée est téléchargeable. Il permet de signer, déchiffrer ou "
        "s'authentifier à la place du serveur (TLS, SSH, JWT, paiement).",
        "Considérez la clé comme compromise : révoquez-la, régénérez-la et stockez-la hors du "
        "dossier web. Ajoutez une règle de blocage sur `*.pem`, `*.key` et `id_rsa`.",
    ),
    SecretPattern(
        "secrets.stripe-live",
        "Clé secrète Stripe de production",
        Severity.CRITICAL,
        re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"),
        "La clé secrète Stripe `sk_live_` donne un contrôle total sur le compte de paiement : "
        "création de remboursements, lecture des transactions, modification des webhooks.",
        "Faites tourner immédiatement la clé dans le tableau de bord Stripe et déplacez la "
        "création des paiements côté serveur (jamais dans un script public).",
    ),
    SecretPattern(
        "secrets.github-token",
        "Jeton GitHub exposé",
        Severity.CRITICAL,
        re.compile(r"\bgh[pousr]_[0-9A-Za-z]{30,}\b"),
        "Un jeton d'accès GitHub fuit : selon ses scopes, il permet de lire des dépôts privés, "
        "de pousser du code ou de modifier la CI.",
        "Révoquez le jeton (Settings → Developer settings), activez l'expiration courte et "
        "utilisez OIDC ou un gestionnaire de secrets dans la CI.",
    ),
    SecretPattern(
        "secrets.sendgrid",
        "Clé API SendGrid exposée",
        Severity.CRITICAL,
        re.compile(r"\bSG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}\b"),
        "Une clé SendGrid permet d'envoyer des e-mails au nom du domaine : phishing crédible "
        "et atteinte à la réputation d'expédition.",
        "Révoquez la clé, restreignez ses permissions et envoyez depuis un service backend "
        "exposé uniquement à votre application.",
    ),
    SecretPattern(
        "secrets.azure-storage",
        "Clé de compte Azure Storage exposée",
        Severity.CRITICAL,
        re.compile(r"AccountKey=[A-Za-z0-9+/]{40,}={0,2}"),
        "La clé d'un compte de stockage Azure permet de lire, modifier et supprimer tous les "
        "blobs, files et tables du compte.",
        "Régénérez la clé et privilégiez les SAS à durée courte ou les identités managées.",
    ),
    SecretPattern(
        "secrets.openai",
        "Clé d'API OpenAI exposée",
        Severity.HIGH,
        re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b"),
        "Une clé d'API de modèle de langage permet de consommer le quota du compte, voire "
        "d'accéder aux données et fine-tunings associés.",
        "Révoquez la clé et proxifiez les appels par votre backend (jamais depuis le navigateur).",
    ),
    SecretPattern(
        "secrets.google-api-key",
        "Clé d'API Google exposée",
        Severity.HIGH,
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "Une clé Google API sans restriction permet d'utiliser Maps, Firebase, Gemini ou "
        "d'autres services facturés à votre compte.",
        "Ajoutez des restrictions (référents HTTP, adresses IP, API autorisées) ou passez par "
        "un backend. Les clés publiques doivent être restreintes par conception.",
    ),
    SecretPattern(
        "secrets.slack",
        "Jeton Slack exposé",
        Severity.HIGH,
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        "Un jeton Slack permet de lire des messages, d'écrire dans des canaux et parfois "
        "d'administrer l'espace de travail.",
        "Révoquez le jeton dans l'application Slack et régénérez-le côté serveur uniquement.",
    ),
    SecretPattern(
        "secrets.slack-webhook",
        "Webhook Slack exposé",
        Severity.HIGH,
        re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+"),
        "Une URL de webhook Slack permet d'inonder un canal interne de messages contrôlés "
        "(hameçonnage interne, désinformation).",
        "Supprimez le webhook, créez-en un nouveau et gardez-le côté serveur.",
    ),
    SecretPattern(
        "secrets.twilio",
        "Jeton Twilio exposé",
        Severity.HIGH,
        re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
        "Un jeton Twilio permet d'envoyer des SMS et des appels facturés à votre compte "
        "(coût direct et usurpation de votre numéro).",
        "Révoquez la clé API et restreignez les envois au backend.",
    ),
    SecretPattern(
        "secrets.npm-token",
        "Jeton npm exposé",
        Severity.HIGH,
        re.compile(r"\bnpm_[0-9A-Za-z]{36}\b"),
        "Un jeton npm permet de publier une version malveillante de vos paquets ou de lire "
        "les paquets privés (chaîne d'approvisionnement).",
        "Révoquez le jeton, activez la 2FA sur npm et publiez depuis une CI dédiée.",
    ),
    SecretPattern(
        "secrets.basic-auth-url",
        "Identifiants dans une URL",
        Severity.HIGH,
        re.compile(r"https?://[^/\s:@\"']{2,}:[^/\s@\"']{6,}@[^\s\"'<>]+"),
        "Des identifiants sont embarqués dans une URL : ils finissent dans l'historique du "
        "navigateur, les journaux des proxys et les en-têtes `Referer`.",
        "Retirez-les, changez le mot de passe et utilisez une authentification par en-tête ou "
        "un jeton à durée courte.",
    ),
    SecretPattern(
        "secrets.firebase",
        "Jeton Firebase exposé",
        Severity.MEDIUM,
        re.compile(r"AAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{30,}"),
        "Un jeton serveur Firebase permet d'envoyer des notifications push à vos utilisateurs.",
        "Révoquez le jeton et gardez l'envoi côté serveur.",
    ),
    SecretPattern(
        "secrets.jwt",
        "Jeton JWT présent dans le code public",
        Severity.MEDIUM,
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "Un JWT signé est présent en clair. S'il n'est pas expiré, il peut ouvrir une session "
        "ou un accès API sans authentification.",
        "Vérifiez sa portée et sa date d'expiration ; ne shipbez jamais de jeton de session dans "
        "les fichiers statiques.",
    ),
    SecretPattern(
        "secrets.generic-assignment",
        "Identifiant potentiellement codé en dur",
        Severity.MEDIUM,
        re.compile(
            r"""(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)"""
            r"""["']?\s*[:=]\s*["'][^"'\s]{8,}["']""",
            re.IGNORECASE,
        ),
        "Une affectation ressemble à un identifiant en clair (mot de passe, clé, jeton). "
        "Même côté client, cela révèle la logique d'authentification et peut donner un accès "
        "direct si la valeur est réutilisée côté serveur.",
        "Déplacez la valeur côté serveur, faites-la tourner et chargez-la depuis un coffre. "
        "Si la valeur est un simple placeholder, ignorez ce constat.",
    ),
    SecretPattern(
        "secrets.mapbox",
        "Jeton Mapbox public",
        Severity.LOW,
        re.compile(r"\bpk\.eyJ[A-Za-z0-9_-]{20,}"),
        "Le jeton public Mapbox est visible par conception, mais sans restriction d'URL il peut "
        "être utilisé par des tiers et consommer votre quota.",
        "Restreignez le jeton aux URL autorisées dans la console Mapbox.",
    ),
    SecretPattern(
        "secrets.stripe-test",
        "Clé Stripe de test exposée",
        Severity.LOW,
        re.compile(r"\bsk_test_[0-9A-Za-z]{20,}\b"),
        "Une clé de test est exposée : pas de risque financier, mais elle révèle l'usage de "
        "Stripe et peut faciliter des tests frauduleux sur votre environnement.",
        "Utilisez les clés publiques (`pk_`) côté navigateur et gardez `sk_test_` côté serveur.",
    ),
)

PLACEHOLDERS = (
    "example",
    "xxxx",
    "your_",
    "your-",
    "changeme",
    "change_me",
    "placeholder",
    "${",
    "{{",
    "%s",
    "<",
    "todo",
    "dummy",
    "fake",
    "...",
)

_INLINE_SCRIPT = re.compile(r"<script[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)


def mask(value: str) -> str:
    """Masque une valeur sensible : on garde de quoi l'identifier, jamais de quoi l'utiliser."""
    value = value.strip()
    if len(value) <= 10:
        return value[:2] + "…"
    return f"{value[:6]}…{value[-4:]}"


def _line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in PLACEHOLDERS)


def find_secrets(text: str) -> list[tuple[SecretPattern, int, str]]:
    """Retourne (motif, numéro de ligne, valeur masquée) pour chaque correspondance."""
    hits: list[tuple[SecretPattern, int, str]] = []
    for pattern in PATTERNS:
        for match in pattern.regex.finditer(text):
            value = match.group(0)
            if _is_placeholder(value):
                continue
            hits.append((pattern, _line_number(text, match.start()), mask(value)))
            if len(hits) > 200:  # garde-fou sur les bundles obèses
                return hits
    return hits


def inline_scripts(html: str) -> str:
    return "\n".join(_INLINE_SCRIPT.findall(html or ""))


def script_urls(scripts: list[str], base_url: str) -> list[str]:
    """Ne garde que les scripts de même origine, dédupliqués, dans l'ordre d'apparition."""
    seen: set[str] = set()
    urls: list[str] = []
    for raw in scripts:
        if not raw or raw.startswith(("data:", "blob:", "javascript:")):
            continue
        absolute = urljoin(base_url, raw)
        if urlsplit(absolute).scheme not in ("http", "https"):
            continue
        if not same_origin(base_url, absolute):
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        urls.append(absolute)
    return urls


def _aggregate(hits: list[tuple[SecretPattern, str, int, str]]) -> list[Finding]:
    grouped: dict[str, dict] = {}
    for pattern, source, line, masked in hits:
        entry = grouped.setdefault(pattern.id, {"pattern": pattern, "hits": [], "sources": []})
        entry["hits"].append((source, line, masked))
        if source not in entry["sources"]:
            entry["sources"].append(source)

    findings: list[Finding] = []
    for entry in grouped.values():
        pattern: SecretPattern = entry["pattern"]
        hits = entry["hits"][:8]
        details = "\n".join(
            f"  · {_short(source)}:{line} → {masked}" for source, line, masked in hits
        )
        extra = (
            f"\n  … et {len(entry['hits']) - len(hits)} autre(s) occurrence(s)"
            if len(entry["hits"]) > len(hits)
            else ""
        )
        sources = entry["sources"]
        findings.append(
            Finding(
                id=pattern.id,
                title=pattern.title,
                severity=pattern.severity,
                category=CATEGORY,
                description=pattern.description,
                evidence=(
                    f"{len(entry['hits'])} occurrence(s) dans {len(sources)} fichier(s) public(s).\n"
                    f"{details}{extra}\n"
                    "Valeurs masquées par principe : le rapport ne recopie jamais un secret en clair."
                ),
                remediation=pattern.remediation,
                reference=pattern.reference,
            )
        )
    return sorted(findings, key=lambda item: (item.severity.rank, item.id))


def _short(url: str) -> str:
    parts = urlsplit(url)
    return parts.path or parts.netloc or url


async def scan_scripts(
    fetcher: Fetcher,
    page_url: str,
    scripts: list[str],
    *,
    inline_html: str = "",
    limit: int = 6,
) -> tuple[list[Finding], dict[str, str]]:
    """Télécharge les scripts publics et cherche des secrets. Retourne (constats, métadonnées)."""
    candidates = script_urls(scripts, page_url)[: max(1, limit)]
    hits: list[tuple[SecretPattern, str, int, str]] = []
    fetched: list[tuple[str, str]] = []

    for pattern, line, masked in find_secrets(inline_scripts(inline_html)):
        hits.append((pattern, page_url, line, masked))

    responses = await asyncio.gather(
        *(fetcher.get(url, max_bytes=MAX_SCRIPT_BYTES) for url in candidates),
        return_exceptions=True,
    )
    for url, response in zip(candidates, responses, strict=False):
        if isinstance(response, Exception) or response.error or response.status >= 400:
            continue
        text = response.text
        fetched.append((url, text))
        for pattern, line, masked in find_secrets(text):
            hits.append((pattern, url, line, masked))

    findings = _aggregate(hits)
    findings.extend(await _source_maps(fetcher, fetched))

    meta: dict[str, str] = {}
    if candidates:
        meta["scripts_analyses"] = str(len(fetched))
    return findings, meta


async def _source_maps(fetcher: Fetcher, scripts: list[tuple[str, str]]) -> list[Finding]:
    """Détecte les source maps publiées : elles exposent le code source complet des bundles."""
    exposed: list[str] = []
    for url, _ in scripts[:6]:
        if not url.endswith((".js", ".mjs")):
            continue
        response = await fetcher.get(f"{url}.map", max_bytes=4096)
        if response.error or response.status != 200:
            continue
        body = response.text
        if '"mappings"' in body or '"sources"' in body:
            exposed.append(url)
    if not exposed:
        return []
    listing = "\n".join(f"  · {_short(url)}.map → HTTP 200" for url in exposed)
    return [
        Finding(
            id="secrets.source-map",
            title="Source maps exposées",
            severity=Severity.MEDIUM,
            category=CATEGORY,
            description="Les fichiers `.map` livrés en production permettent de reconstituer "
            "le code source d'origine : noms de fonctions, commentaires, endpoints internes et "
            "parfois des identifiants laissés dans le code.",
            evidence=f"{len(exposed)} source map(s) accessible(s) :\n{listing}",
            remediation="Désactivez la génération des source maps en production, ou publiez-les "
            "vers un service privé (Sentry) avec un jeton d'accès.",
            reference="https://developer.mozilla.org/fr/docs/Tools/Debugger/How_to/Use_a_source_map",
        )
    ]
