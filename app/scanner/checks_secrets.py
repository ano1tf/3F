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
        re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b"),
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

    SecretPattern(
        "secrets.anthropic",
        "Clé d'API Anthropic exposée",
        Severity.HIGH,
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}\b"),
        "Une clé d'API Anthropic permet de consommer le quota du compte et d'accéder aux "
        "ressources associées (workspaces, fichiers téléversés).",
        "Révoquez la clé dans la console et proxifiez les appels par votre backend.",
    ),
    SecretPattern(
        "secrets.github-pat",
        "Jeton GitHub à granularité fine exposé",
        Severity.CRITICAL,
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b"),
        "Un jeton `github_pat_` donne un accès programmatique aux dépôts et à la CI selon ses "
        "portées : lecture de code privé, écriture, modification des workflows.",
        "Révoquez le jeton, réduisez ses portées et sa durée de vie, et utilisez OIDC dans la CI.",
    ),
    SecretPattern(
        "secrets.gitlab",
        "Jeton GitLab exposé",
        Severity.CRITICAL,
        re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
        "Un jeton d'accès personnel GitLab permet de lire et modifier les projets, les pipelines "
        "et parfois les variables CI/CD (qui contiennent d'autres secrets).",
        "Révoquez le jeton (Preferences → Access Tokens) et privilégiez des jetons de projet "
        "à durée limitée.",
    ),
    SecretPattern(
        "secrets.huggingface",
        "Jeton Hugging Face exposé",
        Severity.HIGH,
        re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),
        "Un jeton Hugging Face donne accès aux modèles et jeux de données privés du compte, et "
        "permet d'en publier en son nom.",
        "Révoquez le jeton et faites les appels d'inférence depuis un backend.",
    ),
    SecretPattern(
        "secrets.stripe-webhook",
        "Secret de webhook Stripe exposé",
        Severity.HIGH,
        re.compile(r"\bwhsec_[A-Za-z0-9]{24,}\b"),
        "Le secret de signature des webhooks Stripe permet de forger des événements valides : "
        "un attaquant peut simuler un paiement réussi ou un abonnement actif.",
        "Faites tourner le secret dans le tableau de bord Stripe et vérifiez la signature côté serveur.",
    ),
    SecretPattern(
        "secrets.npm",
        "Jeton npm exposé",
        Severity.HIGH,
        re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        "Un jeton npm permet de publier des paquets au nom de l'organisation : c'est un vecteur "
        "de chaîne d'approvisionnement (code exécuté chez vos utilisateurs).",
        "Révoquez le jeton, activez le 2FA sur la publication et utilisez des jetons de CI à "
        "portée limitée.",
    ),
    SecretPattern(
        "secrets.pypi",
        "Jeton PyPI exposé",
        Severity.HIGH,
        re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{40,}\b"),
        "Un jeton PyPI permet de publier des paquets au nom du projet : un tiers peut diffuser "
        "une version malveillante.",
        "Révoquez le jeton et restreignez-le au projet concerné (jeton à portée de projet).",
    ),
    SecretPattern(
        "secrets.digitalocean",
        "Jeton DigitalOcean exposé",
        Severity.HIGH,
        re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),
        "Un jeton DigitalOcean permet de créer, modifier ou détruire des ressources (droplets, "
        "bases, volumes) facturées au compte.",
        "Révoquez le jeton et restreignez les portées (read-only, IP autorisées).",
    ),
    SecretPattern(
        "secrets.twilio",
        "Clé d'API Twilio exposée",
        Severity.HIGH,
        re.compile(r"\bSK[a-f0-9]{32}\b"),
        "Une clé Twilio permet d'envoyer des SMS et des appels, avec facturation au compte et "
        "risque d'usurpation du numéro.",
        "Révoquez la clé dans la console Twilio et restreignez-la à un usage serveur.",
    ),
    SecretPattern(
        "secrets.shopify",
        "Jeton d'accès Shopify exposé",
        Severity.CRITICAL,
        re.compile(r"\bshp(?:at|ca|pa)_[a-fA-F0-9]{32}\b"),
        "Un jeton d'accès d'application Shopify donne la main sur la boutique : commandes, "
        "clients, produits et configuration de paiement.",
        "Révoquez l'application dans l'admin Shopify et régénérez le jeton.",
    ),
    SecretPattern(
        "secrets.google-oauth",
        "Secret client OAuth Google exposé",
        Severity.HIGH,
        re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{28}\b"),
        "Le secret client OAuth permet d'usurper l'application auprès de Google et de détourner "
        "le flux d'autorisation (hameçonnage crédible).",
        "Régénérez le secret dans la console Google Cloud et gardez-le côté serveur uniquement.",
    ),
    SecretPattern(
        "secrets.discord-webhook",
        "Webhook Discord exposé",
        Severity.HIGH,
        re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{10,}/[A-Za-z0-9_-]{30,}"),
        "L'URL d'un webhook Discord permet à n'importe qui de publier ou de supprimer des "
        "messages dans le salon cible (désinformation, spam, fuite d'alertes).",
        "Supprimez le webhook dans les paramètres du salon et régénérez-le, côté serveur.",
    ),
    SecretPattern(
        "secrets.slack-webhook",
        "Webhook Slack exposé",
        Severity.HIGH,
        re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{6,}/B[A-Za-z0-9_]{6,}/[A-Za-z0-9_]{20,}"),
        "L'URL d'un webhook Slack permet de publier des messages dans le canal : hameçonnage "
        "interne, diffusion de fausses alertes ou de liens malveillants.",
        "Révoquez le webhook (Apps → Incoming Webhooks) et gardez l'URL côté serveur.",
    ),
    SecretPattern(
        "secrets.airtable",
        "Jeton Airtable exposé",
        Severity.HIGH,
        re.compile(r"\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b"),
        "Un jeton Airtable donne accès aux bases du compte selon ses portées : lecture ou "
        "modification de données métier.",
        "Révoquez le jeton dans les paramètres du compte et restreignez ses portées.",
    ),
    SecretPattern(
        "secrets.database-url",
        "URL de connexion à une base avec identifiants",
        Severity.CRITICAL,
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://"
            r"[^\s:@/'\"<>]+:[^\s:@/'\"<>]{4,}@[^\s'\"<>]+"
        ),
        "Une chaîne de connexion complète (hôte, utilisateur, mot de passe) est exposée dans un "
        "fichier public : la base est accessible directement, sans passer par l'application.",
        "Changez le mot de passe, révoquez l'accès réseau public à la base et gardez la chaîne "
        "de connexion dans un coffre côté serveur.",
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


# --------------------------------------------------------------------------- #
# Analyse des JWT trouvés : un jeton présent n'est pas toujours grave, un jeton
# non signé ou porteur de privilèges l'est.
# --------------------------------------------------------------------------- #

# La signature peut être vide : c'est justement le cas `alg: none` qu'on recherche.
_JWT_TOKEN = re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?)")
_PRIVILEGED_CLAIM = re.compile(
    r'"(?:role|roles|scope|scopes|group|groups|permissions?|authorities)"\s*:\s*'
    r'\[[^\]]{0,120}?|"[^"]{0,40}?\b(?:admin|root|superuser|super_admin|owner|sysadmin)\b',
    re.IGNORECASE,
)
_ADMIN_FLAG = re.compile(r'"(?:is_?admin|admin|superuser|is_staff)"\s*:\s*true', re.IGNORECASE)


def _b64url_json(chunk: str) -> dict | None:
    import base64
    import json

    try:
        padded = chunk + "=" * (-len(chunk) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        value = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001 - un faux positif de regex n'est pas une erreur
        return None
    return value if isinstance(value, dict) else None


def jwt_findings(texts: list[tuple[str, str]]) -> list[Finding]:
    """Analyse les JWT publics : signature absente ou privilèges en clair."""
    import json

    weak: list[str] = []
    privileged: list[str] = []
    seen: set[str] = set()

    for source, text in texts:
        for match in _JWT_TOKEN.finditer(text or ""):
            token = match.group(1)
            if token in seen:
                continue
            seen.add(token)
            header_chunk, payload_chunk = token.split(".")[:2]
            header = _b64url_json(header_chunk)
            if header is None:
                continue
            payload = _b64url_json(payload_chunk) or {}
            alg = str(header.get("alg", "")).strip()
            claims = json.dumps(payload, ensure_ascii=False)
            excerpt = ", ".join(
                f"{key}={payload[key]!r}"
                for key in ("sub", "role", "scope", "iss", "exp")
                if key in payload
            )[:150]

            if alg.lower() in {"none", ""}:
                weak.append(f"  · {_short(source)} → alg: {alg or 'absent'} · {excerpt}")
                continue
            if _ADMIN_FLAG.search(claims) or _PRIVILEGED_CLAIM.search(claims):
                privileged.append(f"  · {_short(source)} → alg: {alg} · {excerpt}")

    findings: list[Finding] = []
    if weak:
        findings.append(
            Finding(
                id="secrets.jwt-alg-none",
                title="JWT sans signature (`alg: none`) exposé",
                severity=Severity.CRITICAL,
                category=CATEGORY,
                description=(
                    "Un jeton JWT déclare `alg: none` : il n'est pas signé. Quiconque le trouve "
                    "peut modifier librement ses revendications (identité, rôle, expiration) et "
                    "le présenter au serveur. Si celui-ci accepte cet algorithme, "
                    "l'authentification est contournable sans aucun secret."
                ),
                evidence=(
                    f"{len(weak)} jeton(s) non signé(s) :\n" + "\n".join(weak[:5])
                    + "\nJeton volontairement masqué : la preuve suffit."
                ),
                remediation=(
                    "Refusez explicitement `alg: none` à la vérification (liste blanche "
                    "d'algorithmes, jamais de valeur fournie par le jeton) et ne générez jamais "
                    "de jeton non signé en production."
                ),
                reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
            )
        )
    if privileged:
        findings.append(
            Finding(
                id="secrets.jwt-privileged",
                title="JWT porteur de privilèges exposé en clair",
                severity=Severity.HIGH,
                category=CATEGORY,
                description=(
                    "Un jeton présent dans un fichier public contient des revendications "
                    "administratives (`role: admin`, `is_admin: true`…). Si le jeton n'est pas "
                    "expiré, il ouvre un accès privilégié direct ; s'il est expiré, il révèle "
                    "le format des revendications à falsifier."
                ),
                evidence=(
                    f"{len(privileged)} jeton(s) privilégié(s) :\n" + "\n".join(privileged[:5])
                    + "\nJeton volontairement masqué : la preuve suffit."
                ),
                remediation=(
                    "Retirez tout jeton des fichiers statiques, faites-le expirer, et vérifiez "
                    "que le serveur contrôle la signature ET les autorisations côté serveur."
                ),
                reference="https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
            )
        )
    return findings


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
    collected: list[tuple[str, str]] | None = None,
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
    # Analyse des JWT sur tout ce qui a été lu (inline compris).
    findings.extend(jwt_findings([(page_url, inline_html)] + fetched))
    if collected is not None:
        # Réutilisé par le contrôle « bibliothèques » : aucune requête en double.
        collected.extend(fetched)

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
