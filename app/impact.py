"""Ce que chaque faille donne accès — en clair, dans le rapport.

Une sévérité « critique » ne dit pas à un décideur *ce qu'il perd*. Ce module
traduit chaque famille de constat en actifs concrets (comptes, base de données,
paiements, code source, infrastructure…) pour répondre à la question :
« si on ne corrige pas, qu'est-ce qui est atteignable ? »

Le mapping est déclaratif et volontairement conservateur : on n'annonce que ce
que la faille permet réellement, sans extrapoler.
"""

from __future__ import annotations

from typing import Any

# Actif -> libellé affiché. Les clés sont stables (API, exports, tests).
ASSETS: dict[str, str] = {
    "comptes": "Comptes utilisateurs",
    "sessions": "Sessions authentifiées",
    "admin": "Console d'administration",
    "donnees_perso": "Données personnelles",
    "paiement": "Paiements et données bancaires",
    "base": "Base de données",
    "code": "Code source et historique Git",
    "cloud": "Infrastructure cloud",
    "serveurs": "Serveurs et accès système",
    "secrets": "Secrets de configuration",
    "integrations": "Intégrations SaaS",
    "email": "Messagerie du domaine",
    "navigation": "Navigateur des visiteurs",
    "contenu": "Contenu et réputation du site",
    "reseaux": "Réseau interne",
}

# Constat (préfixe ou identifiant exact) -> actifs atteignables.
# L'ordre compte : la première règle qui correspond gagne.
RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    # --- Contrôle d'accès (IDOR, paramètres manipulables) ------------------
    ("access.idor", ("comptes", "donnees_perso", "base")),
    ("access.hidden-object-id", ("comptes", "donnees_perso")),
    ("access.parameter-control", ("admin", "comptes")),
    ("access.reflected-parameter", ("navigation", "sessions")),
    ("access.path-parameter", ("serveurs", "base", "donnees_perso")),
    ("access.sensitive-endpoint", ("admin", "comptes")),
    # --- Secrets -----------------------------------------------------------
    ("secrets.database-url", ("base", "donnees_perso")),
    ("secrets.jwt-alg-none", ("comptes", "admin", "sessions")),
    ("secrets.jwt-privileged", ("comptes", "admin", "sessions")),
    ("secrets.jwt", ("comptes", "sessions")),
    ("secrets.stripe", ("paiement", "donnees_perso")),
    ("secrets.shopify", ("paiement", "donnees_perso", "admin")),
    ("secrets.aws", ("cloud", "donnees_perso")),
    ("secrets.azure", ("cloud", "donnees_perso")),
    ("secrets.gcp", ("cloud", "donnees_perso")),
    ("secrets.google-oauth", ("integrations", "comptes")),
    ("secrets.digitalocean", ("cloud", "serveurs")),
    ("secrets.private-key", ("serveurs", "secrets", "cloud")),
    ("secrets.github", ("code", "integrations")),
    ("secrets.gitlab", ("code", "integrations")),
    ("secrets.npm", ("code", "integrations")),
    ("secrets.pypi", ("code", "integrations")),
    ("secrets.sendgrid", ("email", "contenu")),
    ("secrets.mailgun", ("email", "contenu")),
    ("secrets.twilio", ("integrations", "paiement")),
    ("secrets.slack", ("integrations", "contenu")),
    ("secrets.discord", ("integrations", "contenu")),
    ("secrets.stripe-webhook", ("paiement",)),
    ("secrets.openai", ("integrations", "cloud")),
    ("secrets.anthropic", ("integrations", "cloud")),
    ("secrets.huggingface", ("integrations", "cloud")),
    ("secrets.airtable", ("donnees_perso", "integrations")),
    ("secrets.source-map", ("code",)),
    ("secrets.basic-auth-url", ("comptes", "secrets")),
    ("secrets.", ("secrets", "integrations")),
    # --- Exposition de fichiers -------------------------------------------
    ("exposure.git", ("code", "secrets", "cloud")),
    ("exposure.dotenv", ("secrets", "base", "integrations", "email")),
    ("exposure.terraform-state", ("cloud", "serveurs", "secrets", "reseaux")),
    ("exposure.ssh-private-key", ("serveurs", "reseaux")),
    ("exposure.git-credentials", ("code", "integrations")),
    ("exposure.gcp-service-account", ("cloud", "donnees_perso")),
    ("exposure.actuator-heapdump", ("comptes", "sessions", "secrets", "donnees_perso")),
    ("exposure.database-config", ("base", "donnees_perso")),
    ("exposure.symfony-profiler", ("comptes", "sessions", "base", "secrets")),
    ("exposure.htpasswd", ("comptes", "admin")),
    ("exposure.openapi", ("comptes", "donnees_perso")),
    ("exposure.swagger", ("comptes", "donnees_perso")),
    ("exposure.graphiql", ("comptes", "donnees_perso")),
    ("exposure.graphql", ("comptes", "donnees_perso")),
    ("exposure.directory-listing", ("secrets", "contenu")),
    ("exposure.", ("secrets", "contenu")),
    # --- Transport, TLS, navigateur ---------------------------------------
    ("transport.", ("comptes", "sessions", "donnees_perso")),
    ("tls.", ("sessions", "navigation")),
    ("cookies.", ("sessions", "comptes")),
    ("cors.", ("comptes", "donnees_perso")),
    ("headers.debug-token", ("comptes", "sessions", "base", "secrets")),
    ("headers.csp", ("navigation", "sessions")),
    ("headers.clickjacking", ("comptes", "sessions")),
    ("headers.", ("navigation",)),
    ("libs.", ("navigation", "sessions", "comptes")),
    ("content.mixed-content", ("sessions", "navigation")),
    ("content.", ("navigation", "donnees_perso")),
    ("methods.", ("comptes", "contenu")),
    ("surface.", ("navigation", "donnees_perso", "contenu")),
    # --- E-mail, DNS, reconnaissance --------------------------------------
    ("email.", ("email", "comptes")),
    ("dns.", ("email", "comptes")),
    ("recon.subdomain-takeover", ("contenu", "comptes", "email")),
    ("recon.", ("contenu",)),
    ("robots.", ("contenu",)),
    ("errors.", ("secrets", "contenu")),
)

DEFAULT_ASSETS: tuple[str, ...] = ("contenu",)

# Ordre d'affichage : les actifs les plus sensibles d'abord (ordre de ASSETS).
_ORDER: dict[str, int] = {label: index for index, label in enumerate(ASSETS.values())}


def asset_keys(finding_id: str) -> tuple[str, ...]:
    """Clés d'actifs atteignables pour un constat donné."""
    for prefix, keys in RULES:
        if finding_id.startswith(prefix):
            return keys
    return DEFAULT_ASSETS


def labels(finding_id: str) -> list[str]:
    """Libellés lisibles, prêts pour l'affichage."""
    return [ASSETS[key] for key in asset_keys(finding_id) if key in ASSETS]


def annotate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ajoute `grants` (liste) et `grants_text` (résumé) à chaque constat."""
    for finding in findings:
        granted = labels(str(finding.get("id", "")))
        finding["grants"] = granted
        finding["grants_text"] = " · ".join(granted)
    return findings


def reachable(findings: list[dict[str, Any]], limit: int = 6) -> list[str]:
    """Vue « ce que l'attaquant peut atteindre » : actifs uniques, les plus cités d'abord."""
    scores: dict[str, int] = {}
    for finding in findings:
        weight = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
            str(finding.get("severity", "info")), 0
        )
        for asset in finding.get("grants") or []:
            scores[asset] = scores.get(asset, 0) + weight
    ordered = sorted(scores.items(), key=lambda item: (-item[1], _ORDER.get(item[0], 999)))
    return [asset for asset, _score in ordered[:limit]]


__all__ = ["ASSETS", "RULES", "annotate", "asset_keys", "labels", "reachable"]
