"""Référentiels d'un rapport de pentest : CWE, OWASP WSTG et CVSS 3.1.

Un audit remis à un client doit citer des référentiels reconnus, sinon chaque
constat reste une opinion. Ce module associe à chaque famille de constat :

* un **CWE** (nature technique de la faiblesse) ;
* un **test OWASP WSTG** (la méthode qui l'a mise au jour) ;
* un **vecteur CVSS 3.1**, dont le score est *calculé* (jamais saisi à la main)
  pour rester cohérent avec la sévérité affichée.

Le calcul suit la spécification CVSS 3.1 (FIRST). Aucune dépendance externe.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# --- Calculateur CVSS 3.1 ---------------------------------------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """Arrondi CVSS : toujours vers le haut au dixième (spécification FIRST)."""
    return math.ceil(round(value, 6) * 10) / 10


def parse_vector(vector: str) -> dict[str, str]:
    parts: dict[str, str] = {}
    for chunk in vector.split("/"):
        if ":" in chunk:
            key, value = chunk.split(":", 1)
            parts[key.strip().upper()] = value.strip().upper()
    return parts


def cvss_base(vector: str) -> float:
    """Score de base CVSS 3.1 d'un vecteur (`CVSS:3.1/AV:N/...`)."""
    parts = parse_vector(vector)
    try:
        changed = parts["S"] == "C"
        iss = 1 - (1 - _CIA[parts["C"]]) * (1 - _CIA[parts["I"]]) * (1 - _CIA[parts["A"]])
        if changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        if impact <= 0:
            return 0.0
        privileges = (_PR_CHANGED if changed else _PR_UNCHANGED)[parts["PR"]]
        exploitability = (
            8.22 * _AV[parts["AV"]] * _AC[parts["AC"]] * privileges * _UI[parts["UI"]]
        )
        base = (1.08 if changed else 1.0) * (impact + exploitability)
    except KeyError as exc:  # vecteur incomplet ou invalide
        raise ValueError(f"Vecteur CVSS invalide : {vector!r} (manque {exc})") from exc
    return _roundup(min(base, 10.0))


# --- Référentiels -----------------------------------------------------------


@dataclass(frozen=True)
class Standard:
    """Référentiel associé à une famille de constat."""

    cwe: str
    cwe_name: str
    wstg: str
    vector: str

    @property
    def cvss(self) -> float:
        return cvss_base(self.vector)


# Ordre significatif : la première règle dont le préfixe correspond gagne.
RULES: tuple[tuple[str, Standard], ...] = (
    # --- Contrôle d'accès ---------------------------------------------------
    (
        "access.idor",
        Standard(
            "CWE-639",
            "Contournement d'autorisation par référence directe à un objet (IDOR)",
            "WSTG-ATHZ-04",
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        ),
    ),
    (
        "access.hidden-object-id",
        Standard(
            "CWE-915",
            "Modification de champs sensibles contrôlés par l'utilisateur (mass assignment)",
            "WSTG-ATHZ-04",
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
        ),
    ),
    (
        "access.parameter-control",
        Standard(
            "CWE-269",
            "Gestion inappropriée des privilèges",
            "WSTG-ATHZ-01",
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        ),
    ),
    (
        "access.path-parameter",
        Standard(
            "CWE-22",
            "Traversée de répertoire (chemin non restreint)",
            "WSTG-ATHZ-01",
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        ),
    ),
    (
        "access.reflected-parameter",
        Standard(
            "CWE-79",
            "Neutralisation incorrecte d'une entrée dans une page web (XSS)",
            "WSTG-INPV-01",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        ),
    ),
    (
        "access.sensitive-endpoint",
        Standard(
            "CWE-200",
            "Exposition d'informations sensibles",
            "WSTG-INFO-05",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ),
    ),
    ("access.", Standard("CWE-284", "Contrôle d'accès inapproprié", "WSTG-ATHZ-01",
                         "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N")),  # fmt: skip
    # --- Secrets ------------------------------------------------------------
    (
        "secrets.jwt-alg-none",
        Standard(
            "CWE-347",
            "Vérification incorrecte d'une signature cryptographique",
            "WSTG-SESS-10",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ),
    ),
    (
        "secrets.jwt",
        Standard(
            "CWE-522",
            "Protection insuffisante des identifiants",
            "WSTG-SESS-10",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        ),
    ),
    (
        "secrets.source-map",
        Standard(
            "CWE-540",
            "Inclusion d'informations sensibles dans les fichiers source",
            "WSTG-INFO-05",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        ),
    ),
    (
        "secrets.",
        Standard(
            "CWE-798",
            "Utilisation d'identifiants codés en dur",
            "WSTG-CONF-04",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        ),
    ),
    # --- Fichiers exposés ---------------------------------------------------
    (
        "exposure.git",
        Standard(
            "CWE-527",
            "Exposition d'un dépôt de gestion de versions",
            "WSTG-CONF-04",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        ),
    ),
    (
        "exposure.ssh-private-key",
        Standard(
            "CWE-321",
            "Utilisation d'une clé cryptographique codée en dur",
            "WSTG-CONF-04",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        ),
    ),
    (
        "exposure.terraform-state",
        Standard(
            "CWE-538",
            "Fichier ou répertoire exposé",
            "WSTG-CONF-04",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        ),
    ),
    (
        "exposure.directory-listing",
        Standard(
            "CWE-548",
            "Répertoire exposé par un listing",
            "WSTG-CONF-04",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ),
    ),
    (
        "exposure.json-error",
        Standard(
            "CWE-209",
            "Génération d'un message d'erreur contenant des informations sensibles",
            "WSTG-ERRH-01",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ),
    ),
    (
        "exposure.",
        Standard(
            "CWE-538",
            "Fichier ou répertoire exposé",
            "WSTG-CONF-04",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        ),
    ),
    # --- Transport et TLS ---------------------------------------------------
    (
        "transport.no-https",
        Standard(
            "CWE-319",
            "Transmission en clair d'informations sensibles",
            "WSTG-CRYP-03",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        ),
    ),
    (
        "transport.",
        Standard(
            "CWE-319",
            "Transmission en clair d'informations sensibles",
            "WSTG-CRYP-03",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ),
    ),
    (
        "tls.",
        Standard(
            "CWE-295",
            "Validation incorrecte d'un certificat",
            "WSTG-CRYP-01",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        ),
    ),
    # --- En-têtes, cookies, navigateur --------------------------------------
    (
        "headers.csp",
        Standard(
            "CWE-693",
            "Défaillance d'un mécanisme de protection",
            "WSTG-CLNT-01",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        ),
    ),
    (
        "headers.hsts",
        Standard(
            "CWE-319",
            "Transmission en clair d'informations sensibles",
            "WSTG-CRYP-03",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ),
    ),
    (
        "headers.clickjacking",
        Standard(
            "CWE-1021",
            "Rendu incorrect des restrictions d'interface (clickjacking)",
            "WSTG-CLNT-09",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        ),
    ),
    (
        "headers.debug-token",
        Standard(
            "CWE-215",
            "Insertion d'informations sensibles dans un code de débogage",
            "WSTG-INFO-05",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        ),
    ),
    (
        "headers.version-disclosure",
        Standard(
            "CWE-200",
            "Exposition d'informations sensibles",
            "WSTG-INFO-02",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ),
    ),
    (
        "cookies.",
        Standard(
            "CWE-614",
            "Cookie de session transmis sans attribut Secure",
            "WSTG-SESS-02",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        ),
    ),
    (
        "cors.",
        Standard(
            "CWE-942",
            "Politique CORS permissive",
            "WSTG-CLNT-11",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
        ),
    ),
    (
        "content.csrf-token-missing",
        Standard(
            "CWE-352",
            "Falsification de requête intersites (CSRF)",
            "WSTG-SESS-05",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        ),
    ),
    (
        "content.insecure-password-form",
        Standard(
            "CWE-319",
            "Transmission en clair d'informations sensibles",
            "WSTG-CRYP-03",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        ),
    ),
    (
        "content.mixed-content",
        Standard(
            "CWE-319",
            "Transmission en clair d'informations sensibles",
            "WSTG-CRYP-03",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        ),
    ),
    (
        "content.sensitive-page-cacheable",
        Standard(
            "CWE-525",
            "Utilisation du cache du navigateur pour des informations sensibles",
            "WSTG-SESS-06",
            "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ),
    ),
    (
        "content.comments-leak",
        Standard(
            "CWE-615",
            "Commentaires révélant des informations internes",
            "WSTG-INFO-05",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ),
    ),
    (
        "content.iframe-no-sandbox",
        Standard(
            "CWE-1021",
            "Rendu incorrect des restrictions d'interface",
            "WSTG-CLNT-09",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        ),
    ),
    (
        "content.script-integrity",
        Standard(
            "CWE-353",
            "Absence de vérification d'intégrité",
            "WSTG-CONF-07",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        ),
    ),
    (
        "content.blank-noopener",
        Standard(
            "CWE-1022",
            "Utilisation d'une fenêtre non restreinte (tabnabbing)",
            "WSTG-CLNT-04",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        ),
    ),
    (
        "content.",
        Standard(
            "CWE-200",
            "Exposition d'informations sensibles",
            "WSTG-INFO-05",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ),
    ),
    (
        "methods.",
        Standard(
            "CWE-650",
            "Méthodes HTTP dangereuses activées",
            "WSTG-CONF-06",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        ),
    ),
    (
        "surface.third-parties",
        Standard(
            "CWE-829",
            "Inclusion de fonctionnalités issues d'une sphère de contrôle non fiable",
            "WSTG-INFO-04",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        ),
    ),
    (
        "surface.",
        Standard(
            "CWE-200",
            "Exposition d'informations sensibles",
            "WSTG-INFO-05",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ),
    ),
    (
        "web.open-redirect",
        Standard(
            "CWE-601",
            "Redirection vers un site non fiable",
            "WSTG-CLNT-04",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        ),
    ),
    (
        "libs.",
        Standard(
            "CWE-1104",
            "Utilisation de composants tiers non maintenus",
            "WSTG-CONF-07",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        ),
    ),
    # --- Reconnaissance, e-mail, disponibilité ------------------------------
    (
        "dns.zone-transfer",
        Standard(
            "CWE-200",
            "Exposition d'informations sensibles",
            "WSTG-INFO-05",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ),
    ),
    (
        "email.",
        Standard(
            "CWE-290",
            "Contournement d'authentification par usurpation",
            "WSTG-CONF-10",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        ),
    ),
    (
        "dns.",
        Standard(
            "CWE-290",
            "Contournement d'authentification par usurpation",
            "WSTG-CONF-10",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        ),
    ),
    (
        "recon.subdomain-takeover",
        Standard(
            "CWE-350",
            "Dépendance à une source non fiable pour l'autorisation",
            "WSTG-CONF-10",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        ),
    ),
    (
        "recon.",
        Standard(
            "CWE-200",
            "Exposition d'informations sensibles",
            "WSTG-INFO-04",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ),
    ),
    (
        "robots.",
        Standard(
            "CWE-200",
            "Exposition d'informations sensibles",
            "WSTG-INFO-01",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ),
    ),
    (
        "errors.stack-trace",
        Standard(
            "CWE-209",
            "Génération d'un message d'erreur contenant des informations sensibles",
            "WSTG-ERRH-01",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ),
    ),
)


def for_finding(finding_id: str) -> Standard | None:
    """Référentiel applicable à une famille de constat (None si non couverte)."""
    for prefix, standard in RULES:
        if finding_id.startswith(prefix):
            return standard
    return None


def describe(finding_id: str) -> dict[str, str | float]:
    """Forme sérialisable, prête pour les exports."""
    standard = for_finding(finding_id)
    if standard is None:
        return {}
    return {
        "cwe": standard.cwe,
        "cwe_name": standard.cwe_name,
        "wstg": standard.wstg,
        "cvss": standard.cvss,
        "cvss_vector": standard.vector,
    }


__all__ = ["RULES", "Standard", "cvss_base", "describe", "for_finding", "parse_vector"]
