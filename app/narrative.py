"""Synthèse exécutive : traduire un rapport technique en décisions lisibles.

Le public visé n'est pas l'ingénieur qui lira les 40 constats, mais la personne qui décide
où mettre les prochaines heures d'équipe. On garde les faits, on retire le jargon.
"""

from __future__ import annotations

from typing import Any

from . import impact as impact_assets

RISK_LEVELS: tuple[tuple[int, str, str], ...] = (
    (80, "faible", "La posture est saine ; il reste des finitions."),
    (60, "modéré", "Des faiblesses exploitables existent, mais le socle tient."),
    (35, "élevé", "Plusieurs failles exploitables : une action rapide est nécessaire."),
    (0, "critique", "Des accès ou des données sont exposés : à traiter immédiatement."),
)

IMPACTS: tuple[tuple[str, str], ...] = (
    (
        "access.idor",
        "Avec un simple compte, un attaquant lit — et parfois modifie — les données de tous les "
        "autres clients : factures, adresses, commandes, messages.",
    ),
    (
        "access.parameter-control",
        "Un paramètre d'URL suffit à changer de rôle : l'attaquant peut se donner les droits d'un "
        "administrateur sans aucune faille technique à exploiter.",
    ),
    (
        "access.",
        "Une barrière d'autorisation manque ou se contourne : les données d'autrui deviennent "
        "accessibles avec un compte ordinaire.",
    ),
    (
        "exposure.",
        "Un attaquant récupère du code, des sauvegardes ou des secrets sans aucune authentification.",
    ),
    (
        "secrets.",
        "Des accès cloud ou SaaS sont directement utilisables, au nom et aux frais de l'organisation.",
    ),
    (
        "libs.",
        "Une bibliothèque obsolète offre un point d'entrée connu (XSS, exécution de code) dans le "
        "navigateur de vos visiteurs, sans aucune recherche à faire pour l'attaquant.",
    ),
    (
        "transport.",
        "Les identifiants, cookies et contenus circulent en clair et peuvent être interceptés.",
    ),
    (
        "tls.",
        "La connexion peut être usurpée ou interceptée : les visiteurs n'ont aucune garantie sur l'identité du site.",
    ),
    (
        "headers.",
        "Une injection de script peut s'exécuter dans le navigateur de vos visiteurs.",
    ),
    (
        "cookies.",
        "Une session utilisateur peut être volée puis rejouée par un attaquant.",
    ),
    (
        "content.",
        "Les données saisies par vos utilisateurs peuvent être détournées ou altérées.",
    ),
    (
        "email.",
        "N'importe qui peut envoyer des e-mails crédibles en votre nom (phishing, fraude au président).",
    ),
    (
        "dns.",
        "L'usurpation d'e-mail et la délivrance de certificats frauduleux deviennent possibles.",
    ),
    (
        "recon.",
        "La phase de reconnaissance de l'attaquant est accélérée : il sait où frapper.",
    ),
    (
        "surface.",
        "La compromission d'un prestataire devient une compromission de votre site.",
    ),
    (
        "errors.",
        "Les entrailles de l'application sont exposées et orientent directement une attaque.",
    ),
    (
        "robots.",
        "La configuration publique indique à un attaquant les zones que vous cherchez à cacher.",
    ),
)

def _strengths(report: dict[str, Any], present: set[str], is_https: bool) -> list[str]:
    """Une force n'est retenue que si le contrôle a réellement tourné et n'a rien trouvé."""
    checks = {check.get("key"): check.get("status", "ok") for check in report.get("checks") or []}
    ran = lambda key: checks.get(key) == "ok"  # noqa: E731

    families = {
        "csp": any(item.startswith("headers.csp") for item in present)
        or "headers.missing.content-security-policy" in present,
        "clickjacking": "headers.clickjacking" in present,
        "exposure": any(item.startswith("exposure.") for item in present),
        "secrets": any(item.startswith("secrets.") for item in present),
        "spf": "dns.spf-missing" in present,
        "dmarc": "dns.dmarc-missing" in present,
        "transport": any(item.startswith("transport.") for item in present),
        "mixed": "content.mixed-content" in present,
        "third": bool(report.get("third_parties")),
        "libs": any(item.startswith("libs.") for item in present),
    }

    rules: list[tuple[bool, str]] = [
        (is_https and ran("transport") and not families["transport"],
         "HTTPS actif, avec redirection forcée depuis HTTP"),
        (is_https and not families["transport"], "HSTS présent : le navigateur refuse le HTTP"),
        (ran("headers") and not families["csp"], "Content-Security-Policy en place"),
        (ran("headers") and not families["clickjacking"], "Protection anti-clickjacking en place"),
        (ran("exposure") and not families["exposure"],
         "Aucun fichier de développement accessible (.git, .env, sauvegardes)"),
        (ran("dns") and not families["spf"], "SPF publié pour le domaine"),
        (ran("dns") and not families["dmarc"], "DMARC publié pour le domaine"),
        (ran("secrets") and not families["secrets"],
         "Aucun secret détecté dans les scripts publics"),
        (is_https and ran("content") and not families["mixed"],
         "Contenus mixtes absents : tous les actifs sont chargés en HTTPS"),
        (ran("surface") and not families["third"], "Aucune dépendance tierce critique détectée"),
        (ran("libs") and not families["libs"],
         "Bibliothèques front-end à jour (aucune version à vulnérabilité connue)"),
    ]
    return [label for condition, label in rules if condition]


def _impact_for(finding_id: str, category: str) -> str:
    for prefix, impact in IMPACTS:
        if finding_id.startswith(prefix):
            return impact
    return f"Le risque reste localisé à la catégorie « {category} »."


def risk_for(score: int) -> tuple[str, str]:
    for threshold, label, sentence in RISK_LEVELS:
        if score >= threshold:
            return label, sentence
    return "critique", RISK_LEVELS[-1][2]


def build(report: dict[str, Any]) -> dict[str, Any]:
    findings = report.get("findings") or []
    counts = report.get("counts") or {}
    score = int(report.get("score") or 0)
    level, sentence = risk_for(score)

    critical = int(counts.get("critical", 0))
    high = int(counts.get("high", 0))
    total = len(findings)
    danger_max = max((int(finding.get("danger") or 0) for finding in findings), default=0)

    if critical:
        headline = (
            f"{critical} faille(s) critique(s) donnent un accès immédiat : à corriger "
            "avant toute nouvelle fonctionnalité."
        )
    elif high:
        headline = (
            f"Aucune faille critique, mais {high} problème(s) élevé(s) restent exploitables "
            "dans un scénario réaliste."
        )
    elif total:
        headline = (
            "Pas de faille critique : le socle tient. Les constats restants relèvent du "
            "durcissement et de la propreté de configuration."
        )
    else:
        headline = "Aucun problème détecté par les contrôles passifs : la surface est propre."

    pages = report.get("pages") or []
    third_parties = report.get("third_parties") or []
    paragraph = (
        f"Analyse de {len(pages) or 1} page(s) et de {len(report.get('checks') or [])} familles "
        f"de contrôles. {sentence} "
        f"{total} constat(s) au total, dont {critical} critique(s) et {high} élevé(s)."
    )
    if danger_max:
        paragraph += f" Le constat le plus dangereux est coté {danger_max}/10."
    if third_parties:
        paragraph += (
            f" Le site charge {len(third_parties)} domaine(s) tiers, autant de dépendances "
            "dont la sécurité ne vous appartient pas."
        )
    if report.get("verified"):
        paragraph += " La propriété du domaine est vérifiée : le périmètre analysé est établi."

    present = {finding.get("id", "") for finding in findings}
    priorities = report.get("priorities") or []
    ordered = [f for f in findings if f["id"] in priorities] + [
        f for f in findings if f["id"] not in priorities
    ]

    key_risks = []
    for finding in ordered[:3]:
        key_risks.append(
            {
                "id": finding.get("id", ""),
                "title": finding.get("title", ""),
                "severity": finding.get("severity", "info"),
                "severity_label": finding.get("severity_label", "Information"),
                "category": finding.get("category", ""),
                "impact": _impact_for(finding.get("id", ""), finding.get("category", "")),
                "action": finding.get("remediation", ""),
            }
        )

    is_https = (report.get("final_url") or report.get("target") or "").startswith("https://")
    strengths = _strengths(report, present, is_https)
    if report.get("verified"):
        strengths.insert(0, "Propriété du domaine vérifiée (DNS ou .well-known)")

    breakdown = report.get("score_breakdown") or {}
    heaviest = sorted(breakdown.items(), key=lambda item: -item[1])[:6]
    peak = max((value for _label, value in heaviest), default=0) or 1
    radar = [
        {"label": label, "value": min(100, round(100 * value / peak))}
        for label, value in heaviest
    ]

    return {
        "risk_level": level,
        "danger_max": danger_max,
        "radar": radar,
        "score": score,
        "grade": report.get("grade", ""),
        "headline": headline,
        "paragraph": paragraph,
        "key_risks": key_risks,
        "strengths": strengths[:6],
        "counts": {
            "critical": critical,
            "high": high,
            "medium": int(counts.get("medium", 0)),
            "low": int(counts.get("low", 0)),
            "info": int(counts.get("info", 0)),
            "total": total,
        },
        "reachable": impact_assets.reachable(findings),
    }


def confidence_for(finding_id: str) -> str:
    """Certains constats sont des déductions : autant le dire honnêtement."""
    if finding_id in {
        "content.comments-leak",
        "robots.disclosure",
        "secrets.generic-assignment",
    }:
        return "a-confirmer"
    if finding_id in {
        "content.generator-version",
        "surface.third-parties",
        "recon.subdomain-takeover",
    } or finding_id.startswith("recon.subdomain-takeover."):
        return "probable"
    return "certain"
