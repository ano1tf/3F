"""Sécurité e-mail avancée : DMARC, SPF, DKIM, MTA-STS, TLS-RPT.

Uniquement des requêtes DNS publiques : aucun envoi d'e-mail, aucune tentative d'usurpation.
"""

from __future__ import annotations

import asyncio

from ..models import Finding, Severity
from .checks_dns import _txt

CATEGORY = "DNS & e-mail"

DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "s1", "s2", "mail", "k1", "dkim")
SPF_LOOKUP_LIMIT = 10


def _spf_lookup_count(spf: str) -> int:
    """Compte les mécanismes qui consomment un lookup DNS (limite RFC = 10)."""
    tokens = spf.split()[1:]
    return sum(
        1
        for token in tokens
        if token.startswith(("include:", "a", "mx", "ptr", "exists:", "redirect="))
    )


async def _dkim_selectors(domain: str) -> list[str]:
    results = await asyncio.gather(*(_txt(f"{selector}._domainkey.{domain}") for selector in DKIM_SELECTORS))
    found = []
    for selector, records in zip(DKIM_SELECTORS, results, strict=False):
        if any(record.lower().startswith("v=dkim1") or "p=" in record.lower() for record in records):
            found.append(selector)
    return found


async def check_email(domain: str) -> tuple[list[Finding], dict[str, str]]:
    if domain.replace(".", "").isdigit() or ":" in domain:
        return [], {}

    txt, dmarc, mta_sts, tls_rpt, dkim_selectors = await asyncio.gather(
        _txt(domain),
        _txt(f"_dmarc.{domain}"),
        _txt(f"_mta-sts.{domain}"),
        _txt(f"_smtp._tls.{domain}"),
        _dkim_selectors(domain),
    )

    spf = next((record for record in txt if record.lower().startswith("v=spf1")), "")
    dmarc_record = next((record for record in dmarc if record.lower().startswith("v=dmarc1")), "")
    has_mta_sts = any(record.lower().startswith("v=stsv1") for record in mta_sts)
    has_tls_rpt = any(record.lower().startswith("v=tlsrptv1") for record in tls_rpt)

    findings: list[Finding] = []
    meta: dict[str, str] = {}

    # --- DMARC : politique réellement appliquée ---------------------------------
    if dmarc_record:
        lowered = dmarc_record.lower()
        policy = ""
        for part in lowered.split(";"):
            if part.strip().startswith("p="):
                policy = part.strip()[2:].strip()
        if policy:
            meta["dmarc"] = policy
        if policy == "none":
            findings.append(
                Finding(
                    id="email.dmarc-none",
                    title="DMARC en mode surveillance (`p=none`)",
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    description="Avec `p=none`, le destinataire reçoit les rapports mais laisse "
                    "passer les e-mails usurpés. Le domaine est donc toujours utilisable pour du "
                    "phishing crédible, sans que rien ne bloque.",
                    evidence=f"{domain} → {dmarc_record}",
                    remediation="Après une période d'observation, passez à `p=quarantine` puis "
                    "`p=reject` (avec `pct=` pour progresser sans couper le trafic légitime).",
                    reference="https://www.rfc-editor.org/rfc/rfc7489#section-6.3",
                )
            )
        elif policy in ("quarantine", "reject") and "sp=" not in lowered:
            findings.append(
                Finding(
                    id="email.dmarc-subdomain-policy",
                    title="DMARC ne protège pas explicitement les sous-domaines",
                    severity=Severity.LOW,
                    category=CATEGORY,
                    description="Sans `sp=`, les sous-domaines héritent de `p=` seulement pour "
                    "certains receveurs : un sous-domaine oublié reste une porte d'entrée.",
                    evidence=f"Politique `p={policy}` sans `sp=` : {dmarc_record}",
                    remediation="Ajoutez `sp=reject` (ou `sp=quarantine`) pour fermer les "
                    "sous-domaines, et vérifiez la liste de vos sous-domaines actifs.",
                    reference="https://www.rfc-editor.org/rfc/rfc7489#section-6.3",
                )
            )

    # --- SPF : limite de 10 lookups --------------------------------------------
    if spf:
        lookups = _spf_lookup_count(spf)
        meta["spf_lookups"] = str(lookups)
        if lookups > SPF_LOOKUP_LIMIT:
            findings.append(
                Finding(
                    id="email.spf-too-many-lookups",
                    title="SPF dépasse la limite de 10 résolutions DNS",
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    description="Au-delà de 10 mécanismes à résolution DNS, un SPF retourne "
                    "`permerror` : les receveurs ne peuvent plus évaluer la légitimité de vos "
                    "e-mails, et vos messages légitimes peuvent être rejetés ou usurpés.",
                    evidence=f"{lookups} mécanismes de résolution DNS dans : {spf[:220]}",
                    remediation="Aplatissez les `include:` (SPF flattening), supprimez les "
                    "mécanismes inutiles et visez 6 lookups maximum pour garder de la marge.",
                    reference="https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4",
                )
            )

    # --- DKIM : sélecteur introuvable ------------------------------------------
    if dmarc_record or spf:
        if dkim_selectors:
            meta["dkim"] = ", ".join(dkim_selectors[:3])
        else:
            findings.append(
                Finding(
                    id="email.dkim-missing",
                    title="Aucune signature DKIM détectée",
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    description="Sans DKIM, vos e-mails ne peuvent pas être authentifiés "
                    "cryptographiquement : DMARC ne peut alors pas appliquer une politique "
                    "stricte, et vos messages risquent le dossier spam.",
                    evidence=f"Sélecteurs testés : {', '.join(DKIM_SELECTORS)} → aucun "
                    "enregistrement `v=DKIM1`/`p=` trouvé.",
                    remediation="Activez la signature DKIM chez votre fournisseur d'envoi et "
                    "publiez la clé publique (`<sélecteur>._domainkey.<domaine>` TXT).",
                    reference="https://www.rfc-editor.org/rfc/rfc6376",
                )
            )

    # --- MTA-STS / TLS-RPT : chiffrement des échanges SMTP ---------------------
    if (dmarc_record or spf) and not has_mta_sts:
        findings.append(
            Finding(
                id="email.mta-sts-missing",
                title="MTA-STS absent (SMTP non protégé contre le downgrade)",
                severity=Severity.LOW,
                category=CATEGORY,
                description="Sans MTA-STS, un attaquant positionné sur le réseau peut forcer un "
                "serveur d'envoi à livrer en SMTP non chiffré (strip TLS) et lire les messages.",
                evidence=f"Aucun TXT `_mta-sts.{domain}` commençant par `v=STSv1`.",
                remediation="Publiez `_mta-sts.<domaine>` TXT `v=STSv1; id=…`, servez "
                "`https://mta-sts.<domaine>/.well-known/mta-sts.txt` avec `mode: enforce`.",
                reference="https://www.rfc-editor.org/rfc/rfc8461",
            )
        )
    if (dmarc_record or spf) and not has_tls_rpt:
        findings.append(
            Finding(
                id="email.tls-rpt-missing",
                title="Rapports TLS (TLS-RPT) non collectés",
                severity=Severity.INFO,
                category=CATEGORY,
                description="Sans TLS-RPT, personne ne vous prévient quand un serveur distant "
                "négocie le SMTP sans chiffrement : une attaque par downgrade reste invisible.",
                evidence=f"Aucun TXT `_smtp._tls.{domain}` commençant par `v=TLSRPTv1`.",
                remediation="Publiez `_smtp._tls.<domaine>` TXT "
                "`v=TLSRPTv1; rua=mailto:tls-reports@votre-domaine`.",
                reference="https://www.rfc-editor.org/rfc/rfc8460",
            )
        )

    if dmarc_record:
        meta["dmarc_record"] = dmarc_record[:120]
    if has_mta_sts:
        meta["mta_sts"] = "activé"
    if has_tls_rpt:
        meta["tls_rpt"] = "activé"

    return findings, meta
