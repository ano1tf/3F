"""Contrôles DNS : usurpation d'e-mail (SPF/DMARC), CAA, enregistrements publics."""

from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.exception
import dns.resolver

from ..models import Finding, Severity

CATEGORY = "DNS & e-mail"


async def _txt(name: str) -> list[str]:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 6.0
    resolver.timeout = 4.0
    try:
        answer = await resolver.resolve(name, "TXT", raise_on_no_answer=False)
    except (dns.exception.DNSException, OSError):
        return []
    if not answer:
        return []
    values: list[str] = []
    for record in answer:
        chunks = getattr(record, "strings", None)
        if chunks:
            values.append(b"".join(chunks).decode("utf-8", errors="replace"))
        else:
            values.append(record.to_text().strip('"'))
    return values


async def _records(name: str, rtype: str) -> list[str]:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 6.0
    resolver.timeout = 4.0
    try:
        answer = await resolver.resolve(name, rtype, raise_on_no_answer=False)
    except (dns.exception.DNSException, OSError):
        return []
    return [r.to_text() for r in (answer or [])]


async def check_dns(host: str) -> tuple[list[Finding], dict[str, str]]:
    findings: list[Finding] = []
    meta: dict[str, str] = {}

    if host.replace(".", "").isdigit() or ":" in host:
        return findings, meta

    txt_records, dmarc_records, caa, mx = await asyncio.gather(
        _txt(host),
        _txt(f"_dmarc.{host}"),
        _records(host, "TYPE257"),
        _records(host, "MX"),
    )

    spf = [r for r in txt_records if r.lower().startswith("v=spf1")]
    dmarc = [r for r in dmarc_records if r.lower().startswith("v=dmarc1")]

    if mx or spf:
        meta["email"] = "domaine de messagerie"
    if mx:
        meta["mx"] = ", ".join(m.split()[-1].rstrip(".") for m in mx[:3])

    if not spf:
        findings.append(
            Finding(
                id="dns.spf-missing",
                title="SPF absent",
                severity=Severity.MEDIUM,
                category=CATEGORY,
                description="Sans enregistrement SPF, n'importe qui peut envoyer des e-mails en "
                "usurpant votre domaine (phishing crédible pour vos clients).",
                evidence=f"Aucun TXT `v=spf1` trouvé pour {host}.",
                remediation="Publiez un SPF strict, par exemple "
                "`v=spf1 include:_spf.votre-fournisseur.com -all` (finir par `-all`).",
                reference="https://www.rfc-editor.org/rfc/rfc7208",
            )
        )
    else:
        if len(spf) > 1:
            findings.append(
                Finding(
                    id="dns.spf-multiple",
                    title="Plusieurs enregistrements SPF",
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    description="Plusieurs SPF rendent le contrôle imprévisible (échec SPF permanent).",
                    evidence="\n".join(spf),
                    remediation="Fusionnez tous les mécanismes dans un seul enregistrement TXT.",
                    reference="https://www.rfc-editor.org/rfc/rfc7208",
                )
            )
        record = spf[0].lower()
        if "+all" in record:
            findings.append(
                Finding(
                    id="dns.spf-open",
                    title="SPF ouvert (`+all`)",
                    severity=Severity.HIGH,
                    category=CATEGORY,
                    description="`+all` autorise n'importe quel serveur à envoyer au nom du domaine : "
                    "le SPF ne protège plus rien.",
                    evidence=spf[0],
                    remediation="Remplacez `+all` par `-all` (ou `~all` pendant la phase de test).",
                    reference="https://www.rfc-editor.org/rfc/rfc7208",
                )
            )
        elif "~all" in record:
            findings.append(
                Finding(
                    id="dns.spf-softfail",
                    title="SPF en mode softfail (~all)",
                    severity=Severity.LOW,
                    category=CATEGORY,
                    description="Le mode `~all` marque les e-mails illégitimes comme suspects mais ne "
                    "les rejette pas.",
                    evidence=spf[0],
                    remediation="Passez à `-all` après validation du trafic légitime.",
                    reference="https://www.rfc-editor.org/rfc/rfc7208",
                )
            )
        if "?all" in record:
            findings.append(
                Finding(
                    id="dns.spf-neutral",
                    title="SPF neutre (`?all`)",
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    description="`?all` revient à ne pas avoir de SPF.",
                    evidence=spf[0],
                    remediation="Publiez une politique explicite (`-all`).",
                    reference="https://www.rfc-editor.org/rfc/rfc7208",
                )
            )

    if not dmarc:
        findings.append(
            Finding(
                id="dns.dmarc-missing",
                title="DMARC absent",
                severity=Severity.MEDIUM,
                category=CATEGORY,
                description="Sans DMARC, le SPF et le DKIM ne sont pas appliqués : l'usurpation du "
                "domaine reste possible et vous n'avez aucun rapport sur ces tentatives.",
                evidence=f"Aucun TXT `v=DMARC1` pour _dmarc.{host}.",
                remediation="Publiez `v=DMARC1; p=none; rua=mailto:dmarc@votre-domaine` puis durcissez "
                "progressivement vers `p=reject`.",
                reference="https://www.rfc-editor.org/rfc/rfc7489",
            )
        )
    else:
        record = dmarc[0].lower()
        if "p=none" in record:
            findings.append(
                Finding(
                    id="dns.dmarc-none",
                    title="DMARC en surveillance seule (p=none)",
                    severity=Severity.LOW,
                    category=CATEGORY,
                    description="`p=none` ne bloque aucun e-mail usurpé ; il ne fait que collecter "
                    "des rapports.",
                    evidence=dmarc[0],
                    remediation="Après analyse des rapports, passez à `p=quarantine` puis `p=reject`.",
                    reference="https://www.rfc-editor.org/rfc/rfc7489",
                )
            )
        if "p=reject" in record:
            meta["dmarc"] = "p=reject"
        elif "p=quarantine" in record:
            meta["dmarc"] = "p=quarantine"

    if not caa:
        findings.append(
            Finding(
                id="dns.caa-missing",
                title="CAA absent",
                severity=Severity.INFO,
                category=CATEGORY,
                description="Sans CAA, n'importe quelle autorité de certification peut émettre un "
                "certificat pour votre domaine.",
                evidence=f"Aucun enregistrement CAA pour {host}.",
                remediation="Publiez un CAA limitant les émetteurs autorisés, par exemple "
                '`0 issue "letsencrypt.org"`.',
                reference="https://www.rfc-editor.org/rfc/rfc8659",
            )
        )
    else:
        meta["caa"] = ", ".join(caa[:2])

    return findings, meta
