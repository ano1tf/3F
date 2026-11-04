"""Contrôle du certificat et de la négociation TLS."""

from __future__ import annotations

from datetime import UTC, datetime

from ..models import Finding, Severity
from .fetcher import tls_probe


async def _analyse_tls(host: str, port: int) -> tuple[list[Finding], dict]:
    info = await tls_probe(host, port)
    findings: list[Finding] = []

    if not info.get("enabled"):
        findings.append(
            Finding(
                id="tls.unreachable",
                title="TLS injoignable",
                severity=Severity.HIGH,
                category="TLS",
                description="Impossible de négocier une connexion TLS sur ce port. Le site est "
                "peut-être servi uniquement en HTTP, ou un intergiciel interfère.",
                evidence=info.get("error", ""),
                remediation="Exposez le service en HTTPS avec un certificat valide.",
                reference="https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
            )
        )
        return findings, info

    cert = info.get("cert") or {}
    if not cert:
        findings.append(
            Finding(
                id="tls.no-cert",
                title="Aucun certificat lisible",
                severity=Severity.MEDIUM,
                category="TLS",
                description="Le certificat présenté n'a pas pu être analysé.",
                evidence=info.get("cert_error", ""),
                remediation="Vérifiez la chaîne de certification servie par le serveur.",
            )
        )
        return findings, info

    if info.get("cert_error"):
        findings.append(
            Finding(
                id="tls.invalid-cert",
                title="Certificat non valide pour les navigateurs",
                severity=Severity.HIGH,
                category="TLS",
                description="La validation échoue (certificat auto-signé, chaîne incomplète ou nom "
                "d'hôte absent du certificat). Les visiteurs voient un avertissement de sécurité.",
                evidence=info["cert_error"],
                remediation="Installez un certificat émis par une autorité reconnue (Let's Encrypt) "
                "en incluant la chaîne intermédiaire.",
                reference="https://www.ssllabs.com/ssltest/",
            )
        )

    not_after = cert.get("notAfter")
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
            days_left = (expiry - datetime.now(UTC)).days
            if days_left < 0:
                findings.append(
                    Finding(
                        id="tls.expired",
                        title="Certificat expiré",
                        severity=Severity.HIGH,
                        category="TLS",
                        description="Le certificat a expiré : les navigateurs bloquent l'accès.",
                        evidence=f"Expiré le {not_after} ({abs(days_left)} jours).",
                        remediation="Renouvelez immédiatement le certificat et automatisez le "
                        "renouvellement (ACME).",
                    )
                )
            elif days_left < 21:
                findings.append(
                    Finding(
                        id="tls.expiring-soon",
                        title="Certificat bientôt expiré",
                        severity=Severity.MEDIUM,
                        category="TLS",
                        description="L'expiration approche : prévoyez le renouvellement pour éviter "
                        "une indisponibilité.",
                        evidence=f"Expire le {not_after} (dans {days_left} jours).",
                        remediation="Renouvelez le certificat et mettez en place un renouvellement "
                        "automatique.",
                    )
                )
        except ValueError:
            pass

    # Durée de validité : au-delà de 398 jours, Chrome et Safari refusent le certificat.
    not_before = cert.get("notBefore")
    if not_before and not_after:
        try:
            start = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
            end = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            lifetime = (end - start).days
            if lifetime > 398:
                findings.append(
                    Finding(
                        id="tls.validity-too-long",
                        title="Certificat de validité trop longue",
                        severity=Severity.LOW,
                        category="TLS",
                        description="Les navigateurs (Chrome, Safari) rejettent les certificats "
                        "émis pour plus de 398 jours : les visiteurs risquent un avertissement.",
                        evidence=f"Validité de {lifetime} jours ({not_before} → {not_after}).",
                        remediation="Réduisez la durée de vie et automatisez le renouvellement (ACME).",
                        reference="https://cabforum.org/working-groups/server/baseline-requirements/",
                    )
                )
        except ValueError:
            pass

    protocol = info.get("protocol", "")
    cipher = info.get("cipher") or ("", "", 0)
    if protocol in {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}:
        findings.append(
            Finding(
                id="tls.outdated-protocol",
                title=f"Protocole obsolète négocié ({protocol})",
                severity=Severity.HIGH,
                category="TLS",
                description="TLS 1.0/1.1 sont dépréciés et vulnérables (BEAST, POODLE).",
                evidence=f"{protocol} / {cipher[0]}",
                remediation="Configurez TLS 1.2 minimum, idéalement TLS 1.3.",
                reference="https://www.rfc-editor.org/rfc/rfc8996",
            )
        )

    weak = info.get("weak_protocols") or []
    if weak:
        findings.append(
            Finding(
                id="tls.weak-protocols-accepted",
                title="Protocoles TLS obsolètes acceptés",
                severity=Severity.MEDIUM,
                category="TLS",
                description="Le serveur accepte encore des négociations qui devraient être refusées.",
                evidence=f"Acceptés : {', '.join(weak)}",
                remediation="Désactivez TLS 1.0 et TLS 1.1 côté serveur.",
                reference="https://www.rfc-editor.org/rfc/rfc8996",
            )
        )

    if not info.get("supports_tls13"):
        findings.append(
            Finding(
                id="tls.no-tls13",
                title="TLS 1.3 non pris en charge",
                severity=Severity.LOW,
                category="TLS",
                description="TLS 1.3 apporte une meilleure confidentialité et de meilleures "
                "performances ; son absence indique souvent une pile logicielle ancienne.",
                evidence=f"Protocole négocié : {protocol}",
                remediation="Activez TLS 1.3 sur le serveur ou le CDN.",
                reference="https://www.rfc-editor.org/rfc/rfc8446",
            )
        )

    if cipher and cipher[2] and cipher[2] < 128:
        findings.append(
            Finding(
                id="tls.weak-cipher",
                title="Suite cryptographique faible",
                severity=Severity.MEDIUM,
                category="TLS",
                description="La suite de chiffrement négociée utilise une clé courte.",
                evidence=f"{cipher[0]} ({cipher[2]} bits)",
                remediation="Désactivez les suites faibles et privilégiez AEAD (AES-GCM, ChaCha20).",
                reference="https://www.ssllabs.com/ssltest/",
            )
        )
    return findings, info


async def check_tls(host: str, port: int) -> tuple[list[Finding], dict[str, str]]:
    """Contrôle TLS + empreinte lisible (version, chiffrement, certificat)."""
    findings, info = await _analyse_tls(host, port)
    return findings, describe_certificate(info)


def describe_certificate(info: dict) -> dict[str, str]:
    """Résumé lisible du certificat pour l'onglet « empreinte »."""
    cert = info.get("cert") or {}
    if not cert:
        return {}
    subject = {k: v for item in cert.get("subject", ()) for k, v in item}
    issuer = {k: v for item in cert.get("issuer", ()) for k, v in item}
    san = [entry[1] for entry in cert.get("subjectAltName", ()) if entry[0].lower() == "dns"]
    return {
        "tls_version": info.get("protocol", ""),
        "tls_cipher": (info.get("cipher") or ("",))[0],
        "http2": "oui" if info.get("alpn") == "h2" else "non",
        "certificat_sujet": subject.get("commonName", ""),
        "certificat_emetteur": issuer.get("organizationName", "") or issuer.get("commonName", ""),
        "certificat_expire": cert.get("notAfter", ""),
        "certificat_domaines": ", ".join(san[:4]) + ("…" if len(san) > 4 else ""),
    }
