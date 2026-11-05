"""Sécurité e-mail : DMARC, SPF, DKIM, MTA-STS, TLS-RPT (DNS simulé)."""

from __future__ import annotations

import asyncio

from app.scanner import checks_email


def run(records: dict[str, list[str]]):
    async def fake_txt(name: str) -> list[str]:
        return records.get(name, [])

    original = checks_email._txt
    checks_email._txt = fake_txt
    try:
        return asyncio.run(checks_email.check_email("cible.test"))
    finally:
        checks_email._txt = original


def ids_for(records: dict[str, list[str]]) -> set[str]:
    findings, _meta = run(records)
    return {finding.id for finding in findings}


def test_dmarc_none_is_flagged():
    ids = ids_for({"_dmarc.cible.test": ["v=DMARC1; p=none; rua=mailto:dmarc@cible.test"]})
    assert "email.dmarc-none" in ids


def test_dmarc_reject_without_sp_flags_subdomains():
    ids = ids_for({"_dmarc.cible.test": ["v=DMARC1; p=reject; rua=mailto:d@cible.test"]})
    assert "email.dmarc-subdomain-policy" in ids
    assert "email.dmarc-none" not in ids


def test_dmarc_reject_with_sp_is_clean():
    ids = ids_for({"_dmarc.cible.test": ["v=DMARC1; p=reject; sp=reject; rua=mailto:d@cible.test"]})
    assert "email.dmarc-subdomain-policy" not in ids


def test_spf_too_many_lookups():
    includes = " ".join(f"include:spf{i}.test" for i in range(12))
    ids = ids_for({"cible.test": [f"v=spf1 {includes} -all"]})
    assert "email.spf-too-many-lookups" in ids


def test_spf_reasonable_is_clean():
    ids = ids_for({"cible.test": ["v=spf1 include:_spf.google.com include:mail.test -all"]})
    assert "email.spf-too-many-lookups" not in ids


def test_missing_dkim_and_mta_sts_are_reported():
    ids = ids_for({"cible.test": ["v=spf1 -all"], "_dmarc.cible.test": ["v=DMARC1; p=reject"]})
    assert "email.dkim-missing" in ids
    assert "email.mta-sts-missing" in ids
    assert "email.tls-rpt-missing" in ids


def test_full_configuration_is_clean():
    ids = ids_for(
        {
            "cible.test": ["v=spf1 -all"],
            "_dmarc.cible.test": ["v=DMARC1; p=reject; sp=reject"],
            "google._domainkey.cible.test": ["v=DKIM1; k=rsa; p=MIGfMA0GCSq"],
            "_mta-sts.cible.test": ["v=STSv1; id=20260101"],
            "_smtp._tls.cible.test": ["v=TLSRPTv1; rua=mailto:tls@cible.test"],
        }
    )
    assert ids == set()


def test_no_dns_data_no_finding_for_ip():
    findings, meta = asyncio.run(checks_email.check_email("127.0.0.1"))
    assert findings == [] and meta == {}


def test_metadata_written():
    _findings, meta = run(
        {
            "cible.test": ["v=spf1 include:a.test include:b.test -all"],
            "_dmarc.cible.test": ["v=DMARC1; p=quarantine"],
            "default._domainkey.cible.test": ["v=DKIM1; p=ABC"],
            "_mta-sts.cible.test": ["v=STSv1; id=1"],
        }
    )
    assert meta["dmarc"] == "quarantine"
    assert meta["spf_lookups"] == "2"
    assert meta["dkim"] == "default"
    assert meta["mta_sts"] == "activé"
