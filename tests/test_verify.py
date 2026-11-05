"""Preuve de propriété : jeton, instructions, vérification DNS et fichier."""

from __future__ import annotations

import asyncio

from app import verify


def test_status_creates_and_reuses_token(temp_db):
    first = asyncio.run(verify.status("cible.test"))
    second = asyncio.run(verify.status("cible.test"))
    assert first["token"] == second["token"]
    assert len(first["token"]) == 32
    assert first["verified"] is False
    assert first["instructions"]["record_name"] == "_vulnlens.cible.test"
    assert first["token"] in first["instructions"]["record_value"]


def test_dns_check_matches_expected_value(monkeypatch):
    async def fake_txt(name: str) -> list[str]:
        assert name == "_vulnlens.cible.test"
        return ["v=spf1 -all", "vulnlens-verification=abc123"]

    monkeypatch.setattr(verify, "_dns_txt", fake_txt)
    assert asyncio.run(verify.check_dns("cible.test", "abc123")) is True
    assert asyncio.run(verify.check_dns("cible.test", "autre")) is False


def test_verify_marks_domain_verified(monkeypatch, temp_db):
    status = asyncio.run(verify.status("cible.test"))

    async def fake_dns(_host: str, token: str) -> bool:
        return token == status["token"]

    monkeypatch.setattr(verify, "check_dns", fake_dns)
    monkeypatch.setattr(verify, "check_file", _always_false)

    result = asyncio.run(verify.verify("cible.test"))
    assert result["verified"] is True
    assert result["method"] == "dns"
    assert asyncio.run(verify.is_verified("cible.test")) is True


def test_verify_falls_back_to_file(monkeypatch, temp_db):
    async def fake_file(_host: str, token: str) -> bool:
        return bool(token)

    monkeypatch.setattr(verify, "check_dns", _always_false)
    monkeypatch.setattr(verify, "check_file", fake_file)

    result = asyncio.run(verify.verify("cible.test"))
    assert result["verified"] is True
    assert result["method"] == "fichier"


def test_verify_without_proof(monkeypatch, temp_db):
    monkeypatch.setattr(verify, "check_dns", _always_false)
    monkeypatch.setattr(verify, "check_file", _always_false)

    result = asyncio.run(verify.verify("cible.test"))
    assert result["verified"] is False
    assert "Aucune preuve" in result["detail"]


def test_is_verified_is_safe_without_db(monkeypatch):
    def boom(_host: str) -> bool:
        raise RuntimeError("db down")

    monkeypatch.setattr(verify.db, "is_verified", boom)
    assert asyncio.run(verify.is_verified("cible.test")) is False


async def _always_false(_host: str, _token: str) -> bool:
    return False
