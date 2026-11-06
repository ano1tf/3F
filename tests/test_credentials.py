"""En-tête d'authentification : validation stricte, envoi ciblé, jamais reporté."""

from __future__ import annotations

import asyncio
import sys
from urllib.parse import urlsplit

import pytest

from app import config, credentials
from app.scanner.fetcher import Fetcher
from tests.fixtures.bad_server import FixtureServer

sys.path.insert(0, ".")


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


def test_authorization_header_is_accepted():
    name, value = credentials.parse("Authorization: Bearer abc.def.ghi")
    assert (name, value) == ("Authorization", "Bearer abc.def.ghi")


def test_bare_token_becomes_bearer():
    name, value = credentials.parse("abc123")
    assert (name, value) == ("Authorization", "Bearer abc123")


def test_cookie_header_is_accepted():
    name, value = credentials.parse("Cookie: session=xyz; other=1")
    assert name == "Cookie"
    assert value.startswith("session=xyz")


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "X-Forwarded-Host: evil.test",
        "Host: autre.test",
        "Authorization: ",
        "Authorization",
        "Bad Name: valeur",
        "Authorization: Bearer abc\r\nX-Injected: 1",
    ],
)
def test_refused_headers(raw):
    with pytest.raises(credentials.AuthHeaderError):
        credentials.parse(raw)


def test_too_long_value_is_refused():
    with pytest.raises(credentials.AuthHeaderError):
        credentials.parse("Authorization: Bearer " + "a" * (credentials.MAX_LENGTH + 10))


def test_mask_never_reveals_the_token():
    masked = credentials.mask("Bearer supersecrettoken")
    assert "supersecrettoken" not in masked
    assert masked.startswith("Bearer su")


def test_kind_of_authentication():
    assert credentials.kind("Cookie: a=1") == "cookie"
    assert credentials.kind("Authorization: Bearer abc") == "bearer"
    assert credentials.kind("Authorization: Basic YWJj") == "basic"
    assert credentials.kind("X-Api-Key: abc") == "en-tête personnalisé"


# --------------------------------------------------------------------------
# Envoi : uniquement vers l'hôte analysé
# --------------------------------------------------------------------------


def test_auth_header_is_sent_to_the_target_host_only():
    config.ALLOW_PRIVATE_TARGETS = True
    with FixtureServer() as target, FixtureServer() as third_party:
        target_host = urlsplit(target.url).netloc

        async def run() -> tuple[str, str]:
            async with Fetcher(
                allow_private=True,
                auth=("Authorization", "Bearer test-token"),
                auth_host=target_host,
            ) as fetcher:
                ours = await fetcher.get(target.url + "/echo-headers")
                foreign = await fetcher.get(third_party.url + "/echo-headers")
                return ours.text, foreign.text

        mine, other = asyncio.run(run())

    assert "Bearer test-token" in mine
    # Le jeton ne doit jamais partir vers un domaine tiers rencontré en chemin.
    assert "Bearer test-token" not in other
    assert "absente" in other


def test_auth_is_absent_after_a_redirect_to_another_host():
    """Un 302 vers un autre hôte ne doit pas emporter l'en-tête avec lui."""
    from urllib.parse import quote

    config.ALLOW_PRIVATE_TARGETS = True
    with FixtureServer() as target, FixtureServer() as third_party:
        target_host = urlsplit(target.url).netloc
        destination = third_party.url + "/echo-headers"

        async def run() -> str:
            async with Fetcher(
                allow_private=True,
                auth=("Authorization", "Bearer test-token"),
                auth_host=target_host,
            ) as fetcher:
                response = await fetcher.get(
                    target.url + "/redirection-externe?vers=" + quote(destination, safe="")
                )
                return response.text

        body = asyncio.run(run())

    # Le saut a bien eu lieu (contenu de l'autre serveur), sans le jeton.
    assert "Authorization=" in body
    assert "Bearer test-token" not in body


# --------------------------------------------------------------------------
# Journal des requêtes
# --------------------------------------------------------------------------


def test_fetcher_records_every_request_without_query_string():
    config.ALLOW_PRIVATE_TARGETS = True
    with FixtureServer() as server:

        async def run() -> tuple[Fetcher, str]:
            fetcher = Fetcher(allow_private=True)
            try:
                await fetcher.get(server.url + "/recherche?q=secret-interne&token=abc")
                return fetcher, server.url
            finally:
                await fetcher.close()

        fetcher, _ = asyncio.run(run())

    entry = fetcher.log[0]
    assert entry["method"] == "GET"
    assert entry["status"] == 200
    assert entry["url"].endswith("/recherche")
    # La chaîne de requête n'est pas recopiée : elle peut contenir des jetons.
    assert "secret-interne" not in entry["url"]

    summary = fetcher.summary()
    assert summary["total"] == 1
    assert summary["by_method"] == {"GET": 1}
    assert summary["read_only"] is True
    assert summary["write_methods"] == 0


def test_blocked_requests_are_counted():
    config.ALLOW_PRIVATE_TARGETS = False

    async def run() -> Fetcher:
        fetcher = Fetcher(allow_private=False)
        try:
            await fetcher.get("http://127.0.0.1:9/")
            return fetcher
        finally:
            await fetcher.close()

    fetcher = asyncio.run(run())
    assert fetcher.log and fetcher.log[0]["note"] == "bloquée"
    assert fetcher.summary()["blocked"] == 1


# --------------------------------------------------------------------------
# API : refus explicite d'un en-tête non autorisé
# --------------------------------------------------------------------------


def test_api_refuses_unsafe_auth_header(monkeypatch):
    from fastapi.testclient import TestClient

    from app import main

    client = TestClient(main.app)
    response = client.post(
        "/api/scan",
        json={"url": "https://exemple.fr", "authorized": True, "auth": "Host: pirate.test"},
    )
    assert response.status_code == 400
    body = response.json()
    message = body.get("detail") or body.get("error") or ""
    assert "non autorisé" in message


def test_api_accepts_a_valid_auth_header(monkeypatch):
    """L'en-tête valide n'est pas rejeté par la validation (la cible est refusée après)."""
    from fastapi.testclient import TestClient

    from app import main

    monkeypatch.setattr(config, "ALLOW_PRIVATE_TARGETS", False)
    client = TestClient(main.app)
    response = client.post(
        "/api/scan",
        json={"url": "http://127.0.0.1:9/", "authorized": True, "auth": "Cookie: sid=abc"},
    )
    # La validation de l'en-tête passe : le refus vient de la cible interne, pas de l'en-tête.
    assert response.status_code == 200
    assert "non autorisé" not in response.text
    assert "cible interne" in response.text
