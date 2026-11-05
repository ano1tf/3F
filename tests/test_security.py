"""Tests de non-régression sur la sécurité de l'instance VulnLens elle-même.

Chaque test correspond à une faille corrigée : SSRF via redirection, SSRF dans la
vérification de propriété, contournement de la limitation de débit par
`X-Forwarded-For`, CSRF, en-têtes de sécurité, fuite d'erreurs internes.
"""

from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from app import config, db, main, safety, verify
from app.main import app
from app.safety import ScanError, is_public_ip, validate_redirect_url
from app.scanner.fetcher import Fetcher

# --------------------------------------------------------------------------- #
# Serveurs de test : un « site public » qui redirige vers une cible interne
# --------------------------------------------------------------------------- #

class _Handler(BaseHTTPRequestHandler):
    server_version = "Test/1.0"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802
        location = getattr(self.server, "location", "")
        if location and self.path.startswith("/go"):
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.server.hits += 1  # type: ignore[attr-defined]
        payload = b"SECRET-INTERNE"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args: object) -> None:  # silence
        return


class _Server:
    def __init__(self, location: str = "") -> None:
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.location = location  # type: ignore[attr-defined]
        self.httpd.hits = 0  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self) -> _Server:
        self.thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    @property
    def hits(self) -> int:
        return self.httpd.hits  # type: ignore[attr-defined]


@pytest.fixture(autouse=True)
def _clean_rate_limit():
    main._RATE_LIMIT.clear()
    yield
    main._RATE_LIMIT.clear()


@pytest.fixture()
def client(temp_db):
    with TestClient(app) as test_client:
        yield test_client


# --------------------------------------------------------------------------- #
# 1. SSRF : une redirection vers une cible interne doit être refusée
# --------------------------------------------------------------------------- #

def test_redirect_to_cloud_metadata_is_blocked(monkeypatch):
    """Un site public ne doit pas pouvoir faire scanner http://169.254.169.254/.

    L'URL de départ est autorisée (on simule un hôte public) ; seule la
    redirection vise les métadonnées cloud. Avant le correctif, httpx suivait la
    redirection et renvoyait le contenu interne au scanner.
    """
    real = safety.is_public_ip
    monkeypatch.setattr(
        safety,
        "is_public_ip",
        lambda ip: True if str(ip) in {"127.0.0.1", "::1"} else real(ip),
    )

    with _Server("http://169.254.169.254/latest/meta-data/iam/security-credentials/") as site:

        async def run():
            async with Fetcher(allow_private=False) as fetcher:
                return await fetcher.get(f"http://127.0.0.1:{site.port}/go")

        response = asyncio.run(run())

    assert response.blocked is True
    assert response.status == 0
    assert "SSRF" in (response.error or "")
    assert response.history and response.history[0][1] == 302
    assert b"latest/meta-data" not in response.body


def test_redirect_to_internal_service_is_never_fetched(monkeypatch):
    """La cible interne ne reçoit aucune requête : le blocage est côté sortie."""
    real = safety.is_public_ip
    monkeypatch.setattr(
        safety,
        "is_public_ip",
        lambda ip: True if str(ip) == "127.0.0.1" else real(ip),
    )

    with _Server() as internal, _Server() as site:
        site.httpd.location = f"http://[::1]:{internal.port}/admin"  # type: ignore[attr-defined]

        async def run():
            async with Fetcher(allow_private=False) as fetcher:
                return await fetcher.get(f"http://127.0.0.1:{site.port}/go")

        response = asyncio.run(run())
        hits = internal.hits

    assert response.blocked is True
    assert hits == 0
    assert b"SECRET-INTERNE" not in response.body


def test_redirect_to_non_http_scheme_is_blocked(monkeypatch):
    real = safety.is_public_ip
    monkeypatch.setattr(
        safety, "is_public_ip", lambda ip: True if str(ip) == "127.0.0.1" else real(ip)
    )

    with _Server("file:///etc/passwd") as site:

        async def run():
            async with Fetcher(allow_private=False) as fetcher:
                return await fetcher.get(f"http://127.0.0.1:{site.port}/go")

        response = asyncio.run(run())

    assert response.blocked is True
    assert "schéma" in (response.error or "")


def test_redirect_to_localhost_hostname_is_blocked():
    with pytest.raises(ScanError) as excinfo:
        asyncio.run(validate_redirect_url("http://localhost:8080/admin"))
    assert excinfo.value.code == "blocked_redirect"


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/",  # métadonnées Alibaba (CGNAT)
        "http://10.0.0.10/",
        "http://192.168.1.1/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://0.0.0.0/",
        "http://198.18.0.1/",
    ],
)
def test_internal_addresses_are_never_public(url):
    with pytest.raises(ScanError):
        asyncio.run(validate_redirect_url(url, allow_private=False))


def test_public_addresses_are_accepted():
    assert is_public_ip("93.184.216.34") is True
    assert is_public_ip("2606:2800:220:1:248:1893:25c8:1946") is True
    assert is_public_ip("169.254.169.254") is False
    assert is_public_ip("100.100.100.200") is False


def test_allow_private_keeps_local_development_working():
    """Le mode développement (VULNLENS_ALLOW_PRIVATE=1) reste utilisable."""
    target = asyncio.run(validate_redirect_url("http://127.0.0.1:8000/", allow_private=True))
    assert target.host == "127.0.0.1"


# --------------------------------------------------------------------------- #
# 2. SSRF via la vérification de propriété (/api/verify)
# --------------------------------------------------------------------------- #

def test_verify_never_fetches_private_hosts(monkeypatch):
    monkeypatch.setattr(config, "ALLOW_PRIVATE_TARGETS", False)

    async def boom(*_args, **_kwargs):
        raise AssertionError("aucune requête ne doit partir vers un hôte interne")

    monkeypatch.setattr(Fetcher, "_send", boom)

    assert asyncio.run(verify.check_file("169.254.169.254", "jeton")) is False
    assert asyncio.run(verify.check_file("metadata.google.internal", "jeton")) is False
    assert asyncio.run(verify.check_file("127.0.0.1", "jeton")) is False


def test_api_verify_check_rejects_metadata_host(client, monkeypatch):
    monkeypatch.setattr(config, "ALLOW_PRIVATE_TARGETS", False)
    monkeypatch.setattr(verify, "check_dns", _never)
    monkeypatch.setattr(verify, "check_file", _never_async)

    payload = client.post("/api/verify/169.254.169.254/check").json()
    assert payload["verified"] is False


async def _never(*_args, **_kwargs) -> bool:
    return False


async def _never_async(*_args, **_kwargs) -> bool:
    return False


# --------------------------------------------------------------------------- #
# 3. Limitation de débit : X-Forwarded-For n'est plus falsifiable
# --------------------------------------------------------------------------- #

def _request(headers: dict[str, str], client_ip: str = "9.9.9.9") -> Request:
    raw = [(name.lower().encode(), value.encode()) for name, value in headers.items()]
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/scan",
        "headers": raw,
        "client": (client_ip, 4242),
        "query_string": b"",
    }
    return Request(scope)


def test_forwarded_for_is_ignored_by_default(monkeypatch):
    monkeypatch.setattr(config, "TRUST_PROXY_HEADERS", False)
    request = _request({"x-forwarded-for": "1.2.3.4"})
    assert main._client_key(request) == "9.9.9.9"


def test_forwarded_for_used_only_behind_trusted_proxy(monkeypatch):
    monkeypatch.setattr(config, "TRUST_PROXY_HEADERS", True)
    request = _request({"x-forwarded-for": "1.2.3.4, 10.0.0.1"})
    assert main._client_key(request) == "10.0.0.1"


def test_verify_check_is_rate_limited(client, monkeypatch):
    monkeypatch.setattr(verify, "check_dns", _never)
    monkeypatch.setattr(verify, "check_file", _never_async)

    statuses = [
        client.post(
            "/api/verify/cible.test/check",
            headers={"X-Forwarded-For": f"10.0.0.{index}"},
        ).status_code
        for index in range(main._RATE_MAX_VERIFY + 2)
    ]
    assert 429 in statuses
    # Changer X-Forwarded-For ne suffit pas à réinitialiser le compteur.
    assert statuses[-1] == 429


# --------------------------------------------------------------------------- #
# 4. CSRF : une page tierce ne peut pas déclencher d'action
# --------------------------------------------------------------------------- #

def test_cross_origin_post_is_refused(client):
    response = client.post(
        "/api/watch/exemple.fr/run",
        headers={"Origin": "https://attaquant.test"},
    )
    assert response.status_code == 403


def test_cross_site_fetch_metadata_is_refused(client):
    response = client.post(
        "/api/watch/exemple.fr/run",
        headers={"Sec-Fetch-Site": "cross-site"},
    )
    assert response.status_code == 403


def test_same_origin_post_is_allowed(client):
    response = client.post(
        "/api/watch/exemple.fr/run",
        headers={"Origin": "http://testserver"},
    )
    # 404 : la cible n'est pas surveillée. Le point important est l'absence de 403.
    assert response.status_code == 404


# --------------------------------------------------------------------------- #
# 5. En-têtes de sécurité et neutralisation des exports
# --------------------------------------------------------------------------- #

def test_security_headers_on_ui(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"


def test_report_export_is_neutralised(client):
    asyncio.run(
        db.save_scan(
            {
                "scan_id": "export1",
                "target": "https://cible.test/",
                "final_url": "https://cible.test/",
                "started_at": "2026-03-10T09:00:00+00:00",
                "duration_ms": 10,
                "score": 50,
                "grade": "C",
                "profile": "quick",
                "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "findings": [],
            }
        )
    )
    response = client.get("/api/scans/export1/report.html")
    assert response.status_code == 200
    assert response.headers["content-disposition"].startswith("attachment;")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in response.headers["content-security-policy"]


def test_export_filename_ignores_path_characters(client):
    asyncio.run(
        db.save_scan(
            {
                "scan_id": "../../etc/passwd",
                "target": "https://cible.test/",
                "final_url": "https://cible.test/",
                "started_at": "2026-03-10T09:00:00+00:00",
                "duration_ms": 10,
                "score": 50,
                "grade": "C",
                "profile": "quick",
                "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "findings": [],
            }
        )
    )
    response = client.get("/api/scans/..%2F..%2Fetc%2Fpasswd/sarif")
    if response.status_code == 200:
        name = response.headers["content-disposition"]
        assert ".." not in name and "/" not in name.split("filename=")[1]


# --------------------------------------------------------------------------- #
# 6. Authentification et fuite d'erreurs
# --------------------------------------------------------------------------- #

def test_token_check_rejects_prefix_and_empty_values(client, monkeypatch):
    monkeypatch.setattr(config, "AUTH_TOKEN", "s3cret-token")
    assert client.get("/api/meta", headers={"Authorization": "Bearer s3cret"}).status_code == 401
    assert client.get("/api/meta", headers={"Authorization": "Bearer "}).status_code == 401
    assert client.get("/api/meta", headers={"X-API-Key": ""}).status_code == 401
    assert (
        client.get("/api/meta", headers={"Authorization": "Bearer s3cret-token"}).status_code == 200
    )


def test_internal_error_details_are_not_exposed(client, monkeypatch):
    from app.scanner import engine

    async def explode(*_args, **_kwargs):
        raise RuntimeError("mot-de-passe-interne-dans-la-trace")

    monkeypatch.setattr(main, "run_scan", explode)
    assert engine  # garde l'import explicite lisible

    response = client.post(
        "/api/scan", json={"url": "https://exemple.fr", "authorized": True, "profile": "quick"}
    )
    body = response.text
    assert "mot-de-passe-interne" not in body
    assert "internal" in body


# --------------------------------------------------------------------------- #
# 7. AXFR : ne jamais ouvrir de connexion vers un serveur DNS interne
# --------------------------------------------------------------------------- #

def test_axfr_skips_internal_nameservers(monkeypatch):
    import dns.query
    import dns.resolver

    from app.scanner import checks_deep

    class _NS:
        def __init__(self, target: str) -> None:
            self.target = target

    monkeypatch.setattr(config, "ALLOW_PRIVATE_TARGETS", False)
    monkeypatch.setattr(
        dns.resolver, "resolve", lambda *_args, **_kwargs: [_NS("ns1.interne.test.")]
    )
    monkeypatch.setattr(checks_deep, "_resolve", lambda _host: ["10.0.0.5"])

    def boom(*_args, **_kwargs):
        raise AssertionError("aucune connexion AXFR vers une adresse interne")

    monkeypatch.setattr(dns.query, "xfr", boom)

    transferred, _detail = checks_deep._attempt_axfr("cible.test")
    assert transferred is False
