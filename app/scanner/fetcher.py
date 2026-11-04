"""Client HTTP instrumenté : garde la trace des en-têtes, redirections et du corps."""

from __future__ import annotations

import asyncio
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from .. import config


@dataclass
class HttpResponse:
    url: str
    status: int = 0
    headers: httpx.Headers = field(default_factory=httpx.Headers)
    body: bytes = b""
    history: list[tuple[str, int]] = field(default_factory=list)
    elapsed_ms: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and 0 < self.status < 500

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def header(self, name: str) -> str:
        return self.headers.get(name, "") if self.headers else ""


class Fetcher:
    """Petit wrapper httpx avec limites strictes (taille, durée, redirections)."""

    def __init__(self, allow_private: bool = False) -> None:
        self.allow_private = allow_private
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(config.HTTP_TIMEOUT, connect=min(8.0, config.HTTP_TIMEOUT)),
            follow_redirects=True,
            max_redirects=config.MAX_REDIRECTS,
            verify=True,
            headers={
                "User-Agent": config.USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
                "Connection": "close",
            },
            limits=httpx.Limits(max_connections=12, max_keepalive_connections=4),
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> Fetcher:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
        max_bytes: int = config.MAX_BODY_BYTES,
        read_body: bool = True,
        timeout: float | None = None,
    ) -> HttpResponse:
        started = time.perf_counter()
        try:
            async with self._client.stream(
                method,
                url,
                headers=headers,
                follow_redirects=follow_redirects,
                timeout=timeout or config.HTTP_TIMEOUT,
            ) as response:
                body = b""
                if read_body:
                    chunks: list[bytes] = []
                    size = 0
                    async for chunk in response.aiter_bytes():
                        chunks.append(chunk)
                        size += len(chunk)
                        if size >= max_bytes:
                            break
                    body = b"".join(chunks)[:max_bytes]
                history = [(str(r.url), r.status_code) for r in response.history]
                return HttpResponse(
                    url=str(response.url),
                    status=response.status_code,
                    headers=response.headers,
                    body=body,
                    history=history,
                    elapsed_ms=int((time.perf_counter() - started) * 1000),
                )
        except httpx.TooManyRedirects as exc:
            return HttpResponse(url=str(url), error=f"Trop de redirections ({exc})")
        except httpx.TimeoutException:
            return HttpResponse(url=str(url), error="Délai dépassé")
        except httpx.HTTPError as exc:
            return HttpResponse(url=str(url), error=f"{type(exc).__name__}: {exc}")
        except Exception as exc:  # pragma: no cover - filet de sécurité
            return HttpResponse(url=str(url), error=f"Erreur inattendue: {exc}")

    async def get(self, url: str, **kwargs: object) -> HttpResponse:
        return await self.request("GET", url, **kwargs)  # type: ignore[arg-type]

    async def head(self, url: str, **kwargs: object) -> HttpResponse:
        return await self.request("HEAD", url, read_body=False, **kwargs)  # type: ignore[arg-type]

    async def parallel(self, coros: list, limit: int = config.PATH_PROBE_CONCURRENCY) -> list:
        semaphore = asyncio.Semaphore(limit)

        async def guarded(coro):
            async with semaphore:
                return await coro

        return await asyncio.gather(*(guarded(c) for c in coros))


# --------------------------------------------------------------------------
# TLS : négociation directe, certificat et versions de protocole acceptées
# --------------------------------------------------------------------------


def _handshake(host: str, port: int, min_version=None, insecure: bool = False) -> dict:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_default_certs()
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except NotImplementedError:  # pragma: no cover - OpenSSL minimal
        pass
    if min_version is not None:
        ctx.minimum_version = min_version
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")

    with socket_create(host, port, ctx) as ssock:
        cert = ssock.getpeercert() or {}
        try:
            alpn = ssock.selected_alpn_protocol() or ""
        except Exception:  # pragma: no cover
            alpn = ""
        return {
            "protocol": ssock.version() or "",
            "cipher": ssock.cipher() or (),
            "cert": cert,
            "alpn": alpn,
        }


def socket_create(host: str, port: int, ctx: ssl.SSLContext):
    import socket

    raw = socket.create_connection((host, port), timeout=config.HTTP_TIMEOUT)
    try:
        return ctx.wrap_socket(raw, server_hostname=host)
    except Exception:
        raw.close()
        raise


async def tls_probe(host: str, port: int) -> dict:
    """Renvoie protocole, certificat et versions faibles acceptées."""
    result: dict = {"enabled": False, "protocol": "", "cipher": "", "cert": {}, "error": ""}

    def _run() -> dict:
        info: dict = {"enabled": True}
        try:
            main = _handshake(host, port)
            info.update(main)
        except ssl.SSLCertVerificationError as exc:
            info["cert_error"] = exc.verify_message or str(exc)
            info.update(_handshake(host, port, insecure=True))
        except Exception as exc:
            return {"enabled": False, "error": f"{type(exc).__name__}: {exc}"}

        weak: list[str] = []
        for label, version in (
            ("TLS 1.0", ssl.TLSVersion.TLSv1),
            ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
        ):
            try:
                _handshake(host, port, min_version=version, insecure=True)
                weak.append(label)
            except Exception:
                pass
        info["weak_protocols"] = weak

        try:
            _handshake(host, port, min_version=ssl.TLSVersion.TLSv1_3, insecure=True)
            info["supports_tls13"] = True
        except Exception:
            info["supports_tls13"] = False
        return info

    try:
        result = await asyncio.to_thread(_run)
    except Exception as exc:  # pragma: no cover
        result = {"enabled": False, "error": str(exc)}
    return result


def same_origin(url_a: str, url_b: str) -> bool:
    a, b = urlsplit(url_a), urlsplit(url_b)
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)


def absolute(base: str, link: str) -> str:
    try:
        return urljoin(base, link)
    except Exception:
        return link
