"""Point d'entrée FastAPI : UI statique + API d'analyse en streaming (NDJSON)."""

from __future__ import annotations

import asyncio
import json
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import (
    FileResponse,
    JSONResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import config, db, reporting
from .models import SEVERITY_LABELS_FR
from .safety import ScanError, normalize_target
from .scanner.engine import run_scan

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"

@asynccontextmanager
async def lifespan(_app: FastAPI):
    await db.init()
    yield


app = FastAPI(
    title=config.APP_NAME,
    version=config.APP_VERSION,
    description="Scanner de vulnérabilités web passif, pour des tests de sécurité autorisés.",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

_SEMAPHORE = asyncio.Semaphore(config.MAX_CONCURRENT_SCANS)
_RATE_LIMIT: dict[str, deque[float]] = defaultdict(deque)
_RATE_WINDOW = 300.0
_RATE_MAX = 15


class ScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, examples=["https://exemple.fr"])
    authorized: bool = Field(
        False,
        description="Confirme que l'utilisateur est autorisé à tester cette cible.",
    )
    profile: Literal["quick", "deep"] = Field(
        "quick",
        description="`quick` : contrôles passifs standards. `deep` : + AXFR, sous-domaines, redirections ouvertes.",
    )


def _event(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False) + "\n"


def _client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "inconnu"


def _check_rate_limit(key: str) -> None:
    now = time.monotonic()
    bucket = _RATE_LIMIT[key]
    while bucket and now - bucket[0] > _RATE_WINDOW:
        bucket.popleft()
    if len(bucket) >= _RATE_MAX:
        raise HTTPException(
            status_code=429,
            detail="Trop d'analyses lancées. Patiente quelques minutes avant de réessayer.",
        )
    bucket.append(now)


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "app": config.APP_NAME, "version": config.APP_VERSION}


@app.get("/api/meta")
async def meta() -> dict:
    return {
        "app": config.APP_NAME,
        "version": config.APP_VERSION,
        "tagline": config.APP_TAGLINE,
        "user_agent": config.USER_AGENT,
        "profiles": [
            {
                "key": "quick",
                "label": "Rapide",
                "detail": "En-têtes, TLS, cookies, CORS, 38 fichiers, contenu, DNS",
            },
            {
                "key": "deep",
                "label": "Approfondi",
                "detail": "Tout + transfert de zone, sous-domaines, redirections ouvertes",
            },
        ],
        "severities": [
            {"key": sev.value, "label": label, "weight": sev.weight}
            for sev, label in SEVERITY_LABELS_FR.items()
        ],
        "scope": [
            "Transport : HTTPS, redirections, HSTS",
            "TLS : certificat, expiration, protocoles obsolètes",
            "En-têtes : CSP directive par directive, clickjacking, MIME sniffing, Referrer-Policy",
            "Cookies : Secure, HttpOnly, SameSite, préfixes __Host- / __Secure-",
            "CORS : origine reflétée, joker, credentials",
            "Méthodes HTTP : OPTIONS, TRACE",
            "Fichiers exposés : .git/.env, sauvegardes, .aws, logs, Actuator, phpMyAdmin…",
            "Fuite d'information : versions, traces d'erreur, commentaires HTML",
            "Contenu : contenu mixte, formulaires non chiffrés, SRI, iframes, CSRF, cache",
            "DNS : SPF, DMARC, CAA",
        ],
        "limits": [
            "Aucune tentative d'exploitation, aucune charge destructive",
            "Aucun test d'injection, de force brute ou de déni de service",
            "Les cibles internes (localhost, réseau privé) sont refusées",
            "Analyses limitées en débit et en durée",
        ],
    }


@app.post("/api/scan")
async def scan(payload: ScanRequest, request: Request) -> StreamingResponse:
    if not payload.authorized:
        raise HTTPException(
            status_code=403,
            detail="Tu dois confirmer que tu es autorisé à analyser cette cible.",
        )
    try:
        target = normalize_target(payload.url)
    except ScanError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc

    _check_rate_limit(_client_key(request))

    async def driver():
        yield _event({"type": "accepted", "target": target})
        if _SEMAPHORE.locked():
            yield _event(
                {
                    "type": "error",
                    "code": "busy",
                    "message": "Une analyse est déjà en cours. Réessaie dans quelques secondes.",
                }
            )
            return

        queue: asyncio.Queue[str] = asyncio.Queue()

        async def emit(payload_dict: dict) -> None:
            await queue.put(_event(payload_dict))

        async with _SEMAPHORE:
            task = asyncio.create_task(
                asyncio.wait_for(
                    run_scan(target, emit, profile=payload.profile),
                    timeout=config.SCAN_DEADLINE_SECONDS,
                )
            )
            try:
                while True:
                    if task.done() and queue.empty():
                        break
                    try:
                        item = await asyncio.wait_for(queue.get(), timeout=0.2)
                    except TimeoutError:
                        continue
                    yield item
                report = await task
                try:
                    await db.save_scan(report.to_dict(), profile=report.profile)
                except Exception as exc:  # noqa: BLE001
                    yield _event(
                        {
                            "type": "warning",
                            "message": f"Rapport non enregistré dans l'historique : {exc}",
                        }
                    )
            except TimeoutError:
                yield _event(
                    {
                        "type": "error",
                        "code": "timeout",
                        "message": f"L'analyse a dépassé {int(config.SCAN_DEADLINE_SECONDS)} s et a été interrompue.",
                    }
                )
            except ScanError as exc:
                yield _event({"type": "error", "code": exc.code, "message": exc.message})
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                yield _event(
                    {
                        "type": "error",
                        "code": "internal",
                        "message": f"Erreur interne pendant l'analyse : {type(exc).__name__}: {exc}",
                    }
                )
            finally:
                if not task.done():
                    task.cancel()

    return StreamingResponse(
        driver(),
        media_type="application/x-ndjson",
        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
    )


@app.get("/api/scans")
async def api_scans(host: str | None = None, limit: int = 50) -> dict:
    """Historique des analyses enregistrées (les plus récentes d'abord)."""
    return {"scans": await db.list_scans(host, limit)}


@app.get("/api/stats")
async def api_stats() -> dict:
    """Indicateurs du tableau de bord : volume, score moyen, tendance, sévérités."""
    return await db.stats()


@app.get("/api/scans/{scan_id}")
async def api_scan(scan_id: str) -> dict:
    report = await db.get_scan(scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Analyse introuvable.")
    return report


@app.delete("/api/scans/{scan_id}")
async def api_delete_scan(scan_id: str) -> dict:
    deleted = await db.delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Analyse introuvable.")
    return {"deleted": True, "scan_id": scan_id}


async def _report_or_404(scan_id: str) -> dict:
    report = await db.get_scan(scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Analyse introuvable.")
    return report


def _download(content: str, media_type: str, filename: str) -> Response:
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/scans/{scan_id}/sarif")
async def api_scan_sarif(scan_id: str) -> Response:
    report = await _report_or_404(scan_id)
    return _download(
        reporting.dumps_sarif(report), "application/sarif+json", f"vulnlens-{scan_id}.sarif.json"
    )


@app.get("/api/scans/{scan_id}/report.html")
async def api_scan_html(scan_id: str) -> Response:
    report = await _report_or_404(scan_id)
    return _download(reporting.to_html(report), "text/html; charset=utf-8", f"vulnlens-{scan_id}.html")


@app.get("/api/scans/{scan_id}/markdown")
async def api_scan_markdown(scan_id: str) -> Response:
    report = await _report_or_404(scan_id)
    return _download(
        reporting.to_markdown(report), "text/markdown; charset=utf-8", f"vulnlens-{scan_id}.md"
    )


@app.get("/api/scans/{scan_id}/json")
async def api_scan_json(scan_id: str) -> Response:
    report = await _report_or_404(scan_id)
    return _download(
        json.dumps(report, ensure_ascii=False, indent=2),
        "application/json",
        f"vulnlens-{scan_id}.json",
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})
