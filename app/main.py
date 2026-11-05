"""Point d'entrée FastAPI : UI statique + API d'analyse en streaming (NDJSON)."""

from __future__ import annotations

import asyncio
import json
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import (
    FileResponse,
    JSONResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import alerts, config, db, diffing, remediation, reporting, verify, watch
from .models import SEVERITY_LABELS_FR
from .safety import ScanError, normalize_target
from .scanner.engine import run_scan

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"

@asynccontextmanager
async def lifespan(_app: FastAPI):
    await db.init()
    stop = asyncio.Event()
    task: asyncio.Task | None = None
    if config.WATCH_ENABLED:
        task = asyncio.create_task(watch.scheduler_loop(stop), name="vulnlens-watch")
    try:
        yield
    finally:
        if task is not None:
            stop.set()
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task


app = FastAPI(
    title=config.APP_NAME,
    version=config.APP_VERSION,
    description="Scanner de vulnérabilités web passif, pour des tests de sécurité autorisés.",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

_OPEN_PATHS = {"/api/health"}


@app.middleware("http")
async def require_token(request: Request, call_next):
    """Protège l'instance si VULNLENS_TOKEN est défini (déploiement partagé)."""
    if not config.AUTH_TOKEN:
        return await call_next(request)

    path = request.url.path
    if not path.startswith("/api") or path in _OPEN_PATHS:
        return await call_next(request)

    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    token = token or request.headers.get("x-api-key", "").strip()
    if token != config.AUTH_TOKEN:
        return JSONResponse(
            status_code=401,
            content={"error": "Jeton d'API requis (en-tête Authorization: Bearer …)."},
        )
    return await call_next(request)

_SEMAPHORE = asyncio.Semaphore(config.MAX_CONCURRENT_SCANS)
_RATE_LIMIT: dict[str, deque[float]] = defaultdict(deque)
_RATE_WINDOW = 300.0
_RATE_MAX = 15


class WatchRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    profile: Literal["quick", "standard", "deep"] = "standard"
    interval_hours: int = Field(default=24, ge=1, le=24 * 30)
    enabled: bool = True


class ScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, examples=["https://exemple.fr"])
    authorized: bool = Field(
        False,
        description="Confirme que l'utilisateur est autorisé à tester cette cible.",
    )
    profile: Literal["quick", "standard", "deep"] = Field(
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
                "key": "standard",
                "label": "Standard",
                "detail": "Jusqu'à 6 pages, secrets dans les scripts, e-mail avancé, tiers",
            },
            {
                "key": "deep",
                "label": "Approfondi",
                "detail": "12 pages, 10 scripts + AXFR, sous-domaines, takeovers, redirections",
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
            "DNS : SPF, DMARC (p/sp), CAA, DKIM, MTA-STS, TLS-RPT",
            "Secrets : clés cloud/SaaS, clés privées, JWT, identifiants en dur dans les scripts",
            "Surface tierce : domaines chargés, rôles, formulaires qui pointent à l'extérieur",
            "Source maps exposées",
            "Plan d'action : quick/sprint/projet avec gain de score potentiel",
            "Synthèse exécutive : niveau de risque, impacts réels, points forts, radar",
            "Sous-domaines passifs via Certificate Transparency (crt.sh)",
            "Empreinte technique : WAF, CDN, CMS, frameworks, bibliothèques, analytique",
            "Surveillance planifiée : réanalyse périodique et alerte de régression",
        ],
        "watch": {"enabled": config.WATCH_ENABLED, "tick_seconds": config.WATCH_TICK_SECONDS},
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
                    host = _host_of(report.final_url or report.target)
                    previous = await db.previous_scan(host, exclude_id=report.scan_id)
                    asyncio.create_task(alerts.notify(report.to_dict(), previous))
                    yield _event(
                        {
                            "type": "saved",
                            "scan_id": report.scan_id,
                            "verified": report.verified,
                        }
                    )
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


def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _watch_target(raw: str) -> str:
    """Clé de surveillance : domaine + port éventuel (https://exemple.fr:8443 → exemple.fr:8443)."""
    try:
        parsed = urlsplit(normalize_target(raw))
    except ScanError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc
    netloc = (parsed.netloc or "").lower()
    if not netloc:
        raise HTTPException(status_code=400, detail="Nom d'hôte invalide.")
    return netloc


def _clean_host(raw: str) -> str:
    try:
        parsed = urlsplit(normalize_target(raw))
    except ScanError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Nom d'hôte invalide.")
    return parsed.hostname.lower()


@app.get("/api/scans")
async def api_scans(host: str | None = None, limit: int = 50) -> dict:
    """Historique des analyses enregistrées (les plus récentes d'abord)."""
    return {"scans": await db.list_scans(host, limit)}


@app.get("/api/stats")
async def api_stats() -> dict:
    """Indicateurs du tableau de bord : volume, score moyen, tendance, sévérités."""
    return await db.stats()


@app.get("/api/watch")
async def api_watch_list() -> dict:
    """Cibles surveillées, avec échéance et état du planificateur."""
    entries = watch.describe(await db.list_watches())
    return {
        "scheduler": config.WATCH_ENABLED,
        "tick_seconds": config.WATCH_TICK_SECONDS,
        "items": entries,
    }


@app.post("/api/watch")
async def api_watch_add(payload: WatchRequest) -> dict:
    """Ajoute ou met à jour une cible surveillée."""
    host = _watch_target(payload.host)
    entry = await db.upsert_watch(host, payload.profile, payload.interval_hours, payload.enabled)
    return {"ok": True, "item": watch.describe([entry])[0]}


@app.delete("/api/watch/{host}")
async def api_watch_delete(host: str) -> dict:
    deleted = await db.delete_watch(_watch_target(host))
    if not deleted:
        raise HTTPException(status_code=404, detail="Cible non surveillée.")
    return {"deleted": True, "host": host}


@app.post("/api/watch/{host}/run")
async def api_watch_run(host: str) -> dict:
    """Lance immédiatement l'analyse d'une cible surveillée."""
    cleaned = _watch_target(host)
    entries = {entry["host"]: entry for entry in await db.list_watches()}
    entry = entries.get(cleaned)
    if entry is None:
        raise HTTPException(status_code=404, detail="Cible non surveillée.")
    try:
        return await watch.run_watch(entry)
    except ScanError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc


@app.get("/api/trend/{host}")
async def api_trend(host: str, limit: int = 30) -> dict:
    """Série de scores pour tracer une courbe de tendance par hôte."""
    cleaned = _clean_host(host)
    scans = await db.list_scans(host=cleaned, limit=max(2, min(limit, 100)))
    ordered = list(reversed(scans))
    return {
        "host": cleaned,
        "points": [
            {"date": scan["created_at"], "score": scan["score"], "scan_id": scan["id"]}
            for scan in ordered
        ],
    }


@app.get("/api/scans/{scan_id}/plan")
async def api_scan_plan(scan_id: str) -> dict:
    """Plan de remédiation : trois vagues d'effort et gain de score potentiel."""
    return remediation.build_plan(await _report_or_404(scan_id))


@app.get("/api/scans/{scan_id}/diff")
async def api_scan_diff(scan_id: str) -> dict:
    """Écart avec l'analyse précédente du même hôte."""
    report = await _report_or_404(scan_id)
    host = _host_of(report.get("final_url") or report.get("target") or "")
    previous = await db.previous_scan(host, exclude_id=scan_id) if host else None
    return diffing.diff_reports(report, previous)


@app.get("/api/verify/{host}")
async def api_verify_status(host: str) -> dict:
    """Jeton et instructions de vérification de propriété (sans requête réseau)."""
    return await verify.status(_clean_host(host))


@app.post("/api/verify/{host}/check")
async def api_verify_check(host: str) -> dict:
    """Vérifie la présence du TXT ou du fichier .well-known."""
    return await verify.verify(_clean_host(host))


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


async def _report_with_diff(scan_id: str) -> dict:
    """Rapport + écart avec l'analyse précédente (utilisé par les exports)."""
    report = await _report_or_404(scan_id)
    host = _host_of(report.get("final_url") or report.get("target") or "")
    previous = await db.previous_scan(host, exclude_id=scan_id) if host else None
    report["diff"] = diffing.diff_reports(report, previous)
    return report


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
    report = await _report_with_diff(scan_id)
    return _download(reporting.to_html(report), "text/html; charset=utf-8", f"vulnlens-{scan_id}.html")


@app.get("/api/scans/{scan_id}/markdown")
async def api_scan_markdown(scan_id: str) -> Response:
    report = await _report_with_diff(scan_id)
    return _download(
        reporting.to_markdown(report), "text/markdown; charset=utf-8", f"vulnlens-{scan_id}.md"
    )


@app.get("/api/scans/{scan_id}/json")
async def api_scan_json(scan_id: str) -> Response:
    report = await _report_with_diff(scan_id)
    return _download(
        json.dumps(report, ensure_ascii=False, indent=2),
        "application/json",
        f"vulnlens-{scan_id}.json",
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})
