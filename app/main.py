"""Point d'entrée FastAPI : UI statique + API d'analyse en streaming (NDJSON)."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
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

from . import (
    alerts,
    config,
    credentials,
    db,
    diffing,
    remediation,
    reporting,
    triage,
    verify,
    watch,
)
from .models import SEVERITY_LABELS_FR
from .safety import ScanError, normalize_target
from .scanner.engine import run_scan

logger = logging.getLogger("vulnlens")

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"

# En-têtes de sécurité appliqués à toutes les réponses de l'instance.
# La CSP est stricte : l'interface n'embarque ni script ni style en ligne.
CSP_APP = (
    "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; "
    "form-action 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
    "connect-src 'self'; font-src 'self'"
)
# /docs et /redoc (Swagger UI) chargent leurs ressources depuis un CDN.
CSP_DOCS = (
    "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "connect-src 'self'; font-src 'self' https://cdn.jsdelivr.net"
)
DOCS_PATHS = ("/docs", "/redoc", "/docs/oauth2-redirect")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
}

SAFE_SCAN_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _origin_allowed(origin: str, request: Request) -> bool:
    """Vrai si l'origine de la requête correspond bien à cette instance.

    Bloque le CSRF « simple request » : sans jeton, n'importe quelle page web
    ouverte dans le navigateur de l'utilisateur pouvait déclencher
    `POST /api/watch/<hôte>/run`.
    """
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    if not parsed.netloc:
        return False
    candidates = {h.strip().lower() for h in config.ALLOWED_ORIGINS if h.strip()}
    forwarded_host = request.headers.get("x-forwarded-host", "").strip().lower()
    host = request.headers.get("host", "").strip().lower()
    allowed = candidates | {h for h in (host, forwarded_host) if h}
    return parsed.netloc.lower() in allowed


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await db.init()
    if not config.AUTH_TOKEN:
        logger.warning(
            "VULNLENS_TOKEN n'est pas défini : toute personne pouvant joindre ce port peut "
            "lancer des analyses et lire l'historique. Définis un jeton avant d'exposer "
            "l'instance au-delà de localhost."
        )
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
async def security_middleware(request: Request, call_next):
    """Jeton d'API, garde anti-CSRF et en-têtes de sécurité (toutes les réponses)."""
    path = request.url.path
    method = request.method.upper()

    # 1) Garde anti-CSRF sur les routes qui modifient l'état.
    if method in UNSAFE_METHODS and path.startswith("/api"):
        origin = request.headers.get("origin", "").strip()
        fetch_site = request.headers.get("sec-fetch-site", "").strip().lower()
        if origin and not _origin_allowed(origin, request):
            return JSONResponse(
                status_code=403,
                content={"error": "Origine refusée (protection anti-CSRF)."},
            )
        if not origin and fetch_site == "cross-site":
            return JSONResponse(
                status_code=403,
                content={"error": "Requête intersite refusée (protection anti-CSRF)."},
            )

    # 2) Protection optionnelle de l'instance (jeton partagé).
    if config.AUTH_TOKEN and path.startswith("/api") and path not in _OPEN_PATHS:
        header = request.headers.get("authorization", "")
        token = header[7:].strip() if header.lower().startswith("bearer ") else ""
        token = token or request.headers.get("x-api-key", "").strip()
        # Comparaison à temps constant : une comparaison naïve laisse fuir la
        # longueur du préfixe correct par mesure de latence.
        if not token or not secrets.compare_digest(token, config.AUTH_TOKEN):
            response = JSONResponse(
                status_code=401,
                content={"error": "Jeton d'API requis (en-tête Authorization: Bearer …)."},
            )
            _apply_security_headers(response, path, request)
            return response

    response = await call_next(request)
    _apply_security_headers(response, path, request)
    return response


def _apply_security_headers(response: Response, path: str, request: Request) -> None:
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    if path.startswith(DOCS_PATHS) or path.startswith("/openapi.json"):
        response.headers.setdefault("Content-Security-Policy", CSP_DOCS)
    else:
        response.headers.setdefault("Content-Security-Policy", CSP_APP)
    if request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "") == "https":
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )


_SEMAPHORE = asyncio.Semaphore(config.MAX_CONCURRENT_SCANS)
_RATE_LIMIT: dict[str, deque[float]] = defaultdict(deque)
_RATE_WINDOW = 300.0
_RATE_MAX = 15
_RATE_MAX_VERIFY = 10


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
    auth: str | None = Field(
        None,
        max_length=4100,
        description=(
            "En-tête d'authentification optionnel pour couvrir la zone connectée, "
            "au format « Authorization: Bearer … » ou « Cookie: session=… ». "
            "Jamais stocké ni reporté : envoyé au seul hôte analysé."
        ),
    )


class TriageRequest(BaseModel):
    verdict: Literal["a-verifier", "confirme", "faux-positif", "risque-accepte"] = Field(
        ...,
        description="Verdict du pentester sur ce constat.",
    )
    note: str = Field("", max_length=triage.MAX_NOTE, description="Justification courte.")


def _event(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False) + "\n"


def _client_key(request: Request) -> str:
    """Identifiant de limitation de débit.

    `X-Forwarded-For` n'est pris en compte que si l'instance tourne derrière un
    reverse proxy de confiance (`VULNLENS_TRUST_PROXY=1`). Sinon n'importe qui
    pouvait changer d'en-tête à chaque requête et contourner la limite.
    """
    if config.TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            # L'entrée la plus à droite est celle ajoutée par notre proxy.
            return forwarded.split(",")[-1].strip() or "inconnu"
    return request.client.host if request.client else "inconnu"


def _check_rate_limit(key: str, bucket: str = "scan", max_hits: int = _RATE_MAX) -> None:
    now = time.monotonic()
    slot = _RATE_LIMIT[f"{bucket}:{key}"]
    while slot and now - slot[0] > _RATE_WINDOW:
        slot.popleft()
    if len(slot) >= max_hits:
        raise HTTPException(
            status_code=429,
            detail="Trop de requêtes. Patiente quelques minutes avant de réessayer.",
        )
    slot.append(now)


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
                "detail": "En-têtes, TLS, cookies, CORS, 50 fichiers, contenu, DNS, bibliothèques",
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
            "Secrets : 33 signatures (cloud, SaaS, CI, paiements, bases) et analyse des JWT",
            "Bibliothèques front-end : versions à CVE connue (jQuery, Bootstrap, Lodash, AngularJS…)",
            "Configuration exposée : état Terraform, clés SSH/GCP, heap dump, profiler Symfony",
            "En-têtes de débogage : profiler de framework actif en production",
            "Contrôle d'accès : IDOR/BOLA, champs cachés, paramètres de privilège, chemins",
            "CWE, test OWASP WSTG et score CVSS 3.1 calculé sur chaque constat",
            "Journal des requêtes : annexe de preuve de non-intrusivité (HTML, Markdown, SARIF)",
            "Zone authentifiée optionnelle : en-tête fourni, jamais stocké ni reporté",
            "Triage des constats : confirmé / faux positif / risque accepté, avec justification",
            "Score retenu après triage et suppressions SARIF des faux positifs",
            "Équipe d'agents locale (sans API) : hypothèses d'attaque, revue croisée et chaînes d'exploitation",
            "Impact : ce que chaque faille donne accès (comptes, base, paiements, cloud…)",
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
            "L'en-tête d'authentification n'est envoyé qu'à l'hôte analysé et jamais écrit dans le rapport",
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

    parsed_auth: tuple[str, str] | None = None
    if payload.auth:
        try:
            parsed_auth = credentials.parse(payload.auth)
        except credentials.AuthHeaderError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

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
                    run_scan(target, emit, profile=payload.profile, auth=parsed_auth),
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
            except Exception:  # noqa: BLE001
                # Détail complet dans les journaux serveur, message neutre côté client :
                # les traces internes ne doivent pas être exposées.
                logger.exception("Échec de l'analyse de %s", target)
                yield _event(
                    {
                        "type": "error",
                        "code": "internal",
                        "message": (
                            "Erreur interne pendant l'analyse. Réessaie ; si le problème "
                            "persiste, consulte les journaux du serveur."
                        ),
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
    return {"scans": await db.list_scans(host, max(1, min(limit, 200)))}


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
async def api_watch_run(host: str, request: Request) -> dict:
    """Lance immédiatement l'analyse d'une cible surveillée."""
    _check_rate_limit(_client_key(request), bucket="watch-run", max_hits=10)
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
async def api_verify_check(host: str, request: Request) -> dict:
    """Vérifie la présence du TXT ou du fichier .well-known.

    Limité en débit : chaque appel déclenche jusqu'à deux requêtes sortantes, ce
    qui en faisait un amplificateur pratique pour sonder des hôtes arbitraires.
    """
    _check_rate_limit(_client_key(request), bucket="verify", max_hits=_RATE_MAX_VERIFY)
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


@app.get("/api/scans/{scan_id}/triage")
async def api_triage(scan_id: str) -> dict:
    report = await _report_or_404(scan_id)
    return {
        "scan_id": scan_id,
        "entries": {
            finding["id"]: {
                "verdict": finding["verdict"],
                "label": finding["verdict_label"],
                "note": finding["verdict_note"],
                "updated_at": finding.get("verdict_at", ""),
            }
            for finding in report.get("findings") or []
            if finding.get("verdict")
        },
        "summary": report.get("triage_summary") or triage.summary(report.get("findings") or []),
        "score": report.get("score"),
        "score_after_triage": report.get("score_after_triage"),
        "grade_after_triage": report.get("grade_after_triage", ""),
    }


@app.put("/api/scans/{scan_id}/findings/{finding_id}/triage")
async def api_set_triage(scan_id: str, finding_id: str, payload: TriageRequest) -> dict:
    report = await _report_or_404(scan_id)
    known = {str(finding.get("id")) for finding in report.get("findings") or []}
    if finding_id not in known:
        raise HTTPException(status_code=404, detail="Constat introuvable dans cette analyse.")
    try:
        record = triage.entry(payload.verdict, payload.note)
    except triage.TriageError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    await db.set_triage(scan_id, finding_id, record["verdict"], record["note"], record["updated_at"])
    updated = await _report_or_404(scan_id)
    return {
        "scan_id": scan_id,
        "finding_id": finding_id,
        **record,
        "summary": updated.get("triage_summary") or {},
        "score_after_triage": updated.get("score_after_triage"),
        "grade_after_triage": updated.get("grade_after_triage", ""),
    }


@app.delete("/api/scans/{scan_id}/findings/{finding_id}/triage")
async def api_clear_triage(scan_id: str, finding_id: str) -> dict:
    report = await _report_or_404(scan_id)
    entries = await db.clear_triage(scan_id, finding_id)
    merged = triage.merge(report, entries)
    return {
        "scan_id": scan_id,
        "finding_id": finding_id,
        "cleared": True,
        "summary": merged.get("triage_summary") or {},
    }


async def _report_with_diff(scan_id: str) -> dict:
    """Rapport + écart avec l'analyse précédente (utilisé par les exports)."""
    report = await _report_or_404(scan_id)
    host = _host_of(report.get("final_url") or report.get("target") or "")
    previous = await db.previous_scan(host, exclude_id=scan_id) if host else None
    report["diff"] = diffing.diff_reports(report, previous)
    return report


async def _report_or_404(scan_id: str) -> dict:
    # Un identifiant d'analyse est un jeton hexadécimal : tout le reste est refusé
    # avant même d'atteindre la base (défense en profondeur).
    if not SAFE_SCAN_ID.match(scan_id or ""):
        raise HTTPException(status_code=404, detail="Analyse introuvable.")
    report = await db.get_scan(scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Analyse introuvable.")
    return report


def _safe_filename(scan_id: str, extension: str) -> str:
    """Nom de fichier dérivé d'un identifiant non fiable (anti-injection d'en-tête)."""
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "", scan_id or "")[:64] or "rapport"
    return f"vulnlens-{cleaned}.{extension}"


def _download(content: str, media_type: str, filename: str) -> Response:
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Content-Type-Options": "nosniff",
        # Le rapport est du HTML généré : on le neutralise même si le navigateur
        # l'affiche au lieu de le télécharger (défense en profondeur anti-XSS).
        "Content-Security-Policy": (
            "sandbox; default-src 'none'; img-src data:; style-src 'unsafe-inline'"
        ),
        "Cross-Origin-Resource-Policy": "same-origin",
    }
    return Response(content=content, media_type=media_type, headers=headers)


@app.get("/api/scans/{scan_id}/sarif")
async def api_scan_sarif(scan_id: str) -> Response:
    report = await _report_or_404(scan_id)
    return _download(
        reporting.dumps_sarif(report), "application/sarif+json", _safe_filename(scan_id, "sarif.json")
    )


@app.get("/api/scans/{scan_id}/report.html")
async def api_scan_html(scan_id: str) -> Response:
    report = await _report_with_diff(scan_id)
    return _download(reporting.to_html(report), "text/html; charset=utf-8", _safe_filename(scan_id, "html"))


@app.get("/api/scans/{scan_id}/markdown")
async def api_scan_markdown(scan_id: str) -> Response:
    report = await _report_with_diff(scan_id)
    return _download(
        reporting.to_markdown(report), "text/markdown; charset=utf-8", _safe_filename(scan_id, "md")
    )


@app.get("/api/scans/{scan_id}/json")
async def api_scan_json(scan_id: str) -> Response:
    report = await _report_with_diff(scan_id)
    return _download(
        json.dumps(report, ensure_ascii=False, indent=2),
        "application/json",
        _safe_filename(scan_id, "json"),
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})
