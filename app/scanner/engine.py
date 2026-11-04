"""Orchestration d'une analyse : phases, progression temps réel, rapport final."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Awaitable, Callable
from urllib.parse import urlsplit, urlunsplit

from .. import config
from ..models import CheckResult, Finding, ScanReport
from ..safety import ScanError, validate_target
from . import checks_content, checks_dns, checks_exposure, checks_http, checks_tls
from .fetcher import Fetcher, same_origin
from .scoring import count_by_severity, grade_for, score_findings, sort_findings

Emitter = Callable[[dict], Awaitable[None]]

STEPS = [
    ("validation", "Validation de la cible et des garde-fous"),
    ("transport", "Négociation TLS et transport"),
    ("headers", "Analyse des en-têtes de sécurité"),
    ("dns", "Vérification DNS, SPF et DMARC"),
    ("cors", "Test CORS et méthodes HTTP"),
    ("exposure", "Recherche de fichiers exposés"),
    ("content", "Analyse du contenu et des formulaires"),
    ("score", "Calcul du score et du rapport"),
]


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "/", "", ""))


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        unique.append(finding)
    return unique


async def run_scan(raw_target: str, emit: Emitter) -> ScanReport:
    started = time.perf_counter()
    report = ScanReport(
        target=raw_target.strip(),
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    percent = 0

    async def step(key: str, message: str | None = None) -> None:
        nonlocal percent
        label = dict(STEPS).get(key, key)
        await emit(
            {
                "type": "progress",
                "step": key,
                "label": label,
                "message": message or label,
                "percent": percent,
            }
        )

    async def advance(key: str, pct: int, message: str) -> None:
        nonlocal percent
        percent = pct
        await step(key, message)

    await step("validation")
    try:
        target = await validate_target(raw_target)
    except ScanError as exc:
        # L'erreur est traduite en événement par la couche API (une seule fois).
        report.errors.append(exc.message)
        raise

    report.final_url = target.url
    await advance("validation", 6, f"Cible validée : {target.host} ({', '.join(target.addresses[:3])})")

    findings: list[Finding] = []
    checks: list[CheckResult] = []

    async with Fetcher(allow_private=config.ALLOW_PRIVATE_TARGETS) as fetcher:
        # ------------------------------------------------------------------
        # Phase 1 — transport : page principale, variante HTTP, TLS, DNS
        # ------------------------------------------------------------------
        await advance("transport", 14, f"Connexion à {target.url}")
        http_url = f"http://{urlsplit(target.url).netloc}/"
        main_task = asyncio.create_task(fetcher.get(target.url))
        http_task = (
            asyncio.create_task(fetcher.get(http_url, max_bytes=8192))
            if target.url.startswith("https://")
            else None
        )
        tls_task = (
            asyncio.create_task(checks_tls.check_tls(target.host, target.port))
            if target.url.startswith("https://")
            else None
        )
        dns_task = asyncio.create_task(checks_dns.check_dns(target.host))

        response = await main_task
        if response.error:
            message = (
                f"Impossible de joindre {target.url} : {response.error}. "
                "Vérifie l'adresse, le port et que le site est bien accessible."
            )
            report.errors.append(message)
            for task in (http_task, tls_task, dns_task):
                if task is not None:
                    task.cancel()
            raise ScanError(message, "unreachable")

        report.final_url = response.url
        http_response = await http_task if http_task is not None else None

        transport_findings = checks_http.check_transport(target.url, response, http_response)  # type: ignore[arg-type]
        findings.extend(transport_findings)
        checks.append(
            CheckResult(
                "transport",
                "Transport & redirections",
                detail=f"{response.status} en {response.elapsed_ms} ms",
                findings=transport_findings,
            )
        )

        if tls_task is not None:
            tls_findings = await tls_task
            findings.extend(tls_findings)
            checks.append(CheckResult("tls", "Certificat & TLS", findings=tls_findings))
        else:
            checks.append(
                CheckResult(
                    "tls",
                    "Certificat & TLS",
                    status="skipped",
                    detail="Cible servie en HTTP : aucun certificat à analyser.",
                )
            )

        await advance("headers", 28, "Contrôle des en-têtes (HSTS, CSP, cookies…)")
        is_https = urlsplit(response.url).scheme == "https"
        header_findings = checks_http.check_headers(response, is_https)
        header_findings += checks_http.check_cookies(response)
        findings.extend(header_findings)
        checks.append(CheckResult("headers", "En-têtes & cookies", findings=header_findings))

        await advance("dns", 38, "Vérification SPF, DMARC et CAA")
        try:
            dns_findings, dns_meta = await asyncio.wait_for(dns_task, timeout=12)
        except Exception as exc:  # noqa: BLE001
            dns_findings, dns_meta = [], {}
            checks.append(
                CheckResult("dns", "DNS & e-mail", status="error", detail=f"Résolution DNS indisponible ({exc})")
            )
        else:
            findings.extend(dns_findings)
            checks.append(CheckResult("dns", "DNS & e-mail", findings=dns_findings))
        report.fingerprint.update(dns_meta)

        await advance("cors", 48, "Test CORS et méthodes HTTP")
        try:
            cors_findings, method_findings = await asyncio.gather(
                checks_http.check_cors(fetcher, response.url),
                checks_http.check_methods(fetcher, response.url),
            )
        except Exception as exc:  # noqa: BLE001
            cors_findings, method_findings = [], []
            checks.append(CheckResult("cors", "CORS & méthodes", status="error", detail=str(exc)))
        else:
            findings.extend(cors_findings + method_findings)
            checks.append(
                CheckResult("cors", "CORS & méthodes", findings=cors_findings + method_findings)
            )

        # ------------------------------------------------------------------
        # Phase 2 — exposition de fichiers (sur l'origine finale)
        # ------------------------------------------------------------------
        base = _origin(response.url)
        await advance("exposure", 62, f"Recherche de fichiers sensibles sur {base}")
        exposure_findings: list[Finding] = []
        try:
            exposed, exposure_meta = await checks_exposure.check_exposed_files(fetcher, base)
            exposure_findings.extend(exposed)
            report.fingerprint.update(exposure_meta)
            exposure_findings += await checks_exposure.check_robots(fetcher, base)
            exposure_findings += await checks_exposure.check_directory_listing(fetcher, base)
            exposure_findings += await checks_exposure.check_error_pages(fetcher, base)
            checks.append(CheckResult("exposure", "Fichiers exposés", findings=exposure_findings))
        except Exception as exc:  # noqa: BLE001
            checks.append(
                CheckResult("exposure", "Fichiers exposés", status="error", detail=f"Phase interrompue : {exc}")
            )
        findings.extend(exposure_findings)

        # ------------------------------------------------------------------
        # Phase 3 — contenu de la page
        # ------------------------------------------------------------------
        await advance("content", 80, "Analyse du HTML, des formulaires et des scripts")
        page_findings: list[Finding] = []
        try:
            page_findings, page_info = checks_content.check_page(response)
            if page_info.generator:
                report.fingerprint.setdefault("generateur", page_info.generator)
            checks.append(CheckResult("content", "Contenu & formulaires", findings=page_findings))
        except Exception as exc:  # noqa: BLE001
            checks.append(CheckResult("content", "Contenu & formulaires", status="error", detail=str(exc)))
        findings.extend(page_findings)

        headers_map = {k.lower(): v for k, v in response.headers.items()}
        headers_map["__url__"] = response.url
        report.fingerprint.update(checks_exposure.detect_fingerprint(headers_map, response.text))
        if same_origin(target.url, response.url) is False:
            report.fingerprint["redirige_vers"] = response.url

        # ------------------------------------------------------------------
        # Phase 4 — score
        # ------------------------------------------------------------------
        await advance("score", 94, "Calcul du score et classement des constats")
        findings = dedupe(findings)
        report.findings = sort_findings(findings)
        report.score = score_findings(report.findings)
        report.grade, _ = grade_for(report.score)
        # Les constats d'un domaine redirigé ne doivent pas compter deux fois.
        report.counts = count_by_severity(report.findings)
        report.checks = checks
        report.duration_ms = int((time.perf_counter() - started) * 1000)

    await emit(
        {
            "type": "result",
            "percent": 100,
            "report": report.to_dict(),
        }
    )
    return report
