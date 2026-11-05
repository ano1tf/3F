"""Orchestration d'une analyse : phases, progression temps réel, rapport final."""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit

from .. import config, verify
from ..models import CheckResult, Finding, ScanReport
from ..safety import ScanError, validate_target
from . import (
    checks_content,
    checks_deep,
    checks_dns,
    checks_email,
    checks_exposure,
    checks_http,
    checks_secrets,
    checks_thirdparty,
    checks_tls,
)
from .aggregate import aggregate, coverage_note
from .crawl import CrawlPage, crawl
from .fetcher import Fetcher, same_origin
from .scoring import (
    compute_breakdown,
    count_by_severity,
    grade_for,
    priorities,
    score_findings,
    sort_findings,
)

Emitter = Callable[[dict], Awaitable[None]]

PROFILES: dict[str, dict] = {
    "quick": {"pages": 1, "deep": False, "scripts": 3, "email": False, "label": "Rapide"},
    "standard": {"pages": 6, "deep": False, "scripts": 6, "email": True, "label": "Standard"},
    "deep": {"pages": 12, "deep": True, "scripts": 10, "email": True, "label": "Approfondi"},
}

STEPS = [
    ("validation", "Validation de la cible et des garde-fous"),
    ("transport", "Négociation TLS et transport"),
    ("crawl", "Exploration des pages internes"),
    ("headers", "Analyse des en-têtes de sécurité"),
    ("dns", "Vérification DNS, SPF et DMARC"),
    ("email", "Authentification e-mail avancée (DKIM, MTA-STS, TLS-RPT)"),
    ("cors", "Test CORS et méthodes HTTP"),
    ("exposure", "Recherche de fichiers exposés"),
    ("content", "Analyse du contenu et des formulaires"),
    ("surface", "Cartographie des dépendances tierces"),
    ("secrets", "Recherche de secrets dans les scripts"),
    ("deep", "Contrôles approfondis (AXFR, sous-domaines, redirections)"),
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


async def run_scan(
    raw_target: str,
    emit: Emitter,
    profile: str = "quick",
) -> ScanReport:
    started = time.perf_counter()
    selected = PROFILES.get(profile, PROFILES["quick"])
    report = ScanReport(
        target=raw_target.strip(),
        started_at=datetime.now(UTC).isoformat(timespec="seconds"),
        scan_id=uuid.uuid4().hex[:12],
        profile=profile if profile in PROFILES else "quick",
    )
    percent = 0

    async def step(key: str, message: str | None = None) -> None:
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
    target = await validate_target(raw_target)
    report.final_url = target.url
    report.verified = await verify.is_verified(target.host)

    badge = " · domaine vérifié ✓" if report.verified else ""
    await advance(
        "validation",
        6,
        f"Cible validée : {target.host} ({', '.join(target.addresses[:3])}){badge}",
    )

    findings: list[Finding] = []
    checks: list[CheckResult] = []

    async with Fetcher(allow_private=config.ALLOW_PRIVATE_TARGETS) as fetcher:
        # ------------------------------------------------------------------
        # Phase 1 — transport
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
        email_task = (
            asyncio.create_task(checks_email.check_email(target.host))
            if selected.get("email")
            else None
        )

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

        transport_findings = checks_http.check_transport(target.url, response, http_response)
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
            tls_findings, tls_meta = await tls_task
            report.fingerprint.update(tls_meta)
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

        # ------------------------------------------------------------------
        # Phase 2 — exploration des pages internes
        # ------------------------------------------------------------------
        await advance("crawl", 24, f"Exploration des pages internes (max {selected['pages']})")
        pages: list[CrawlPage] = [CrawlPage(url=response.url, response=response)]
        skipped = 0
        try:
            crawl_result = await crawl(
                fetcher,
                target.url,
                max_pages=int(selected["pages"]),
                initial=response,
            )
            skipped = crawl_result.skipped
            usable = [page for page in crawl_result.pages if page.ok]
            if usable:
                pages = usable
            report.pages = [page.summary() for page in crawl_result.pages]
            checks.append(
                CheckResult(
                    "crawl",
                    "Exploration",
                    detail=coverage_note(len(pages), skipped),
                    findings=[],
                )
            )
        except Exception as exc:  # noqa: BLE001
            checks.append(
                CheckResult("crawl", "Exploration", status="error", detail=f"Exploration interrompue : {exc}")
            )
            report.pages = [{"url": response.url, "status": response.status, "title": "", "ms": 0, "error": ""}]
        if not report.pages:
            report.pages = [{"url": response.url, "status": response.status, "title": "", "ms": 0, "error": ""}]

        is_https = urlsplit(response.url).scheme == "https"

        # ------------------------------------------------------------------
        # Phase 3 — en-têtes, cookies et contenu, page par page
        # ------------------------------------------------------------------
        await advance("headers", 34, f"Contrôle des en-têtes sur {len(pages)} page(s)")
        headers_per_page = [
            (
                page.url,
                checks_http.check_headers(page.response, is_https)
                + checks_http.check_cookies(page.response),
            )
            for page in pages
        ]
        header_findings = aggregate(headers_per_page, len(pages))
        findings.extend(header_findings)
        checks.append(
            CheckResult(
                "headers",
                "En-têtes & cookies",
                detail=f"{len(pages)} page(s)",
                findings=header_findings,
            )
        )

        await advance("dns", 44, "Vérification SPF, DMARC et CAA")
        email_findings: list[Finding] = []
        email_meta: dict[str, str] = {}
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

        if email_task is not None:
            try:
                email_findings, email_meta = await asyncio.wait_for(email_task, timeout=12)
            except Exception as exc:  # noqa: BLE001
                checks.append(
                    CheckResult(
                        "email",
                        "Authentification e-mail",
                        status="error",
                        detail=f"Contrôles e-mail indisponibles ({exc})",
                    )
                )
            else:
                findings.extend(email_findings)
                checks.append(
                    CheckResult("email", "Authentification e-mail", findings=email_findings)
                )
                report.fingerprint.update(email_meta)

        await advance("cors", 54, "Test CORS et méthodes HTTP")
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
        # Phase 4 — exposition de fichiers (sur l'origine finale)
        # ------------------------------------------------------------------
        base = _origin(response.url)
        await advance("exposure", 66, f"Recherche de fichiers sensibles sur {base}")
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
        # Phase 5 — contenu HTML, page par page
        # ------------------------------------------------------------------
        await advance("content", 78, f"Analyse du contenu de {len(pages)} page(s)")
        content_per_page = []
        generator = ""
        try:
            for page in pages:
                page_findings, page_info = checks_content.check_page(page.response)
                content_per_page.append((page.url, page_findings))
                if page_info.generator and not generator:
                    generator = page_info.generator
            content_findings = aggregate(content_per_page, len(pages))
            checks.append(
                CheckResult(
                    "content",
                    "Contenu & formulaires",
                    detail=f"{len(pages)} page(s)",
                    findings=content_findings,
                )
            )
        except Exception as exc:  # noqa: BLE001
            content_findings = []
            checks.append(CheckResult("content", "Contenu & formulaires", status="error", detail=str(exc)))
        findings.extend(content_findings)
        if generator:
            report.fingerprint.setdefault("generateur", generator)

        # ------------------------------------------------------------------
        # Phase 5 bis — dépendances tierces et secrets dans les scripts
        # ------------------------------------------------------------------
        await advance("surface", 84, f"Cartographie des dépendances tierces ({len(pages)} page(s))")
        try:
            report.third_parties = checks_thirdparty.summarize(pages)
            surface_findings = checks_thirdparty.build_findings(report.third_parties, len(pages))
            findings.extend(surface_findings)
            checks.append(
                CheckResult(
                    "surface",
                    "Surface tierce",
                    detail=f"{len(report.third_parties)} domaine(s) tiers",
                    findings=surface_findings,
                )
            )
        except Exception as exc:  # noqa: BLE001
            checks.append(
                CheckResult("surface", "Surface tierce", status="error", detail=f"Phase interrompue : {exc}")
            )

        await advance("secrets", 88, "Recherche de secrets dans les scripts publics")
        try:
            scripts: list[str] = []
            for page in pages:
                scripts.extend(checks_content.parse_page(page.response.text).scripts)
            secret_findings, secret_meta = await checks_secrets.scan_scripts(
                fetcher,
                response.url,
                scripts,
                inline_html=response.text,
                limit=int(selected.get("scripts", 6)),
            )
            report.fingerprint.update(secret_meta)
            findings.extend(secret_findings)
            checks.append(
                CheckResult(
                    "secrets",
                    "Secrets & scripts",
                    detail=f"{secret_meta.get('scripts_analyses', '0')} script(s) analysé(s)",
                    findings=secret_findings,
                )
            )
        except Exception as exc:  # noqa: BLE001
            checks.append(
                CheckResult("secrets", "Secrets & scripts", status="error", detail=f"Phase interrompue : {exc}")
            )

        headers_map = {k.lower(): v for k, v in response.headers.items()}
        headers_map["__url__"] = response.url
        report.fingerprint.update(checks_exposure.detect_fingerprint(headers_map, response.text))
        report.fingerprint["pages_analysees"] = str(len(pages))
        if not same_origin(target.url, response.url):
            report.fingerprint["redirige_vers"] = response.url

        # ------------------------------------------------------------------
        # Phase 6 — contrôles approfondis (profil « deep »)
        # ------------------------------------------------------------------
        if selected["deep"]:
            await advance("deep", 92, "AXFR, sous-domaines et redirections ouvertes")
            deep_findings: list[Finding] = []
            try:
                deep_findings = await checks_deep.run_deep(fetcher, target.host, response.url)
                checks.append(CheckResult("deep", "Contrôles approfondis", findings=deep_findings))
            except Exception as exc:  # noqa: BLE001
                checks.append(
                    CheckResult(
                        "deep",
                        "Contrôles approfondis",
                        status="error",
                        detail=f"Phase interrompue : {exc}",
                    )
                )
            findings.extend(deep_findings)

        # ------------------------------------------------------------------
        # Phase 7 — score
        # ------------------------------------------------------------------
        await advance("score", 95, "Calcul du score et classement des constats")
        # Un formulaire envoyé à un tiers est couvert par la surface tierce : on évite le doublon.
        if any(finding.id == "surface.foreign-form-action" for finding in findings):
            findings = [
                finding for finding in findings if finding.id != "content.external-form-action"
            ]
        findings = dedupe(findings)
        report.findings = sort_findings(findings)
        report.score = score_findings(report.findings)
        report.grade, _ = grade_for(report.score)
        report.score_breakdown = compute_breakdown(report.findings)
        report.priorities = [f.id for f in priorities(report.findings)]
        report.counts = count_by_severity(report.findings)
        report.checks = checks
        report.duration_ms = int((time.perf_counter() - started) * 1000)

    await emit({"type": "result", "percent": 100, "report": report.to_dict()})
    return report
