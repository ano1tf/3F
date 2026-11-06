"""CLI VulnLens — pensé pour la CI : seuil de score, sorties JSON/SARIF/Markdown/HTML.

Exemples :
    python -m app.cli scan https://exemple.fr
    python -m app.cli scan exemple.fr --profile deep --fail-under 80
    python -m app.cli scan exemple.fr --format sarif --output vulnlens.sarif.json
    python -m app.cli watch add exemple.fr --interval 24
    python -m app.cli watch run exemple.fr
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

from . import config, credentials, db, remediation, reporting, verify
from .models import Severity
from .safety import ScanError, normalize_target
from .scanner.engine import run_scan

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_ERROR = 2


async def _scan(
    target: str,
    profile: str,
    verbose: bool,
    auth: tuple[str, str] | None = None,
):
    async def emit(event: dict) -> None:
        if not verbose:
            return
        if event.get("type") == "progress" and event.get("message"):
            print(f"  · {event['message']}", file=sys.stderr)
        elif event.get("type") == "error":
            print(f"  ! {event.get('message')}", file=sys.stderr)

    return await run_scan(target, emit, profile=profile, auth=auth)


def _print_summary(report) -> None:
    counts = report.counts
    total = sum(counts.values())
    print(f"\n{config.APP_NAME} — {report.final_url or report.target}", file=sys.stderr)
    risk = (report.executive or {}).get("risk_level", "")
    suffix = f" · risque {risk}" if risk else ""
    print(
        f"Score : {report.score}/100 (note {report.grade}) en {report.duration_ms} ms{suffix}",
        file=sys.stderr,
    )
    line = " · ".join(
        f"{counts.get(severity.value, 0)} {severity.value}"
        for severity in Severity
    )
    print(f"Constats : {total} ({line})", file=sys.stderr)

    top = [f for f in report.findings if f.id in report.priorities]
    if top:
        print("\nÀ corriger en priorité :", file=sys.stderr)
        for finding in top:
            danger = f" — danger {finding.danger}/10" if finding.danger else ""
            print(
                f"  {finding.severity.value.upper():8} {finding.title}{danger}",
                file=sys.stderr,
            )


async def _watch_command(args: argparse.Namespace) -> int:
    from . import watch as watch_module

    await db.init()

    if args.watch_command == "list":
        entries = watch_module.describe(await db.list_watches())
        if args.json:
            print(json.dumps(entries, ensure_ascii=False, indent=2))
            return EXIT_OK
        if not entries:
            print("Aucune cible surveillée. Ajoutez-en une avec : vulnlens watch add exemple.fr")
            return EXIT_OK
        print(f"{'CIBLE':32} {'PROFIL':9} {'FRÉQ.':6} {'ÉTAT':8} {'SCORE':6} PROCHAIN")
        for entry in entries:
            score = "—" if entry["last_score"] is None else str(entry["last_score"])
            state = "actif" if entry["enabled"] else "pause"
            next_run = entry["next_run"] or "—"
            print(
                f"{entry['host'][:32]:32} {entry['profile']:9} {entry['interval_hours']:>3} h  "
                f"{state:8} {score:6} {next_run}"
            )
        return EXIT_OK

    if args.watch_command == "add":
        try:
            host = urlsplit(normalize_target(args.target)).hostname or args.target
        except ScanError as exc:
            print(f"Domaine invalide : {exc.message}", file=sys.stderr)
            return EXIT_ERROR
        entry = await db.upsert_watch(host, args.profile, args.interval, True)
        print(
            f"{entry['host']} surveillé · profil {entry['profile']} · "
            f"toutes les {entry['interval_hours']} h"
        )
        return EXIT_OK

    if args.watch_command == "remove":
        try:
            host = urlsplit(normalize_target(args.target)).hostname or args.target
        except ScanError as exc:
            print(f"Domaine invalide : {exc.message}", file=sys.stderr)
            return EXIT_ERROR
        if await db.delete_watch(host):
            print(f"{host} retiré de la surveillance")
            return EXIT_OK
        print(f"{host} n'est pas surveillé", file=sys.stderr)
        return EXIT_THRESHOLD

    # run
    try:
        host = urlsplit(normalize_target(args.target)).hostname or args.target
    except ScanError as exc:
        print(f"Domaine invalide : {exc.message}", file=sys.stderr)
        return EXIT_ERROR
    entries = {entry["host"]: entry for entry in await db.list_watches()}
    entry = entries.get(host)
    if entry is None:
        print(f"{host} n'est pas surveillé (ajoutez-le avec : vulnlens watch add {host})", file=sys.stderr)
        return EXIT_THRESHOLD
    result = await watch_module.run_watch(entry)
    print(
        f"{result['host']} · score {result['score']}/100 ({result['grade']}) · "
        f"{result['findings']} constat(s) · analyse {result['scan_id']}"
    )
    return EXIT_OK


async def _verify(host: str, show_token_only: bool) -> int:
    try:
        domain = urlsplit(normalize_target(host)).hostname or host
    except ScanError as exc:
        print(f"Domaine invalide : {exc.message}", file=sys.stderr)
        return EXIT_ERROR

    info = await verify.status(domain)
    if show_token_only:
        print(info["token"])
        return EXIT_OK

    instructions = info["instructions"]
    print(f"Domaine        : {domain}")
    print(f"Jeton          : {info['token']}")
    print(f"Déjà vérifié   : {'oui' if info['verified'] else 'non'}")
    print()
    print("Option A — enregistrement DNS :")
    print(f"  {instructions['record_name']}  TXT  \"{instructions['record_value']}\"")
    print()
    print("Option B — fichier :")
    print(f"  {instructions['file_url']}  →  {info['token']}")
    print()

    result = await verify.verify(domain)
    if result["verified"]:
        print(f"✓ Propriété confirmée via {result['method']}.")
        return EXIT_OK
    print(f"✗ {result['detail']}")
    return EXIT_THRESHOLD


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnlens",
        description="Scanner de vulnérabilités web passif (tests autorisés uniquement).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Analyser une cible")
    scan.add_argument("url", help="Domaine ou URL à analyser")
    scan.add_argument(
        "--profile",
        choices=["quick", "standard", "deep"],
        default="standard",
        help="quick : 1 page ; standard : 6 pages (défaut) ; deep : 12 pages + AXFR, sous-domaines, takeovers",
    )
    scan.add_argument(
        "--format",
        choices=["text", "json", "sarif", "markdown", "html", "plan"],
        default="text",
        help="Format de sortie : text, json, sarif, markdown, html, plan (défaut : text)",
    )
    scan.add_argument("--output", "-o", help="Écrire le rapport dans un fichier")
    scan.add_argument(
        "--fail-under",
        type=int,
        default=None,
        metavar="N",
        help="Code de sortie 1 si le score est inférieur à N (usage CI)",
    )
    scan.add_argument(
        "--auth",
        metavar="« NOM: VALEUR »",
        help=(
            "En-tête d'authentification pour couvrir la zone connectée, ex. "
            "« Authorization: Bearer … » ou « Cookie: session=… ». "
            "Jamais écrit dans le rapport ni dans l'historique."
        ),
    )
    scan.add_argument(
        "--auth-env",
        metavar="VARIABLE",
        help="Lit l'en-tête d'authentification depuis une variable d'environnement (recommandé).",
    )
    scan.add_argument("--no-save", action="store_true", help="Ne pas enregistrer dans l'historique")
    scan.add_argument("--verbose", "-v", action="store_true", help="Afficher la progression")
    scan.add_argument("--quiet", "-q", action="store_true", help="N'afficher que le rapport")

    watch_parser = sub.add_parser("watch", help="Gérer la surveillance planifiée")
    watch_sub = watch_parser.add_subparsers(dest="watch_command", required=True)

    watch_list = watch_sub.add_parser("list", help="Lister les cibles surveillées")
    watch_list.add_argument("--json", action="store_true", help="Sortie JSON")

    watch_add = watch_sub.add_parser("add", help="Ajouter ou mettre à jour une cible")
    watch_add.add_argument("target", help="Domaine à surveiller")
    watch_add.add_argument("--profile", choices=["quick", "standard", "deep"], default="standard")
    watch_add.add_argument("--interval", type=int, default=24, metavar="HEURES")

    watch_remove = watch_sub.add_parser("remove", help="Retirer une cible")
    watch_remove.add_argument("target", help="Domaine à retirer")

    watch_run = watch_sub.add_parser("run", help="Analyser maintenant une cible surveillée")
    watch_run.add_argument("target", help="Domaine à analyser")

    verify_parser = sub.add_parser(
        "verify", help="Vérifier la propriété d'un domaine (DNS TXT ou .well-known)"
    )
    verify_parser.add_argument("host", help="Domaine à vérifier")
    verify_parser.add_argument(
        "--show-token",
        action="store_true",
        help="Afficher uniquement le jeton et les instructions",
    )

    return parser


def _render(report_dict: dict, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(report_dict, ensure_ascii=False, indent=2)
    if fmt == "sarif":
        return reporting.dumps_sarif(report_dict)
    if fmt == "markdown":
        return reporting.to_markdown(report_dict)
    if fmt == "html":
        return reporting.to_html(report_dict)
    if fmt == "plan":
        return remediation.to_markdown(remediation.build_plan(report_dict))
    # text
    lines = [
        f"{report_dict['final_url'] or report_dict['target']}",
        f"Score {report_dict['score']}/100 — note {report_dict['grade']}",
        "",
    ]
    for finding in report_dict["findings"]:
        danger = f" · danger {finding['danger']}/10" if finding.get("danger") else ""
        lines.append(f"[{finding['severity_label'].upper():11}] {finding['title']}{danger}")
        if finding.get("evidence"):
            lines.append(f"              {finding['evidence'].splitlines()[0][:120]}")
    if len(lines) == 3:
        lines.append("Aucun constat.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "watch":
        return asyncio.run(_watch_command(args))

    if args.command == "verify":
        return asyncio.run(_verify(args.host, args.show_token))

    if args.command != "scan":  # pragma: no cover - argparse gère déjà
        parser.print_help()
        return EXIT_ERROR

    try:
        raw_auth = args.auth or (os.environ.get(args.auth_env) if args.auth_env else None)
        parsed_auth = credentials.parse(raw_auth) if raw_auth else None
        report = asyncio.run(_scan(args.url, args.profile, args.verbose, parsed_auth))
    except credentials.AuthHeaderError as exc:
        print(f"En-tête d'authentification refusé : {exc}", file=sys.stderr)
        return EXIT_ERROR
    except ScanError as exc:
        print(f"Analyse impossible : {exc.message}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:  # pragma: no cover
        print("Interrompu.", file=sys.stderr)
        return EXIT_ERROR

    report_dict = report.to_dict()

    if not args.no_save:
        try:
            asyncio.run(db.save_scan(report_dict, profile=report.profile))
        except Exception as exc:  # noqa: BLE001
            print(f"Historique indisponible ({exc}) — rapport non enregistré.", file=sys.stderr)

    if not args.quiet:
        _print_summary(report)

    output = _render(report_dict, args.format)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        if not args.quiet:
            print(f"\nRapport écrit dans {args.output}", file=sys.stderr)
    else:
        print(output)

    if args.fail_under is not None and report.score < args.fail_under:
        if not args.quiet:
            print(
                f"\nÉchec : score {report.score} < seuil {args.fail_under}.",
                file=sys.stderr,
            )
        return EXIT_THRESHOLD
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
