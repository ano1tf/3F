"""CLI VulnLens — pensé pour la CI : seuil de score, sorties JSON/SARIF/Markdown/HTML.

Exemples :
    python -m app.cli scan https://exemple.fr
    python -m app.cli scan exemple.fr --profile deep --fail-under 80
    python -m app.cli scan exemple.fr --format sarif --output vulnlens.sarif.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from . import config, db, reporting
from .models import Severity
from .safety import ScanError
from .scanner.engine import run_scan

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_ERROR = 2


async def _scan(target: str, profile: str, verbose: bool):
    async def emit(event: dict) -> None:
        if not verbose:
            return
        if event.get("type") == "progress" and event.get("message"):
            print(f"  · {event['message']}", file=sys.stderr)
        elif event.get("type") == "error":
            print(f"  ! {event.get('message')}", file=sys.stderr)

    return await run_scan(target, emit, profile=profile)


def _print_summary(report) -> None:
    counts = report.counts
    total = sum(counts.values())
    print(f"\n{config.APP_NAME} — {report.final_url or report.target}", file=sys.stderr)
    print(f"Score : {report.score}/100 (note {report.grade}) en {report.duration_ms} ms", file=sys.stderr)
    line = " · ".join(
        f"{counts.get(severity.value, 0)} {severity.value}"
        for severity in Severity
    )
    print(f"Constats : {total} ({line})", file=sys.stderr)

    top = [f for f in report.findings if f.id in report.priorities]
    if top:
        print("\nÀ corriger en priorité :", file=sys.stderr)
        for finding in top:
            print(f"  {finding.severity.value.upper():8} {finding.title}", file=sys.stderr)


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
        choices=["quick", "deep"],
        default="quick",
        help="quick : contrôles passifs (défaut) ; deep : + AXFR, sous-domaines, redirections",
    )
    scan.add_argument(
        "--format",
        choices=["text", "json", "sarif", "markdown", "html"],
        default="text",
        help="Format de sortie (défaut : text)",
    )
    scan.add_argument("--output", "-o", help="Écrire le rapport dans un fichier")
    scan.add_argument(
        "--fail-under",
        type=int,
        default=None,
        metavar="N",
        help="Code de sortie 1 si le score est inférieur à N (usage CI)",
    )
    scan.add_argument("--no-save", action="store_true", help="Ne pas enregistrer dans l'historique")
    scan.add_argument("--verbose", "-v", action="store_true", help="Afficher la progression")
    scan.add_argument("--quiet", "-q", action="store_true", help="N'afficher que le rapport")

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
    # text
    lines = [
        f"{report_dict['final_url'] or report_dict['target']}",
        f"Score {report_dict['score']}/100 — note {report_dict['grade']}",
        "",
    ]
    for finding in report_dict["findings"]:
        lines.append(f"[{finding['severity_label'].upper():11}] {finding['title']}")
        if finding.get("evidence"):
            lines.append(f"              {finding['evidence'].splitlines()[0][:120]}")
    if len(lines) == 3:
        lines.append("Aucun constat.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":  # pragma: no cover - argparse gère déjà
        parser.print_help()
        return EXIT_ERROR

    try:
        report = asyncio.run(_scan(args.url, args.profile, args.verbose))
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
