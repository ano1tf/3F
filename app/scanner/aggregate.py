"""Fusion des constats multi-pages.

Un problème présent sur 8 pages ne doit pas produire 8 constats : on garde un
constat, enrichi du nombre de pages concernées et de la liste des URL touchées.
"""

from __future__ import annotations

from dataclasses import replace

from ..models import Finding

MAX_PAGES_LISTED = 6


def aggregate(per_page: list[tuple[str, list[Finding]]], total_pages: int) -> list[Finding]:
    """`per_page` : [(url, findings)] → constats uniques, preuves enrichies."""
    grouped: dict[str, dict] = {}
    order: list[str] = []

    for url, findings in per_page:
        for finding in findings:
            entry = grouped.get(finding.id)
            if entry is None:
                grouped[finding.id] = {"finding": finding, "urls": [url]}
                order.append(finding.id)
            elif url not in entry["urls"]:
                entry["urls"].append(url)

    results: list[Finding] = []
    for finding_id in order:
        entry = grouped[finding_id]
        finding: Finding = entry["finding"]
        urls: list[str] = entry["urls"]

        if len(urls) <= 1 or total_pages <= 1:
            results.append(finding)
            continue

        listed = "\n".join(f"  · {url}" for url in urls[:MAX_PAGES_LISTED])
        suffix = f"\n  · … et {len(urls) - MAX_PAGES_LISTED} autre(s)" if len(urls) > MAX_PAGES_LISTED else ""
        evidence = (
            f"Constat présent sur {len(urls)} des {total_pages} pages analysées.\n"
            f"{finding.evidence}\nPages concernées :\n{listed}{suffix}"
        )
        results.append(replace(finding, evidence=evidence))

    return results


def coverage_note(total_pages: int, skipped: int) -> str:
    if total_pages <= 1:
        return "Analyse d'une seule page (profil rapide)."
    note = f"{total_pages} pages analysées"
    if skipped:
        note += f", {skipped} URL externes ou non pertinentes ignorées"
    return note + "."
