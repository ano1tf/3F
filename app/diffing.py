"""Comparaison de deux analyses d'un même hôte : nouveaux, corrigés, persistants."""

from __future__ import annotations

from typing import Any

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _brief(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": finding.get("id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "severity_label": finding.get("severity_label"),
        "category": finding.get("category"),
    }


def diff_reports(current: dict[str, Any], previous: dict[str, Any] | None) -> dict[str, Any]:
    """Renvoie l'écart entre l'analyse courante et la précédente du même hôte."""
    if not previous:
        return {
            "available": False,
            "reason": "Aucune analyse antérieure pour cet hôte.",
        }

    current_findings = {f["id"]: f for f in current.get("findings", [])}
    previous_findings = {f["id"]: f for f in previous.get("findings", [])}

    new_ids = [fid for fid in current_findings if fid not in previous_findings]
    fixed_ids = [fid for fid in previous_findings if fid not in current_findings]
    kept_ids = [fid for fid in current_findings if fid in previous_findings]

    changed = [
        {
            "id": fid,
            "title": current_findings[fid].get("title"),
            "from": previous_findings[fid].get("severity"),
            "to": current_findings[fid].get("severity"),
        }
        for fid in kept_ids
        if SEVERITY_RANK.get(current_findings[fid].get("severity"), 9)
        != SEVERITY_RANK.get(previous_findings[fid].get("severity"), 9)
    ]

    def _sorted(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            findings,
            key=lambda f: (SEVERITY_RANK.get(f.get("severity"), 9), f.get("title") or ""),
        )

    return {
        "available": True,
        "previous_id": previous.get("scan_id"),
        "previous_at": previous.get("started_at"),
        "previous_score": previous.get("score"),
        "current_score": current.get("score"),
        "score_delta": int(current.get("score") or 0) - int(previous.get("score") or 0),
        "new": _sorted([_brief(current_findings[fid]) for fid in new_ids]),
        "fixed": _sorted([_brief(previous_findings[fid]) for fid in fixed_ids]),
        "changed": _sorted(changed),
        "persistent_count": len(kept_ids),
        "summary": {
            "new": len(new_ids),
            "fixed": len(fixed_ids),
            "persistent": len(kept_ids),
        },
    }
