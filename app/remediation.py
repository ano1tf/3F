"""Plan de remédiation : transformer une liste de constats en feuille de route exécutable."""

from __future__ import annotations

from typing import Any

from .models import SEVERITY_LABELS_FR, Severity

EFFORTS = {
    "quick": {
        "label": "Aujourd'hui — moins d'une heure",
        "detail": "Réglages de configuration, aucun développement.",
    },
    "sprint": {
        "label": "Ce sprint — quelques jours",
        "detail": "Modifications applicatives ou DNS à coordonner.",
    },
    "project": {
        "label": "Projet — deux à six semaines",
        "detail": "Refonte de brique, rotation de secrets, durcissement global.",
    },
}

# Constats dont la correction tient à un réglage : toujours « immédiat ».
QUICK_IDS = {
    "exposure.security-txt",
    "content.blank-noopener",
    "content.script-integrity",
    "content.iframe-no-sandbox",
    "content.generator-version",
    "content.comments-leak",
    "errors.stack-trace",
    "exposure.directory-listing",
    "robots.disclosure",
    "headers.methods-allowed",
    "headers.debug-token",
    "exposure.symfony-profiler",
}

PREFIX_EFFORT: tuple[tuple[str, str], ...] = (
    ("secrets.", "project"),
    ("libs.", "sprint"),
    ("recon.subdomain-takeover", "quick"),
    ("recon.", "sprint"),
    ("tls.", "sprint"),
    ("transport.", "sprint"),
    ("exposure.", "sprint"),
    ("email.", "sprint"),
    ("dns.", "sprint"),
    ("surface.", "sprint"),
    ("headers.", "quick"),
    ("cookies.", "quick"),
    ("content.", "quick"),
    ("errors.", "quick"),
    ("robots.", "quick"),
)


def effort_for(finding_id: str, severity: str) -> str:
    """Classe un constat : critique = tout de suite, sinon par nature de correctif."""
    if finding_id in QUICK_IDS:
        return "quick"
    if severity == Severity.CRITICAL.value:
        return "quick"
    for prefix, effort in PREFIX_EFFORT:
        if finding_id.startswith(prefix):
            return effort
    return "sprint"


def build_plan(report: dict[str, Any]) -> dict[str, Any]:
    """Regroupe les constats en trois vagues d'effort, prêtes à être planifiées."""
    findings = report.get("findings") or []
    buckets: dict[str, list[dict[str, Any]]] = {"quick": [], "sprint": [], "project": []}

    for finding in findings:
        effort = effort_for(finding.get("id", ""), finding.get("severity", "info"))
        buckets[effort].append(
            {
                "id": finding.get("id", ""),
                "title": finding.get("title", ""),
                "severity": finding.get("severity", "info"),
                "severity_label": finding.get(
                    "severity_label",
                    SEVERITY_LABELS_FR.get(Severity(finding.get("severity", "info")), "Info"),
                ),
                "category": finding.get("category", ""),
                "action": finding.get("remediation", ""),
                "reference": finding.get("reference", ""),
                "effort": effort,
            }
        )

    order = {severity.value: severity.rank for severity in Severity}
    for items in buckets.values():
        items.sort(key=lambda item: (order.get(item["severity"], 5), item["id"]))

    score = int(report.get("score") or 0)
    recoverable = sum(order_weight(item["severity"]) for item in findings)
    potential = max(0, min(100 - score, recoverable))

    counts = {effort: len(items) for effort, items in buckets.items()}
    return {
        "available": bool(findings),
        "counts": counts,
        "total": len(findings),
        "potential_gain": potential,
        "current_score": score,
        "projected_score": min(100, score + potential),
        "quick_wins": [item["id"] for item in buckets["quick"][:5]],
        "buckets": {
            effort: {
                "key": effort,
                "label": EFFORTS[effort]["label"],
                "detail": EFFORTS[effort]["detail"],
                "items": items,
            }
            for effort, items in buckets.items()
        },
    }


def order_weight(severity: str) -> int:
    try:
        return Severity(severity).weight
    except ValueError:
        return 0


def to_markdown(plan: dict[str, Any]) -> str:
    if not plan.get("available"):
        return "Aucun constat : rien à planifier."
    lines = [
        f"Score actuel **{plan['current_score']}/100** → potentiel "
        f"**{plan['projected_score']}/100** (+{plan['potential_gain']} pts une fois tout corrigé).",
        "",
    ]
    for key in ("quick", "sprint", "project"):
        bucket = plan["buckets"][key]
        if not bucket["items"]:
            continue
        lines.append(f"### {bucket['label']} — {len(bucket['items'])} action(s)")
        lines.append(f"_{bucket['detail']}_")
        for item in bucket["items"]:
            lines.append(f"- **[{item['severity_label']}] {item['title']}** — {item['action']}")
        lines.append("")
    return "\n".join(lines)
