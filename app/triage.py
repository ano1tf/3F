"""Triage d'un rapport : ce que le pentester retient vraiment.

Un scanner produit des constats, un pentester produit un **verdict**. Entre les
deux, il y a un travail que l'outil ne peut pas faire à sa place : vérifier,
écarter les faux positifs, assumer un risque accepté par le client.

Ce module porte les trois verdicts, la note associée, et leurs conséquences :
score recalculé sans les faux positifs, exports annotés (SARIF `suppressions`),
synthèse du triage.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from .models import Severity
from .scanner.scoring import grade_for, score_findings

# Verdict -> libellé affiché. L'ordre est celui de l'interface.
VERDICTS: dict[str, str] = {
    "a-verifier": "À vérifier",
    "confirme": "Confirmé",
    "faux-positif": "Faux positif",
    "risque-accepte": "Risque accepté",
}
DEFAULT_VERDICT = "a-verifier"
MAX_NOTE = 500

# Verdicts qui retirent le constat du score : le problème n'existe pas, ou le
# client l'a explicitement accepté (il reste listé, mais ne pénalise plus).
OUT_OF_SCORE = {"faux-positif", "risque-accepte"}


class TriageError(ValueError):
    """Verdict inconnu ou note trop longue."""


def normalize(verdict: str) -> str:
    candidate = (verdict or "").strip().lower()
    if candidate not in VERDICTS:
        allowed = ", ".join(VERDICTS)
        raise TriageError(f"Verdict inconnu : « {verdict} ». Valeurs acceptées : {allowed}.")
    return candidate


def clean_note(note: str) -> str:
    text = " ".join((note or "").split())
    if len(text) > MAX_NOTE:
        raise TriageError(f"Note trop longue ({len(text)} caractères, max {MAX_NOTE}).")
    return text


def entry(verdict: str, note: str = "", updated_at: str = "") -> dict[str, Any]:
    """Entrée de triage normalisée, prête à persister ou à fusionner."""
    normalized = normalize(verdict)
    return {
        "verdict": normalized,
        "label": VERDICTS[normalized],
        "note": clean_note(note),
        "updated_at": updated_at or datetime.now(UTC).isoformat(timespec="seconds"),
    }


def summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Répartition des verdicts, pour la synthèse et les exports."""
    counts = {key: 0 for key in VERDICTS}
    for finding in findings:
        verdict = finding.get("verdict") or DEFAULT_VERDICT
        counts[verdict if verdict in counts else DEFAULT_VERDICT] += 1
    return {
        "counts": counts,
        "triaged": sum(count for key, count in counts.items() if key != DEFAULT_VERDICT),
        "untriaged": counts[DEFAULT_VERDICT],
        "total": len(findings),
    }


def visible_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Constats qui pèsent encore dans le score (faux positifs et acceptés exclus)."""
    return [f for f in findings if (f.get("verdict") or DEFAULT_VERDICT) not in OUT_OF_SCORE]


def rescore(findings: list[dict[str, Any]]) -> tuple[int, str]:
    """Score et note après triage : on ne garde que ce qui est réellement dû."""
    proxies = [
        SimpleNamespace(
            category=finding.get("category", ""),
            severity=Severity(finding.get("severity", "info")),
        )
        for finding in visible_findings(findings)
    ]
    score = score_findings(proxies)  # type: ignore[arg-type]
    grade, _label = grade_for(score)
    return score, grade


def merge(report: dict[str, Any], entries: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Injecte les verdicts dans un rapport et ajoute la synthèse de triage."""
    findings = report.get("findings") or []
    for finding in findings:
        stored = entries.get(str(finding.get("id", "")))
        if stored:
            finding["verdict"] = stored["verdict"]
            finding["verdict_label"] = stored.get("label") or VERDICTS[stored["verdict"]]
            finding["verdict_note"] = stored.get("note", "")
            finding["verdict_at"] = stored.get("updated_at", "")
        else:
            finding["verdict"] = ""
            finding["verdict_label"] = ""
            finding["verdict_note"] = ""
            finding["verdict_at"] = ""

    if not entries:
        report["triage_summary"] = {}
        report["score_after_triage"] = None
        report["grade_after_triage"] = ""
        return report

    report["triage_summary"] = summary(findings)
    score, grade = rescore(findings)
    report["score_after_triage"] = score
    report["grade_after_triage"] = grade
    return report


__all__ = [
    "DEFAULT_VERDICT",
    "MAX_NOTE",
    "OUT_OF_SCORE",
    "TriageError",
    "VERDICTS",
    "clean_note",
    "entry",
    "merge",
    "normalize",
    "rescore",
    "summary",
    "visible_findings",
]
