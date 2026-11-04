"""Notation : pénalités par sévérité, score sur 100 et note A→F."""

from __future__ import annotations

from ..models import Finding, Severity

GRADES = [
    (90, "A", "Excellent"),
    (80, "B", "Bon"),
    (65, "C", "Correct"),
    (50, "D", "Faible"),
    (30, "E", "Mauvais"),
    (0, "F", "Critique"),
]


def grade_for(score: int) -> tuple[str, str]:
    for threshold, grade, label in GRADES:
        if score >= threshold:
            return grade, label
    return "F", "Critique"


def count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def score_findings(findings: list[Finding]) -> int:
    penalty = sum(f.severity.weight for f in findings)
    # Les constats informatifs ne pénalisent pas, et une seule famille de problème
    # ne doit pas écraser artificiellement le score.
    return max(0, min(100, 100 - penalty))


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (f.severity.rank, f.category, f.title),
    )
