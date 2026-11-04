"""Notation : pénalités par sévérité, rendements décroissants, score et note A→F.

Principe : les premiers constats d'une même famille coûtent cher, les suivants de
moins en moins (un site qui oublie 8 en-têtes n'est pas 8 fois plus vulnérable
qu'un site qui en oublie un). Le score reste donc lisible et comparable entre
deux analyses.
"""

from __future__ import annotations

from collections import defaultdict

from ..models import Finding, Severity

GRADES = [
    (90, "A", "Excellent"),
    (80, "B", "Bon"),
    (65, "C", "Correct"),
    (50, "D", "Faible"),
    (30, "E", "Mauvais"),
    (0, "F", "Critique"),
]

# Facteurs appliqués aux constats d'une même catégorie, du plus grave au moins grave.
DIMINISHING_FACTORS = (1.0, 0.6, 0.35, 0.2, 0.12, 0.08)
FLOOR_FACTOR = 0.05


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


def compute_breakdown(findings: list[Finding]) -> dict[str, int]:
    """Pénalité arrondie par catégorie, pour expliquer le score dans le rapport."""
    by_category: dict[str, list[int]] = defaultdict(list)
    for finding in findings:
        if finding.severity.weight:
            by_category[finding.category].append(finding.severity.weight)

    breakdown: dict[str, int] = {}
    for category, weights in by_category.items():
        total = 0.0
        for index, weight in enumerate(sorted(weights, reverse=True)):
            factor = (
                DIMINISHING_FACTORS[index]
                if index < len(DIMINISHING_FACTORS)
                else FLOOR_FACTOR
            )
            total += weight * factor
        rounded = int(round(total))
        if rounded:
            breakdown[category] = rounded
    return dict(sorted(breakdown.items(), key=lambda item: -item[1]))


def score_findings(findings: list[Finding]) -> int:
    penalty = sum(compute_breakdown(findings).values())
    return max(0, min(100, 100 - penalty))


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.severity.rank, f.category, f.title))


def priorities(findings: list[Finding], limit: int = 3) -> list[Finding]:
    """Les constats à corriger en premier : les plus graves, hors simples informations."""
    ranked = [f for f in sort_findings(findings) if f.severity is not Severity.INFO]
    return ranked[:limit]
