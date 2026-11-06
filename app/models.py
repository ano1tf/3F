"""Modèle de données d'une analyse : constats, score, rapport."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {"critical": 20, "high": 8, "medium": 3, "low": 1, "info": 0}[self.value]

    @property
    def rank(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[self.value]


SEVERITY_LABELS_FR = {
    Severity.CRITICAL: "Critique",
    Severity.HIGH: "Élevée",
    Severity.MEDIUM: "Moyenne",
    Severity.LOW: "Faible",
    Severity.INFO: "Information",
}


@dataclass
class Finding:
    """Un problème détecté, avec preuve et remédiation."""

    id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: str = ""
    remediation: str = ""
    reference: str = ""
    confidence: str = "certain"  # certain | probable | a-confirmer
    danger: int = 0  # 1-10, calculé par app.attack
    danger_label: str = ""
    access: list[str] = field(default_factory=list)
    reveals: str = ""
    skill: str = ""
    grants: list[str] = field(default_factory=list)  # actifs atteignables (comptes, base…)
    grants_text: str = ""
    # Référentiels : CWE, test OWASP WSTG, CVSS 3.1 (app.standards)
    cwe: str = ""
    cwe_name: str = ""
    wstg: str = ""
    cvss: float = 0.0
    cvss_vector: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "severity_label": SEVERITY_LABELS_FR[self.severity],
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "reference": self.reference,
            "confidence": self.confidence,
            "danger": self.danger,
            "danger_label": self.danger_label,
            "access": self.access,
            "reveals": self.reveals,
            "skill": self.skill,
            "grants": self.grants,
            "grants_text": self.grants_text,
            "cwe": self.cwe,
            "cwe_name": self.cwe_name,
            "wstg": self.wstg,
            "cvss": self.cvss,
            "cvss_vector": self.cvss_vector,
        }


@dataclass
class CheckResult:
    """Résultat d'une brique d'analyse (succès, échec ou ignorée)."""

    key: str
    label: str
    status: str = "ok"  # ok | error | skipped
    detail: str = ""
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "status": self.status,
            "detail": self.detail,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ScanReport:
    target: str
    final_url: str = ""
    started_at: str = ""
    duration_ms: int = 0
    score: int = 100
    grade: str = "A"
    findings: list[Finding] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)
    fingerprint: dict[str, str] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    score_breakdown: dict[str, int] = field(default_factory=dict)
    priorities: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_id: str = ""
    profile: str = "quick"
    verified: bool = False
    pages: list[dict[str, Any]] = field(default_factory=list)
    third_parties: list[dict[str, Any]] = field(default_factory=list)
    executive: dict[str, Any] = field(default_factory=dict)
    # Annexe « preuve de non-intrusivité » : chaque requête réellement émise.
    requests: list[dict[str, Any]] = field(default_factory=list)
    requests_summary: dict[str, Any] = field(default_factory=dict)
    auth_used: bool = False
    auth_kind: str = ""
    # Lecture « red team » produite par l'équipe d'agents (app.agents)
    attack_plan: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "final_url": self.final_url,
            "started_at": self.started_at,
            "duration_ms": self.duration_ms,
            "score": self.score,
            "grade": self.grade,
            "findings": [f.to_dict() for f in self.findings],
            "checks": [c.to_dict() for c in self.checks],
            "fingerprint": self.fingerprint,
            "counts": self.counts,
            "score_breakdown": self.score_breakdown,
            "priorities": self.priorities,
            "scan_id": self.scan_id,
            "profile": self.profile,
            "verified": self.verified,
            "pages": self.pages,
            "third_parties": self.third_parties,
            "executive": self.executive,
            "requests": self.requests,
            "requests_summary": self.requests_summary,
            "auth_used": self.auth_used,
            "auth_kind": self.auth_kind,
            "attack_plan": self.attack_plan,
            "errors": self.errors,
        }
