"""Socle de l'équipe d'agents : tableau noir, hypothèses, chaînes, interface Agent.

Tout est symbolique et déterministe : un agent lit le tableau noir, produit des
hypothèses, et peut contester celles des autres. Aucun appel réseau, aucune API
de modèle, aucune dépendance : le raisonnement tient dans des règles explicites,
donc auditable et reproductible.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

# Poids d'impact par actif atteignable (utilisé pour classer les chaînes).
ASSET_WEIGHTS: dict[str, int] = {
    "Console d'administration": 10,
    "Comptes utilisateurs": 9,
    "Paiements et données bancaires": 9,
    "Base de données": 8,
    "Données personnelles": 8,
    "Secrets de configuration": 7,
    "Serveurs et accès système": 7,
    "Infrastructure cloud": 7,
    "Code source et historique Git": 6,
    "Sessions authentifiées": 6,
    "Intégrations SaaS": 5,
    "Réseau interne": 5,
    "Messagerie du domaine": 4,
    "Navigateur des visiteurs": 4,
    "Contenu et réputation du site": 2,
}

# Échelle de compétence (1 = script kiddie, 3 = attaquant organisé).
SKILL_LEVEL = {"aucune": 1, "faible": 1, "intermédiaire": 2, "élevée": 3, "expert": 3}

STAGE_LABELS = {
    "recon": "Reconnaissance",
    "access": "Accès initial",
    "escalation": "Élévation de privilèges",
    "exfiltration": "Exfiltration",
    "persistence": "Persistance",
}


@dataclass
class Hypothesis:
    """Une affirmation d'attaque, appuyée sur des preuves identifiées."""

    id: str
    claim: str
    asset: str
    stage: str
    confidence: float
    evidence: list[str]
    techniques: list[str]
    verification: str
    agent: str
    rationale: str = ""

    @property
    def weight(self) -> int:
        return ASSET_WEIGHTS.get(self.asset, 3)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "claim": self.claim,
            "asset": self.asset,
            "stage": self.stage,
            "stage_label": STAGE_LABELS.get(self.stage, self.stage),
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
            "techniques": self.techniques,
            "verification": self.verification,
            "agent": self.agent,
            "rationale": self.rationale,
        }


@dataclass
class Chain:
    """Une chaîne d'exploitation : plusieurs hypothèses qui s'enchaînent."""

    id: str
    title: str
    summary: str
    impact: list[str]
    steps: list[Hypothesis] = field(default_factory=list)
    difficulty: str = "faible"
    confidence: float = 0.0
    techniques: list[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        impact_weight = max((ASSET_WEIGHTS.get(asset, 3) for asset in self.impact), default=3)
        ease = {"aucune": 1.0, "faible": 0.9, "intermédiaire": 0.65, "élevée": 0.4}.get(
            self.difficulty, 0.8
        )
        return round(impact_weight * self.confidence * ease, 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "summary": self.summary,
            "impact": self.impact,
            "steps": [step.to_dict() for step in self.steps],
            "difficulty": self.difficulty,
            "confidence": round(self.confidence, 2),
            "techniques": self.techniques,
            "score": self.score,
        }


class Blackboard:
    """Mémoire partagée : ce que l'équipe sait, et ce qu'elle a décidé."""

    def __init__(self, report: dict[str, Any]) -> None:
        self.report = report
        self.findings: dict[str, dict[str, Any]] = {
            str(finding.get("id", "")): finding for finding in report.get("findings") or []
        }
        self.pages: list[dict[str, Any]] = report.get("pages") or []
        self.third_parties: list[dict[str, Any]] = report.get("third_parties") or []
        self.fingerprint: dict[str, Any] = report.get("fingerprint") or {}
        self.target: str = report.get("final_url") or report.get("target") or ""
        self.hypotheses: list[Hypothesis] = []
        self.chains: list[Chain] = []
        self.trace: list[dict[str, str]] = []
        self.notes: list[str] = []

    # --- lecture des preuves ------------------------------------------------

    def has(self, *finding_ids: str) -> bool:
        return any(finding_id in self.findings for finding_id in finding_ids)

    def with_prefix(self, *prefixes: str) -> list[dict[str, Any]]:
        return [
            finding
            for finding_id, finding in self.findings.items()
            if any(finding_id.startswith(prefix) for prefix in prefixes)
        ]

    def first_id(self, *prefixes: str) -> str:
        for finding_id in self.findings:
            if any(finding_id.startswith(prefix) for prefix in prefixes):
                return finding_id
        return ""

    def ids(self, *prefixes: str) -> list[str]:
        return [finding["id"] for finding in self.with_prefix(*prefixes)]

    def severity(self, *prefixes: str) -> str:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        found = self.with_prefix(*prefixes)
        if not found:
            return ""
        return sorted(found, key=lambda f: order.get(f.get("severity", "info"), 4))[0]["severity"]

    def grants(self, *prefixes: str) -> list[str]:
        collected: list[str] = []
        for finding in self.with_prefix(*prefixes):
            for asset in finding.get("grants") or []:
                if asset not in collected:
                    collected.append(asset)
        return collected

    # --- écriture -----------------------------------------------------------

    def add(self, hypothesis: Hypothesis) -> Hypothesis:
        if len(self.hypotheses) >= 40:
            self.notes.append("Budget d'hypothèses atteint : les suivantes sont ignorées.")
            return hypothesis
        if any(item.id == hypothesis.id for item in self.hypotheses):
            return next(item for item in self.hypotheses if item.id == hypothesis.id)
        self.hypotheses.append(hypothesis)
        return hypothesis

    def adjust(self, hypothesis_id: str, delta: float, reason: str, agent: str) -> None:
        """Revue par les pairs : un agent corrige la confiance d'une hypothèse."""
        for hypothesis in self.hypotheses:
            if hypothesis.id == hypothesis_id:
                before = hypothesis.confidence
                hypothesis.confidence = max(0.05, min(0.98, hypothesis.confidence + delta))
                if abs(hypothesis.confidence - before) > 1e-9:
                    self.log(
                        agent,
                        f"{hypothesis_id} : confiance {before:.2f} → "
                        f"{hypothesis.confidence:.2f} ({reason})",
                        "review",
                    )
                return

    def get(self, hypothesis_id: str) -> Hypothesis | None:
        return next((item for item in self.hypotheses if item.id == hypothesis_id), None)

    def log(self, agent: str, message: str, kind: str = "info") -> None:
        self.trace.append({"agent": agent, "kind": kind, "message": message})

    # --- synthèse -----------------------------------------------------------

    def by_stage(self, stage: str) -> list[Hypothesis]:
        return [item for item in self.hypotheses if item.stage == stage]

    def sorted_hypotheses(self) -> list[Hypothesis]:
        return sorted(
            self.hypotheses,
            key=lambda item: (-item.weight * item.confidence, item.id),
        )


class Agent:
    """Un spécialiste : un domaine, une méthode d'analyse, des hypothèses."""

    name: str = "agent"
    role: str = "Spécialiste"
    domain: str = "général"

    def __init__(self) -> None:
        self.messages: list[str] = []

    # Chaque agent implémente cette méthode.
    def analyse(self, board: Blackboard) -> Iterable[Hypothesis]:  # pragma: no cover - interface
        return []

    # Un agent peut contester les hypothèses des autres : c'est la revue par les pairs.
    def review(self, board: Blackboard) -> list[Hypothesis]:
        return []

    def run(self, board: Blackboard) -> list[Hypothesis]:
        produced = list(self.analyse(board))
        for hypothesis in produced:
            board.add(hypothesis)
        if produced:
            board.log(self.name, f"{len(produced)} hypothèse(s) formulée(s).")
        else:
            board.log(self.name, "Aucune hypothèse : rien de pertinent dans son domaine.", "skip")
        return produced

    def describe(self) -> dict[str, str]:
        return {"name": self.name, "role": self.role, "domain": self.domain}
