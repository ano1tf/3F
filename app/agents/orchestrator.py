"""Orchestrateur : fait travailler l'équipe et rend la lecture red team.

Déroulé, entièrement local et déterministe :

1. **Perception** — le tableau noir reçoit les preuves déjà collectées (constats,
   pages, empreinte, dépendances tierces).
2. **Délibération** — chaque spécialiste formule ses hypothèses, sans se
   concerter, pour éviter le biais de groupe.
3. **Revue par les pairs** — les agents corrigent la confiance des hypothèses
   des autres (une pile identifiée crédibilise, une CSP stricte tempère).
4. **Arbitrage** — le chef d'équipe écarte le non étayé, fusionne les doublons,
   assemble les chaînes, écrit la narration.

Aucune requête réseau n'est émise pendant cette phase : les agents ne peuvent
pas « aller voir » — c'est la garantie qu'aucun exploit ne sera tenté.
"""

from __future__ import annotations

import time
from typing import Any

from .base import Blackboard
from .critic import CriticAgent
from .specialists import SPECIALISTS


def run_team(report: dict[str, Any], max_chains: int = 3) -> dict[str, Any]:
    """Fait délibérer l'équipe sur un rapport déjà produit."""
    started = time.perf_counter()
    board = Blackboard(report)

    if not board.findings:
        return {
            "available": False,
            "narrative": "Aucun constat : l'équipe n'a rien à analyser.",
            "chains": [],
            "hypotheses": [],
            "next_steps": [],
            "dissent": [],
            "stats": {"hypotheses": 0, "chains": 0, "confidence": 0.0, "coverage": []},
            "stages": {},
            "stage_labels": {},
            "doctrine": "",
            "trace": [{"agent": "lead", "kind": "skip", "message": "Rapport vide."}],
            "duration_ms": 0,
        }

    agents = [specialist() for specialist in SPECIALISTS]
    for agent in agents:
        agent.run(board)

    # Revue croisée : chacun peut contredire les autres, dans son domaine.
    for agent in agents:
        agent.review(board)

    critic = CriticAgent()
    result = critic.deliver(board, max_chains=max_chains)
    result["agents"] = [
        {
            **agent.describe(),
            "hypotheses": len([h for h in board.hypotheses if h.agent == agent.name]),
        }
        for agent in agents
    ] + [{"name": critic.name, "role": critic.role, "domain": critic.domain, "hypotheses": 0}]
    result["duration_ms"] = int((time.perf_counter() - started) * 1000)
    return result


__all__ = ["run_team"]
