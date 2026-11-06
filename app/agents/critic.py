"""Le chef d'équipe : arbitrer, enchaîner, trancher.

Il ne produit pas de nouvelles hypothèses. Il coupe celles qui ne tiennent pas,
relie les autres en chaînes d'exploitation, et écrit la lecture « red team » :
ce que l'équipe retient, ce qu'elle écarte et pourquoi.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .base import ASSET_WEIGHTS, STAGE_LABELS, Blackboard, Chain, Hypothesis

STAGE_ORDER = {"recon": 0, "access": 1, "escalation": 2, "exfiltration": 3, "persistence": 4}

DOCTRINE = (
    "Aucun agent n'exécute d'exploit, ne forge de jeton, ne soumet de formulaire ni ne modifie "
    "de donnée : l'équipe raisonne sur les preuves déjà collectées et désigne la vérification "
    "manuelle non destructive à mener. Toute confirmation exige l'accord du client et des "
    "comptes de test dédiés."
)


class CriticAgent:
    """Arbitre final : cohérence, chaînes, narration."""

    name = "lead"
    role = "Chef d'équipe red team — arbitrage et narration"
    domain = "synthèse"

    def __init__(self, min_confidence: float = 0.3) -> None:
        self.min_confidence = min_confidence
        self.dissent: list[dict[str, str]] = []

    # --- arbitrage ----------------------------------------------------------

    def prune(self, board: Blackboard) -> None:
        kept: list[Hypothesis] = []
        for hypothesis in board.hypotheses:
            severe = hypothesis.weight >= 8 and hypothesis.confidence >= 0.45
            if hypothesis.confidence < self.min_confidence and not severe:
                self.dissent.append(
                    {
                        "hypothesis": hypothesis.id,
                        "reason": (
                            f"confiance trop faible ({hypothesis.confidence:.2f}) pour figurer "
                            "dans la chaîne ; à revoir si le contexte change"
                        ),
                    }
                )
                board.log(self.name, f"{hypothesis.id} écartée (confiance faible).", "drop")
                continue
            kept.append(hypothesis)
        board.hypotheses = kept

    def arbitrate(self, board: Blackboard) -> None:
        """Résout les doublons de sens : deux hypothèses identiques ne comptent qu'une fois."""
        seen: dict[str, Hypothesis] = {}
        unique: list[Hypothesis] = []
        for hypothesis in board.hypotheses:
            key = f"{hypothesis.stage}:{hypothesis.asset}:{hypothesis.claim[:40]}"
            if key in seen:
                winner = seen[key]
                if hypothesis.confidence > winner.confidence:
                    unique[unique.index(winner)] = hypothesis
                    seen[key] = hypothesis
                board.log(self.name, f"{hypothesis.id} fusionnée dans {seen[key].id}.", "merge")
                continue
            seen[key] = hypothesis
            unique.append(hypothesis)
        board.hypotheses = unique

    # --- chaînes ------------------------------------------------------------

    def _chain(
        self,
        board: Blackboard,
        chain_id: str,
        title: str,
        summary: str,
        steps: list[Hypothesis],
    ) -> Chain | None:
        steps = [step for step in steps if step is not None]
        if not steps:
            return None
        steps.sort(key=lambda item: STAGE_ORDER.get(item.stage, 9))
        # Une chaîne sans point d'entrée (elle commence déjà à l'exfiltration) n'en est pas une :
        # on ne saurait pas par où l'attaquant serait entré.
        if STAGE_ORDER.get(steps[0].stage, 9) >= STAGE_ORDER["exfiltration"]:
            board.log(
                self.name,
                f"Chaîne « {title} » écartée : pas de point d'entrée "
                f"({STAGE_LABELS.get(steps[0].stage, steps[0].stage)}).",
                "drop",
            )
            return None
        impact: list[str] = []
        for step in steps:
            if step.asset not in impact:
                impact.append(step.asset)
        confidence = min(step.confidence for step in steps)
        difficulty = (
            "faible"
            if confidence >= 0.7
            else "intermédiaire"
            if confidence >= 0.45
            else "élevée"
        )
        techniques: list[str] = []
        for step in steps:
            for technique in step.techniques:
                if technique not in techniques:
                    techniques.append(technique)
        chain = Chain(
            id=chain_id,
            title=title,
            summary=summary,
            impact=impact,
            steps=steps,
            difficulty=difficulty,
            confidence=confidence,
            techniques=techniques,
        )
        board.log(
            self.name,
            f"Chaîne retenue : {title} (score {chain.score}, {len(steps)} étape(s)).",
        )
        return chain

    def build_chains(self, board: Blackboard) -> list[Chain]:
        chains: list[Chain] = []
        ranked = board.sorted_hypotheses()

        def pick(predicate: Callable[[Hypothesis], bool], limit: int = 3) -> list[Hypothesis]:
            return [item for item in ranked if predicate(item)][:limit]

        # 1. Prise de contrôle d'un compte
        accounts = pick(
            lambda h: h.agent in {"credentials", "access", "transport"}
            and h.asset in {"Comptes utilisateurs", "Console d'administration", "Sessions authentifiées"}
            and h.stage in {"access", "escalation", "exfiltration"}
        )
        if accounts:
            chains.append(
                self._chain(
                    board,
                    "chain:account-takeover",
                    "Prise de contrôle d'un compte",
                    (
                        "Un attaquant obtient un compte valide — ou les droits d'un administrateur — "
                        "sans jamais casser de mot de passe : la faille est dans la vérification, pas dans le secret."
                    ),
                    accounts,
                )
            )

        # 2. Exfiltration de données
        data = pick(
            lambda h: h.asset in {"Données personnelles", "Base de données", "Paiements et données bancaires"}
            or h.stage == "exfiltration"
        )
        if data:
            chains.append(
                self._chain(
                    board,
                    "chain:data-exfiltration",
                    "Exfiltration de données clients",
                    (
                        "Les données partent objet par objet : chaque identifiant manipulé ramène un dossier "
                        "de plus. C'est la fuite la plus coûteuse en RGPD, et la plus discrète."
                    ),
                    data,
                )
            )

        # 3. Compromission d'infrastructure
        infra = pick(
            lambda h: h.asset
            in {"Infrastructure cloud", "Serveurs et accès système", "Secrets de configuration", "Code source et historique Git"}
        )
        if infra:
            chains.append(
                self._chain(
                    board,
                    "chain:infrastructure",
                    "Compromission de l'infrastructure",
                    (
                        "Un secret de déploiement suffit à sortir du site : l'attaquant ne cherche plus la "
                        "faille applicative, il prend la main sur les machines et les factures cloud."
                    ),
                    infra,
                )
            )

        # 4. Compromission du navigateur des visiteurs
        clients = pick(
            lambda h: h.asset in {"Navigateur des visiteurs", "Contenu et réputation du site"}
            and h.agent in {"clientside", "supplychain"}
        )
        if clients:
            chains.append(
                self._chain(
                    board,
                    "chain:client-compromise",
                    "Compromission des visiteurs",
                    (
                        "Le site devient l'arme : script tiers, bibliothèque obsolète ou paramètre reflété, "
                        "et ce sont les visiteurs — parfois vos clients — qui exécutent le code."
                    ),
                    clients,
                )
            )

        # 5. Cartographie préalable, même sans faille exploitable
        if not chains:
            recon = pick(lambda h: h.stage == "recon", limit=2)
            fallback = self._chain(
                board,
                "chain:reconnaissance",
                "Reconnaissance exploitable",
                (
                    "Aucune chaîne complète n'est étayée par les preuves actuelles, mais la surface "
                    "reste cartographiable : c'est la matière première d'une attaque ultérieure."
                ),
                recon,
            )
            if fallback:
                chains.append(fallback)

        return sorted(chains, key=lambda chain: -chain.score)

    # --- narration ----------------------------------------------------------

    def narrate(self, board: Blackboard, chains: list[Chain]) -> str:
        if not chains:
            return (
                "L'équipe n'a pas pu étayer de chaîne d'exploitation à partir des preuves "
                "collectées : la surface connue ne suffit pas à décrire une attaque réaliste. "
                "C'est un bon signe, pas une garantie."
            )
        top = chains[0]
        impact = ", ".join(top.impact[:3])
        return (
            f"{len(chains)} chaîne(s) d'exploitation étayée(s). La plus dangereuse : "
            f"« {top.title} » (score {top.score}, confiance {top.confidence:.0%}, "
            f"difficulté {top.difficulty}). Point d'entrée : {top.steps[0].claim} "
            f"Impact atteignable : {impact}."
        )

    def next_steps(self, board: Blackboard, limit: int = 5) -> list[dict[str, str]]:
        steps: list[dict[str, str]] = []
        seen: set[str] = set()
        for hypothesis in board.sorted_hypotheses():
            key = hypothesis.verification[:60]
            if key in seen:
                continue
            seen.add(key)
            steps.append(
                {
                    "hypothesis": hypothesis.id,
                    "action": hypothesis.verification,
                    "asset": hypothesis.asset,
                    "confidence": f"{hypothesis.confidence:.0%}",
                }
            )
            if len(steps) >= limit:
                break
        return steps

    # --- livraison ----------------------------------------------------------

    def deliver(self, board: Blackboard, max_chains: int = 3) -> dict[str, Any]:
        self.prune(board)
        self.arbitrate(board)
        chains = self.build_chains(board)[:max_chains]
        board.chains = chains
        hypotheses = board.sorted_hypotheses()[:12]
        narrative = self.narrate(board, chains)

        return {
            "available": bool(board.hypotheses),
            "narrative": narrative,
            "chains": [chain.to_dict() for chain in chains],
            "hypotheses": [hypothesis.to_dict() for hypothesis in hypotheses],
            "next_steps": self.next_steps(board),
            "dissent": self.dissent,
            "stats": {
                "hypotheses": len(board.hypotheses),
                "chains": len(chains),
                "confidence": round(
                    sum(item.confidence for item in board.hypotheses) / len(board.hypotheses), 2
                )
                if board.hypotheses
                else 0.0,
                "coverage": sorted({item.agent for item in board.hypotheses}),
            },
            "stages": {
                stage: len([h for h in board.hypotheses if h.stage == stage])
                for stage in STAGE_ORDER
            },
            "stage_labels": STAGE_LABELS,
            "doctrine": DOCTRINE,
            "trace": board.trace,
        }


def impact_weight(assets: list[str]) -> int:
    return max((ASSET_WEIGHTS.get(asset, 3) for asset in assets), default=0)
