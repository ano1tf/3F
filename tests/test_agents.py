"""Équipe d'agents red team : hypothèses, revue croisée, chaînes, garanties.

Ces tests verrouillent la doctrine : raisonnement symbolique déterministe, aucune
requête réseau, aucune charge exploitable produite.
"""

from __future__ import annotations

import socket

import pytest

from app.agents import run_team
from app.agents.base import STAGE_LABELS, Hypothesis
from app.agents.critic import STAGE_ORDER, CriticAgent, impact_weight
from app.agents.specialists import SPECIALISTS, ClientSideAgent, ReconAgent
from app.models import ScanReport

# --- utilitaires -----------------------------------------------------------


def finding(finding_id: str, severity: str = "high", **extra) -> dict:
    return {"id": finding_id, "severity": severity, "title": finding_id, **extra}


def report(*findings: dict, pages: list[dict] | None = None, third: list[dict] | None = None) -> dict:
    return {
        "target": "https://exemple.test",
        "final_url": "https://exemple.test/",
        "findings": list(findings),
        "pages": pages or [],
        "third_parties": third or [],
        "fingerprint": {},
    }


def hypothesis(
    hyp_id: str,
    *,
    stage: str = "access",
    asset: str = "Comptes utilisateurs",
    confidence: float = 0.6,
    agent: str = "access",
    claim: str = "Affirmation de test",
) -> Hypothesis:
    return Hypothesis(
        id=hyp_id,
        claim=claim,
        asset=asset,
        stage=stage,
        confidence=confidence,
        evidence=["evidence.test"],
        techniques=["T1078"],
        verification="Vérifier manuellement, sans charge.",
        agent=agent,
    )


# --- spécialistes ----------------------------------------------------------


def test_specialists_are_described_and_unique():
    agents = [specialist() for specialist in SPECIALISTS]
    assert len(agents) == 7
    names = [agent.name for agent in agents]
    assert len(set(names)) == len(names)
    for agent in agents:
        description = agent.describe()
        assert description["name"] and description["role"] and description["domain"]


def test_recon_agent_maps_the_surface():
    board_report = report(
        finding("headers.version-disclosure", "low"),
        finding("errors.stack-trace", "medium"),
        finding("robots.disclosure", "low"),
    )
    hypotheses = list(ReconAgent().analyse(board_report_board(board_report)))
    ids = {item.id for item in hypotheses}
    assert {"recon:version:stack", "recon:trace:paths", "recon:robots:endpoints"} <= ids
    for item in hypotheses:
        assert item.id.startswith("recon:")
        assert item.agent == "recon"
        assert item.stage == "recon"
        assert item.evidence  # chaque hypothèse cite ses preuves
        assert item.verification.strip()
        assert 0.0 < item.confidence <= 1.0


def board_report_board(payload: dict):
    from app.agents.base import Blackboard

    return Blackboard(payload)


def test_one_agent_stays_silent_without_evidence():
    agent = ReconAgent()
    hypotheses = list(agent.analyse(board_report_board(report(finding("cookies.flags", "medium")))))
    assert hypotheses == []


def test_exposure_agent_chains_git_then_history():
    payload = report(finding("exposure.git", "critical"), finding("exposure.git-head", "high"))
    hypotheses = {item.id: item for item in _run_specialist("exposure", payload)}
    assert hypotheses["exposure:source:git"].stage == "access"
    assert hypotheses["exposure:secrets:history"].stage == "exfiltration"
    assert hypotheses["exposure:source:git"].weight == 6  # code source
    assert hypotheses["exposure:secrets:history"].weight == 7  # secrets


def _run_specialist(name: str, payload: dict):
    from app.agents.base import Blackboard

    agent = next(specialist() for specialist in SPECIALISTS if specialist.name == name)
    board = Blackboard(payload)
    return list(agent.analyse(board))


def test_confidence_follows_severity():
    low = _run_specialist("access", report(finding("access.idor-object-id", "low")))
    high = _run_specialist("access", report(finding("access.idor-object-id", "critical")))
    assert low and high
    assert high[0].confidence > low[0].confidence


# --- revue croisée ---------------------------------------------------------


def test_csp_review_tempers_xss_dependency():
    from app.agents.base import Blackboard

    board = Blackboard(report(finding("content.reflected-parameter", "medium")))
    xss = board.add(hypothesis("clientside:xss:reflected", agent="clientside", asset="Navigateur des visiteurs"))
    before = xss.confidence

    ClientSideAgent().review(board)
    assert xss.confidence == pytest.approx(before - 0.05)

    strict = Blackboard(report(finding("headers.csp-unsafe", "medium")))
    kept = strict.add(
        hypothesis("clientside:xss:reflected", agent="clientside", asset="Navigateur des visiteurs")
    )
    ClientSideAgent().review(strict)
    assert kept.confidence == pytest.approx(before)  # CSP trouée : pas de tempérament


def test_session_theft_requires_xss_evidence():
    from app.agents.base import Blackboard
    from app.agents.specialists import CredentialAgent

    board = Blackboard(report(finding("cookies.flags", "high")))
    theft = board.add(hypothesis("credentials:session:theft", agent="credentials"))
    before = theft.confidence
    CredentialAgent().review(board)
    assert theft.confidence == pytest.approx(before - 0.1)

    supported = Blackboard(report(finding("cookies.flags", "high")))
    xss = supported.add(hypothesis("clientside:xss:reflected", agent="clientside"))
    theft = supported.add(hypothesis("credentials:session:theft", agent="credentials"))
    ClientSideAgent().review(supported)  # la revue CSP peut modérer le XSS
    before = theft.confidence
    CredentialAgent().review(supported)
    assert xss is not None and theft.confidence == pytest.approx(before)


def test_stack_knowledge_boosts_server_hypotheses():
    from app.agents.base import Blackboard

    board = Blackboard(report(finding("headers.version-disclosure", "low")))
    server = board.add(
        hypothesis("recon:version:stack", stage="recon", asset="Serveurs et accès système", agent="recon")
    )
    other = board.add(hypothesis("access:idor:horizontal", asset="Données personnelles"))
    before_server, before_other = server.confidence, other.confidence
    ReconAgent().review(board)
    assert server.confidence == pytest.approx(before_server + 0.05)
    assert other.confidence == pytest.approx(before_other)


def test_confidence_is_bounded():
    from app.agents.base import Blackboard

    board = Blackboard(report())
    item = board.add(hypothesis("x", confidence=0.96))
    board.adjust(item.id, 0.5, "test", "critic")
    assert item.confidence <= 0.98
    board.adjust(item.id, -2.0, "test", "critic")
    assert item.confidence >= 0.05


# --- arbitrage -------------------------------------------------------------


def test_prune_drops_unsupported_hypotheses():
    from app.agents.base import Blackboard

    board = Blackboard(report())
    board.add(hypothesis("low", confidence=0.2))
    critic = CriticAgent()
    critic.prune(board)
    assert board.hypotheses == []
    assert critic.dissent and critic.dissent[0]["hypothesis"] == "low"
    assert critic.dissent[0]["reason"].startswith("confiance trop faible")


def test_prune_keeps_severe_hypothesis_without_full_confidence():
    from app.agents.base import Blackboard

    board = Blackboard(report())
    board.add(hypothesis("critical", asset="Comptes utilisateurs", confidence=0.45))
    board.add(hypothesis("weak", asset="Contenu et réputation du site", confidence=0.45))
    critic = CriticAgent(min_confidence=0.6)
    critic.prune(board)
    ids = {item.id for item in board.hypotheses}
    assert ids == {"critical"}


def test_arbitrate_merges_duplicates_and_keeps_the_strongest():
    from app.agents.base import Blackboard

    board = Blackboard(report())
    weak = board.add(hypothesis("dup:a", confidence=0.4, claim="Même constat, même sens"))
    strong = board.add(hypothesis("dup:b", confidence=0.8, claim="Même constat, même sens"))
    assert weak.id != strong.id
    critic = CriticAgent()
    critic.arbitrate(board)
    assert len(board.hypotheses) == 1
    assert board.hypotheses[0].id == "dup:b"
    assert any(entry["kind"] == "merge" for entry in board.trace)


# --- chaînes ---------------------------------------------------------------


def test_build_chains_orders_stages_and_takes_min_confidence():
    from app.agents.base import Blackboard

    board = Blackboard(report())
    board.add(hypothesis("step:2", stage="exfiltration", asset="Données personnelles", confidence=0.5, agent="access"))
    board.add(hypothesis("step:1", stage="access", asset="Base de données", confidence=0.9, agent="access"))
    board.add(
        hypothesis(
            "step:0", stage="access", asset="Comptes utilisateurs", confidence=0.7, agent="credentials"
        )
    )
    chains = CriticAgent().build_chains(board)

    data = next(chain for chain in chains if chain.id == "chain:data-exfiltration")
    assert [step.id for step in data.steps] == ["step:1", "step:2"]
    assert data.confidence == pytest.approx(0.5)  # maillon le plus faible
    assert all(
        STAGE_ORDER[step.stage] >= STAGE_ORDER[previous.stage]
        for previous, step in zip(data.steps, data.steps[1:], strict=False)
    )


def test_chain_score_combines_impact_confidence_and_ease():
    from app.agents.base import Blackboard

    board = Blackboard(report())
    board.add(hypothesis("one", stage="access", asset="Comptes utilisateurs", confidence=0.8, agent="access"))
    chain = CriticAgent().build_chains(board)[0]
    expected = round(impact_weight(chain.impact) * chain.confidence * 0.9, 2)
    assert chain.score == pytest.approx(expected)
    assert chain.difficulty == "faible"


def test_chain_requires_an_entry_point():
    from app.agents.base import Blackboard

    board = Blackboard(report())
    late = board.add(hypothesis("late", stage="exfiltration", confidence=0.8))
    early = board.add(hypothesis("early", stage="access", confidence=0.8))
    critic = CriticAgent()
    # Une chaîne qui démarre déjà à l'exfiltration n'explique pas l'entrée : elle est écartée.
    assert critic._chain(board, "chain:test", "Test", "Résumé", [late]) is None
    assert any(entry["kind"] == "drop" for entry in board.trace)
    # Avec un point d'entrée, les étapes sont remises dans l'ordre logique.
    chain = critic._chain(board, "chain:test", "Test", "Résumé", [late, early])
    assert chain is not None and [step.id for step in chain.steps] == ["early", "late"]


# --- orchestration ---------------------------------------------------------


def _full_report() -> dict:
    return report(
        finding("headers.version-disclosure", "low"),
        finding("exposure.git", "critical"),
        finding("exposure.dotenv", "critical"),
        finding("access.idor-object-id", "high"),
        finding("cookies.flags", "medium"),
        finding("headers.csp-unsafe", "medium"),
        finding("transport.no-https", "high"),
        finding("libs.jquery", "medium"),
        finding("surface.third-parties", "info"),
        finding("errors.stack-trace", "medium"),
    )


def test_run_team_produces_a_defensible_plan():
    plan = run_team(_full_report())

    assert plan["available"] is True
    assert plan["narrative"].strip()
    assert plan["doctrine"].strip()
    assert plan["chains"] and len(plan["chains"]) <= 3
    assert plan["hypotheses"]
    assert plan["stats"]["hypotheses"] >= len(plan["hypotheses"])
    assert plan["stats"]["chains"] == len(plan["chains"])
    assert 0.0 < plan["stats"]["confidence"] <= 1.0
    assert set(plan["stats"]["coverage"]) <= {agent["name"] for agent in plan["agents"]}
    assert sum(plan["stages"].values()) == plan["stats"]["hypotheses"]
    assert plan["stage_labels"] == STAGE_LABELS

    for chain in plan["chains"]:
        assert chain["score"] > 0
        assert 0.0 < chain["confidence"] <= 1.0
        assert chain["steps"] and chain["impact"]
        for step in chain["steps"]:
            assert step["stage_label"]
            assert step["verification"]
            assert step["evidence"]

    for step in plan["next_steps"]:
        assert step["action"] and step["confidence"].endswith("%")


def test_max_chains_is_respected():
    plan = run_team(_full_report(), max_chains=1)
    assert len(plan["chains"]) == 1


def test_empty_report_is_reported_as_unavailable():
    plan = run_team(report())
    assert plan["available"] is False
    assert plan["chains"] == [] and plan["hypotheses"] == []
    assert plan["stats"]["hypotheses"] == 0
    assert plan["trace"]


def test_team_is_deterministic():
    first = run_team(_full_report())
    second = run_team(_full_report())
    first.pop("duration_ms")
    second.pop("duration_ms")
    assert first == second


def test_agents_never_touch_the_network(monkeypatch):
    def boom(*args, **kwargs):  # pragma: no cover - le test échoue si appelé
        raise AssertionError("L'équipe d'agents ne doit émettre aucune requête réseau")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)

    plan = run_team(_full_report())
    assert plan["available"] is True
    assert plan["chains"]


def test_agents_never_produce_an_exploit():
    plan = run_team(_full_report())
    forbidden = ("curl ", "wget ", "<script", "DROP TABLE", "' OR 1=1", "POST ", "payload=")
    rendered = repr(plan).lower()
    for token in forbidden:
        assert token.lower() not in rendered


def test_scan_report_exposes_the_attack_plan():
    report_obj = ScanReport(target="https://exemple.test", final_url="https://exemple.test/")
    assert report_obj.attack_plan == {}
    report_obj.attack_plan = run_team(_full_report())
    assert report_obj.to_dict()["attack_plan"]["chains"]
