"""Équipe d'agents d'analyse — raisonnement symbolique, sans aucune API externe.

Le principe : plusieurs agents spécialisés observent les **preuves déjà
collectées** par le scanner (constats, pages, empreinte, dépendances tierces),
puis délibèrent sur un tableau noir commun pour produire des hypothèses
d'attaque, se les critiquer mutuellement et proposer des chaînes
d'exploitation réalistes.

Aucun agent n'exécute d'exploit, n'envoie de charge, ne forge de requête : ils
raisonnent, hiérarchisent et indiquent la vérification manuelle non destructive
à faire. C'est un « red team » de papier — exactement ce qu'un pentester
prépare avant de toucher au clavier.
"""

from __future__ import annotations

from .orchestrator import run_team

__all__ = ["run_team"]
