"""En-tête d'authentification fourni par le pentester, pour un scan autorisé.

Un auditeur doit pouvoir analyser la zone connectée : sans cela, la moitié de la
surface (espaces clients, back-offices) reste invisible. Mais un cookie de
session est un secret : il ne doit **jamais** entrer dans un rapport, une base,
un journal ou une URL.

Ce module est le seul endroit qui accepte, valide et masque cette valeur.
"""

from __future__ import annotations

import re

# En-têtes acceptés : ceux qui servent réellement à s'authentifier.
ALLOWED_HEADERS = {
    "authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
}

MAX_LENGTH = 4096
_HEADER_NAME = re.compile(r"^[A-Za-z0-9-]+$")
# Un en-tête ne contient pas de saut de ligne : sinon injection d'en-têtes.
_FORBIDDEN = re.compile(r"[\r\n\x00]")


class AuthHeaderError(ValueError):
    """En-tête refusé : nom non autorisé, valeur vide ou caractère interdit."""


def parse(raw: str) -> tuple[str, str]:
    """Transforme `Authorization: Bearer …` en couple (nom, valeur).

    Accepte aussi une valeur seule pour `Authorization` (`Bearer abc…`).
    """
    if not isinstance(raw, str):
        raise AuthHeaderError("Format attendu : « Nom: valeur ».")
    candidate = raw.strip()
    if not candidate:
        raise AuthHeaderError("En-tête vide.")
    if _FORBIDDEN.search(candidate):
        raise AuthHeaderError("Retour à la ligne interdit dans l'en-tête.")

    if ":" in candidate:
        name, _, value = candidate.partition(":")
        name = name.strip()
        value = value.strip()
    elif candidate.lower() in ALLOWED_HEADERS:
        raise AuthHeaderError(
            f"Valeur manquante : écrivez « {candidate}: … » ou donnez directement le jeton."
        )
    else:
        # Valeur seule : on suppose un jeton porteur.
        name, value = "Authorization", candidate
        if not value.lower().startswith(("bearer ", "basic ", "token ")):
            value = f"Bearer {value}"

    if not _HEADER_NAME.match(name):
        raise AuthHeaderError(f"Nom d'en-tête invalide : {name!r}.")
    if name.lower() not in ALLOWED_HEADERS:
        allowed = ", ".join(sorted(ALLOWED_HEADERS))
        raise AuthHeaderError(f"En-tête non autorisé : {name}. Utilisez : {allowed}.")
    if not value:
        raise AuthHeaderError("Valeur d'authentification vide.")
    if len(value) > MAX_LENGTH:
        raise AuthHeaderError(f"Valeur trop longue (max {MAX_LENGTH} caractères).")
    return name, value


def mask(value: str) -> str:
    """Aperçu non réversible : `Bearer abcd…` → `Bearer ab…`."""
    if not value:
        return ""
    scheme, _, token = value.partition(" ")
    if not token:
        scheme, token = "", value
    head = token[:2]
    tail = "…" if len(token) > 2 else ""
    return f"{scheme} {head}{tail}".strip() if scheme else f"{head}{tail}"


def kind_for(name: str, value: str) -> str:
    """Famille d'authentification, pour l'affichage (« cookie », « bearer »…)."""
    if name.lower() == "cookie":
        return "cookie"
    lowered = value.lower()
    if lowered.startswith("bearer "):
        return "bearer"
    if lowered.startswith("basic "):
        return "basic"
    return "en-tête personnalisé"


def kind(raw: str) -> str:
    name, value = parse(raw)
    return kind_for(name, value)


__all__ = ["ALLOWED_HEADERS", "AuthHeaderError", "kind", "kind_for", "mask", "parse"]
