"""Fixtures partagées : serveur cible local + base temporaire."""

from __future__ import annotations

import pytest

from app import config, db
from tests.fixtures.bad_server import FixtureServer


@pytest.fixture()
def vulnerable_server(monkeypatch):
    """Serveur HTTP local volontairement mal configuré (jamais un site réel)."""
    monkeypatch.setattr(config, "ALLOW_PRIVATE_TARGETS", True)
    with FixtureServer() as server:
        yield server


@pytest.fixture()
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db._INITIALIZED.clear()
    yield tmp_path / "test.db"
    db._INITIALIZED.clear()
