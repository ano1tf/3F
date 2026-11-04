"""Garde-fous : normalisation des cibles et refus des adresses internes."""

from __future__ import annotations

import asyncio

import pytest

from app.safety import ScanError, normalize_target, validate_target


def test_normalize_adds_https_scheme():
    assert normalize_target("exemple.fr") == "https://exemple.fr/"


def test_normalize_keeps_path_and_query():
    assert normalize_target("http://exemple.fr/a?b=1#frag") == "http://exemple.fr/a?b=1"


def test_normalize_lowercases_host():
    assert normalize_target("HTTPS://Exemple.FR/") == "https://exemple.fr/"


def test_normalize_keeps_custom_port():
    assert normalize_target("https://exemple.fr:8443/x") == "https://exemple.fr:8443/x"


@pytest.mark.parametrize("value", ["", "   ", "ftp://exemple.fr", "javascript:alert(1)"])
def test_normalize_rejects_invalid(value):
    with pytest.raises(ScanError):
        normalize_target(value)


def test_normalize_rejects_credentials():
    with pytest.raises(ScanError):
        normalize_target("https://user:pass@exemple.fr/")


@pytest.mark.parametrize(
    "target",
    ["http://127.0.0.1/", "http://localhost/", "http://10.0.0.5/", "http://192.168.1.10:8080/", "http://[::1]/"],
)
def test_private_targets_are_blocked_by_default(target):
    with pytest.raises(ScanError) as excinfo:
        asyncio.run(validate_target(target, allow_private=False))
    assert excinfo.value.code == "private_target"


def test_private_target_allowed_explicitly():
    result = asyncio.run(validate_target("http://127.0.0.1:9999/", allow_private=True))
    assert result.host == "127.0.0.1"
    assert result.port == 9999
