"""Tests for src/data/as_database.py.

TDD: these tests are written BEFORE the implementation (RED phase).
"""

from __future__ import annotations

import pytest

from src.data.as_database import AS_DATABASE, ASInfo, lookup_as

# ---------------------------------------------------------------------------
# Individual entry tests
# ---------------------------------------------------------------------------


def test_tcloud() -> None:
    """AS399077 → TCLOUD Computing, IX-MLPE."""
    info = lookup_as(399077)
    assert info is not None
    assert info.name == "TCLOUD Computing"
    assert info.as_type == "IX-MLPE"


def test_sggs() -> None:
    """AS24482 → SG.GS, IX-MLPE."""
    info = lookup_as(24482)
    assert info is not None
    assert info.name == "SG.GS"
    assert info.as_type == "IX-MLPE"


def test_fah() -> None:
    """AS10075 → Fiber@Home (F@H), Backhaul-Peer."""
    info = lookup_as(10075)
    assert info is not None
    assert info.name == "Fiber@Home (F@H)"
    assert info.as_type == "Backhaul-Peer"


def test_novocom() -> None:
    """AS132267 → Novocom, ISP-Client."""
    info = lookup_as(132267)
    assert info is not None
    assert info.name == "Novocom"
    assert info.as_type == "ISP-Client"


def test_google() -> None:
    """AS15169 → Google, PNI."""
    info = lookup_as(15169)
    assert info is not None
    assert info.name == "Google"
    assert info.as_type == "PNI"


def test_bsccl_own() -> None:
    """AS132602 → BSCCL, Self (own ASN)."""
    info = lookup_as(132602)
    assert info is not None
    assert info.name == "BSCCL"
    assert info.as_type == "Self"


def test_unknown_as() -> None:
    """AS99999 → None (triggers external lookup in production)."""
    result = lookup_as(99999)
    assert result is None


def test_ntt() -> None:
    """AS2914 → NTT Communications, Transit."""
    info = lookup_as(2914)
    assert info is not None
    assert info.name == "NTT Communications"
    assert info.as_type == "Transit"


def test_facebook() -> None:
    """AS32934 → Facebook/Meta, PNI."""
    info = lookup_as(32934)
    assert info is not None
    assert info.name == "Facebook/Meta"
    assert info.as_type == "PNI"


# ---------------------------------------------------------------------------
# Completeness test
# ---------------------------------------------------------------------------


def test_all_entries_exist() -> None:
    """AS_DATABASE must contain at least 120 entries."""
    assert len(AS_DATABASE) >= 120, f"Expected >= 120 entries, got {len(AS_DATABASE)}"


# ---------------------------------------------------------------------------
# Dataclass immutability
# ---------------------------------------------------------------------------


def test_as_info_is_frozen() -> None:
    """ASInfo must be a frozen dataclass (immutable)."""
    info = ASInfo(name="Test", as_type="Transit", router="EQ-RTR-01")
    with pytest.raises((AttributeError, TypeError)):
        info.name = "Modified"  # type: ignore[misc]
