"""Tests for suspicion score exponential decay."""

import math
from datetime import datetime, timedelta, timezone

import pytest

from peerwatch.config import PeerWatchConfig
from peerwatch.peer_store import PeerStore

from tests.simulation.factories import scan, warm_up


def _store_with_score(score: float) -> tuple[PeerStore, str]:
    """Return a warmed-up store and the peer's internal_id, with score injected."""
    store = PeerStore()
    baseline = scan()
    peer = warm_up(store, baseline)
    peer.suspicion_score = score
    return store, peer.internal_id


class TestSuspicionDecay:
    def test_zero_score_not_decayed(self):
        """Score of 0.0 must stay at 0.0 regardless of elapsed time."""
        store = PeerStore()
        baseline = scan()
        peer = warm_up(store, baseline)
        assert peer.suspicion_score == pytest.approx(0.0)

        # Push last_seen_at back 7 days
        peer.last_seen_at = datetime.now(timezone.utc) - timedelta(days=7)
        # Trigger decay by calling add_or_update_peer (which calls _apply_suspicion_decay)
        store.add_or_update_peer(baseline)
        assert peer.suspicion_score == pytest.approx(0.0)

    def test_half_life_halves_score(self):
        """Score halves after exactly one half-life period (default 3.5 days)."""
        store, pid = _store_with_score(4.0)
        peer = store.peers[pid]

        half_life = store._cfg.suspicion_half_life_days
        peer.last_seen_at = datetime.now(timezone.utc) - timedelta(days=half_life)

        store.add_or_update_peer(scan())
        assert peer.suspicion_score == pytest.approx(2.0, abs=0.05)

    def test_two_half_lives_quarter_score(self):
        """Score is one-quarter after two half-life periods."""
        store, pid = _store_with_score(8.0)
        peer = store.peers[pid]

        half_life = store._cfg.suspicion_half_life_days
        peer.last_seen_at = datetime.now(timezone.utc) - timedelta(days=2 * half_life)

        store.add_or_update_peer(scan())
        assert peer.suspicion_score == pytest.approx(2.0, abs=0.05)

    def test_zero_elapsed_no_change(self):
        """Decay applied at t=0 (last_seen = now) must leave score unchanged."""
        store, pid = _store_with_score(5.0)
        peer = store.peers[pid]
        peer.last_seen_at = datetime.now(timezone.utc)

        store.add_or_update_peer(scan())
        # elapsed_days ≈ 0 → score *= 0.5^0 = 1.0
        assert peer.suspicion_score >= 5.0 - 0.1  # score may also accrue from the scan

    def test_decay_formula_matches_math(self):
        """Verify decay matches score * 0.5^(days/half_life) analytically."""
        cfg = PeerWatchConfig(suspicion_half_life_days=3.5)
        store = PeerStore(config=cfg)
        baseline = scan()
        peer = warm_up(store, baseline)
        peer.suspicion_score = 10.0

        days = 1.75  # half of half-life → should decay to 10 * 0.5^0.5
        peer.last_seen_at = datetime.now(timezone.utc) - timedelta(days=days)

        store.add_or_update_peer(baseline)
        expected = 10.0 * (0.5 ** (days / cfg.suspicion_half_life_days))
        assert peer.suspicion_score == pytest.approx(expected, abs=0.05)

    def test_custom_half_life_respected(self):
        """A shorter half-life decays score faster."""
        cfg_fast = PeerWatchConfig(suspicion_half_life_days=1.0)
        store = PeerStore(config=cfg_fast)
        baseline = scan()
        peer = warm_up(store, baseline)
        peer.suspicion_score = 4.0

        peer.last_seen_at = datetime.now(timezone.utc) - timedelta(days=1.0)
        store.add_or_update_peer(baseline)
        # After exactly 1 day with half_life=1.0, score should be ~2.0
        assert peer.suspicion_score == pytest.approx(2.0, abs=0.1)
