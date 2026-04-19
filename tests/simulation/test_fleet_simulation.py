"""
Fleet-level correlation simulation tests.

Each scenario injects events across multiple peers and verifies that
FleetCorrelator fires the correct pattern and applies score boosts.

Scenario summary:
  F1 — ARP Poisoning Campaign      3 peers, arp_poisoning pattern, boost +2.0 each
  F2 — Gateway Swap (Route Shift)  4 peers, route_shift pattern, boost +1.5 each
  F3 — OS Normalisation Attack     3 peers, os_normalisation pattern, boost +1.5 each
  F4 — Identity Sweep              2 peers, identity_sweep pattern, boost +2.0 each
  F5 — No Pattern (below threshold) 1 peer with ARP event — no fleet pattern fires
  F6 — Boost cap                   peer hits cap after two patterns
"""

from datetime import datetime, timedelta, timezone

import pytest

from peerwatch.config import PeerWatchConfig
from peerwatch.fleet_correlator import FleetCorrelator
from peerwatch.peer_store import PeerStore

from .factories import scan, warm_up

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_store(cfg: PeerWatchConfig | None = None) -> PeerStore:
    store = PeerStore(config=cfg or PeerWatchConfig())
    # Set last_tick_at to 1 minute ago so all events fall inside the window.
    store.last_tick_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    return store


def _inject_event(store: PeerStore, peer_id: str, event: str) -> None:
    """Directly append an identity event to a peer's history."""
    from peerwatch.peer_store import IdentityEvent
    peer = store.peers[peer_id]
    peer.identity_history.append(
        IdentityEvent(
            timestamp=datetime.now(timezone.utc),
            event=event,
            details={},
        )
    )


def assert_pattern_fired(fleet_events, pattern: str) -> None:
    patterns = [fe.pattern for fe in fleet_events]
    assert pattern in patterns, (
        f"Expected fleet pattern '{pattern}' to fire; got {patterns}"
    )


def assert_pattern_not_fired(fleet_events, pattern: str) -> None:
    patterns = [fe.pattern for fe in fleet_events]
    assert pattern not in patterns, (
        f"Fleet pattern '{pattern}' fired unexpectedly"
    )


# ---------------------------------------------------------------------------
# Scenario F1 — ARP Poisoning Campaign
#
# Attack: attacker poisons ARP caches for 3 hosts simultaneously.
# Each host fires arp_spoofing_detected in the same tick.
# Fleet correlator should detect arp_poisoning and boost each peer +2.0.
# ---------------------------------------------------------------------------

def test_f1_arp_poisoning_campaign():
    cfg = PeerWatchConfig(fleet_arp_min_peers=2)
    store = _make_store(cfg)

    peers = [
        warm_up(store, scan(mac=f"AA:BB:CC:DD:EE:0{i}", ip=f"192.168.1.{10 + i}"))
        for i in range(3)
    ]
    baseline_scores = [p.suspicion_score for p in peers]

    for peer in peers:
        _inject_event(store, peer.internal_id, "arp_spoofing_detected")

    fleet_events = FleetCorrelator(store, cfg).analyse()

    assert_pattern_fired(fleet_events, "arp_poisoning")

    fe = next(fe for fe in fleet_events if fe.pattern == "arp_poisoning")
    assert len(fe.peer_ids) == 3
    assert fe.suspicion_boost == 2.0

    # Each peer's score should have increased by the boost amount.
    for peer, baseline in zip(peers, baseline_scores):
        assert peer.suspicion_score == pytest.approx(baseline + 2.0), (
            f"Peer {peer.internal_id[:8]} score not boosted"
        )

    # Each peer should have a fleet_correlation_boost event recorded.
    for peer in peers:
        events = {e.event for e in peer.identity_history}
        assert "fleet_correlation_boost" in events


# ---------------------------------------------------------------------------
# Scenario F2 — Gateway Swap (Route Shift)
#
# Attack: infrastructure replacement — a switch or gateway is swapped.
# 4 peers all see route_changed in the same tick.
# Fleet correlator should detect route_shift.
# ---------------------------------------------------------------------------

def test_f2_gateway_swap_route_shift():
    cfg = PeerWatchConfig(fleet_route_min_peers=3)
    store = _make_store(cfg)

    peers = [
        warm_up(store, scan(mac=f"BB:CC:DD:EE:FF:0{i}", ip=f"192.168.1.{20 + i}"))
        for i in range(4)
    ]

    for peer in peers:
        _inject_event(store, peer.internal_id, "route_changed")

    fleet_events = FleetCorrelator(store, cfg).analyse()

    assert_pattern_fired(fleet_events, "route_shift")

    fe = next(fe for fe in fleet_events if fe.pattern == "route_shift")
    assert len(fe.peer_ids) == 4
    assert fe.event_count == 4


# ---------------------------------------------------------------------------
# Scenario F3 — OS Normalisation Attack
#
# Attack: attacker carefully changes fingerprints on 3 devices to match
# a target OS profile. Each fires os_family_changed.
# ---------------------------------------------------------------------------

def test_f3_os_normalisation():
    cfg = PeerWatchConfig(fleet_os_min_peers=3)
    store = _make_store(cfg)

    peers = [
        warm_up(store, scan(mac=f"CC:DD:EE:FF:00:0{i}", ip=f"192.168.1.{30 + i}"))
        for i in range(3)
    ]

    for peer in peers:
        _inject_event(store, peer.internal_id, "os_family_changed")

    fleet_events = FleetCorrelator(store, cfg).analyse()

    assert_pattern_fired(fleet_events, "os_normalisation")

    fe = next(fe for fe in fleet_events if fe.pattern == "os_normalisation")
    assert len(fe.peer_ids) == 3
    assert fe.suspicion_boost == 1.5

    for peer in peers:
        assert peer.suspicion_score > 0


# ---------------------------------------------------------------------------
# Scenario F4 — Identity Sweep
#
# Attack: 2 peers show full_identity_shift in the same tick.
# ---------------------------------------------------------------------------

def test_f4_identity_sweep():
    cfg = PeerWatchConfig(fleet_identity_min_peers=2)
    store = _make_store(cfg)

    peers = [
        warm_up(store, scan(mac=f"DD:EE:FF:00:11:0{i}", ip=f"192.168.1.{40 + i}"))
        for i in range(2)
    ]

    for peer in peers:
        _inject_event(store, peer.internal_id, "full_identity_shift")

    fleet_events = FleetCorrelator(store, cfg).analyse()

    assert_pattern_fired(fleet_events, "identity_sweep")

    fe = next(fe for fe in fleet_events if fe.pattern == "identity_sweep")
    assert set(fe.peer_ids) == {p.internal_id for p in peers}


# ---------------------------------------------------------------------------
# Scenario F5 — No Pattern (below threshold)
#
# Only 1 peer fires arp_spoofing_detected — min_peers=2 not met.
# No fleet pattern should fire.
# ---------------------------------------------------------------------------

def test_f5_no_pattern_below_threshold():
    cfg = PeerWatchConfig(fleet_arp_min_peers=2)
    store = _make_store(cfg)

    peer = warm_up(store, scan(mac="EE:FF:00:11:22:33", ip="192.168.1.50"))
    _inject_event(store, peer.internal_id, "arp_spoofing_detected")

    fleet_events = FleetCorrelator(store, cfg).analyse()

    assert_pattern_not_fired(fleet_events, "arp_poisoning")
    # Score should not have been boosted by fleet correlation.
    assert "fleet_correlation_boost" not in {e.event for e in peer.identity_history}


# ---------------------------------------------------------------------------
# Scenario F6 — Boost cap
#
# A peer matches two patterns (arp_poisoning + identity_sweep).
# With cap=2.5 the second boost should be clipped.
# ---------------------------------------------------------------------------

def test_f6_boost_cap():
    cfg = PeerWatchConfig(
        fleet_arp_min_peers=2,
        fleet_identity_min_peers=2,
        fleet_boost_cap=2.5,
    )
    store = _make_store(cfg)

    peers = [
        warm_up(store, scan(mac=f"FF:00:11:22:33:0{i}", ip=f"192.168.1.{60 + i}"))
        for i in range(2)
    ]
    baseline_scores = [p.suspicion_score for p in peers]

    for peer in peers:
        _inject_event(store, peer.internal_id, "arp_spoofing_detected")
        _inject_event(store, peer.internal_id, "full_identity_shift")

    FleetCorrelator(store, cfg).analyse()

    # arp_poisoning boost = 2.0, identity_sweep boost = 2.0
    # cap = 2.5 → first boost applied in full (2.0), second capped to 0.5
    for peer, baseline in zip(peers, baseline_scores):
        actual_boost = peer.suspicion_score - baseline
        assert actual_boost == pytest.approx(2.5), (
            f"Expected capped boost of 2.5, got {actual_boost:.2f}"
        )


# ---------------------------------------------------------------------------
# Scenario F7 — No window (first tick)
#
# last_tick_at is None — correlator should return empty list, no crashes.
# ---------------------------------------------------------------------------

def test_f7_no_window_first_tick():
    cfg = PeerWatchConfig()
    store = PeerStore(config=cfg)
    # Deliberately leave last_tick_at as None (default).

    peer = warm_up(store, scan(mac="00:11:22:33:44:55", ip="192.168.1.70"))
    _inject_event(store, peer.internal_id, "arp_spoofing_detected")

    fleet_events = FleetCorrelator(store, cfg).analyse()

    assert fleet_events == []
