"""
Fleet-level correlation simulation tests.

Each scenario injects events across multiple peers and verifies that
FleetCorrelator fires the correct pattern and applies score boosts.

Scenario summary:
  F1  — ARP Poisoning Campaign         3 peers, arp_poisoning pattern, boost +2.0 each
  F2  — Gateway Swap (Route Shift)     4 peers, route_shift pattern, boost +1.5 each
  F3  — OS Normalisation Attack        3 peers, os_normalisation pattern, boost +1.5 each
  F4  — Identity Sweep                 2 peers, identity_sweep pattern, boost +2.0 each
  F5  — No Pattern (below threshold)   1 peer with ARP event — no fleet pattern fires
  F6  — Boost cap                      peer hits cap after two patterns
  F7  — No window (first tick)         last_tick_at is None — returns empty
  F8  — Service sweep                  4 peers, service_sweep pattern, boost +1.0 each
  F9  — TTL shift                      3 peers, ttl_shift pattern, boost +1.5 each
  F10 — Identity sweep via conflict    2 peers, identity_conflict_detected OR branch
  F11 — Window boundary                stale events (before last_tick_at) excluded
  F12 — Threshold crossing via fleet   Scenario D closure: peers below 3.0 individually,
                                       fleet boost tips both above investigation threshold
  F13 — Partial fleet match            only matching peers boosted; others untouched
  F14 — Multiple events per peer       event_count reflects multi-fire peers
  F15 — Empty tick                     last_tick_at set, no events this tick → []
  F16 — FleetEvent field completeness  all fields on a FleetEvent verified
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


def _inject_event(
    store: PeerStore,
    peer_id: str,
    event: str,
    ts: datetime | None = None,
) -> None:
    """Directly append an identity event to a peer's history.

    *ts* defaults to now; pass an explicit value to test window boundary logic.
    """
    from peerwatch.peer_store import IdentityEvent
    peer = store.peers[peer_id]
    peer.identity_history.append(
        IdentityEvent(
            timestamp=ts or datetime.now(timezone.utc),
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


# ---------------------------------------------------------------------------
# Scenario F8 — Service Sweep
#
# Attack: attacker installs backdoor services on 4 hosts simultaneously;
# each host's port fingerprint changes service type on a known port.
#
# References: MITRE ATT&CK T1543 (Create or Modify System Process)
# ---------------------------------------------------------------------------

def test_f8_service_sweep():
    cfg = PeerWatchConfig(fleet_service_min_peers=4)
    store = _make_store(cfg)

    peers = [
        warm_up(store, scan(mac=f"11:22:33:44:55:0{i}", ip=f"192.168.1.{80 + i}"))
        for i in range(4)
    ]
    baseline_scores = [p.suspicion_score for p in peers]

    for peer in peers:
        _inject_event(store, peer.internal_id, "service_type_changed")

    fleet_events = FleetCorrelator(store, cfg).analyse()

    assert_pattern_fired(fleet_events, "service_sweep")

    fe = next(fe for fe in fleet_events if fe.pattern == "service_sweep")
    assert len(fe.peer_ids) == 4
    assert fe.suspicion_boost == 1.0

    for peer, baseline in zip(peers, baseline_scores):
        assert peer.suspicion_score == pytest.approx(baseline + 1.0)


# ---------------------------------------------------------------------------
# Scenario F9 — TTL Shift (Infrastructure MITM)
#
# Attack: a MITM device is inserted between the scanner and 3 hosts,
# adding an extra hop and altering observed TTLs.
#
# References: MITRE ATT&CK T1557 (Adversary-in-the-Middle)
# ---------------------------------------------------------------------------

def test_f9_ttl_shift():
    cfg = PeerWatchConfig(fleet_ttl_min_peers=3)
    store = _make_store(cfg)

    peers = [
        warm_up(store, scan(mac=f"22:33:44:55:66:0{i}", ip=f"192.168.1.{90 + i}"))
        for i in range(3)
    ]
    baseline_scores = [p.suspicion_score for p in peers]

    for peer in peers:
        _inject_event(store, peer.internal_id, "ttl_deviation")

    fleet_events = FleetCorrelator(store, cfg).analyse()

    assert_pattern_fired(fleet_events, "ttl_shift")

    fe = next(fe for fe in fleet_events if fe.pattern == "ttl_shift")
    assert len(fe.peer_ids) == 3
    assert fe.suspicion_boost == 1.5

    for peer, baseline in zip(peers, baseline_scores):
        assert peer.suspicion_score == pytest.approx(baseline + 1.5)


# ---------------------------------------------------------------------------
# Scenario F10 — Identity Sweep via identity_conflict_detected
#
# Verifies the OR branch in the identity_sweep pattern: the pattern accepts
# either full_identity_shift OR identity_conflict_detected.
# ---------------------------------------------------------------------------

def test_f10_identity_sweep_via_conflict_detected():
    cfg = PeerWatchConfig(fleet_identity_min_peers=2)
    store = _make_store(cfg)

    peers = [
        warm_up(store, scan(mac=f"33:44:55:66:77:0{i}", ip=f"192.168.2.{10 + i}"))
        for i in range(2)
    ]

    for peer in peers:
        _inject_event(store, peer.internal_id, "identity_conflict_detected")

    fleet_events = FleetCorrelator(store, cfg).analyse()

    assert_pattern_fired(fleet_events, "identity_sweep")

    fe = next(fe for fe in fleet_events if fe.pattern == "identity_sweep")
    assert set(fe.peer_ids) == {p.internal_id for p in peers}
    assert fe.suspicion_boost == 2.0


# ---------------------------------------------------------------------------
# Scenario F11 — Window Boundary: Stale Events Excluded
#
# Events timestamped before last_tick_at must not contribute to fleet detection.
# An off-by-one in the >= comparison would silently include them.
# ---------------------------------------------------------------------------

def test_f11_window_boundary_stale_events_excluded():
    cfg = PeerWatchConfig(fleet_arp_min_peers=2)
    store = _make_store(cfg)

    peers = [
        warm_up(store, scan(mac=f"44:55:66:77:88:0{i}", ip=f"192.168.2.{20 + i}"))
        for i in range(3)
    ]

    # Inject stale events: 1 second before last_tick_at — must be excluded.
    stale_ts = store.last_tick_at - timedelta(seconds=1)
    for peer in peers:
        _inject_event(store, peer.internal_id, "arp_spoofing_detected", ts=stale_ts)

    # Only 1 peer gets a current in-window event — below min_peers=2.
    _inject_event(store, peers[0].internal_id, "arp_spoofing_detected")

    fleet_events = FleetCorrelator(store, cfg).analyse()

    # Pattern must NOT fire: only 1 peer has an in-window event.
    assert_pattern_not_fired(fleet_events, "arp_poisoning")
    for peer in peers:
        assert "fleet_correlation_boost" not in {e.event for e in peer.identity_history}


# ---------------------------------------------------------------------------
# Scenario F12 — Threshold Crossing via Fleet Boost (Scenario D Closure)
#
# Two peers with identity conflicts score ~1.0 individually — below the 3.0
# investigation threshold. Fleet correlation (identity_sweep, +2.0) tips both
# above the threshold, making the attack detectable.
#
# This closes the Scenario D gap documented in the benchmark:
#   "Cross-device identity conflict scores ≥1.0 — below threshold without fleet."
#
# References: MITRE ATT&CK T1465 (Rogue Wi-Fi Access Points / device swap)
# ---------------------------------------------------------------------------

def test_f12_threshold_crossing_scenario_d_closure():
    cfg = PeerWatchConfig(
        fleet_identity_min_peers=2,
        suspicion_threshold=3.0,
    )
    store = _make_store(cfg)

    peers = [
        warm_up(store, scan(mac=f"55:66:77:88:99:0{i}", ip=f"192.168.2.{30 + i}"))
        for i in range(2)
    ]

    # Simulate per-peer identity conflict score (≈1.0 — below threshold).
    for peer in peers:
        peer.suspicion_score = 1.0
        _inject_event(store, peer.internal_id, "identity_conflict_detected")

    # Confirm both are below the investigation threshold before fleet analysis.
    for peer in peers:
        assert peer.suspicion_score < cfg.suspicion_threshold

    fleet_events = FleetCorrelator(store, cfg).analyse()

    assert_pattern_fired(fleet_events, "identity_sweep")

    # Fleet boost (+2.0) should push both peers above the threshold.
    for peer in peers:
        assert peer.suspicion_score >= cfg.suspicion_threshold, (
            f"Expected score >= {cfg.suspicion_threshold} after fleet boost, "
            f"got {peer.suspicion_score:.2f}"
        )


# ---------------------------------------------------------------------------
# Scenario F13 — Partial Fleet Match: Non-Matching Peers Unaffected
#
# Only the subset of peers that fired the pattern event are boosted.
# Peers in the store with no matching events must be left unchanged.
# ---------------------------------------------------------------------------

def test_f13_partial_fleet_match():
    cfg = PeerWatchConfig(fleet_arp_min_peers=2)
    store = _make_store(cfg)

    all_peers = [
        warm_up(store, scan(mac=f"66:77:88:99:AA:0{i}", ip=f"192.168.2.{40 + i}"))
        for i in range(5)
    ]
    matching = all_peers[:3]
    unaffected = all_peers[3:]

    for peer in matching:
        _inject_event(store, peer.internal_id, "arp_spoofing_detected")

    baseline_unaffected = [p.suspicion_score for p in unaffected]

    fleet_events = FleetCorrelator(store, cfg).analyse()

    assert_pattern_fired(fleet_events, "arp_poisoning")

    fe = next(fe for fe in fleet_events if fe.pattern == "arp_poisoning")
    assert set(fe.peer_ids) == {p.internal_id for p in matching}

    # Matching peers got the boost.
    for peer in matching:
        assert "fleet_correlation_boost" in {e.event for e in peer.identity_history}

    # Non-matching peers were not touched.
    for peer, baseline in zip(unaffected, baseline_unaffected):
        assert peer.suspicion_score == pytest.approx(baseline)
        assert "fleet_correlation_boost" not in {e.event for e in peer.identity_history}


# ---------------------------------------------------------------------------
# Scenario F14 — Multiple Events Per Peer: event_count Accuracy
#
# When a peer fires the same pattern event more than once in a tick,
# event_count on the FleetEvent should reflect the total across all peers.
# The per-peer boost is still applied once (not multiplied by event count).
# ---------------------------------------------------------------------------

def test_f14_multiple_events_per_peer_event_count():
    cfg = PeerWatchConfig(fleet_arp_min_peers=2)
    store = _make_store(cfg)

    peers = [
        warm_up(store, scan(mac=f"77:88:99:AA:BB:0{i}", ip=f"192.168.2.{50 + i}"))
        for i in range(2)
    ]
    baseline_scores = [p.suspicion_score for p in peers]

    # Each peer fires arp_spoofing_detected twice — 4 total events.
    for peer in peers:
        _inject_event(store, peer.internal_id, "arp_spoofing_detected")
        _inject_event(store, peer.internal_id, "arp_spoofing_detected")

    fleet_events = FleetCorrelator(store, cfg).analyse()

    assert_pattern_fired(fleet_events, "arp_poisoning")

    fe = next(fe for fe in fleet_events if fe.pattern == "arp_poisoning")
    assert fe.event_count == 4

    # Boost is still +2.0 per peer regardless of event count.
    for peer, baseline in zip(peers, baseline_scores):
        assert peer.suspicion_score == pytest.approx(baseline + 2.0)


# ---------------------------------------------------------------------------
# Scenario F15 — Empty Tick: No Events Recorded
#
# last_tick_at is set (not the first tick) but no identity events were recorded
# after that timestamp. FleetCorrelator should return an empty list cleanly.
# ---------------------------------------------------------------------------

def test_f15_empty_tick_no_events():
    cfg = PeerWatchConfig()
    store = _make_store(cfg)

    # Peers exist but no events injected after last_tick_at.
    peers = [
        warm_up(store, scan(mac=f"88:99:AA:BB:CC:0{i}", ip=f"192.168.2.{60 + i}"))
        for i in range(3)
    ]
    baseline_scores = [p.suspicion_score for p in peers]

    fleet_events = FleetCorrelator(store, cfg).analyse()

    assert fleet_events == []
    for peer, baseline in zip(peers, baseline_scores):
        assert peer.suspicion_score == pytest.approx(baseline)


# ---------------------------------------------------------------------------
# Scenario F16 — FleetEvent Field Completeness
#
# Exhaustive check of every field on a FleetEvent produced by a real analysis.
# ---------------------------------------------------------------------------

def test_f16_fleet_event_field_completeness():
    cfg = PeerWatchConfig(fleet_arp_min_peers=2)
    store = _make_store(cfg)

    peers = [
        warm_up(store, scan(mac=f"99:AA:BB:CC:DD:0{i}", ip=f"192.168.2.{70 + i}"))
        for i in range(3)
    ]

    for peer in peers:
        _inject_event(store, peer.internal_id, "arp_spoofing_detected")

    t_before = datetime.now(timezone.utc)
    fleet_events = FleetCorrelator(store, cfg).analyse()
    t_after = datetime.now(timezone.utc)

    assert_pattern_fired(fleet_events, "arp_poisoning")
    fe = next(fe for fe in fleet_events if fe.pattern == "arp_poisoning")

    # peer_ids contains exactly the 3 matching peers
    assert set(fe.peer_ids) == {p.internal_id for p in peers}

    # ips contains all IPs of matched peers
    expected_ips = sorted(ip for p in peers for ip in p.ips)
    assert sorted(fe.ips) == expected_ips

    # event_count equals number of matching events (one per peer)
    assert fe.event_count == 3

    # boost amount
    assert fe.suspicion_boost == 2.0

    # window timestamps are ordered and plausible
    assert fe.window_start == store.last_tick_at
    assert t_before <= fe.window_end <= t_after
    assert fe.window_start < fe.window_end

    # description mentions peer count and event type
    assert "3" in fe.description
    assert "arp_spoofing_detected" in fe.description
