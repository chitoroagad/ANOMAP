"""
Phase 2 passive-capture simulation tests.

Injects TTL, ARP, TCP-fingerprint, IP-ID, and route observations directly
into PeerStore.ingest_*() without requiring a live capture session or scapy.

Scenario summary:
  J — TTL Anomaly                      score: +2.0  → combined with Phase 1 events
  K — ARP Spoofing                     score: +3.0  → crosses threshold alone
  L — TCP Fingerprint Mismatch         score: +2.0  → crosses threshold with OS change
  M — IP ID Counter Jump               score: +1.0  → weak signal; combined
  N — Route Hop Sequence Change        score: +1.0  → combined
  O — Route ASN Change                 score: +1.5  → combined
  P — Cross-device conflict + ARP      score: ≥4.0  → Scenario D crosses threshold
  Q — TTL + ARP baseline (negative)   score: 0.0   → no anomaly during warmup/baseline
"""

import pytest

from peerwatch.peer_store import (
    ARP_SPOOF_SUSPICION,
    IP_ID_ANOMALY_SUSPICION,
    IP_ID_MIN_SAMPLES,
    ROUTE_ASN_CHANGE_SUSPICION,
    ROUTE_HOP_CHANGE_SUSPICION,
    TCP_FINGERPRINT_MISMATCH_SUSPICION,
    TTL_BASELINE_MIN_SAMPLES,
    TTL_DEVIATION_SUSPICION,
    Peer,
    PeerStore,
)
from peerwatch.route_tracker import RouteChangeKind

from .factories import scan, warm_up

THRESHOLD = 3.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def assert_events_fired(peer: Peer, *events: str) -> None:
    fired = {e.event for e in peer.identity_history}
    for event in events:
        assert event in fired, f"Expected event '{event}' not fired; got {fired}"


def assert_events_not_fired(peer: Peer, *events: str) -> None:
    fired = {e.event for e in peer.identity_history}
    for event in events:
        assert event not in fired, f"Event '{event}' fired unexpectedly"


def assert_score_above(peer: Peer, threshold: float = THRESHOLD) -> None:
    assert peer.suspicion_score >= threshold, (
        f"suspicion_score={peer.suspicion_score:.2f} did not reach {threshold}"
    )


def assert_score_below(peer: Peer, threshold: float = THRESHOLD) -> None:
    assert peer.suspicion_score < threshold, (
        f"suspicion_score={peer.suspicion_score:.2f} unexpectedly reached {threshold}"
    )


def _establish_ttl_baseline(store: PeerStore, ip: str, ttl: int) -> Peer:
    """Feed TTL_BASELINE_MIN_SAMPLES identical TTL observations to lock in a baseline."""
    peer = None
    for _ in range(TTL_BASELINE_MIN_SAMPLES):
        peer = store.ingest_ttl_observation(ip=ip, ttl=ttl)
    assert peer is not None
    return peer


def _establish_ip_id_sequential(store: PeerStore, ip: str, start: int = 100) -> Peer:
    """Feed IP_ID_MIN_SAMPLES sequential IP IDs so ip_id_sequential becomes True."""
    peer = None
    for i in range(IP_ID_MIN_SAMPLES):
        peer = store.ingest_ip_id_observation(ip=ip, ip_id=start + i * 5)
    assert peer is not None
    assert peer.ip_id_sequential, "Expected sequential IP ID pattern not detected"
    return peer


# ---------------------------------------------------------------------------
# Scenario J — TTL Anomaly Detection
#
# A device whose TTL baseline is 64 (Linux) suddenly sends packets with TTL=120.
# The deviation (56) exceeds TTL_DEVIATION_THRESHOLD (15), triggering detection.
#
# Score: TTL_DEVIATION_SUSPICION (+2.0)
# ---------------------------------------------------------------------------


class TestTTLAnomalyDetection:
    MAC = "AA:BB:CC:DD:EE:FF"
    IP = "192.168.1.10"

    @pytest.fixture
    def store_with_peer(self):
        store = PeerStore()
        baseline = scan(mac=self.MAC, ip=self.IP, os="Linux", os_candidates={"Linux": 96})
        warm_up(store, baseline)
        return store

    def test_no_anomaly_during_baseline_collection(self, store_with_peer):
        store = store_with_peer
        for _ in range(TTL_BASELINE_MIN_SAMPLES - 1):
            peer = store.ingest_ttl_observation(ip=self.IP, ttl=60)
        assert peer.suspicion_score == pytest.approx(0.0)
        assert_events_not_fired(peer, "ttl_deviation")

    def test_baseline_established_event_fires(self, store_with_peer):
        store = store_with_peer
        peer = _establish_ttl_baseline(store, self.IP, ttl=60)
        assert peer.expected_ttl == 64, "TTL 60 should snap to OS default 64"
        assert_events_fired(peer, "ttl_baseline_established")

    def test_large_ttl_deviation_raises_suspicion(self, store_with_peer):
        store = store_with_peer
        _establish_ttl_baseline(store, self.IP, ttl=60)
        # Attacker's device sends TTL=120 (Windows default) instead of ~60
        peer = store.ingest_ttl_observation(ip=self.IP, ttl=120)
        assert peer.suspicion_score == pytest.approx(TTL_DEVIATION_SUSPICION)
        assert_events_fired(peer, "ttl_deviation")

    def test_ttl_deviation_event_details(self, store_with_peer):
        store = store_with_peer
        _establish_ttl_baseline(store, self.IP, ttl=60)
        peer = store.ingest_ttl_observation(ip=self.IP, ttl=120)

        events = [e for e in peer.identity_history if e.event == "ttl_deviation"]
        assert events, "ttl_deviation event missing"
        details = events[0].details
        assert details["observed_ttl"] == 120
        assert details["expected_ttl"] == 64

    def test_small_ttl_deviation_no_event(self, store_with_peer):
        """A few hops difference (TTL 58 vs expected 64) is normal routing — no alert."""
        store = store_with_peer
        _establish_ttl_baseline(store, self.IP, ttl=60)
        peer = store.ingest_ttl_observation(ip=self.IP, ttl=58)
        assert peer.suspicion_score == pytest.approx(0.0)
        assert_events_not_fired(peer, "ttl_deviation")

    def test_unknown_ip_returns_none(self, store_with_peer):
        result = store_with_peer.ingest_ttl_observation(ip="10.0.0.99", ttl=64)
        assert result is None


# ---------------------------------------------------------------------------
# Scenario K — ARP Spoofing Detection
#
# Attack: An attacker broadcasts ARP replies claiming a victim's IP is at the
# attacker's MAC address (classic ARP cache poisoning / MITM precursor).
#
# References:
#   CVE-2020-25705 (SAD DNS) — ARP-poisoning used to position attacker on-path.
#   MITRE ATT&CK T1557.002 — ARP Cache Poisoning.
#
# Score: ARP_SPOOF_SUSPICION (+3.0) → crosses threshold alone.
# ---------------------------------------------------------------------------


class TestARPSpoofingDetection:
    MAC = "AA:BB:CC:DD:EE:FF"
    IP = "192.168.1.10"
    ATTACKER_MAC = "DE:AD:BE:EF:00:01"

    @pytest.fixture
    def store_with_peer(self):
        store = PeerStore()
        baseline = scan(mac=self.MAC, ip=self.IP, os="Linux", os_candidates={"Linux": 96})
        warm_up(store, baseline)
        return store

    def test_arp_reply_matching_known_mac_no_event(self, store_with_peer):
        """A legitimate ARP reply from the device's own MAC should not raise suspicion."""
        peer = store_with_peer.ingest_arp_observation(ip=self.IP, mac=self.MAC)
        assert peer.suspicion_score == pytest.approx(0.0)
        assert_events_not_fired(peer, "arp_spoofing_detected")

    def test_spoofed_arp_crosses_threshold(self, store_with_peer):
        peer = store_with_peer.ingest_arp_observation(ip=self.IP, mac=self.ATTACKER_MAC)
        assert peer.suspicion_score == pytest.approx(ARP_SPOOF_SUSPICION)
        assert_score_above(peer)

    def test_arp_spoof_event_fires(self, store_with_peer):
        peer = store_with_peer.ingest_arp_observation(ip=self.IP, mac=self.ATTACKER_MAC)
        assert_events_fired(peer, "arp_spoofing_detected")

    def test_arp_spoof_event_details(self, store_with_peer):
        peer = store_with_peer.ingest_arp_observation(ip=self.IP, mac=self.ATTACKER_MAC)
        events = [e for e in peer.identity_history if e.event == "arp_spoofing_detected"]
        assert events
        d = events[0].details
        assert d["ip"] == self.IP
        assert d["known_mac"].upper() == self.MAC.upper()
        assert d["claimed_mac"].upper() == self.ATTACKER_MAC.upper()

    def test_unknown_ip_returns_none(self, store_with_peer):
        result = store_with_peer.ingest_arp_observation(ip="10.0.0.99", mac=self.ATTACKER_MAC)
        assert result is None

    def test_volatile_peer_no_arp_event(self):
        """Volatile peers (no confirmed MAC) should not trigger ARP alerts."""
        store = PeerStore()
        # Create peer without MAC
        baseline = scan(mac="unknown", ip="192.168.1.50", os="Linux")
        warm_up(store, baseline)
        peer = store.ingest_arp_observation(ip="192.168.1.50", mac="AA:BB:CC:DD:EE:FF")
        # No known MAC → no conflict
        if peer is not None:
            assert_events_not_fired(peer, "arp_spoofing_detected")


# ---------------------------------------------------------------------------
# Scenario L — TCP Fingerprint Mismatch
#
# Attack: Device is replaced; the new device runs Windows but the nmap baseline
# shows Linux. The TCP SYN packet reveals a Windows TCP stack
# (window=64240, options=[MSS, NOP, WScale, NOP, NOP, SACK]).
#
# Score: TCP_FINGERPRINT_MISMATCH_SUSPICION (+2.0)
# Combined with os_family_changed (+2.0) from nmap scan: total 4.0 ≥ threshold.
# ---------------------------------------------------------------------------


class TestTCPFingerprintMismatch:
    MAC = "BB:CC:DD:EE:FF:00"
    IP = "192.168.1.20"

    @pytest.fixture
    def store_with_linux_peer(self):
        store = PeerStore()
        baseline = scan(
            mac=self.MAC, ip=self.IP, os="Linux", os_candidates={"Linux": 96},
            ports=[22, 80], services={22: "ssh-OpenSSH", 80: "http-Apache"},
        )
        warm_up(store, baseline)
        return store

    def test_matching_linux_fingerprint_no_event(self, store_with_linux_peer):
        """Linux TCP stack observed for a known Linux peer — no alert."""
        peer = store_with_linux_peer.ingest_tcp_fingerprint(
            ip=self.IP,
            window_size=29200,
            tcp_options=["MSS", "SACK", "TS", "NOP", "WScale"],
            mss=1460,
        )
        assert peer.suspicion_score == pytest.approx(0.0)
        assert_events_not_fired(peer, "tcp_fingerprint_mismatch")

    def test_windows_fingerprint_on_linux_peer_raises_suspicion(
        self, store_with_linux_peer
    ):
        """Windows TCP stack on a known-Linux peer is a strong device-change signal."""
        peer = store_with_linux_peer.ingest_tcp_fingerprint(
            ip=self.IP,
            window_size=64240,
            tcp_options=["MSS", "NOP", "WScale", "NOP", "NOP", "SACK"],
            mss=1460,
        )
        assert peer.suspicion_score == pytest.approx(TCP_FINGERPRINT_MISMATCH_SUSPICION)
        assert_events_fired(peer, "tcp_fingerprint_mismatch")

    def test_mismatch_event_identifies_implied_os(self, store_with_linux_peer):
        store_with_linux_peer.ingest_tcp_fingerprint(
            ip=self.IP,
            window_size=64240,
            tcp_options=["MSS", "NOP", "WScale", "NOP", "NOP", "SACK"],
            mss=1460,
        )
        peer = store_with_linux_peer.get_peer(ip=self.IP)
        events = [e for e in peer.identity_history if e.event == "tcp_fingerprint_mismatch"]
        assert events
        assert events[0].details["implied_os"] == "Windows"

    def test_tcp_implied_os_updated_on_peer(self, store_with_linux_peer):
        store_with_linux_peer.ingest_tcp_fingerprint(
            ip=self.IP,
            window_size=64240,
            tcp_options=["MSS", "NOP", "WScale", "NOP", "NOP", "SACK"],
            mss=1460,
        )
        peer = store_with_linux_peer.get_peer(ip=self.IP)
        assert peer.tcp_implied_os == "Windows"

    def test_ambiguous_fingerprint_no_event(self, store_with_linux_peer):
        """Insufficient TCP option overlap → no implied OS → no event."""
        peer = store_with_linux_peer.ingest_tcp_fingerprint(
            ip=self.IP,
            window_size=1024,
            tcp_options=["MSS"],  # only 1 option — below confidence threshold
            mss=None,
        )
        assert peer.suspicion_score == pytest.approx(0.0)

    def test_unknown_ip_returns_none(self, store_with_linux_peer):
        result = store_with_linux_peer.ingest_tcp_fingerprint(
            ip="10.0.0.99",
            window_size=64240,
            tcp_options=["MSS", "NOP", "WScale", "NOP", "NOP", "SACK"],
            mss=1460,
        )
        assert result is None


# ---------------------------------------------------------------------------
# Scenario M — IP ID Counter Jump
#
# Attack: A spoofed source IP generates packets; the legitimate device's IP ID
# counter is at ~500, but spoofed packets inject an ID from the attacker's own
# counter (~40000), producing an impossible jump.
#
# Score: IP_ID_ANOMALY_SUSPICION (+1.0)
# Weak signal; combined with other indicators to cross the threshold.
# ---------------------------------------------------------------------------


class TestIPIDAnomalyDetection:
    MAC = "CC:DD:EE:FF:00:11"
    IP = "192.168.1.30"

    @pytest.fixture
    def store_with_peer(self):
        store = PeerStore()
        baseline = scan(mac=self.MAC, ip=self.IP, os="Windows",
                        os_candidates={"Microsoft": 95},
                        ports=[3389, 445], services={3389: "rdp-ms-rdp", 445: "microsoft-ds"})
        warm_up(store, baseline)
        return store

    def test_sequential_pattern_detected(self, store_with_peer):
        peer = _establish_ip_id_sequential(store_with_peer, self.IP, start=100)
        assert peer.ip_id_sequential is True

    def test_no_anomaly_during_baseline_collection(self, store_with_peer):
        peer = None
        for i in range(IP_ID_MIN_SAMPLES - 1):
            peer = store_with_peer.ingest_ip_id_observation(ip=self.IP, ip_id=100 + i * 5)
        assert peer is not None
        assert peer.suspicion_score == pytest.approx(0.0)

    def test_large_ip_id_jump_raises_suspicion(self, store_with_peer):
        _establish_ip_id_sequential(store_with_peer, self.IP, start=100)
        # Spoofed packet arrives with IP ID far from expected range
        peer = store_with_peer.ingest_ip_id_observation(ip=self.IP, ip_id=40000)
        assert peer.suspicion_score == pytest.approx(IP_ID_ANOMALY_SUSPICION)
        assert_events_fired(peer, "ip_id_anomaly")

    def test_small_ip_id_step_no_event(self, store_with_peer):
        """A normal sequential step (e.g. +5) must not raise an alert."""
        _establish_ip_id_sequential(store_with_peer, self.IP, start=100)
        # One more sequential step
        peer = store_with_peer.ingest_ip_id_observation(
            ip=self.IP, ip_id=100 + (IP_ID_MIN_SAMPLES * 5) + 5
        )
        assert peer.suspicion_score == pytest.approx(0.0)

    def test_non_sequential_os_no_anomaly(self):
        """Modern Linux uses random IP IDs — no sequential pattern, no anomaly."""
        store = PeerStore()
        baseline = scan(mac="DD:EE:FF:00:11:22", ip="192.168.1.31", os="Linux",
                        os_candidates={"Linux": 96})
        warm_up(store, baseline)

        import random
        rng = random.Random(42)

        peer = None
        for _ in range(IP_ID_MIN_SAMPLES):
            peer = store.ingest_ip_id_observation(
                ip="192.168.1.31", ip_id=rng.randint(0, 65535)
            )
        assert peer is not None
        assert peer.ip_id_sequential is False

        # More random IDs should not trigger anomaly (pattern not sequential)
        for _ in range(5):
            peer = store.ingest_ip_id_observation(
                ip="192.168.1.31", ip_id=rng.randint(0, 65535)
            )
        assert peer.suspicion_score == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# Scenario N — Route Hop Sequence Change
#
# A device's traffic starts traversing a new intermediate hop — possible
# MITM insertion point or rogue gateway.
#
# Score: ROUTE_HOP_CHANGE_SUSPICION (+1.0)
# ---------------------------------------------------------------------------


class TestRouteHopChange:
    MAC = "EE:FF:00:11:22:33"
    IP = "192.168.1.50"
    DEST = "8.8.8.8"

    @pytest.fixture
    def store_with_peer(self):
        store = PeerStore()
        baseline = scan(mac=self.MAC, ip=self.IP, os="Linux", os_candidates={"Linux": 96})
        warm_up(store, baseline)
        return store

    def test_route_change_recorded_and_scored(self, store_with_peer):
        peer = store_with_peer.ingest_route_change(
            ip=self.IP,
            destination=self.DEST,
            new_hops=["192.168.1.254", "10.0.0.1", "203.0.113.1", "8.8.8.8"],
            change_kind=RouteChangeKind.HOP_SEQUENCE_CHANGED,
            details={"jaccard": 0.2, "new_hops": ["203.0.113.1"]},
        )
        assert peer.suspicion_score == pytest.approx(ROUTE_HOP_CHANGE_SUSPICION)
        assert_events_fired(peer, "route_changed")

    def test_route_stored_on_peer(self, store_with_peer):
        store_with_peer.ingest_route_change(
            ip=self.IP,
            destination=self.DEST,
            new_hops=["192.168.1.254", "10.0.0.1", "8.8.8.8"],
            change_kind=RouteChangeKind.HOP_SEQUENCE_CHANGED,
        )
        peer = store_with_peer.get_peer(ip=self.IP)
        assert self.DEST in peer.known_routes
        assert peer.known_routes[self.DEST] == ["192.168.1.254", "10.0.0.1", "8.8.8.8"]

    def test_unknown_ip_returns_none(self, store_with_peer):
        result = store_with_peer.ingest_route_change(
            ip="10.99.99.99",
            destination=self.DEST,
            new_hops=["192.168.1.254"],
            change_kind=RouteChangeKind.HOP_SEQUENCE_CHANGED,
        )
        assert result is None


# ---------------------------------------------------------------------------
# Scenario O — Route ASN Change
#
# A device's traffic path now crosses an unexpected autonomous system — a
# potential BGP hijack or rogue network insertion.
#
# Score: ROUTE_ASN_CHANGE_SUSPICION (+1.5)
# ---------------------------------------------------------------------------


class TestRouteASNChange:
    MAC = "FF:00:11:22:33:44"
    IP = "192.168.1.60"
    DEST = "1.1.1.1"

    @pytest.fixture
    def store_with_peer(self):
        store = PeerStore()
        baseline = scan(mac=self.MAC, ip=self.IP, os="Linux", os_candidates={"Linux": 96})
        warm_up(store, baseline)
        return store

    def test_asn_change_raises_higher_suspicion(self, store_with_peer):
        peer = store_with_peer.ingest_route_change(
            ip=self.IP,
            destination=self.DEST,
            new_hops=["192.168.1.254", "198.51.100.5", "1.1.1.1"],
            change_kind=RouteChangeKind.NEW_ASN_IN_PATH,
            details={"new_asns": ["AS64496"]},
        )
        assert peer.suspicion_score == pytest.approx(ROUTE_ASN_CHANGE_SUSPICION)
        assert_events_fired(peer, "route_changed")

    def test_asn_change_score_greater_than_hop_change(self, store_with_peer):
        """BGP-level deviation is scored higher than a simple hop change."""
        assert ROUTE_ASN_CHANGE_SUSPICION > ROUTE_HOP_CHANGE_SUSPICION


# ---------------------------------------------------------------------------
# Scenario P — Cross-Device Conflict + ARP Pushes Scenario D Over Threshold
#
# Scenario D (identity_conflict_detected) scores ~1.0-1.5 from nmap alone.
# Adding an ARP spoofing observation (+3.0) pushes the combined score to ≥ 4.0.
#
# This validates the Phase 2 design goal stated in test_simulation.py Scenario D:
#   "In the full system it combines with Phase 2 passive packet analysis
#   (TTL anomalies, ARP monitoring) to cross 3.0."
# ---------------------------------------------------------------------------


class TestCrossDeviceConflictWithARP:
    MAC_A = "AA:BB:CC:DD:EE:FF"
    IP_A = "192.168.1.10"
    MAC_B = "BB:CC:DD:EE:FF:00"
    IP_B = "192.168.1.20"
    ATTACKER_MAC = "DE:AD:BE:EF:CA:FE"

    @pytest.fixture
    def store_after_identity_conflict(self):
        store = PeerStore()
        device_a = scan(mac=self.MAC_A, ip=self.IP_A, os="Linux")
        device_b = scan(mac=self.MAC_B, ip=self.IP_B, os="Windows",
                        os_candidates={"Microsoft": 95},
                        ports=[3389], services={3389: "rdp-ms-rdp"})
        warm_up(store, device_a)
        warm_up(store, device_b)
        # Trigger identity conflict (MAC_A + IP_B)
        attacker_scan = scan(mac=self.MAC_A, ip=self.IP_B, os="Linux")
        store.add_or_update_peer(attacker_scan)
        return store

    def test_identity_conflict_alone_below_threshold(
        self, store_after_identity_conflict
    ):
        """The conflict itself scores ≥1.0 but typically < 3.0 without passive data.

        After resolution MAC_A's peer is merged into device_b (MAC_B becomes survivor).
        Lookup by IP_A since both IPs are mapped to the surviving merged peer.
        """
        store = store_after_identity_conflict
        survivor = store.get_peer(ip=self.IP_A)
        assert survivor is not None
        assert_score_below(survivor)

    def test_arp_spoof_pushes_combined_score_over_threshold(
        self, store_after_identity_conflict
    ):
        """After the nmap-based conflict, an ARP spoof adds +3.0 → crosses 3.0."""
        store = store_after_identity_conflict
        # Attacker now sends ARP replies for IP_A with a different MAC
        survivor = store.ingest_arp_observation(ip=self.IP_A, mac=self.ATTACKER_MAC)
        assert survivor is not None
        assert_score_above(survivor)
        assert_events_fired(survivor, "arp_spoofing_detected")


# ---------------------------------------------------------------------------
# Scenario Q — No False Positives During Baseline Collection (negative)
#
# Ensures TTL and ARP ingestion during warmup / baseline-collection do not
# produce false-positive events or increase suspicion score.
# ---------------------------------------------------------------------------


class TestNoFalsePositivesDuringBaseline:
    MAC = "11:22:33:44:55:66"
    IP = "192.168.1.100"

    @pytest.fixture
    def store_with_peer(self):
        store = PeerStore()
        baseline = scan(mac=self.MAC, ip=self.IP, os="Linux", os_candidates={"Linux": 96})
        warm_up(store, baseline)
        return store

    def test_ttl_baseline_collection_zero_suspicion(self, store_with_peer):
        """Before expected_ttl is set, no events should fire."""
        for _ in range(TTL_BASELINE_MIN_SAMPLES - 1):
            peer = store_with_peer.ingest_ttl_observation(ip=self.IP, ttl=62)
        assert peer.suspicion_score == pytest.approx(0.0)
        assert_events_not_fired(peer, "ttl_deviation")

    def test_arp_matching_known_mac_zero_suspicion(self, store_with_peer):
        peer = store_with_peer.ingest_arp_observation(ip=self.IP, mac=self.MAC)
        assert peer.suspicion_score == pytest.approx(0.0)
        assert_events_not_fired(peer, "arp_spoofing_detected")

    def test_repeated_consistent_ttl_zero_suspicion(self, store_with_peer):
        """Stable TTL on an established baseline should produce no events."""
        _establish_ttl_baseline(store_with_peer, self.IP, ttl=60)
        for _ in range(10):
            peer = store_with_peer.ingest_ttl_observation(ip=self.IP, ttl=60)
        assert peer.suspicion_score == pytest.approx(0.0)
