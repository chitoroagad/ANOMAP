"""Tests for Comparator drift report summariser."""

from datetime import datetime, timezone

import pytest

from peerwatch.comparator import Comparator
from peerwatch.peer_store import IdentityEvent, PeerStore

from tests.simulation.factories import scan, warm_up


class TestComparatorSummarise:
    def test_empty_store_returns_empty_list(self):
        store = PeerStore()
        cmp = Comparator(store)
        assert cmp.summarise() == []

    def test_single_peer_no_events(self):
        store = PeerStore()
        warm_up(store, scan())
        cmp = Comparator(store)
        summaries = cmp.summarise()
        assert len(summaries) == 1
        assert summaries[0].suspicion_score == pytest.approx(0.0)

    def test_summary_contains_correct_mac(self):
        store = PeerStore()
        warm_up(store, scan(mac="AA:BB:CC:DD:EE:FF"))
        cmp = Comparator(store)
        summaries = cmp.summarise()
        assert summaries[0].mac_address is not None
        assert summaries[0].mac_address.upper() == "AA:BB:CC:DD:EE:FF"

    def test_summary_contains_ip(self):
        store = PeerStore()
        warm_up(store, scan(ip="10.0.0.50"))
        cmp = Comparator(store)
        summaries = cmp.summarise()
        assert "10.0.0.50" in summaries[0].ips

    def test_scan_count_matches_warm_up(self):
        store = PeerStore()
        warm_up(store, scan(), n=6)
        cmp = Comparator(store)
        summaries = cmp.summarise()
        assert summaries[0].scan_count == 6

    def test_event_counts_correct(self):
        store = PeerStore()
        baseline = scan()
        peer = warm_up(store, baseline)

        ts = datetime.now(timezone.utc)
        peer.identity_history.append(IdentityEvent(timestamp=ts, event="os_family_changed", details={}))
        peer.identity_history.append(IdentityEvent(timestamp=ts, event="os_family_changed", details={}))
        peer.identity_history.append(IdentityEvent(timestamp=ts, event="port_profile_changed", details={}))

        cmp = Comparator(store)
        summaries = cmp.summarise()
        counts = summaries[0].event_counts
        assert counts.get("os_family_changed") == 2
        assert counts.get("port_profile_changed") == 1

    def test_sorted_by_suspicion_score_descending(self):
        store = PeerStore()
        peer_a = warm_up(store, scan(mac="AA:BB:CC:DD:EE:01", ip="10.0.0.1"))
        peer_b = warm_up(store, scan(mac="AA:BB:CC:DD:EE:02", ip="10.0.0.2"))
        peer_a.suspicion_score = 2.0
        peer_b.suspicion_score = 5.0

        cmp = Comparator(store)
        summaries = cmp.summarise()
        scores = [s.suspicion_score for s in summaries]
        assert scores == sorted(scores, reverse=True)

    def test_first_seen_last_seen_populated(self):
        store = PeerStore()
        peer = warm_up(store, scan())

        # Replace history with controlled timestamps to verify min/max logic
        peer.identity_history.clear()
        t1 = datetime(2025, 1, 1, tzinfo=timezone.utc)
        t2 = datetime(2025, 6, 1, tzinfo=timezone.utc)
        peer.identity_history.append(IdentityEvent(timestamp=t1, event="peer_created", details={}))
        peer.identity_history.append(IdentityEvent(timestamp=t2, event="os_family_changed", details={}))

        cmp = Comparator(store)
        summaries = cmp.summarise()
        assert summaries[0].first_seen == t1
        assert summaries[0].last_seen == t2

    def test_first_seen_last_seen_none_when_no_history(self):
        store = PeerStore()
        peer = warm_up(store, scan())
        peer.identity_history.clear()

        cmp = Comparator(store)
        summaries = cmp.summarise()
        assert summaries[0].first_seen is None
        assert summaries[0].last_seen is None

    def test_multiple_peers_all_summarised(self):
        store = PeerStore()
        warm_up(store, scan(mac="AA:BB:CC:DD:EE:01", ip="10.0.0.1"))
        warm_up(store, scan(mac="AA:BB:CC:DD:EE:02", ip="10.0.0.2"))
        warm_up(store, scan(mac="AA:BB:CC:DD:EE:03", ip="10.0.0.3"))

        cmp = Comparator(store)
        assert len(cmp.summarise()) == 3

    def test_score_rounded_to_two_decimal_places(self):
        store = PeerStore()
        peer = warm_up(store, scan())
        peer.suspicion_score = 3.141592

        cmp = Comparator(store)
        summaries = cmp.summarise()
        assert summaries[0].suspicion_score == pytest.approx(3.14)
