"""Phase 3 tests: MAC OUI vendor / OS family mismatch detection."""

import pytest

from peerwatch.parser import NormalisedData
from peerwatch.peer_store import PeerStore

from tests.simulation.factories import scan, warm_up


class TestMacVendorOsMismatch:
    def _store(self) -> PeerStore:
        return PeerStore()

    def test_apple_mac_linux_os_triggers_event(self):
        store = self._store()
        baseline = scan(
            mac="AA:BB:CC:DD:EE:FF",
            ip="192.168.1.10",
            os="Linux",
            os_candidates={"Linux": 96},
            device_vendor="Apple",
        )
        warm_up(store, baseline)
        peer = store.add_or_update_peer(baseline)

        events = [e for e in peer.identity_history if e.event == "mac_vendor_os_mismatch"]
        assert len(events) == 1
        assert events[0].details["vendor"] == "Apple"
        assert "Apple" in events[0].details["expected_os_families"]
        assert "Linux" in events[0].details["observed_os_families"]

    def test_apple_mac_linux_os_adds_suspicion(self):
        store = self._store()
        baseline = scan(
            mac="AA:BB:CC:DD:EE:FF",
            ip="192.168.1.10",
            os="Linux",
            os_candidates={"Linux": 96},
            device_vendor="Apple",
        )
        warm_up(store, baseline)
        peer = store.add_or_update_peer(baseline)

        assert peer.suspicion_score == pytest.approx(2.0, abs=0.01)

    def test_apple_mac_macos_no_mismatch(self):
        store = self._store()
        baseline = scan(
            mac="AA:BB:CC:DD:EE:FF",
            ip="192.168.1.10",
            os="Apple",
            os_candidates={"Apple": 96},
            device_vendor="Apple",
        )
        warm_up(store, baseline)
        peer = store.add_or_update_peer(baseline)

        events = [e for e in peer.identity_history if e.event == "mac_vendor_os_mismatch"]
        assert len(events) == 0

    def test_raspberry_pi_mac_windows_triggers_event(self):
        store = self._store()
        baseline = scan(
            mac="AA:BB:CC:DD:EE:FF",
            ip="192.168.1.20",
            os="Windows",
            os_candidates={"Microsoft": 95},
            device_vendor="Raspberry Pi Foundation",
        )
        warm_up(store, baseline)
        peer = store.add_or_update_peer(baseline)

        events = [e for e in peer.identity_history if e.event == "mac_vendor_os_mismatch"]
        assert len(events) == 1

    def test_mismatch_fires_only_once(self):
        store = self._store()
        baseline = scan(
            mac="AA:BB:CC:DD:EE:FF",
            ip="192.168.1.10",
            os="Linux",
            os_candidates={"Linux": 96},
            device_vendor="Apple",
        )
        warm_up(store, baseline)
        for _ in range(3):
            peer = store.add_or_update_peer(baseline)

        events = [e for e in peer.identity_history if e.event == "mac_vendor_os_mismatch"]
        assert len(events) == 1

    def test_generic_vendor_no_check(self):
        """Intel NICs can run any OS — no mismatch raised."""
        store = self._store()
        baseline = scan(
            mac="AA:BB:CC:DD:EE:FF",
            ip="192.168.1.10",
            os="Windows",
            os_candidates={"Microsoft": 96},
            device_vendor="Intel Corporate",
        )
        warm_up(store, baseline)
        peer = store.add_or_update_peer(baseline)

        events = [e for e in peer.identity_history if e.event == "mac_vendor_os_mismatch"]
        assert len(events) == 0

    def test_unknown_vendor_no_check(self):
        store = self._store()
        baseline = scan(
            mac="AA:BB:CC:DD:EE:FF",
            ip="192.168.1.10",
            os="Linux",
            os_candidates={"Linux": 96},
            device_vendor="unknown",
        )
        warm_up(store, baseline)
        peer = store.add_or_update_peer(baseline)

        events = [e for e in peer.identity_history if e.event == "mac_vendor_os_mismatch"]
        assert len(events) == 0

    def test_no_mismatch_during_warmup(self):
        """Mismatch check must not fire during baseline warmup (< BASELINE_MIN_SCANS=5)."""
        store = self._store()
        baseline = scan(
            mac="AA:BB:CC:DD:EE:FF",
            ip="192.168.1.10",
            os="Linux",
            os_candidates={"Linux": 96},
            device_vendor="Apple",
        )
        # 3 scans — still in warmup
        peer = None
        for _ in range(3):
            peer = store.add_or_update_peer(baseline)

        events = [e for e in peer.identity_history if e.event == "mac_vendor_os_mismatch"]
        assert len(events) == 0
