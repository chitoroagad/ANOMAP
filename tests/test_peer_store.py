import pytest
from peerwatch.peer_store import PeerStore, Peer, UNKNOWN_KEY
from peerwatch.parser import NormalisedData


class TestPeerStore:
    @pytest.fixture
    def sample_normalised_data(self):
        return NormalisedData(
            mac_address="00:11:22:33:44:55",
            ipv4="192.168.1.1",
            os="Linux",
            open_ports=[22, 80],
            services={22: "ssh-OpenSSH", 80: "http-Apache"},
        )

    @pytest.fixture
    def peer_store(self):
        return PeerStore()

    def test_add_peer_creates_new_peer(self, peer_store, sample_normalised_data):
        peer = peer_store.add_or_update_peer(sample_normalised_data)

        assert peer.mac_address == "00:11:22:33:44:55"
        assert "192.168.1.1" in peer.ips
        assert len(peer_store.peers) == 1

    def test_get_peer_by_mac(self, peer_store, sample_normalised_data):
        peer_store.add_or_update_peer(sample_normalised_data)

        found = peer_store.get_peer(mac="00:11:22:33:44:55")

        assert found is not None
        assert found.mac_address == "00:11:22:33:44:55"

    def test_get_peer_by_ip(self, peer_store, sample_normalised_data):
        peer_store.add_or_update_peer(sample_normalised_data)

        found = peer_store.get_peer(ip="192.168.1.1")

        assert found is not None
        assert "192.168.1.1" in found.ips

    def test_get_peer_returns_none_for_unknown(self, peer_store):
        found = peer_store.get_peer(mac="00:11:22:33:44:55")

        assert found is None

    def test_unknown_mac_returns_none(self, peer_store):
        data = NormalisedData(mac_address=UNKNOWN_KEY, ipv4="192.168.1.1")
        peer_store.add_or_update_peer(data)

        found = peer_store.get_peer(mac=UNKNOWN_KEY)
        assert found is None

    def test_update_existing_peer_adds_ip(self, peer_store):
        data1 = NormalisedData(mac_address="00:11:22:33:44:55", ipv4="192.168.1.1")
        data2 = NormalisedData(mac_address="00:11:22:33:44:55", ipv4="192.168.1.2")

        peer_store.add_or_update_peer(data1)
        peer = peer_store.add_or_update_peer(data2)

        assert "192.168.1.1" in peer.ips
        assert "192.168.1.2" in peer.ips

    def test_mac_promotion_sets_not_volatile(self, peer_store):
        data1 = NormalisedData(ipv4="192.168.1.1")
        data2 = NormalisedData(mac_address="00:11:22:33:44:55", ipv4="192.168.1.1")

        peer_store.add_or_update_peer(data1)
        peer = peer_store.add_or_update_peer(data2)

        assert peer.mac_address == "00:11:22:33:44:55"
        assert peer.is_volatile is False

    def test_mac_conflict_increases_suspicion(self, peer_store):
        data1 = NormalisedData(mac_address="00:11:22:33:44:55", ipv4="192.168.1.1")
        data2 = NormalisedData(mac_address="00:11:22:33:44:66", ipv4="192.168.1.1")

        peer_store.add_or_update_peer(data1)
        peer = peer_store.add_or_update_peer(data2)

        assert peer.suspicion_score >= 0.5

    def test_identity_history_records_events(self, peer_store, sample_normalised_data):
        peer_store.add_or_update_peer(sample_normalised_data)

        assert len(peer_store.peers) == 1
        peer = peer_store.peers[next(iter(peer_store.peers))]
        assert len(peer.identity_history) > 0
        assert peer.identity_history[0].event == "peer_created"

    def test_reset_clears_all_data(self, peer_store, sample_normalised_data):
        peer_store.add_or_update_peer(sample_normalised_data)
        peer_store.reset()

        assert len(peer_store.peers) == 0
        assert len(peer_store.mac_to_id) == 0
        assert len(peer_store.ip_to_id) == 0

    def test_multiple_candidates_uses_highest_confidence(self, peer_store):
        data1 = NormalisedData(mac_address="00:11:22:33:44:55", ipv4="192.168.1.1")
        data2 = NormalisedData(ipv4="192.168.1.2")

        p1 = peer_store.add_or_update_peer(data1)
        p1.is_volatile = False
        peer_store.add_or_update_peer(data2)

        data3 = NormalisedData(mac_address="00:11:22:33:44:55", ipv4="192.168.1.2")
        survivor = peer_store.add_or_update_peer(data3)

        assert len(peer_store.peers) < 3


class TestFingerprintComparison:
    def _data(self, **kwargs) -> NormalisedData:
        return NormalisedData(**kwargs)

    def test_identical_data_no_events(self):
        data = self._data(
            os="Linux",
            open_ports=[22, 80],
            services={22: "ssh-OpenSSH", 80: "http-Apache"},
        )
        result = PeerStore._compare_fingerprints(data, data)

        assert result.events == []
        assert result.os_match is True
        assert result.port_jaccard == pytest.approx(1.0)
        assert result.overall_score == pytest.approx(1.0)

    def test_os_family_change_triggers_event(self):
        prev = self._data(os="Linux", open_ports=[22])
        incoming = self._data(os="Windows", open_ports=[22])
        result = PeerStore._compare_fingerprints(prev, incoming)

        assert "os_family_changed" in result.events
        assert result.os_match is False

    def test_os_candidate_overlap_suppresses_false_positive(self):
        # Simulates a TV/media device where nmap's top pick flips between Sony and Pioneer.
        # Both scans have overlapping candidates so no alert should fire.
        prev = self._data(
            os="Sony", os_candidates={"Sony": 95, "Pioneer": 95, "Bush": 95}
        )
        incoming = self._data(
            os="Pioneer", os_candidates={"Pioneer": 95, "Bush": 95, "Sony": 95}
        )
        result = PeerStore._compare_fingerprints(prev, incoming)

        assert "os_family_changed" not in result.events
        assert result.os_match is True

    def test_os_candidate_no_overlap_triggers_event(self):
        # Linux device suddenly fingerprints as Windows with no shared families.
        prev = self._data(os="Linux", os_candidates={"Linux": 96})
        incoming = self._data(os="Windows", os_candidates={"Microsoft": 95})
        result = PeerStore._compare_fingerprints(prev, incoming)

        assert "os_family_changed" in result.events
        assert result.os_match is False

    def test_os_partial_candidate_overlap_scores_between_0_and_1(self):
        # Two candidates in prev, one shared with incoming — overlap is partial.
        prev = self._data(os="Linux", os_candidates={"Linux": 96, "Google": 93})
        incoming = self._data(os="Linux", os_candidates={"Linux": 96})
        result = PeerStore._compare_fingerprints(prev, incoming)

        assert result.os_match is True
        # os_score = 1/2 = 0.5, ports Jaccard = 1.0 (both empty), service = 1.0
        # overall = 0.5*0.5 + 0.3*1.0 + 0.2*1.0 = 0.75
        assert result.overall_score == pytest.approx(0.75)

    def test_os_unknown_does_not_trigger_event(self):
        prev = self._data(os="unknown", open_ports=[22])
        incoming = self._data(os="Linux", open_ports=[22])
        result = PeerStore._compare_fingerprints(prev, incoming)

        assert "os_family_changed" not in result.events
        assert result.os_match is True

    def test_port_profile_changed_below_threshold(self):
        prev = self._data(open_ports=[22, 80, 443])
        incoming = self._data(open_ports=[8080, 8443, 9000])
        result = PeerStore._compare_fingerprints(prev, incoming)

        assert "port_profile_changed" in result.events
        assert result.port_jaccard == pytest.approx(0.0)

    def test_port_profile_unchanged_above_threshold(self):
        prev = self._data(open_ports=[22, 80, 443])
        incoming = self._data(open_ports=[22, 80, 443, 8080])
        result = PeerStore._compare_fingerprints(prev, incoming)

        # jaccard = 3/4 = 0.75 > threshold
        assert "port_profile_changed" not in result.events
        assert result.port_jaccard == pytest.approx(0.75)

    def test_service_type_change_on_shared_port(self):
        prev = self._data(open_ports=[22], services={22: "ssh-OpenSSH"})
        incoming = self._data(open_ports=[22], services={22: "http-nginx"})
        result = PeerStore._compare_fingerprints(prev, incoming)

        assert "service_type_changed" in result.events
        assert 22 in result.service_type_changes
        assert result.service_type_changes[22] == ["ssh-OpenSSH", "http-nginx"]

    def test_service_type_change_records_per_port_event(self):
        store = PeerStore()
        data1 = NormalisedData(
            mac_address="AA:BB:CC:DD:EE:FF",
            ipv4="10.0.0.1",
            open_ports=[22, 80],
            services={22: "ssh-OpenSSH", 80: "http-Apache"},
        )
        data2 = NormalisedData(
            mac_address="AA:BB:CC:DD:EE:FF",
            ipv4="10.0.0.1",
            open_ports=[22, 80],
            services={22: "http-nginx", 80: "http-Apache"},  # port 22 flipped to http
        )
        store.add_or_update_peer(data1)
        peer = store.add_or_update_peer(data2)

        svc_events = [
            e for e in peer.identity_history if e.event == "service_type_changed"
        ]
        assert len(svc_events) == 1
        assert svc_events[0].details["port"] == 22
        assert svc_events[0].details["old_service"] == "ssh-OpenSSH"
        assert svc_events[0].details["new_service"] == "http-nginx"

    def test_oscillating_service_only_fires_once(self):
        # Simulates nmap alternating between two valid fingerprints on the same port.
        # The second and subsequent oscillations should not produce new events.
        store = PeerStore()
        mac = "AA:BB:CC:DD:EE:FF"
        ip = "10.0.0.1"

        def scan(svc):
            return NormalisedData(
                mac_address=mac, ipv4=ip, open_ports=[8009], services={8009: svc}
            )

        store.add_or_update_peer(scan("ajp13"))  # baseline: ajp13 known
        store.add_or_update_peer(
            scan("castv2-Driver")
        )  # novel → fires event, castv2 now known
        store.add_or_update_peer(scan("ajp13"))  # already known → no event
        peer = store.add_or_update_peer(
            scan("castv2-Driver")
        )  # already known → no event

        svc_events = [
            e for e in peer.identity_history if e.event == "service_type_changed"
        ]
        assert len(svc_events) == 1
        assert svc_events[0].details["new_service"] == "castv2-Driver"

    def test_service_version_change_does_not_trigger(self):
        # Same protocol type (ssh), different product version — not suspicious
        prev = self._data(open_ports=[22], services={22: "ssh-OpenSSH 7.9"})
        incoming = self._data(open_ports=[22], services={22: "ssh-OpenSSH 8.4"})
        result = PeerStore._compare_fingerprints(prev, incoming)

        assert "service_type_changed" not in result.events

    def test_full_identity_shift(self):
        prev = self._data(
            os="Linux",
            open_ports=[22, 80],
            services={22: "ssh-OpenSSH", 80: "http-Apache"},
        )
        incoming = self._data(
            os="Windows",
            open_ports=[3389, 445],
            services={},
        )
        result = PeerStore._compare_fingerprints(prev, incoming)

        assert "full_identity_shift" in result.events
        assert "os_family_changed" in result.events
        assert result.port_jaccard == pytest.approx(0.0)

    def test_overall_score_all_match(self):
        data = self._data(os="Linux", open_ports=[22], services={22: "ssh-OpenSSH"})
        result = PeerStore._compare_fingerprints(data, data)

        assert result.overall_score == pytest.approx(1.0)

    def test_overall_score_os_mismatch(self):
        prev = self._data(os="Linux", open_ports=[22], services={22: "ssh-OpenSSH"})
        incoming = self._data(
            os="Windows", open_ports=[22], services={22: "ssh-OpenSSH"}
        )
        result = PeerStore._compare_fingerprints(prev, incoming)

        # os_score=0, port_jaccard=1, service_match=1 → 0*0.5 + 1*0.3 + 1*0.2 = 0.5
        assert result.overall_score == pytest.approx(0.5)


class TestPeer:
    def test_peer_str_representation(self):
        data = NormalisedData(mac_address="00:11:22:33:44:55", ipv4="192.168.1.1")

        peer = Peer(
            mac_address="00:11:22:33:44:55",
            ips={"192.168.1.1"},
            metadata=data,
        )

        assert "00:11:22:33:44:55" in str(peer)
        assert "192.168.1.1" in str(peer)

    def test_record_event_adds_to_history(self):
        data = NormalisedData(mac_address="00:11:22:33:44:55")

        peer = Peer(
            mac_address="00:11:22:33:44:55",
            metadata=data,
        )

        peer.record_event("test_event", key="value")

        assert len(peer.identity_history) == 1
        assert peer.identity_history[0].event == "test_event"
        assert peer.identity_history[0].details["key"] == "value"
