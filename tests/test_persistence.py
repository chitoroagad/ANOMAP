"""Tests for PeerStore save/load round-trip and ingested_scan_files deduplication."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from peerwatch.config import PeerWatchConfig
from peerwatch.peer_store import PeerStore

from tests.simulation.factories import scan, warm_up

SNAPSHOT_VERSION = PeerStore._SNAPSHOT_VERSION


class TestPeerStorePersistence:
    def test_round_trip_preserves_peer_count(self, tmp_path):
        store = PeerStore()
        warm_up(store, scan(mac="AA:BB:CC:DD:EE:FF", ip="10.0.0.1"))
        warm_up(store, scan(mac="11:22:33:44:55:66", ip="10.0.0.2"))

        path = tmp_path / "store.json"
        store.save(path)
        loaded = PeerStore.load(path)

        assert len(loaded.peers) == 2

    def test_round_trip_preserves_mac_index(self, tmp_path):
        store = PeerStore()
        warm_up(store, scan(mac="AA:BB:CC:DD:EE:FF", ip="10.0.0.1"))

        path = tmp_path / "store.json"
        store.save(path)
        loaded = PeerStore.load(path)

        assert loaded.get_peer(mac="AA:BB:CC:DD:EE:FF") is not None

    def test_round_trip_preserves_ip_index(self, tmp_path):
        store = PeerStore()
        warm_up(store, scan(mac="AA:BB:CC:DD:EE:FF", ip="10.0.0.1"))

        path = tmp_path / "store.json"
        store.save(path)
        loaded = PeerStore.load(path)

        assert loaded.get_peer(ip="10.0.0.1") is not None

    def test_round_trip_preserves_suspicion_score(self, tmp_path):
        store = PeerStore()
        baseline = scan()
        peer = warm_up(store, baseline)
        peer.suspicion_score = 4.5

        path = tmp_path / "store.json"
        store.save(path)
        loaded = PeerStore.load(path)

        loaded_peer = loaded.get_peer(mac=peer.mac_address)
        assert loaded_peer is not None
        assert loaded_peer.suspicion_score == pytest.approx(4.5)

    def test_round_trip_preserves_ingested_scan_files(self, tmp_path):
        store = PeerStore()
        store.ingested_scan_files = {"scan_001.json", "scan_002.json"}

        path = tmp_path / "store.json"
        store.save(path)
        loaded = PeerStore.load(path)

        assert loaded.ingested_scan_files == {"scan_001.json", "scan_002.json"}

    def test_round_trip_preserves_last_tick_at(self, tmp_path):
        store = PeerStore()
        ts = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        store.last_tick_at = ts

        path = tmp_path / "store.json"
        store.save(path)
        loaded = PeerStore.load(path)

        assert loaded.last_tick_at is not None
        assert loaded.last_tick_at.replace(tzinfo=timezone.utc) == ts or \
               loaded.last_tick_at == ts

    def test_load_nonexistent_path_returns_empty_store(self, tmp_path):
        loaded = PeerStore.load(tmp_path / "nonexistent.json")
        assert len(loaded.peers) == 0

    def test_load_version_mismatch_returns_empty_store(self, tmp_path):
        path = tmp_path / "store.json"
        bad_snapshot = {"version": SNAPSHOT_VERSION + 99, "peers": {}}
        path.write_text(json.dumps(bad_snapshot))

        loaded = PeerStore.load(path)
        assert len(loaded.peers) == 0

    def test_volatile_peer_preserved_across_round_trip(self, tmp_path):
        store = PeerStore()
        # MAC-less device: mac_address="unknown" makes it volatile (keyed by IP only)
        volatile = scan(mac="unknown", ip="10.0.0.99")
        warm_up(store, volatile)

        path = tmp_path / "store.json"
        store.save(path)
        loaded = PeerStore.load(path)

        peer = loaded.get_peer(ip="10.0.0.99")
        assert peer is not None
        assert peer.is_volatile


class TestIngestedScanFileDeduplication:
    def test_same_file_not_ingested_twice(self, tmp_path):
        """ingested_scan_files prevents re-ingesting a file on daemon restart."""
        store = PeerStore()
        store.ingested_scan_files.add("scan_001.json")

        path = tmp_path / "store.json"
        store.save(path)

        loaded = PeerStore.load(path)
        # The file should still be in the set after reload
        assert "scan_001.json" in loaded.ingested_scan_files

    def test_new_file_not_blocked(self, tmp_path):
        store = PeerStore()
        store.ingested_scan_files.add("scan_001.json")

        path = tmp_path / "store.json"
        store.save(path)
        loaded = PeerStore.load(path)

        assert "scan_002.json" not in loaded.ingested_scan_files

    def test_ingested_set_empty_on_fresh_store(self):
        store = PeerStore()
        assert len(store.ingested_scan_files) == 0
