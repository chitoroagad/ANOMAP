"""Tests for PeerWatchConfig validation and load_config helper."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from peerwatch.config import PeerWatchConfig, load_config


class TestPeerWatchConfigDefaults:
    def test_default_subnet(self):
        assert PeerWatchConfig().subnet == "192.168.1.0/24"

    def test_default_remediation_mode(self):
        assert PeerWatchConfig().remediation_mode == "dry_run"

    def test_default_suspicion_threshold(self):
        assert PeerWatchConfig().suspicion_threshold == pytest.approx(3.0)

    def test_default_block_confidence_floor(self):
        assert PeerWatchConfig().block_confidence_floor == pytest.approx(5.0)

    def test_default_never_block_is_empty_list(self):
        assert PeerWatchConfig().never_block == []

    def test_default_model(self):
        assert PeerWatchConfig().model == "phi4:latest"

    def test_default_half_life_days(self):
        assert PeerWatchConfig().suspicion_half_life_days == pytest.approx(3.5)

    def test_default_baseline_min_scans(self):
        assert PeerWatchConfig().baseline_min_scans == 5


class TestPeerWatchConfigValidation:
    def test_invalid_remediation_mode_raises(self):
        with pytest.raises(ValidationError):
            PeerWatchConfig(remediation_mode="nuke")

    def test_valid_remediation_modes(self):
        for mode in ("dry_run", "confirm", "enforce"):
            cfg = PeerWatchConfig(remediation_mode=mode)
            assert cfg.remediation_mode == mode

    def test_override_threshold(self):
        cfg = PeerWatchConfig(suspicion_threshold=5.0)
        assert cfg.suspicion_threshold == pytest.approx(5.0)

    def test_override_never_block(self):
        cfg = PeerWatchConfig(never_block=["10.0.0.1", "AA:BB:CC:DD:EE:FF"])
        assert "10.0.0.1" in cfg.never_block
        assert "AA:BB:CC:DD:EE:FF" in cfg.never_block

    def test_override_model(self):
        cfg = PeerWatchConfig(model="llama3:latest")
        assert cfg.model == "llama3:latest"


class TestLoadConfig:
    def test_load_config_no_path_returns_defaults(self):
        cfg = load_config(None)
        assert cfg.remediation_mode == "dry_run"

    def test_load_config_missing_file_returns_defaults(self, tmp_path):
        cfg = load_config(tmp_path / "nonexistent.json")
        assert cfg.remediation_mode == "dry_run"

    def test_load_config_reads_fields_from_file(self, tmp_path):
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({
            "subnet": "10.0.0.0/8",
            "suspicion_threshold": 4.0,
            "remediation_mode": "confirm",
        }))
        cfg = load_config(config_path)
        assert cfg.subnet == "10.0.0.0/8"
        assert cfg.suspicion_threshold == pytest.approx(4.0)
        assert cfg.remediation_mode == "confirm"

    def test_load_config_partial_file_uses_defaults_for_missing(self, tmp_path):
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"subnet": "172.16.0.0/12"}))
        cfg = load_config(config_path)
        assert cfg.subnet == "172.16.0.0/12"
        assert cfg.remediation_mode == "dry_run"  # default

    def test_load_config_accepts_path_object(self, tmp_path):
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({}))
        cfg = load_config(config_path)
        assert cfg is not None

    def test_load_config_accepts_string_path(self, tmp_path):
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({}))
        cfg = load_config(str(config_path))
        assert cfg is not None
