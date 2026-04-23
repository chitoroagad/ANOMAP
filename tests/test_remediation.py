"""Tests for Remediator guard chain and dry_run/enforce modes."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from peerwatch.agent import InvestigationReport, ScanRecommendation
from peerwatch.config import PeerWatchConfig
from peerwatch.peer_store import PeerStore
from peerwatch.remediation import BlockRecord, Remediator

from tests.simulation.factories import scan, warm_up


def _report(
    ip: str = "192.168.1.10",
    mac: str | None = "AA:BB:CC:DD:EE:FF",
    score: float = 6.0,
    severity: str = "high",
    peer_id: str = "test-peer-id",
) -> InvestigationReport:
    return InvestigationReport(
        peer_id=peer_id,
        mac_address=mac,
        ips=[ip] if ip else [],
        suspicion_score=score,
        timestamp=datetime.now(timezone.utc),
        severity=severity,
        explanation="test explanation",
        recommended_scans=[],
        scan_results=[],
        recommended_actions=[],
    )


def _remediator(tmp_path: Path, cfg: PeerWatchConfig | None = None) -> Remediator:
    cfg = cfg or PeerWatchConfig(remediation_mode="dry_run")
    return Remediator(cfg, tmp_path / "blocks.jsonl")


class TestRemediatorGuards:
    def test_clears_all_guards(self, tmp_path):
        rem = _remediator(tmp_path)
        store = PeerStore()
        action = rem.evaluate(_report(), store)
        assert action is not None

    def test_ip_in_never_block_returns_none(self, tmp_path):
        cfg = PeerWatchConfig(remediation_mode="dry_run", never_block=["192.168.1.10"])
        rem = _remediator(tmp_path, cfg)
        store = PeerStore()
        assert rem.evaluate(_report(ip="192.168.1.10"), store) is None

    def test_mac_in_never_block_returns_none(self, tmp_path):
        cfg = PeerWatchConfig(remediation_mode="dry_run", never_block=["AA:BB:CC:DD:EE:FF"])
        rem = _remediator(tmp_path, cfg)
        store = PeerStore()
        assert rem.evaluate(_report(mac="AA:BB:CC:DD:EE:FF"), store) is None

    def test_score_below_floor_returns_none(self, tmp_path):
        cfg = PeerWatchConfig(remediation_mode="dry_run", block_confidence_floor=5.0)
        rem = _remediator(tmp_path, cfg)
        store = PeerStore()
        assert rem.evaluate(_report(score=4.9), store) is None

    def test_score_at_floor_passes(self, tmp_path):
        cfg = PeerWatchConfig(remediation_mode="dry_run", block_confidence_floor=5.0)
        rem = _remediator(tmp_path, cfg)
        store = PeerStore()
        assert rem.evaluate(_report(score=5.0), store) is not None

    def test_severity_medium_returns_none(self, tmp_path):
        rem = _remediator(tmp_path)
        store = PeerStore()
        assert rem.evaluate(_report(severity="medium"), store) is None

    def test_severity_low_returns_none(self, tmp_path):
        rem = _remediator(tmp_path)
        store = PeerStore()
        assert rem.evaluate(_report(severity="low"), store) is None

    def test_no_ip_returns_none(self, tmp_path):
        rem = _remediator(tmp_path)
        store = PeerStore()
        # Report with empty ips list
        report = _report(ip="192.168.1.10")
        report = report.model_copy(update={"ips": []})
        assert rem.evaluate(report, store) is None

    def test_active_block_returns_none(self, tmp_path):
        rem = _remediator(tmp_path)
        store = PeerStore()

        # Write an active block record for this IP
        now = datetime.now(timezone.utc)
        active = BlockRecord(
            peer_id="test-peer-id",
            ip="192.168.1.10",
            mac=None,
            suspicion_score=6.0,
            severity="high",
            reason="prior block",
            block_cmds=[],
            unblock_cmds=[],
            issued_at=now - timedelta(hours=1),
            expires_at=now + timedelta(hours=23),
            executed=True,
            unblocked_at=None,
        )
        blocks_path = tmp_path / "blocks.jsonl"
        blocks_path.write_text(active.model_dump_json() + "\n")

        assert rem.evaluate(_report(), store) is None

    def test_expired_block_does_not_block_re_evaluation(self, tmp_path):
        rem = _remediator(tmp_path)
        store = PeerStore()

        now = datetime.now(timezone.utc)
        expired = BlockRecord(
            peer_id="test-peer-id",
            ip="192.168.1.10",
            mac=None,
            suspicion_score=6.0,
            severity="high",
            reason="old block",
            block_cmds=[],
            unblock_cmds=[],
            issued_at=now - timedelta(hours=25),
            expires_at=now - timedelta(hours=1),  # expired
            executed=True,
            unblocked_at=None,
        )
        blocks_path = tmp_path / "blocks.jsonl"
        blocks_path.write_text(expired.model_dump_json() + "\n")

        # Expired block should not prevent a new block
        assert rem.evaluate(_report(), store) is not None


class TestRemediatorDryRun:
    def test_dry_run_returns_record_not_executed(self, tmp_path):
        rem = _remediator(tmp_path)
        store = PeerStore()
        action = rem.evaluate(_report(), store)
        assert action is not None
        record = rem.act(action)
        assert record.executed is False

    def test_dry_run_appends_to_blocks_file(self, tmp_path):
        rem = _remediator(tmp_path)
        store = PeerStore()
        action = rem.evaluate(_report(), store)
        rem.act(action)
        blocks_path = tmp_path / "blocks.jsonl"
        assert blocks_path.exists()
        lines = [l for l in blocks_path.read_text().splitlines() if l.strip()]
        assert len(lines) == 1

    def test_dry_run_does_not_call_subprocess(self, tmp_path):
        rem = _remediator(tmp_path)
        store = PeerStore()
        action = rem.evaluate(_report(), store)
        with patch("peerwatch.remediation.subprocess.run") as mock_run:
            rem.act(action)
            mock_run.assert_not_called()

    def test_block_action_has_correct_iptables_commands(self, tmp_path):
        rem = _remediator(tmp_path)
        store = PeerStore()
        action = rem.evaluate(_report(ip="10.0.0.5"), store)
        assert action is not None
        assert any("10.0.0.5" in " ".join(cmd) for cmd in action.block_cmds)
        assert any("INPUT" in " ".join(cmd) for cmd in action.block_cmds)
        assert any("OUTPUT" in " ".join(cmd) for cmd in action.block_cmds)


class TestRemediatorEnforce:
    def test_enforce_calls_iptables(self, tmp_path):
        cfg = PeerWatchConfig(remediation_mode="enforce")
        with patch("peerwatch.remediation.os.geteuid", return_value=0):
            rem = Remediator(cfg, tmp_path / "blocks.jsonl")

        store = PeerStore()
        action = rem.evaluate(_report(), store)
        assert action is not None

        with patch("peerwatch.remediation.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            record = rem.act(action)
            assert record.executed is True
            assert mock_run.call_count == 2  # INPUT + OUTPUT rules

    def test_enforce_downgraded_to_dry_run_without_root(self, tmp_path):
        cfg = PeerWatchConfig(remediation_mode="enforce")
        with patch("peerwatch.remediation.os.geteuid", return_value=1000):
            rem = Remediator(cfg, tmp_path / "blocks.jsonl")

        store = PeerStore()
        action = rem.evaluate(_report(), store)
        assert action is not None

        with patch("peerwatch.remediation.subprocess.run") as mock_run:
            record = rem.act(action)
            mock_run.assert_not_called()
            assert record.executed is False


class TestUnblockExpired:
    def test_unblock_expired_runs_unblock_cmds(self, tmp_path):
        cfg = PeerWatchConfig(remediation_mode="enforce")
        with patch("peerwatch.remediation.os.geteuid", return_value=0):
            rem = Remediator(cfg, tmp_path / "blocks.jsonl")

        now = datetime.now(timezone.utc)
        expired = BlockRecord(
            peer_id="test-peer-id",
            ip="10.0.0.1",
            mac=None,
            suspicion_score=6.0,
            severity="high",
            reason="test",
            block_cmds=[["iptables", "-I", "INPUT", "-s", "10.0.0.1", "-j", "DROP"]],
            unblock_cmds=[["iptables", "-D", "INPUT", "-s", "10.0.0.1", "-j", "DROP"]],
            issued_at=now - timedelta(hours=25),
            expires_at=now - timedelta(hours=1),
            executed=True,
            unblocked_at=None,
        )
        (tmp_path / "blocks.jsonl").write_text(expired.model_dump_json() + "\n")

        with patch("peerwatch.remediation.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            unblocked = rem.unblock_expired()

        assert len(unblocked) == 1
        assert unblocked[0].ip == "10.0.0.1"
        assert unblocked[0].unblocked_at is not None

    def test_non_expired_block_not_unblocked(self, tmp_path):
        rem = _remediator(tmp_path)
        now = datetime.now(timezone.utc)
        active = BlockRecord(
            peer_id="test-peer-id",
            ip="10.0.0.2",
            mac=None,
            suspicion_score=6.0,
            severity="high",
            reason="test",
            block_cmds=[],
            unblock_cmds=[],
            issued_at=now,
            expires_at=now + timedelta(hours=23),
            executed=True,
            unblocked_at=None,
        )
        (tmp_path / "blocks.jsonl").write_text(active.model_dump_json() + "\n")
        unblocked = rem.unblock_expired()
        assert len(unblocked) == 0

    def test_no_blocks_file_returns_empty(self, tmp_path):
        rem = _remediator(tmp_path)
        assert rem.unblock_expired() == []
