"""
PeerWatch autonomous remediation.

Evaluates investigation reports and, depending on the configured mode, blocks
suspicious peers via iptables. All decisions are logged to blocks/blocks.jsonl
for audit and auto-unblock on TTL expiry.

Enforcement decision is purely rule-based — the LLM is NOT in the authorization
path. A peer is block-eligible only when:

    suspicion_score >= block_confidence_floor   (default 5.0)
    AND severity == "high"
    AND ip/mac not in never_block whitelist
    AND no active block already exists for this IP

Modes
-----
dry_run  — log what would happen, execute nothing (default, safe)
confirm  — print the command and wait for operator y/n before executing
enforce  — execute iptables commands immediately, requires root/CAP_NET_ADMIN

State machine per block:

    [peer eligible]
         │
         ├─ dry_run  → LOGGED  (executed=False)
         ├─ confirm  → prompt → yes → ACTIVE / no → LOGGED
         └─ enforce  → iptables -I → ACTIVE (executed=True)
                                        │
                               [unblock_expired() on next tick]
                                        │
                              expires_at < now → iptables -D → UNBLOCKED
"""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from peerwatch.agent import InvestigationReport
from peerwatch.peer_store import PeerStore

RemediationMode = Literal["dry_run", "confirm", "enforce"]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class BlockAction(BaseModel):
    """Describes a block that is about to be executed (or dry-run'd)."""
    peer_id: str
    ip: str | None
    mac: str | None
    suspicion_score: float
    severity: str
    reason: str
    block_cmds: list[list[str]]
    unblock_cmds: list[list[str]]
    issued_at: datetime
    expires_at: datetime


class BlockRecord(BlockAction):
    """A BlockAction that has been actioned and written to blocks.jsonl."""
    executed: bool
    unblocked_at: datetime | None = None


# ---------------------------------------------------------------------------
# Remediator
# ---------------------------------------------------------------------------

class Remediator:
    """
    Evaluates investigation reports and enforces blocks according to config.

    Designed to be created once at daemon startup and reused every tick.
    """

    def __init__(self, cfg, blocks_path: Path) -> None:
        self._cfg = cfg
        self._blocks_path = blocks_path
        blocks_path.parent.mkdir(parents=True, exist_ok=True)

        # Downgrade enforce → dry_run if not running as root
        if cfg.remediation_mode == "enforce" and os.geteuid() != 0:
            logging.error(
                "remediation_mode=enforce requires root (CAP_NET_ADMIN). "
                "Downgrading to dry_run."
            )
            self._mode: RemediationMode = "dry_run"
        else:
            self._mode = cfg.remediation_mode

        self._never_block: frozenset[str] = frozenset(cfg.never_block)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self, report: InvestigationReport, peer_store: PeerStore
    ) -> BlockAction | None:
        """
        Return a BlockAction if the peer clears all guards, None otherwise.

        Guards (all must pass):
          1. IP/MAC not in never_block whitelist
          2. suspicion_score >= block_confidence_floor
          3. severity == "high"
          4. No active block already exists for this IP
          5. At least one IP available to block
        """
        ip = (report.ips or [None])[0]
        mac = report.mac_address

        if ip and ip in self._never_block:
            logging.debug(f"Remediation skip {ip}: in never_block")
            return None
        if mac and mac in self._never_block:
            logging.debug(f"Remediation skip {mac}: in never_block")
            return None

        if report.suspicion_score < self._cfg.block_confidence_floor:
            return None
        if report.severity.lower() != "high":
            return None

        if not ip:
            logging.debug(f"Remediation skip {report.peer_id}: no IP available")
            return None

        if self._is_active_block(ip):
            logging.debug(f"Remediation skip {ip}: active block already exists")
            return None

        peer = peer_store.peers.get(report.peer_id)
        recent_events = (
            [e.event for e in peer.identity_history[-5:]] if peer else []
        )
        reason = (
            ", ".join(recent_events) if recent_events else report.explanation[:120]
        )

        block_cmds = [
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            ["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
        ]
        unblock_cmds = [
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
        ]

        now = datetime.now(timezone.utc)
        return BlockAction(
            peer_id=report.peer_id,
            ip=ip,
            mac=mac,
            suspicion_score=report.suspicion_score,
            severity=report.severity,
            reason=reason,
            block_cmds=block_cmds,
            unblock_cmds=unblock_cmds,
            issued_at=now,
            expires_at=now + timedelta(hours=self._cfg.block_ttl_hours),
        )

    def act(self, action: BlockAction) -> BlockRecord:
        """Execute or log a BlockAction according to the configured mode."""
        if self._mode == "dry_run":
            return self._dry_run(action)
        if self._mode == "confirm":
            return self._confirm(action)
        return self._enforce(action)

    def unblock_expired(self) -> list[BlockRecord]:
        """
        Unblock any peers whose TTL has elapsed. Call once per daemon tick.

        Reads blocks.jsonl, runs unblock_cmds for expired+executed records, and
        rewrites the file with updated unblocked_at timestamps.
        """
        if not self._blocks_path.exists():
            return []

        now = datetime.now(timezone.utc)
        records = self._read_records()
        changed = False

        newly_unblocked: list[BlockRecord] = []
        for record in records:
            if (
                record.executed
                and record.unblocked_at is None
                and record.expires_at <= now
            ):
                self._run_cmds(record.unblock_cmds, label="unblock")
                record.unblocked_at = now
                newly_unblocked.append(record)
                changed = True
                logging.info(
                    f"Auto-unblocked {record.ip or record.peer_id[:8]} "
                    f"(TTL expired {record.expires_at.isoformat()})"
                )

        if changed:
            self._rewrite_records(records)

        return newly_unblocked

    # ------------------------------------------------------------------
    # Mode handlers
    # ------------------------------------------------------------------

    def _dry_run(self, action: BlockAction) -> BlockRecord:
        record = BlockRecord(**action.model_dump(), executed=False)
        logging.info(
            f"[DRY RUN] Would block {action.ip} "
            f"score={action.suspicion_score:.1f} reason='{action.reason}'"
        )
        for cmd in action.block_cmds:
            logging.info(f"  [DRY RUN]  {' '.join(cmd)}")
        self._append_record(record)
        return record

    def _confirm(self, action: BlockAction) -> BlockRecord:
        cmds_preview = "\n".join(f"    {' '.join(c)}" for c in action.block_cmds)
        print(
            f"\n[CONFIRM] Block {action.ip}?\n"
            f"  Score  : {action.suspicion_score:.1f}\n"
            f"  Reason : {action.reason}\n"
            f"  Expiry : {action.expires_at.isoformat()}\n"
            f"  Commands:\n{cmds_preview}"
        )
        try:
            answer = input("  Execute? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"

        if answer == "y":
            return self._enforce(action)

        record = BlockRecord(**action.model_dump(), executed=False)
        self._append_record(record)
        logging.info(f"Block declined by operator: {action.ip}")
        return record

    def _enforce(self, action: BlockAction) -> BlockRecord:
        ok = self._run_cmds(action.block_cmds, label="block")
        record = BlockRecord(**action.model_dump(), executed=ok)
        self._append_record(record)
        if ok:
            logging.warning(
                f"BLOCKED {action.ip} "
                f"score={action.suspicion_score:.1f} "
                f"expires={action.expires_at.isoformat()}"
            )
        return record

    # ------------------------------------------------------------------
    # iptables helpers
    # ------------------------------------------------------------------

    def _run_cmds(self, cmds: list[list[str]], label: str) -> bool:
        """Run a list of iptables commands. Returns True if all succeeded."""
        all_ok = True
        for cmd in cmds:
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode != 0:
                    logging.warning(
                        f"iptables {label} failed (exit {proc.returncode}): "
                        f"{' '.join(cmd)} — {proc.stderr.strip()}"
                    )
                    all_ok = False
            except FileNotFoundError:
                logging.error("iptables not found in PATH — cannot enforce blocks")
                all_ok = False
            except Exception as exc:
                logging.error(f"iptables error during {label}: {exc}")
                all_ok = False
        return all_ok

    # ------------------------------------------------------------------
    # blocks.jsonl I/O
    # ------------------------------------------------------------------

    def _is_active_block(self, ip: str) -> bool:
        now = datetime.now(timezone.utc)
        for record in self._read_records():
            if (
                record.ip == ip
                and record.executed
                and record.unblocked_at is None
                and record.expires_at > now
            ):
                return True
        return False

    def _read_records(self) -> list[BlockRecord]:
        if not self._blocks_path.exists():
            return []
        records: list[BlockRecord] = []
        with open(self._blocks_path) as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(BlockRecord.model_validate_json(line))
                except Exception as exc:
                    logging.warning(
                        f"{self._blocks_path}:{lineno}: could not parse record: {exc}"
                    )
        return records

    def _append_record(self, record: BlockRecord) -> None:
        with open(self._blocks_path, "a") as f:
            f.write(record.model_dump_json() + "\n")

    def _rewrite_records(self, records: list[BlockRecord]) -> None:
        """Atomically overwrite blocks.jsonl (used when updating unblocked_at)."""
        dir_ = self._blocks_path.parent
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", dir=dir_, delete=False, suffix=".tmp"
            ) as tmp:
                for record in records:
                    tmp.write(record.model_dump_json() + "\n")
                tmp_path = Path(tmp.name)
            tmp_path.replace(self._blocks_path)
        except Exception as exc:
            logging.error(f"Failed to rewrite {self._blocks_path}: {exc}")
