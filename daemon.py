#!/usr/bin/env python
"""
PeerWatch daemon — periodically scans the configured subnet and runs the full
detection pipeline on each tick.

Injection demo: drop a crafted nmap XML into data/raw/ between scheduled scans
and the daemon will pick it up on the next tick via the ingested_scan_files
tracking already built into PeerStore.

Usage:
    python daemon.py
    python daemon.py --config /path/to/config.json
"""

import argparse
import glob
import ipaddress
import json
import logging
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

import xmltodict

from peerwatch import NmapParser
from peerwatch.agent import InvestigationReport, SuspiciousAgent
from peerwatch.comparator import Comparator
from peerwatch.config import load_config
from peerwatch.fleet_correlator import FleetCorrelator, FleetEvent
from peerwatch.peer_store import PeerStore
from peerwatch.remediation import Remediator

PEER_STORE_PATH = Path("data/peer_store.json")
RAW_DIR = Path("data/raw")
PROCESSED_DIR = Path("data/processed")
ALERTS_PATH = Path("alerts/alerts.jsonl")
FLEET_ALERTS_PATH = Path("alerts/fleet_alerts.jsonl")
BLOCKS_PATH = Path("blocks/blocks.jsonl")

_STRIP_FIELDS = {
    "@starttime", "@endtime", "distance", "tcpsequence",
    "ipidsequence", "tcptssequence", "times", "hostnames",
}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging() -> None:
    Path("logs").mkdir(exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("logs/daemon.log"),
            logging.StreamHandler(sys.stdout),
        ],
    )


# ---------------------------------------------------------------------------
# nmap helpers
# ---------------------------------------------------------------------------

def run_nmap(subnet: str, output_dir: Path) -> Path | None:
    """Run nmap against subnet, write XML to output_dir. Returns path or None."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = output_dir / f"scan_{timestamp}.xml"
    try:
        logging.info(f"Scanning {subnet} ...")
        proc = subprocess.run(
            ["nmap", "-sV", "-O", "--osscan-guess", "-oX", str(output_path), subnet],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if proc.returncode != 0:
            logging.error(f"nmap exited {proc.returncode}: {proc.stderr.strip()}")
            return None
        logging.info(f"Scan complete → {output_path.name}")
        return output_path
    except subprocess.TimeoutExpired:
        logging.error("nmap timed out after 300s")
        return None
    except FileNotFoundError:
        logging.error("nmap not found in PATH")
        return None
    except Exception as exc:
        logging.error(f"nmap error: {exc}")
        return None


def jsonify_xml(xml_path: Path, output_dir: Path) -> Path | None:
    """Convert a single nmap XML file to JSON. Returns output path or None."""
    try:
        raw = xmltodict.parse(xml_path.read_text())
        hosts = raw["nmaprun"]["host"]
        if isinstance(hosts, dict):
            hosts = [hosts]
        for host in hosts:
            for field in _STRIP_FIELDS:
                host.pop(field, None)
        out_path = output_dir / (xml_path.stem + ".json")
        out_path.write_text(json.dumps(hosts, indent=2))
        return out_path
    except KeyError:
        logging.warning(f"{xml_path.name}: no hosts in scan output")
        return None
    except Exception as exc:
        logging.error(f"jsonify failed for {xml_path.name}: {exc}")
        return None


def convert_pending_xml(output_dir: Path) -> None:
    """Convert any XML files in data/raw/ that don't yet have a JSON counterpart.

    This is the injection demo path — files dropped externally are picked up here.
    """
    for xml_path in RAW_DIR.glob("*.xml"):
        json_equiv = output_dir / (xml_path.stem + ".json")
        if not json_equiv.exists():
            logging.info(f"New XML detected: {xml_path.name}")
            jsonify_xml(xml_path, output_dir)


# ---------------------------------------------------------------------------
# Alert output
# ---------------------------------------------------------------------------

def write_alert(
    report: InvestigationReport,
    peer_store: PeerStore,
    alerts_path: Path,
) -> None:
    """Append a one-line JSON alert record to alerts/alerts.jsonl."""
    alerts_path.parent.mkdir(parents=True, exist_ok=True)

    peer = peer_store.peers.get(report.peer_id)
    recent_events = (
        [e.event for e in peer.identity_history[-10:]] if peer else []
    )

    record = {
        "ts": report.timestamp.isoformat(),
        "peer_id": report.peer_id,
        "ip": (report.ips or [None])[0],
        "mac": report.mac_address,
        "suspicion_score": report.suspicion_score,
        "severity": report.severity,
        "recent_events": recent_events,
        "explanation": report.explanation,
        "recommended_actions": report.recommended_actions,
    }

    with open(alerts_path, "a") as f:
        f.write(json.dumps(record) + "\n")

    logging.info(
        f"ALERT [{report.severity.upper()}] "
        f"{report.mac_address or report.peer_id[:8]} "
        f"score={report.suspicion_score:.1f}"
    )


# ---------------------------------------------------------------------------
# Fleet alert output
# ---------------------------------------------------------------------------

def write_fleet_alert(fleet_event: FleetEvent, fleet_alerts_path: Path) -> None:
    """Append a one-line JSON fleet alert record to alerts/fleet_alerts.jsonl."""
    fleet_alerts_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": fleet_event.window_end.isoformat(),
        "pattern": fleet_event.pattern,
        "peer_ids": fleet_event.peer_ids,
        "ips": fleet_event.ips,
        "event_count": fleet_event.event_count,
        "window_start": fleet_event.window_start.isoformat(),
        "window_end": fleet_event.window_end.isoformat(),
        "suspicion_boost": fleet_event.suspicion_boost,
        "description": fleet_event.description,
    }
    with open(fleet_alerts_path, "a") as f:
        f.write(json.dumps(record) + "\n")
    logging.warning(
        f"FLEET [{fleet_event.pattern.upper()}] "
        f"{len(fleet_event.peer_ids)} peers — {fleet_event.description}"
    )


# ---------------------------------------------------------------------------
# Detection pipeline (one tick)
# ---------------------------------------------------------------------------

def run_pipeline(
    peer_store: PeerStore,
    cfg,
    alerts_path: Path,
    remediator: Remediator,
) -> int:
    """Ingest new scan files, run comparator + fleet + agent + remediation. Returns alert count."""
    all_files = glob.glob(str(PROCESSED_DIR / "*.json"))
    new_files = [
        f for f in all_files
        if Path(f).name not in peer_store.ingested_scan_files
    ]

    if new_files:
        logging.info(f"Ingesting {len(new_files)} new scan file(s)")
        for file in new_files:
            with open(file) as f:
                data = json.load(f)
            for host in data:
                peer_store.add_or_update_peer(NmapParser(host).parse())
            peer_store.ingested_scan_files.add(Path(file).name)
    else:
        logging.info("No new scan files this tick")

    Comparator(peer_store).print_report()

    # Fleet correlation — must run after all peers are ingested, before agent.
    fleet_events = FleetCorrelator(peer_store, cfg).analyse()
    for fe in fleet_events:
        write_fleet_alert(fe, FLEET_ALERTS_PATH)

    evicted = peer_store.evict_stale_volatile_peers()
    if evicted:
        logging.info(f"Evicted {len(evicted)} stale volatile peer(s)")

    # Stamp tick time before saving so it persists across restarts.
    peer_store.last_tick_at = datetime.now(timezone.utc)
    peer_store.save(PEER_STORE_PATH)

    agent = SuspiciousAgent(
        peer_store=peer_store,
        output_dir="./reports",
        model=cfg.model,
        threshold=cfg.suspicion_threshold,
    )
    reports = agent.investigate_all(fleet_events=fleet_events)

    for report in reports:
        write_alert(report, peer_store, alerts_path)
        action = remediator.evaluate(report, peer_store)
        if action:
            remediator.act(action)

    remediator.unblock_expired()

    return len(reports)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def _is_private(subnet: str) -> bool:
    try:
        return ipaddress.ip_network(subnet, strict=False).is_private
    except ValueError:
        return False


def _sleep_interruptible(seconds: int, shutdown_flag: list[bool]) -> None:
    """Sleep for `seconds`, waking every second to check for shutdown."""
    for _ in range(seconds):
        if shutdown_flag[0]:
            return
        time.sleep(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="PeerWatch daemon")
    parser.add_argument("--config", default="config.json", metavar="PATH")
    args = parser.parse_args()

    setup_logging()
    cfg = load_config(args.config)

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    if not _is_private(cfg.subnet):
        logging.warning(
            f"Subnet {cfg.subnet!r} is not RFC 1918 — scanning public addresses "
            "may be disruptive or illegal. Press Ctrl-C within 5s to abort."
        )
        _sleep_interruptible(5, [False])

    logging.info("=" * 60)
    logging.info("PeerWatch daemon starting")
    logging.info(f"  subnet      : {cfg.subnet}")
    logging.info(f"  interval    : {cfg.scan_interval_minutes}m")
    logging.info(f"  min gap     : {cfg.min_scan_interval_minutes}m")
    logging.info(f"  threshold   : {cfg.suspicion_threshold}")
    logging.info(f"  model       : {cfg.model}")
    logging.info(f"  remediation : {cfg.remediation_mode} "
                 f"(floor={cfg.block_confidence_floor}, ttl={cfg.block_ttl_hours}h)")
    if cfg.never_block:
        logging.info(f"  never_block : {', '.join(cfg.never_block)}")
    logging.info("=" * 60)

    peer_store = PeerStore.load(PEER_STORE_PATH, config=cfg)
    remediator = Remediator(cfg, BLOCKS_PATH)

    interval_s = cfg.scan_interval_minutes * 60
    min_interval_s = cfg.min_scan_interval_minutes * 60
    last_scan_at: float = 0.0

    shutdown: list[bool] = [False]

    def handle_signal(sig, frame):
        logging.info("Shutdown requested — finishing current work ...")
        shutdown[0] = True

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    while not shutdown[0]:
        now = time.time()

        # Rate-limit guard
        elapsed = now - last_scan_at
        if last_scan_at > 0 and elapsed < min_interval_s:
            remaining = int(min_interval_s - elapsed)
            logging.warning(
                f"Rate limit: last scan was {int(elapsed)}s ago "
                f"(min gap {min_interval_s}s) — waiting {remaining}s"
            )
            _sleep_interruptible(remaining, shutdown)
            continue

        # --- Scan ---
        xml_path = run_nmap(cfg.subnet, RAW_DIR)
        last_scan_at = time.time()

        # Convert the new scan (and any injected XMLs)
        if xml_path:
            jsonify_xml(xml_path, PROCESSED_DIR)
        convert_pending_xml(PROCESSED_DIR)

        # --- Detect + Remediate ---
        alert_count = run_pipeline(peer_store, cfg, ALERTS_PATH, remediator)
        logging.info(
            f"Tick complete — {alert_count} alert(s). "
            f"Next scan in {cfg.scan_interval_minutes}m"
        )

        _sleep_interruptible(interval_s, shutdown)

    peer_store.save(PEER_STORE_PATH)
    logging.info("PeerWatch daemon stopped.")


if __name__ == "__main__":
    main()
