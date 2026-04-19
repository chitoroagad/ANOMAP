"""
PeerWatch runtime configuration.

Load from JSON with load_config(); falls back to defaults if no file provided.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class PeerWatchConfig(BaseModel):
    # --- Phase 1 suspicion weights (nmap active scan) ---
    port_jaccard_threshold: float = Field(
        default=0.6,
        description="Minimum Jaccard similarity between port sets before flagging drift",
    )
    service_change_suspicion: float = Field(
        default=1.0,
        description="Score added when a service type changes on a known port",
    )
    port_protocol_mismatch_suspicion: float = Field(
        default=3.0,
        description="Score added when a well-known port runs the wrong protocol",
    )

    # --- Phase 2 suspicion weights (passive capture) ---
    ttl_baseline_min_samples: int = Field(
        default=5,
        description="TTL observations required before locking in expected_ttl",
    )
    ttl_deviation_threshold: int = Field(
        default=15,
        description="Absolute TTL deviation that triggers suspicion",
    )
    ttl_deviation_suspicion: float = Field(
        default=2.0,
        description="Score added for a confirmed TTL anomaly",
    )
    arp_spoof_suspicion: float = Field(
        default=3.0,
        description="Score added when ARP reply claims wrong MAC for a known peer",
    )
    tcp_fingerprint_mismatch_suspicion: float = Field(
        default=2.0,
        description="Score added when passive TCP OS contradicts nmap OS",
    )
    ip_id_min_samples: int = Field(
        default=8,
        description="IP ID samples required before enabling anomaly detection",
    )
    ip_id_jump_threshold: int = Field(
        default=5000,
        description="IP ID counter jump size that triggers suspicion",
    )
    ip_id_anomaly_suspicion: float = Field(
        default=1.0,
        description="Score added for a confirmed IP ID jump anomaly",
    )
    route_hop_change_suspicion: float = Field(
        default=1.0,
        description="Score added when route hop sequence changes",
    )
    route_asn_change_suspicion: float = Field(
        default=1.5,
        description="Score added when a new ASN appears in traceroute path",
    )

    # --- Scoring / lifecycle ---
    suspicion_half_life_days: float = Field(
        default=3.5,
        description="Suspicion score halves every this many days of clean activity",
    )
    baseline_min_scans: int = Field(
        default=5,
        description="Scans required before anomaly scoring begins (warmup period)",
    )
    volatile_peer_ttl_hours: int = Field(
        default=24,
        description="Hours before a MAC-less peer is evicted for inactivity",
    )

    # --- Phase 3: MAC vendor/OS cross-reference ---
    mac_vendor_mismatch_suspicion: float = Field(
        default=2.0,
        description="Score added when MAC OUI vendor contradicts nmap OS family (e.g. Apple MAC + Linux)",
    )

    # --- Phase 3: cryptographic identity checks ---
    ssh_host_key_change_suspicion: float = Field(
        default=3.0,
        description="Score added when SSH host key fingerprint changes (near-certain device swap)",
    )
    ssl_cert_change_suspicion: float = Field(
        default=2.0,
        description="Score added when SSL/TLS certificate fingerprint changes on a known port",
    )

    # --- Fleet correlation ---
    fleet_min_window_seconds: int = Field(
        default=300,
        description="Maximum age (seconds) of an event to be included in fleet correlation",
    )
    fleet_arp_min_peers: int = Field(
        default=2,
        description="Minimum peers with arp_spoofing_detected to fire arp_poisoning pattern",
    )
    fleet_route_min_peers: int = Field(
        default=3,
        description="Minimum peers with route_changed to fire route_shift pattern",
    )
    fleet_os_min_peers: int = Field(
        default=3,
        description="Minimum peers with os_family_changed to fire os_normalisation pattern",
    )
    fleet_identity_min_peers: int = Field(
        default=2,
        description="Minimum peers with identity events to fire identity_sweep pattern",
    )
    fleet_service_min_peers: int = Field(
        default=4,
        description="Minimum peers with service_type_changed to fire service_sweep pattern",
    )
    fleet_ttl_min_peers: int = Field(
        default=3,
        description="Minimum peers with ttl_deviation to fire ttl_shift pattern",
    )
    fleet_boost_cap: float = Field(
        default=4.0,
        description="Maximum total fleet suspicion boost per peer per tick",
    )

    # --- Agent ---
    suspicion_threshold: float = Field(
        default=3.0,
        description="Suspicion score that triggers LLM investigation",
    )
    model: str = Field(
        default="phi4:latest",
        description="Ollama model used by SuspiciousAgent",
    )

    # --- Daemon ---
    subnet: str = Field(
        default="192.168.1.0/24",
        description="Subnet to scan (CIDR notation)",
    )
    scan_interval_minutes: int = Field(
        default=5,
        description="How often to run a new nmap scan",
    )
    min_scan_interval_minutes: int = Field(
        default=2,
        description="Minimum gap between scans — skips a tick if too soon",
    )

    # --- Remediation ---
    remediation_mode: Literal["dry_run", "confirm", "enforce"] = Field(
        default="dry_run",
        description=(
            "dry_run: log only | confirm: prompt before executing | "
            "enforce: execute iptables rules immediately (requires root)"
        ),
    )
    block_confidence_floor: float = Field(
        default=5.0,
        description=(
            "Minimum suspicion_score required to trigger a block. "
            "Higher than the 3.0 investigation threshold to reduce false positives."
        ),
    )
    block_ttl_hours: int = Field(
        default=24,
        description="Hours before an active block is automatically removed",
    )
    never_block: list[str] = Field(
        default_factory=list,
        description=(
            "IPs or MAC addresses that will never be blocked. "
            "Add your gateway, DNS server, etc. here."
        ),
    )


def load_config(path: str | Path | None = None) -> PeerWatchConfig:
    """Load config from JSON file; return defaults if path is None or missing."""
    if path is None:
        return PeerWatchConfig()
    p = Path(path)
    if not p.exists():
        return PeerWatchConfig()
    with p.open() as f:
        data = json.load(f)
    return PeerWatchConfig(**data)
