"""
PeerWatch runtime configuration.

Load from JSON with load_config(); falls back to defaults if no file provided.
"""

from __future__ import annotations

import json
from pathlib import Path

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

    # --- Agent ---
    suspicion_threshold: float = Field(
        default=3.0,
        description="Suspicion score that triggers LLM investigation",
    )
    model: str = Field(
        default="phi4-mini:latest",
        description="Ollama model used by SuspiciousAgent",
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
