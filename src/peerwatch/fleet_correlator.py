"""
PeerWatch fleet-level anomaly correlator.

Detects coordinated attacks that span multiple peers within a single scan tick.
Operates on the full PeerStore after per-peer ingestion is complete.

Algorithm:
  1. Collect identity events recorded since last_tick_at on the PeerStore.
  2. Match events against named patterns (see _PATTERNS).
  3. Emit one FleetEvent per matched pattern.
  4. Apply suspicion boosts to every matching peer.

Called once per daemon tick, before SuspiciousAgent.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from pydantic import BaseModel

if TYPE_CHECKING:
    from peerwatch.config import PeerWatchConfig
    from peerwatch.peer_store import PeerStore

# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------
# Each entry: (pattern_name, frozenset of matching event types, config_attr, score_boost)
# A peer "matches" a pattern if it fired at least one event in the event_types set.
# The pattern fires if the number of matching peers >= config_attr value.

_PATTERNS: list[tuple[str, frozenset[str], str, float]] = [
    (
        "arp_poisoning",
        frozenset({"arp_spoofing_detected"}),
        "fleet_arp_min_peers",
        2.0,
    ),
    (
        "route_shift",
        frozenset({"route_changed"}),
        "fleet_route_min_peers",
        1.5,
    ),
    (
        "os_normalisation",
        frozenset({"os_family_changed"}),
        "fleet_os_min_peers",
        1.5,
    ),
    (
        "identity_sweep",
        frozenset({"identity_conflict_detected", "full_identity_shift"}),
        "fleet_identity_min_peers",
        2.0,
    ),
    (
        "service_sweep",
        frozenset({"service_type_changed"}),
        "fleet_service_min_peers",
        1.0,
    ),
    (
        "ttl_shift",
        frozenset({"ttl_deviation"}),
        "fleet_ttl_min_peers",
        1.5,
    ),
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class FleetEvent(BaseModel):
    pattern: str
    peer_ids: list[str]
    ips: list[str]
    event_count: int
    window_start: datetime
    window_end: datetime
    suspicion_boost: float
    description: str


# ---------------------------------------------------------------------------
# Correlator
# ---------------------------------------------------------------------------

class FleetCorrelator:
    """
    Detects coordinated anomalies across multiple peers in one tick window.

    Usage::

        correlator = FleetCorrelator(peer_store, config)
        fleet_events = correlator.analyse()
        # Score boosts are applied to peer_store as a side effect.
    """

    def __init__(self, peer_store: "PeerStore", config: "PeerWatchConfig") -> None:
        self._store = peer_store
        self._cfg = config

    def analyse(self) -> list[FleetEvent]:
        """
        Run pattern matching over events recorded since last_tick_at.

        Returns a list of FleetEvents. As a side effect, applies suspicion boosts
        to matched peers and records a ``fleet_correlation_boost`` identity event.
        """
        window_start = self._store.last_tick_at
        window_end = datetime.now(timezone.utc)

        if window_start is None:
            # First tick — no baseline window to compare against.
            return []

        # Collect events per peer that fall inside the tick window.
        recent: dict[str, list[str]] = {}
        for peer_id, peer in self._store.peers.items():
            events_in_window = [
                e.event for e in peer.identity_history
                if e.timestamp >= window_start
            ]
            if events_in_window:
                recent[peer_id] = events_in_window

        if not recent:
            return []

        fleet_events: list[FleetEvent] = []
        # Track total boost applied per peer this tick to enforce the cap.
        boost_applied: dict[str, float] = {}

        for pattern_name, event_types, min_peers_attr, boost in _PATTERNS:
            min_peers: int = getattr(self._cfg, min_peers_attr, 2)

            matching_peer_ids = [
                pid for pid, events in recent.items()
                if any(e in event_types for e in events)
            ]

            if len(matching_peer_ids) < min_peers:
                continue

            event_count = sum(
                sum(1 for e in recent[pid] if e in event_types)
                for pid in matching_peer_ids
            )

            ips: list[str] = []
            for pid in matching_peer_ids:
                peer = self._store.peers.get(pid)
                if peer:
                    ips.extend(sorted(peer.ips))

            description = (
                f"{len(matching_peer_ids)} peers fired "
                f"{' or '.join(sorted(event_types))} "
                f"within one scan window ({event_count} total events)"
            )

            fleet_event = FleetEvent(
                pattern=pattern_name,
                peer_ids=list(matching_peer_ids),
                ips=ips,
                event_count=event_count,
                window_start=window_start,
                window_end=window_end,
                suspicion_boost=boost,
                description=description,
            )
            fleet_events.append(fleet_event)

            # Apply boosts (capped per peer per tick)
            cap = getattr(self._cfg, "fleet_boost_cap", 4.0)
            for pid in matching_peer_ids:
                already = boost_applied.get(pid, 0.0)
                headroom = max(0.0, cap - already)
                actual_boost = min(boost, headroom)
                if actual_boost > 0:
                    self._store.add_suspicion(
                        pid, actual_boost, reason=f"fleet:{pattern_name}"
                    )
                    boost_applied[pid] = already + actual_boost

            ip_preview = ", ".join(ips[:4]) + ("..." if len(ips) > 4 else "")
            logging.warning(
                "Fleet pattern '%s': %d peers matched (%s) — boost +%.1f each",
                pattern_name,
                len(matching_peer_ids),
                ip_preview,
                boost,
            )

        return fleet_events
