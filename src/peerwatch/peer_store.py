import json
import logging
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from peerwatch.config import PeerWatchConfig
from peerwatch.parser import NormalisedData
from peerwatch.util import _extract_ips, _jaccard_similarity, _normalise_mac

UNKNOWN_KEY = "unknown"

# --- Port -> expected service-type (first segment of nmap service string) ---
# Conservative list of ports where a protocol mismatch is a strong backdoor signal.
# Uses nmap's service-name conventions (split on "-", take first token).
# MAC OUI vendor keywords → OS families that are compatible with that vendor.
# Only vendors with a strongly constrained OS family are listed — generic NIC
# vendors (Intel, Realtek, ASUSTek, etc.) are intentionally omitted to avoid
# false positives on commodity PCs that can run any OS.
# Keys are lowercase substrings; matching uses `key in vendor.lower()`.
VENDOR_OS_COMPATIBILITY: dict[str, set[str]] = {
    "apple": {"Apple", "macOS", "iOS"},
    "raspberry pi": {"Linux"},
    "microsoft": {"Microsoft", "Windows"},
    "xbox": {"Microsoft", "Windows"},
    "sony": {"Sony", "Android", "Linux", "Google"},
    "amazon": {"Amazon", "Linux", "Android", "Google"},
}

WELL_KNOWN_PORT_PROTOCOLS: dict[int, set[str]] = {
    21: {"ftp"},
    22: {"ssh"},
    53: {"domain"},
    80: {"http"},
    443: {"https", "http", "ssl"},  # nmap may report "http" when TLS is transparent
    3306: {"mysql"},
    5432: {"postgresql"},
    6379: {"redis"},
    27017: {"mongod"},
}


def _os_candidate_families(data: "NormalisedData") -> set[str]:  # noqa: F821
    """Return the set of OS family names from all nmap candidates.
    Falls back to the single os field when no candidates were parsed."""
    if data.os_candidates:
        return set(data.os_candidates.keys())
    if data.os != UNKNOWN_KEY:
        return {data.os}
    return set()


class IdentityEvent(BaseModel):
    timestamp: datetime
    event: str
    details: dict


class Peer(BaseModel):
    """
    Canonical representation of a network peer/device.
    """

    internal_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    mac_address: str | None = None
    ips: set[str] = Field(default_factory=set)

    is_volatile: bool = True  # False if MAC is confirmed
    suspicion_score: float = 0.0  # increases with conflicting observations

    scan_count: int = 0
    last_seen_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    metadata: NormalisedData
    # All service types ever seen per port — used to suppress oscillation false positives.
    # e.g. {8009: {"ajp13", "castv2"}} means both have been observed and neither is novel.
    known_services: dict[int, set[str]] = Field(default_factory=dict)
    # Ports where a protocol mismatch has already been recorded — prevents repeated flagging.
    flagged_port_mismatches: set[int] = Field(default_factory=set)
    # Set to True once a MAC OUI vendor / OS family mismatch has been recorded.
    flagged_vendor_mismatch: bool = False
    metadata_history: list[NormalisedData] = Field(default_factory=list)
    identity_history: list[IdentityEvent] = Field(default_factory=list)

    # TTL tracking: expected_ttl is None until TTL_BASELINE_MIN_SAMPLES observations
    # have been collected and snapped to the nearest OS-default origin (64/128/255).
    expected_ttl: int | None = None
    ttl_samples: list[int] = Field(default_factory=list)

    # IP ID tracking: recent sample window.  Once IP_ID_MIN_SAMPLES are collected
    # and a sequential pattern is detected, large jumps are flagged.
    ip_id_samples: list[int] = Field(default_factory=list)
    ip_id_sequential: bool = False  # True once samples show sequential behaviour

    # TCP passive fingerprint: the OS family implied by the most recent SYN packet.
    # Updated on each new TCPFingerprintObservation; compared against nmap OS.
    tcp_implied_os: str | None = None

    # Route observations: map destination IP → list of responding hop IPs in order.
    # Populated by ingest_route_change() after RouteTracker fires events.
    known_routes: dict[str, list[str]] = Field(default_factory=dict)

    # Cryptographic identity anchors (Phase 3).
    # ssh_host_keys: port → sorted list of SHA256 fingerprints (one per key type).
    # ssl_cert_fingerprints: port → hex SHA-256 cert fingerprint.
    # Both fields are populated by SuspiciousAgent during investigation and compared
    # on every subsequent scan to detect device-swap (near-certain spoofing signal).
    ssh_host_keys: dict[int, list[str]] = Field(default_factory=dict)
    ssl_cert_fingerprints: dict[int, str] = Field(default_factory=dict)

    def record_event(self, event: str, **details):
        self.identity_history.append(
            IdentityEvent(
                timestamp=datetime.now(timezone.utc),
                event=event,
                details=details,
            )
        )

    def __str__(self) -> str:
        return f"""id: {self.internal_id}, mac: {self.mac_address}, ips: {self.ips}
        is_volatile: {self.is_volatile}, suspicion_score: {self.suspicion_score}\n"""

    def __repr__(self) -> str:
        return self.__str__()


class PeerStore:
    """
    Secure peer identity store designed for network attack and spoofing detection.

    Identity resolution is conservative:
    - MAC addresses are treated as strong but *not absolute* identifiers
    - IP addresses are weak and may be shared or reassigned
    - Conflicts increase suspicion rather than being silently resolved

    The store preserves historical observations to support forensic analysis.
    """

    class FingerprintComparison(BaseModel):
        os_match: bool
        port_jaccard: float
        service_type_changes: dict[int, list[str]]  # port → [old_service, new_service]
        events: list[str]
        overall_score: float

    peers: dict[str, Peer]
    mac_to_id: dict[str, str]
    ip_to_id: dict[str, str]

    _lock: threading.Lock = threading.Lock()

    def __init__(self, config: PeerWatchConfig | None = None):
        self.peers = {}
        self.mac_to_id = {}
        self.ip_to_id = {}
        self._cfg = config if config is not None else PeerWatchConfig()
        # Basenames of scan files already ingested — used to skip re-ingest on reload.
        self.ingested_scan_files: set[str] = set()
        # Timestamp of the previous tick's end — used by FleetCorrelator as event
        # window start. None on first tick (no window to compare against).
        self.last_tick_at: datetime | None = None

    # --------------------
    # Public API
    # --------------------

    def get_peer(self, mac: str | None = None, ip: str | None = None) -> Peer | None:
        with self._lock:
            if mac and mac != UNKNOWN_KEY and mac in self.mac_to_id:
                return self.peers.get(self.mac_to_id[mac])

            if ip and ip != UNKNOWN_KEY and ip in self.ip_to_id:
                return self.peers.get(self.ip_to_id[ip])

            return None

    def add_or_update_peer(self, data: NormalisedData) -> Peer:
        """
        Checks peer for anomaly then adds/updates store
        """
        mac = _normalise_mac(data.mac_address)
        ips = _extract_ips(data)

        with self._lock:
            mac_id = self.mac_to_id.get(mac) if mac else None
            ip_ids = {self.ip_to_id[ip] for ip in ips if ip in self.ip_to_id}

            candidate_ids = set(filter(None, [mac_id])) | ip_ids

            if not candidate_ids:
                peer = self._create_peer(mac, ips, data)
                return peer

            if len(candidate_ids) == 1:
                peer = self.peers[next(iter(candidate_ids))]
                self._apply_suspicion_decay(peer)
                suspicion = self._check_incoming_fingerprint(peer, data)
                self._update_peer(peer, mac, ips, data)
                peer.suspicion_score += suspicion
                return peer

            # Multiple candidates → possible spoofing or identity collision
            peer = self._resolve_conflict(candidate_ids, mac, ips, data)
            return peer

    def reset(self):
        logging.warning("Resetting Peer Store")
        with self._lock:
            self.peers = {}
            self.mac_to_id = {}
            self.ip_to_id = {}

    def add_suspicion(self, peer_id: str, delta: float, reason: str = "") -> None:
        """Add *delta* to the suspicion score of *peer_id* and record an event.

        Used by FleetCorrelator to apply fleet-pattern boosts after per-peer
        ingestion is complete. No-ops silently if the peer_id is unknown.
        """
        peer = self.peers.get(peer_id)
        if peer is None:
            return
        with self._lock:
            peer.suspicion_score += delta
            peer.record_event("fleet_correlation_boost", delta=delta, reason=reason)

    def evict_stale_volatile_peers(self, now: datetime | None = None) -> list[str]:
        """Remove volatile (MAC-less) peers not seen within VOLATILE_PEER_TTL_HOURS.

        Returns the list of evicted internal IDs.
        """
        if now is None:
            now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(hours=self._cfg.volatile_peer_ttl_hours)).replace(
            tzinfo=timezone.utc
        )
        evicted = []
        with self._lock:
            for pid, peer in list(self.peers.items()):
                if peer.mac_address:
                    continue  # not volatile
                last = peer.last_seen_at
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                if last < cutoff:
                    for ip in peer.ips:
                        self.ip_to_id.pop(ip, None)
                    del self.peers[pid]
                    evicted.append(pid)
                    logging.info(f"Evicted stale volatile peer {pid}")
        return evicted

    # --------------------
    # Persistence
    # --------------------

    _SNAPSHOT_VERSION = 1

    def save(self, path: str | Path) -> None:
        """Serialize PeerStore state to a JSON snapshot file.

        Saves all peer data (including suspicion scores, history, cryptographic
        anchors, and passive-capture baselines) plus the set of already-ingested
        scan file basenames so that the next run skips re-ingest.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            snapshot = {
                "version": self._SNAPSHOT_VERSION,
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "last_tick_at": self.last_tick_at.isoformat() if self.last_tick_at else None,
                "ingested_scan_files": sorted(self.ingested_scan_files),
                "peers": {
                    pid: peer.model_dump(mode="json")
                    for pid, peer in self.peers.items()
                },
            }
        with open(path, "w") as f:
            json.dump(snapshot, f, indent=2, default=str)
        logging.info("PeerStore saved: %d peers → %s", len(self.peers), path)
        print(f"PeerStore saved: {len(self.peers)} peers → {path}")

    @classmethod
    def load(cls, path: str | Path, config: PeerWatchConfig | None = None) -> "PeerStore":
        """Load PeerStore from a JSON snapshot produced by :meth:`save`.

        Rebuilds the MAC→ID and IP→ID indexes from peer data.
        Returns a fresh empty store if *path* does not exist.
        """
        path = Path(path)
        store = cls(config=config)
        if not path.exists():
            logging.info("No PeerStore snapshot at %s, starting fresh", path)
            return store
        with open(path) as f:
            snapshot = json.load(f)
        version = snapshot.get("version", 0)
        if version != cls._SNAPSHOT_VERSION:
            logging.warning(
                "PeerStore snapshot version mismatch (got %d, expected %d) — starting fresh",
                version,
                cls._SNAPSHOT_VERSION,
            )
            return store
        for pid, peer_data in snapshot.get("peers", {}).items():
            try:
                peer = Peer.model_validate(peer_data)
            except Exception as e:
                logging.warning("Skipping malformed peer %s: %s", pid, e)
                continue
            store.peers[pid] = peer
            if peer.mac_address:
                store.mac_to_id[peer.mac_address] = pid
            for ip in peer.ips:
                store.ip_to_id[ip] = pid
        store.ingested_scan_files = set(snapshot.get("ingested_scan_files", []))
        raw_tick = snapshot.get("last_tick_at")
        if raw_tick:
            try:
                store.last_tick_at = datetime.fromisoformat(raw_tick)
            except ValueError:
                pass
        logging.info(
            "PeerStore loaded: %d peers, %d ingested files ← %s",
            len(store.peers),
            len(store.ingested_scan_files),
            path,
        )
        print(
            f"PeerStore loaded: {len(store.peers)} peers, "
            f"{len(store.ingested_scan_files)} previously ingested files."
        )
        return store

    def ingest_ttl_observation(self, ip: str, ttl: int) -> Peer | None:
        """Record a TTL observation for the peer at *ip*.

        Builds a baseline from the first TTL_BASELINE_MIN_SAMPLES observations
        (snapping to the nearest OS-default origin).  Once the baseline is set,
        deviations larger than TTL_DEVIATION_THRESHOLD add TTL_DEVIATION_SUSPICION
        and record a ``ttl_deviation`` event.

        Returns the peer that was updated, or None if no peer is known for *ip*.
        """
        from peerwatch.packet_capture import snap_ttl_to_os_default

        peer = self.get_peer(ip=ip)
        if peer is None:
            return None

        with self._lock:
            peer.ttl_samples.append(ttl)

            if peer.expected_ttl is None:
                if len(peer.ttl_samples) >= self._cfg.ttl_baseline_min_samples:
                    # Use the median sample to resist outliers, then snap to an OS default.
                    import statistics as _stats

                    median_ttl = _stats.median(peer.ttl_samples)
                    peer.expected_ttl = snap_ttl_to_os_default(int(median_ttl))
                    peer.record_event(
                        "ttl_baseline_established",
                        expected_ttl=peer.expected_ttl,
                        samples=len(peer.ttl_samples),
                    )
                    logging.info(
                        "TTL baseline for peer %s: expected=%d",
                        peer.internal_id,
                        peer.expected_ttl,
                    )
            else:
                deviation = abs(ttl - peer.expected_ttl)
                if deviation > self._cfg.ttl_deviation_threshold:
                    peer.record_event(
                        "ttl_deviation",
                        observed_ttl=ttl,
                        expected_ttl=peer.expected_ttl,
                        deviation=deviation,
                    )
                    peer.suspicion_score += self._cfg.ttl_deviation_suspicion
                    logging.warning(
                        "TTL anomaly for peer %s: observed=%d expected=%d (Δ%d)",
                        peer.internal_id,
                        ttl,
                        peer.expected_ttl,
                        deviation,
                    )

        return peer

    def ingest_arp_observation(self, ip: str, mac: str) -> Peer | None:
        """Record an ARP reply claiming *ip* is at *mac*.

        If a peer is known for *ip* and its confirmed MAC differs from the
        claimed *mac*, a ``arp_spoofing_detected`` event is recorded and
        ARP_SPOOF_SUSPICION is added.

        Returns the peer whose MAC was challenged, or None if *ip* is unknown.
        """
        from peerwatch import util

        normalised_mac = _normalise_mac(mac)
        if normalised_mac is None:
            return None

        peer = self.get_peer(ip=ip)
        if peer is None:
            return None

        with self._lock:
            if peer.mac_address and peer.mac_address.upper() != normalised_mac.upper():
                peer.record_event(
                    "arp_spoofing_detected",
                    ip=ip,
                    known_mac=peer.mac_address,
                    claimed_mac=normalised_mac,
                )
                peer.suspicion_score += self._cfg.arp_spoof_suspicion
                logging.warning(
                    "ARP spoofing: peer %s (IP %s) — known MAC %s, ARP claims %s",
                    peer.internal_id,
                    ip,
                    peer.mac_address,
                    normalised_mac,
                )

        return peer

    def ingest_tcp_fingerprint(
        self,
        ip: str,
        window_size: int,
        tcp_options: list[str],
        mss: int | None,
    ) -> Peer | None:
        """Record a passive TCP fingerprint observation for the peer at *ip*.

        Infers the implied OS from the fingerprint and cross-references it
        against the nmap-derived OS stored in the peer's metadata.  A
        mismatch (e.g. TCP stack says Windows but nmap says Linux) records a
        ``tcp_fingerprint_mismatch`` event and adds TCP_FINGERPRINT_MISMATCH_SUSPICION.

        The ``tcp_implied_os`` field on Peer is updated on every call.

        Returns the peer, or None if *ip* is unknown.
        """
        from peerwatch.packet_capture import infer_os_from_tcp_fingerprint

        peer = self.get_peer(ip=ip)
        if peer is None:
            return None

        implied_os = infer_os_from_tcp_fingerprint(window_size, tcp_options, mss)
        if implied_os is None:
            return peer  # insufficient confidence to compare

        with self._lock:
            peer.tcp_implied_os = implied_os

            # Compare against nmap OS (using the candidate set for robustness)
            nmap_families = set(peer.metadata.os_candidates.keys())
            if not nmap_families and peer.metadata.os != UNKNOWN_KEY:
                nmap_families = {peer.metadata.os}

            if nmap_families:
                # Check whether any nmap candidate OS family could produce the TCP fingerprint.
                # We map implied_os back to broader family names used in nmap output.
                _IMPLIED_TO_NMAP: dict[str, set[str]] = {
                    "Linux": {"Linux", "Android", "Google"},
                    "Windows": {"Microsoft", "Windows"},
                    "macOS": {"Apple", "macOS"},
                }
                compatible_families = _IMPLIED_TO_NMAP.get(implied_os, {implied_os})
                if not (nmap_families & compatible_families):
                    peer.record_event(
                        "tcp_fingerprint_mismatch",
                        implied_os=implied_os,
                        nmap_os_candidates=sorted(nmap_families),
                        window_size=window_size,
                        tcp_options=tcp_options,
                        mss=mss,
                    )
                    peer.suspicion_score += self._cfg.tcp_fingerprint_mismatch_suspicion
                    logging.warning(
                        "TCP fingerprint mismatch for peer %s: TCP implies %s, nmap sees %s",
                        peer.internal_id,
                        implied_os,
                        nmap_families,
                    )

        return peer

    def ingest_ip_id_observation(self, ip: str, ip_id: int) -> Peer | None:
        """Record an IP ID field observation for the peer at *ip*.

        Builds a sample window of IP_ID_MIN_SAMPLES.  Once the window is full:
        - Checks whether the samples form a roughly sequential pattern.
        - On subsequent observations, a jump larger than IP_ID_JUMP_THRESHOLD
          that breaks the sequential pattern records an ``ip_id_anomaly`` event
          and adds IP_ID_ANOMALY_SUSPICION.

        Returns the peer, or None if *ip* is unknown.
        """
        peer = self.get_peer(ip=ip)
        if peer is None:
            return None

        with self._lock:
            samples = peer.ip_id_samples

            if len(samples) < self._cfg.ip_id_min_samples:
                samples.append(ip_id)
                if len(samples) == self._cfg.ip_id_min_samples:
                    peer.ip_id_sequential = _detect_sequential_ip_ids(samples)
                return peer

            # Sliding window: replace oldest sample
            prev_ip_id = samples[-1]
            samples.append(ip_id)
            if len(samples) > self._cfg.ip_id_min_samples * 2:
                samples.pop(0)

            if peer.ip_id_sequential:
                # 16-bit wrap-around: IP IDs are mod-65536
                jump = (ip_id - prev_ip_id) % 65536
                if jump > self._cfg.ip_id_jump_threshold:
                    peer.record_event(
                        "ip_id_anomaly",
                        prev_ip_id=prev_ip_id,
                        observed_ip_id=ip_id,
                        jump=jump,
                    )
                    peer.suspicion_score += self._cfg.ip_id_anomaly_suspicion
                    logging.warning(
                        "IP ID anomaly for peer %s: jump of %d (prev=%d, now=%d)",
                        peer.internal_id,
                        jump,
                        prev_ip_id,
                        ip_id,
                    )

        return peer

    def ingest_route_change(
        self,
        ip: str,
        destination: str,
        new_hops: list[str],
        change_kind: str,
        details: dict | None = None,
    ) -> Peer | None:
        """Record a route change for the peer at *ip* towards *destination*.

        Called by callers who have processed RouteTracker.observe() events.
        Adds ROUTE_HOP_CHANGE_SUSPICION or ROUTE_ASN_CHANGE_SUSPICION depending
        on *change_kind* and records a ``route_changed`` event.

        Returns the peer, or None if *ip* is unknown.
        """
        from peerwatch.route_tracker import RouteChangeKind

        peer = self.get_peer(ip=ip)
        if peer is None:
            return None

        score = 0.0
        if change_kind == RouteChangeKind.HOP_SEQUENCE_CHANGED:
            score = self._cfg.route_hop_change_suspicion
        elif change_kind == RouteChangeKind.NEW_ASN_IN_PATH:
            score = self._cfg.route_asn_change_suspicion
        elif change_kind in (
            RouteChangeKind.HOP_COUNT_CHANGED,
            RouteChangeKind.ASYMMETRIC_PATH,
        ):
            score = self._cfg.route_hop_change_suspicion

        with self._lock:
            peer.known_routes[destination] = new_hops
            event_details: dict = {
                "destination": destination,
                "change_kind": str(change_kind),
                "new_hops": new_hops,
            }
            if details:
                event_details.update(details)
            peer.record_event("route_changed", **event_details)
            peer.suspicion_score += score
            logging.warning(
                "Route change for peer %s to %s: %s",
                peer.internal_id,
                destination,
                change_kind,
            )

        return peer

    def ingest_ssh_hostkeys(
        self, ip: str, port: int, fingerprints: list[str]
    ) -> Peer | None:
        """Record SSH host key fingerprints for the peer at *ip* on *port*.

        On first observation the keys are stored as the trusted baseline.
        On subsequent calls, if the key set differs (any key added, removed, or
        replaced) a ``ssh_host_key_changed`` event is recorded and
        ``ssh_host_key_change_suspicion`` is added to the score.

        Returns the peer, or None if *ip* is unknown.
        """
        peer = self.get_peer(ip=ip)
        if peer is None:
            return None

        sorted_fps = sorted(fingerprints)
        with self._lock:
            if port in peer.ssh_host_keys:
                if peer.ssh_host_keys[port] != sorted_fps:
                    peer.record_event(
                        "ssh_host_key_changed",
                        port=port,
                        old_keys=peer.ssh_host_keys[port],
                        new_keys=sorted_fps,
                    )
                    peer.suspicion_score += self._cfg.ssh_host_key_change_suspicion
                    logging.warning(
                        "SSH host key changed for peer %s on port %d",
                        peer.internal_id,
                        port,
                    )
            peer.ssh_host_keys[port] = sorted_fps

        return peer

    def ingest_ssl_cert(
        self, ip: str, port: int, fingerprint: str
    ) -> Peer | None:
        """Record an SSL/TLS certificate SHA-256 fingerprint for *ip* on *port*.

        On first observation the fingerprint is stored as the trusted baseline.
        On subsequent calls, if the fingerprint differs a ``ssl_cert_changed``
        event is recorded and ``ssl_cert_change_suspicion`` is added to the score.

        Returns the peer, or None if *ip* is unknown.
        """
        peer = self.get_peer(ip=ip)
        if peer is None:
            return None

        with self._lock:
            if port in peer.ssl_cert_fingerprints:
                if peer.ssl_cert_fingerprints[port] != fingerprint:
                    peer.record_event(
                        "ssl_cert_changed",
                        port=port,
                        old_fingerprint=peer.ssl_cert_fingerprints[port],
                        new_fingerprint=fingerprint,
                    )
                    peer.suspicion_score += self._cfg.ssl_cert_change_suspicion
                    logging.warning(
                        "SSL cert changed for peer %s on port %d",
                        peer.internal_id,
                        port,
                    )
            peer.ssl_cert_fingerprints[port] = fingerprint

        return peer

    # --------------------
    # Internal helpers
    # --------------------

    def _check_incoming_fingerprint(
        self, prev: Peer, incoming_data: NormalisedData
    ) -> float:
        # During the warmup period we record events but do not score them so that
        # noisy early scans don't permanently taint the suspicion score.
        in_warmup = prev.scan_count < self._cfg.baseline_min_scans

        comparison = self._compare_fingerprints(prev.metadata, incoming_data)
        suspicion = 0.0

        for event in comparison.events:
            if event == "service_type_changed":
                continue  # recorded per-port below
            prev.record_event(event, port_jaccard=comparison.port_jaccard)

        for port, (old_svc, new_svc) in comparison.service_type_changes.items():
            new_type = new_svc.split("-")[0] if new_svc else ""
            if new_type in prev.known_services.get(port, set()):
                # This service type has been seen before on this port — oscillation, not a
                # real change. Silently re-add the old type so it stays in the known set.
                old_type = old_svc.split("-")[0] if old_svc else ""
                if old_type:
                    prev.known_services.setdefault(port, set()).add(old_type)
                continue

            prev.record_event(
                "service_type_changed",
                port=port,
                old_service=old_svc,
                new_service=new_svc,
            )
            if not in_warmup:
                suspicion += self._cfg.service_change_suspicion
            if new_type:
                prev.known_services.setdefault(port, set()).add(new_type)

        if not in_warmup:
            if "full_identity_shift" in comparison.events:
                suspicion += 2.0
            if "os_family_changed" in comparison.events:
                suspicion += 2.0
            if "port_profile_changed" in comparison.events:
                suspicion += 0.5

            # MAC OUI vendor vs observed OS — fires once, strong spoofing signal.
            suspicion += self._check_mac_vendor_os_mismatch(prev, incoming_data)

            # Port–protocol mismatch: well-known port running the wrong service type.
            # Strong backdoor signal — only score after baseline is established.
            for port, expected, actual in self._check_port_protocol_mismatches(
                incoming_data
            ):
                if port in prev.flagged_port_mismatches:
                    continue  # already flagged; don't accumulate on every scan
                prev.record_event(
                    "port_protocol_mismatch",
                    port=port,
                    expected=sorted(expected),
                    actual=actual,
                )
                suspicion += self._cfg.port_protocol_mismatch_suspicion
                prev.flagged_port_mismatches.add(port)

        return suspicion

    def _create_peer(
        self,
        mac: str | None,
        ips: set[str],
        data: NormalisedData,
    ) -> Peer:
        known_services: dict[int, set[str]] = {}
        for port, svc in data.services.items():
            svc_type = svc.split("-")[0] if svc else ""
            if svc_type:
                known_services[port] = {svc_type}

        now = datetime.now(timezone.utc)
        peer = Peer.model_construct(
            internal_id=str(uuid.uuid4()),
            mac_address=mac,
            ips=set(ips),
            is_volatile=mac is None,
            suspicion_score=0.0,
            scan_count=1,
            last_seen_at=now,
            metadata=data,
            known_services=known_services,
            flagged_port_mismatches=set(),
            flagged_vendor_mismatch=False,
            metadata_history=[],
            identity_history=[],
            expected_ttl=None,
            ttl_samples=[],
            ip_id_samples=[],
            ip_id_sequential=False,
            tcp_implied_os=None,
            known_routes={},
        )

        peer.record_event("peer_created", mac=mac, ips=list(ips))
        self.peers[peer.internal_id] = peer

        if mac:
            self.mac_to_id[mac] = peer.internal_id
        for ip in ips:
            self.ip_to_id[ip] = peer.internal_id

        return peer

    def _update_peer(
        self,
        peer: Peer,
        mac: str | None,
        ips: set[str],
        data: NormalisedData,
    ):
        peer.metadata_history.append(peer.metadata)
        peer.metadata = data
        peer.scan_count += 1
        peer.last_seen_at = datetime.now(timezone.utc)

        if mac and peer.mac_address and mac != peer.mac_address:
            peer.suspicion_score += 0.5
            peer.record_event("mac_conflict", old_mac=peer.mac_address, new_mac=mac)
            logging.warning(f"MAC conflict for peer {peer.internal_id}")

        if mac and not peer.mac_address:
            peer.mac_address = mac
            peer.is_volatile = False
            self.mac_to_id[mac] = peer.internal_id
            peer.record_event("mac_promoted", mac=mac)

        for ip in ips:
            if ip not in peer.ips:
                peer.ips.add(ip)
                peer.record_event("ip_added", ip=ip)
            self.ip_to_id[ip] = peer.internal_id

    def _resolve_conflict(
        self,
        candidate_ids: set[str],
        mac: str | None,
        ips: set[str],
        data: NormalisedData,
    ) -> Peer:
        # Choose highest confidence peer as survivor
        peers = [self.peers[i] for i in candidate_ids]
        survivor = max(peers, key=lambda p: p.is_volatile)
        print(f"conflicting peers: {peers}")
        print("Check this as it might be broken")

        survivor.suspicion_score += 1
        survivor.record_event(
            "identity_conflict_detected", conflicting_peers=list(candidate_ids)
        )
        logging.warning(f"Identity conflict detected; survivor={survivor.internal_id}")

        for peer in peers:
            if peer.internal_id == survivor.internal_id:
                continue
            self._merge_peers(survivor, peer)

        print(f"Resolving conflict between {peers}")
        self._update_peer(survivor, mac, ips, data)
        return survivor

    def _merge_peers(self, survivor: Peer, ghost: Peer):
        survivor.metadata_history.append(ghost.metadata)
        survivor.metadata_history.extend(ghost.metadata_history)

        survivor.identity_history.extend(ghost.identity_history)
        survivor.suspicion_score += ghost.suspicion_score

        for ip in ghost.ips:
            survivor.ips.add(ip)
            self.ip_to_id[ip] = survivor.internal_id

        if ghost.mac_address and not survivor.mac_address:
            survivor.mac_address = ghost.mac_address
            self.mac_to_id[survivor.mac_address] = survivor.internal_id

        for port, types in ghost.known_services.items():
            survivor.known_services.setdefault(port, set()).update(types)

        survivor.record_event("peer_merged", ghost_id=ghost.internal_id)

        del self.peers[ghost.internal_id]

    def _apply_suspicion_decay(self, peer: Peer) -> None:
        """Exponential decay based on time since last scan.

        Suspicion halves every suspicion_half_life_days days of clean activity,
        so legitimate one-off anomalies (e.g. an OS upgrade) don't keep a device
        permanently flagged.
        """
        if peer.suspicion_score <= 0:
            return
        now = datetime.now(timezone.utc)
        last = peer.last_seen_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        elapsed_days = (now - last).total_seconds() / 86400
        if elapsed_days > 0:
            peer.suspicion_score *= 0.5 ** (
                elapsed_days / self._cfg.suspicion_half_life_days
            )

    def _check_port_protocol_mismatches(
        self,
        data: NormalisedData,
    ) -> list[tuple[int, set[str], str]]:
        """Return (port, expected_protocols, actual_service) for well-known ports
        whose detected service type doesn't match the expected protocol.

        Skips ports where nmap couldn't identify the service (empty or 'tcpwrapped').
        """
        mismatches = []
        for port, service in data.services.items():
            expected = WELL_KNOWN_PORT_PROTOCOLS.get(port)
            if not expected:
                continue
            svc_type = service.split("-")[0].lower() if service else ""
            if not svc_type or svc_type == "tcpwrapped":
                continue
            if svc_type not in expected:
                mismatches.append((port, expected, service))
        return mismatches

    def _check_mac_vendor_os_mismatch(
        self, peer: Peer, data: NormalisedData
    ) -> float:
        """Cross-reference MAC OUI vendor against observed OS family.

        Fires at most once per peer (guarded by flagged_vendor_mismatch).
        Only checks vendors in VENDOR_OS_COMPATIBILITY — generic NIC vendors
        are skipped to avoid false positives.

        Returns the suspicion increment (0.0 if no mismatch or already flagged).
        """
        if peer.flagged_vendor_mismatch:
            return 0.0

        vendor = (data.device_vendor or "").strip().lower()
        if not vendor or vendor == "unknown":
            return 0.0

        # Substring match against known-constrained vendor keywords
        compatible_os: set[str] | None = None
        for keyword, families in VENDOR_OS_COMPATIBILITY.items():
            if keyword in vendor:
                compatible_os = families
                break

        if compatible_os is None:
            return 0.0  # vendor not constrained enough to draw conclusions

        scan_families = _os_candidate_families(data)
        if not scan_families:
            return 0.0  # insufficient OS info from nmap

        if scan_families & compatible_os:
            return 0.0  # at least one compatible family matches

        # Genuine mismatch
        peer.flagged_vendor_mismatch = True
        peer.record_event(
            "mac_vendor_os_mismatch",
            vendor=data.device_vendor,
            expected_os_families=sorted(compatible_os),
            observed_os_families=sorted(scan_families),
        )
        logging.warning(
            "MAC vendor/OS mismatch for peer %s: vendor=%r implies %s, nmap sees %s",
            peer.internal_id,
            data.device_vendor,
            compatible_os,
            scan_families,
        )
        return self._cfg.mac_vendor_mismatch_suspicion

    def _compare_fingerprints(
        self, prev: NormalisedData, incoming: NormalisedData
    ) -> "PeerStore.FingerprintComparison":
        events = []

        # 1. OS family — compare candidate sets rather than single top pick.
        # nmap's top-ranked OS can vary between scans on the same device (e.g. a TV that
        # scores Sony/Pioneer/Bush all at 95% may flip each scan). Using the full set of
        # candidate families means any overlap between scans counts as a match, so only a
        # genuinely new OS family (e.g. Linux → Windows) raises the alarm.
        prev_families = _os_candidate_families(prev)
        curr_families = _os_candidate_families(incoming)
        if not prev_families or not curr_families:
            os_match = True  # insufficient data to compare
        else:
            os_match = bool(prev_families & curr_families)
        if not os_match:
            events.append("os_family_changed")

        # 2. Port set — Jaccard similarity
        prev_ports = set(prev.open_ports)
        curr_ports = set(incoming.open_ports)
        port_jaccard = _jaccard_similarity(prev_ports, curr_ports)
        if (
            prev_ports | curr_ports
        ) and port_jaccard < self._cfg.port_jaccard_threshold:
            events.append("port_profile_changed")

        # 3. Service type on shared ports
        # Only the protocol type (first part of "ssh-OpenSSH") is checked — version
        # changes within the same protocol are expected and not suspicious.
        shared_ports = prev_ports & curr_ports
        service_type_changes: dict[int, list[str]] = {}
        for port in shared_ports:
            old_svc = prev.services.get(port, "")
            new_svc = incoming.services.get(port, "")
            old_type = old_svc.split("-")[0] if old_svc else ""
            new_type = new_svc.split("-")[0] if new_svc else ""
            if old_type and new_type and old_type != new_type:
                service_type_changes[port] = [old_svc, new_svc]
        if service_type_changes:
            events.append("service_type_changed")

        # 4. Full identity shift — all three dimensions changed significantly.
        # No shared ports counts as a service change (nothing in common).
        if (
            not os_match
            and port_jaccard < 0.4
            and (service_type_changes or not shared_ports)
        ):
            events.append("full_identity_shift")

        # Overall score (0–1): weighted combination across the three dimensions.
        # OS score uses candidate Jaccard when available — partial overlap (e.g. Linux+Android
        # vs Linux) gives a score between 0 and 1 rather than hard 0/1.
        if prev_families and curr_families:
            os_score = len(prev_families & curr_families) / len(
                prev_families | curr_families
            )
        else:
            os_score = 1.0 if os_match else 0.0
        service_match_rate = (
            1.0 - len(service_type_changes) / len(shared_ports) if shared_ports else 1.0
        )
        overall = 0.5 * os_score + 0.3 * port_jaccard + 0.2 * service_match_rate

        return PeerStore.FingerprintComparison(
            os_match=os_match,
            port_jaccard=port_jaccard,
            service_type_changes=service_type_changes,
            events=events,
            overall_score=overall,
        )

    def __str__(self) -> str:
        return (
            f"PeerStore({len(self.peers)} peers: "
            + ", ".join(str(p) for p in self.peers.values())
            + ")"
        )


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _detect_sequential_ip_ids(samples: list[int]) -> bool:
    """Return True if the IP ID samples look sequential (typical of Windows / older stacks).

    Computes per-step deltas (mod 65536) and checks whether the median step is
    small (≤ 100), which is characteristic of a global counter that increments
    by a fixed amount.  Modern Linux uses random IP IDs per connection, which
    produce large, irregular deltas — those return False.
    """
    if len(samples) < 2:
        return False
    import statistics as _stats

    deltas = [(samples[i + 1] - samples[i]) % 65536 for i in range(len(samples) - 1)]
    median_delta = _stats.median(deltas)
    return median_delta <= 100
