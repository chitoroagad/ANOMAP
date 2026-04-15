import logging
import threading
import uuid
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, Field

UNKNOWN_KEY = "unknown"

# --- Suspicion weights ---
# Validated against 86 scans per device on a home network:
# - Port Jaccard stays at 1.0 for stable devices; drops below 0.6 only for genuine
#   profile changes or ephemeral iOS ports (handled by baseline warmup).
# - OS candidates are stable for real devices; "unknown" gaps are guarded separately.
PORT_JACCARD_THRESHOLD = 0.6
SERVICE_CHANGE_SUSPICION = 1.0       # protocol change on a shared port (e.g. ssh → http)
PORT_PROTOCOL_MISMATCH_SUSPICION = 3.0  # well-known port running wrong protocol (backdoor signal)

# --- Decay ---
# Suspicion halves every 3.5 days of clean scans, reaching ~25% after one week
# and near-zero (~6%) after two weeks. Keeps legitimate one-off anomalies
# (e.g. an OS upgrade) from permanently flagging a device.
SUSPICION_HALF_LIFE_DAYS = 3.5

# --- Baseline warmup ---
# First N scans build a fingerprint baseline; anomaly scoring starts after that.
BASELINE_MIN_SCANS = 5

# --- Volatile peer TTL ---
# Peers with no confirmed MAC are evicted after this many hours of inactivity.
VOLATILE_PEER_TTL_HOURS = 24

# --- Port → expected service-type (first segment of nmap service string) ---
# Conservative list of ports where a protocol mismatch is a strong backdoor signal.
# Uses nmap's service-name conventions (split on "-", take first token).
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

from peerwatch import util
from peerwatch.parser import NormalisedData


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
    metadata_history: list[NormalisedData] = Field(default_factory=list)
    identity_history: list[IdentityEvent] = Field(default_factory=list)

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

    def __init__(self):
        self.peers = {}
        self.mac_to_id = {}
        self.ip_to_id = {}

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
        mac = util._normalise_mac(data.mac_address)
        ips = util._extract_ips(data)

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

    def evict_stale_volatile_peers(self, now: datetime | None = None) -> list[str]:
        """Remove volatile (MAC-less) peers not seen within VOLATILE_PEER_TTL_HOURS.

        Returns the list of evicted internal IDs.
        """
        if now is None:
            now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(hours=VOLATILE_PEER_TTL_HOURS)).replace(tzinfo=timezone.utc)
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
    # Internal helpers
    # --------------------

    def _check_incoming_fingerprint(
        self, prev: Peer, incoming_data: NormalisedData
    ) -> float:
        # During the warmup period we record events but do not score them so that
        # noisy early scans don't permanently taint the suspicion score.
        in_warmup = prev.scan_count < BASELINE_MIN_SCANS

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
                suspicion += SERVICE_CHANGE_SUSPICION
            if new_type:
                prev.known_services.setdefault(port, set()).add(new_type)

        if not in_warmup:
            if "full_identity_shift" in comparison.events:
                suspicion += 2.0
            if "os_family_changed" in comparison.events:
                suspicion += 2.0
            if "port_profile_changed" in comparison.events:
                suspicion += 0.5

            # Port–protocol mismatch: well-known port running the wrong service type.
            # Strong backdoor signal — only score after baseline is established.
            for port, expected, actual in self._check_port_protocol_mismatches(incoming_data):
                if port in prev.flagged_port_mismatches:
                    continue  # already flagged; don't accumulate on every scan
                prev.record_event(
                    "port_protocol_mismatch",
                    port=port,
                    expected=sorted(expected),
                    actual=actual,
                )
                suspicion += PORT_PROTOCOL_MISMATCH_SUSPICION
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
            metadata_history=[],
            identity_history=[],
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

    @staticmethod
    def _apply_suspicion_decay(peer: Peer) -> None:
        """Exponential decay based on time since last scan.

        Suspicion halves every SUSPICION_HALF_LIFE_DAYS days of clean activity,
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
            peer.suspicion_score *= 0.5 ** (elapsed_days / SUSPICION_HALF_LIFE_DAYS)

    @staticmethod
    def _check_port_protocol_mismatches(
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

    @staticmethod
    def _compare_fingerprints(
        prev: NormalisedData, incoming: NormalisedData
    ) -> "PeerStore.FingerprintComparison":  # noqa: F821
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
        port_jaccard = util._jaccard_similarity(prev_ports, curr_ports)
        if (prev_ports | curr_ports) and port_jaccard < PORT_JACCARD_THRESHOLD:
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
