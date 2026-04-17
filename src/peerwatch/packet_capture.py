"""
Provides:
  - Data models for TTL, ARP, TCP-fingerprint, and IP-ID observations.
  - TTL snap / OS-inference helpers.
  - TCP passive fingerprint OS inference against known profiles.
  - PassiveCaptureObserver: thin wrapper that turns raw scapy packets into
    observation objects (decoupled from PeerStore so it can run independently).
  - SniffCaptureLoop: drives scapy.sniff() and feeds the observer.

The observation models are intentionally dependency-free: tests inject them
directly into PeerStore.ingest_*() without needing a live capture session or
scapy installed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TTL helpers
# ---------------------------------------------------------------------------

# Canonical OS TTL origins (the starting TTL a device sends).  Observed TTLs
# are always ≤ the origin because each router decrements by 1.
TTL_OS_DEFAULTS: dict[str, int] = {
    "Linux": 64,
    "macOS": 64,
    "FreeBSD": 64,
    "Android": 64,
    "Windows": 128,
    "Cisco": 255,
    "Solaris": 255,
}

_TTL_THRESHOLDS: list[int] = sorted(set(TTL_OS_DEFAULTS.values()))  # [64, 128, 255]


def snap_ttl_to_os_default(raw_ttl: int) -> int:
    """Round an observed TTL *up* to the nearest OS-default origin.

    Real-world TTLs are always ≤ the device's starting TTL because each router
    decrements by 1.  Snapping upwards recovers the plausible origin.

    Examples
    --------
    >>> snap_ttl_to_os_default(60)   # Linux/macOS with 4 hops
    64
    >>> snap_ttl_to_os_default(120)  # Windows with 8 hops
    128
    >>> snap_ttl_to_os_default(250)  # Cisco with 5 hops
    255
    """
    for threshold in _TTL_THRESHOLDS:
        if raw_ttl <= threshold:
            return threshold
    return _TTL_THRESHOLDS[-1]


def ttl_to_os_hint(raw_ttl: int) -> str:
    """Return a coarse OS-family hint inferred from a raw TTL observation."""
    snapped = snap_ttl_to_os_default(raw_ttl)
    return {64: "Linux/macOS", 128: "Windows", 255: "Cisco/Solaris"}.get(
        snapped, "unknown"
    )


# ---------------------------------------------------------------------------
# TCP passive fingerprint profiles
# ---------------------------------------------------------------------------

# Each entry: canonical option sequence (kinds as strings) and typical window
# sizes.  We compare by option-kind order, ignoring version/value details.
# Sources: p0f, nmap OS templates, Wireshark wiki.
TCP_FINGERPRINT_PROFILES: dict[str, dict] = {
    "Linux": {
        # kernel ≥ 3.x: window 29200 (scaling to 65535), options MSS SACK TS NOP WScale
        "option_signatures": [
            ["MSS", "SACK", "TS", "NOP", "WScale"],
            ["MSS", "NOP", "NOP", "TS", "NOP", "WScale", "SACK"],
        ],
        "window_hint": range(14600, 65536),
        "ttl": 64,
    },
    "Windows": {
        # Windows 10/11: window 64240, options MSS NOP WScale NOP NOP SACK
        "option_signatures": [
            ["MSS", "NOP", "WScale", "NOP", "NOP", "SACK"],
            ["MSS", "NOP", "NOP", "SACK", "NOP", "WScale"],
        ],
        "window_hint": [8192, 64240, 65535],
        "ttl": 128,
    },
    "macOS": {
        # macOS: window 65535, options MSS NOP WScale NOP NOP TS SACK EOL
        "option_signatures": [
            ["MSS", "NOP", "WScale", "NOP", "NOP", "TS", "SACK", "EOL"],
            ["MSS", "NOP", "WScale", "NOP", "NOP", "TS", "NOP", "SACK"],
        ],
        "window_hint": [65535],
        "ttl": 64,
    },
}


def infer_os_from_tcp_fingerprint(
    window_size: int,
    tcp_options: list[str],
    mss: int | None,
) -> str | None:
    """Return the best-matching OS family from a passive TCP fingerprint.

    Scoring per profile signature:
      +1.0  per option kind present in both signature and observation
      -0.5  per option kind in signature but absent from observation
             (penalises signatures that expect options we didn't see)
      -0.3  per option kind in observation but absent from signature
             (minor penalty for extra options)
      +1.0  window size exact match in known list
      +0.5  window size falls within a known range

    A minimum score of 2.0 is required to avoid wild guesses on sparse input.
    Returns None if no profile meets the threshold.
    """
    best: str | None = None
    best_score = 0.0

    obs_set = set(tcp_options)

    for os_name, profile in TCP_FINGERPRINT_PROFILES.items():
        for sig in profile["option_signatures"]:
            sig_set = set(sig)
            overlap = len(sig_set & obs_set)
            if overlap == 0:
                continue

            missing_from_obs = len(sig_set - obs_set)
            extra_in_obs = len(obs_set - sig_set)
            score = float(overlap) - 0.5 * missing_from_obs - 0.3 * extra_in_obs

            # Window size bonus
            wh = profile["window_hint"]
            if isinstance(wh, list):
                if window_size in wh:
                    score += 1.0
            elif hasattr(wh, "__contains__"):
                if window_size in wh:
                    score += 0.5

            if score > best_score:
                best_score = score
                best = os_name

    return best if best_score >= 2.0 else None


# ---------------------------------------------------------------------------
# Observation data models
# ---------------------------------------------------------------------------


@dataclass
class TTLObservation:
    """A single TTL value observed from packets originating at *ip*."""

    ip: str
    ttl: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ARPObservation:
    """An ARP reply claiming that *ip* is reachable at *mac*."""

    ip: str
    mac: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class TCPFingerprintObservation:
    """Passive TCP handshake fingerprint from a SYN or SYN-ACK packet.

    tcp_options is a list of option kind names in the order they appear,
    e.g. ["MSS", "NOP", "WScale", "SACK", "TS"].
    """

    ip: str
    window_size: int
    tcp_options: list[str]
    mss: int | None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class IPIDObservation:
    """IP Identification field from a packet originating at *ip*.

    Collected observations build a per-source sequence.  Sudden large jumps
    that break an otherwise-sequential pattern indicate that the source IP
    may have been spoofed (the attacker's IP-ID counter diverges from the
    legitimate device's counter).
    """

    ip: str
    ip_id: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Passive capture observer
# ---------------------------------------------------------------------------


class PassiveCaptureObserver:
    """Converts raw scapy packets into typed observation objects.

    Callers register callbacks for each observation type; the observer
    dispatches to them as packets are processed.

    Usage (without scapy — inject manually in tests)::

        observer = PassiveCaptureObserver()
        observer.on_ttl(my_ttl_handler)
        observer.process_ttl_observation(TTLObservation(ip="10.0.0.1", ttl=60))

    Usage (with scapy)::

        loop = SniffCaptureLoop(observer, iface="eth0")
        loop.start()
    """

    def __init__(self) -> None:
        self._ttl_callbacks: list[Callable[[TTLObservation], None]] = []
        self._arp_callbacks: list[Callable[[ARPObservation], None]] = []
        self._tcp_fp_callbacks: list[Callable[[TCPFingerprintObservation], None]] = []
        self._ipid_callbacks: list[Callable[[IPIDObservation], None]] = []

    # ── Registration ──────────────────────────────────────────────────────

    def on_ttl(self, cb: Callable[[TTLObservation], None]) -> None:
        self._ttl_callbacks.append(cb)

    def on_arp(self, cb: Callable[[ARPObservation], None]) -> None:
        self._arp_callbacks.append(cb)

    def on_tcp_fingerprint(
        self, cb: Callable[[TCPFingerprintObservation], None]
    ) -> None:
        self._tcp_fp_callbacks.append(cb)

    def on_ip_id(self, cb: Callable[[IPIDObservation], None]) -> None:
        self._ipid_callbacks.append(cb)

    # ── Dispatch ──────────────────────────────────────────────────────────

    def process_ttl_observation(self, obs: TTLObservation) -> None:
        for cb in self._ttl_callbacks:
            cb(obs)

    def process_arp_observation(self, obs: ARPObservation) -> None:
        for cb in self._arp_callbacks:
            cb(obs)

    def process_tcp_fingerprint_observation(
        self, obs: TCPFingerprintObservation
    ) -> None:
        for cb in self._tcp_fp_callbacks:
            cb(obs)

    def process_ip_id_observation(self, obs: IPIDObservation) -> None:
        for cb in self._ipid_callbacks:
            cb(obs)

    # ── Packet parsing (requires scapy) ───────────────────────────────────

    def process_packet(self, packet: object) -> None:  # noqa: ANN401
        """Parse a scapy packet and dispatch any derived observations.

        This method is dynamically imported so that the rest of the module
        stays importable even when scapy is not installed.
        """
        try:
            from scapy.layers.inet import IP, TCP  # type: ignore[import]
            from scapy.layers.l2 import ARP, Ether  # type: ignore[import]
        except ImportError:
            logger.warning("scapy not available — process_packet() is a no-op")
            return

        # ARP
        if packet.haslayer(ARP):
            arp = packet[ARP]
            if arp.op == 2:  # ARP reply (is-at)
                self.process_arp_observation(
                    ARPObservation(ip=arp.psrc, mac=arp.hwsrc.upper())
                )

        if not packet.haslayer(IP):
            return

        ip = packet[IP]
        src = ip.src

        # TTL
        self.process_ttl_observation(TTLObservation(ip=src, ttl=ip.ttl))

        # IP ID
        self.process_ip_id_observation(IPIDObservation(ip=src, ip_id=ip.id))

        # TCP passive fingerprint (SYN packets only — cleanest handshake signal)
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.flags & 0x02 and not (tcp.flags & 0x10):  # SYN, not ACK
                opts = _parse_tcp_options(tcp.options)
                mss = _extract_mss(tcp.options)
                self.process_tcp_fingerprint_observation(
                    TCPFingerprintObservation(
                        ip=src,
                        window_size=tcp.window,
                        tcp_options=opts,
                        mss=mss,
                    )
                )


def _parse_tcp_options(options: list) -> list[str]:
    """Convert a scapy TCP options list to a list of option kind names."""
    kind_map = {
        0: "EOL",
        1: "NOP",
        2: "MSS",
        3: "WScale",
        4: "SACK",
        5: "SACKdata",
        8: "TS",
    }
    result = []
    for opt in options:
        if isinstance(opt, tuple):
            kind = opt[0]
        else:
            kind = opt
        if isinstance(kind, int):
            result.append(kind_map.get(kind, f"opt{kind}"))
        elif isinstance(kind, str):
            result.append(kind)
    return result


def _extract_mss(options: list) -> int | None:
    """Extract the MSS value from a scapy TCP options list."""
    for opt in options:
        if isinstance(opt, tuple) and len(opt) == 2:
            kind, value = opt
            if kind in (2, "MSS") and isinstance(value, int):
                return value
    return None


# ---------------------------------------------------------------------------
# Sniff loop
# ---------------------------------------------------------------------------


class SniffCaptureLoop:
    """Runs scapy.sniff() in a background thread and feeds PassiveCaptureObserver.

    Requires scapy to be installed.  Import and instantiate only when you
    actually want to capture live traffic.
    """

    def __init__(
        self,
        observer: PassiveCaptureObserver,
        iface: str | None = None,
        bpf_filter: str = "ip or arp",
    ) -> None:
        self.observer = observer
        self.iface = iface
        self.bpf_filter = bpf_filter
        self._thread: object = None

    def start(self, timeout: int | None = None) -> None:
        """Start sniffing in a daemon thread."""
        import threading

        try:
            from scapy.all import sniff  # type: ignore[import]
        except ImportError as exc:
            raise RuntimeError(
                "scapy is required for live capture. "
                "Install it or inject observations manually."
            ) from exc

        def _sniff() -> None:
            sniff(
                iface=self.iface,
                filter=self.bpf_filter,
                prn=self.observer.process_packet,
                store=False,
                timeout=timeout,
            )

        t = threading.Thread(target=_sniff, daemon=True, name="peerwatch-sniff")
        t.start()
        self._thread = t
        logger.info(
            "SniffCaptureLoop started on iface=%s filter=%r",
            self.iface or "default",
            self.bpf_filter,
        )

    def stop(self) -> None:
        """Request stop (scapy sniff will stop at next packet or timeout)."""
        # scapy does not provide a clean cancellation API; rely on timeout or
        # daemon thread exit when the main process ends.
        logger.info("SniffCaptureLoop stop requested (will stop at next event)")
