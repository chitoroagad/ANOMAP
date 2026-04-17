"""
Route stability tracking via traceroute.

Provides:
  - RouteHop / RouteObservation data models.
  - ASN lookup via Team Cymru's DNS-based BGP origin service.
  - RouteTracker: runs traceroute (subprocess), parses output into
    RouteObservation, maintains per-destination baseline, and flags:
      * Changed hop sequence (different intermediate IPs or hop count).
      * New ASN in path (traffic crossing unexpected autonomous system).
      * Asymmetric-path indicator when reverse traceroute disagrees.

Design: RouteTracker is independent of PeerStore; callers convert
RouteChangeEvent objects into PeerStore.ingest_route_change() calls.
"""

from __future__ import annotations

import logging
import re
import socket
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class RouteHop:
    """A single hop in a traceroute path."""

    hop_number: int
    ip: str | None          # None if the hop didn't respond (*)
    rtt_ms: float | None    # round-trip time in milliseconds (None if *)
    asn: str | None = None  # populated after ASN lookup


@dataclass
class RouteObservation:
    """Result of one traceroute run to a destination."""

    destination: str
    hops: list[RouteHop]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def responding_ips(self) -> list[str]:
        return [h.ip for h in self.hops if h.ip is not None]

    @property
    def asns(self) -> list[str]:
        return [h.asn for h in self.hops if h.asn is not None]


class RouteChangeKind(str, Enum):
    HOP_SEQUENCE_CHANGED = "hop_sequence_changed"
    NEW_ASN_IN_PATH = "new_asn_in_path"
    HOP_COUNT_CHANGED = "hop_count_changed"
    ASYMMETRIC_PATH = "asymmetric_path"


@dataclass
class RouteChangeEvent:
    """Emitted when a new observation differs from the stored baseline."""

    destination: str
    kind: RouteChangeKind
    baseline: RouteObservation
    observed: RouteObservation
    details: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# ASN lookup
# ---------------------------------------------------------------------------

# Team Cymru DNS-based BGP origin service.
# Query format: <reversed-octets>.origin.asn.cymru.com
# Example: 8.8.8.8 → 8.8.8.8.origin.asn.cymru.com
# Response TXT: "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"

_CYMRU_SUFFIX = "origin.asn.cymru.com"
_ASN_CACHE: dict[str, str | None] = {}


def lookup_asn(ip: str, timeout: float = 2.0) -> str | None:
    """Return the ASN (e.g. "AS15169") for *ip* via Team Cymru DNS.

    Returns None on timeout, DNS failure, or private/link-local addresses.
    Results are cached in-process.
    """
    if ip in _ASN_CACHE:
        return _ASN_CACHE[ip]

    # Skip RFC-1918 and loopback — no public ASN
    if _is_private_ip(ip):
        _ASN_CACHE[ip] = None
        return None

    try:
        reversed_octets = ".".join(reversed(ip.split(".")))
        query = f"{reversed_octets}.{_CYMRU_SUFFIX}"
        import dns.resolver  # type: ignore[import]

        answers = dns.resolver.resolve(query, "TXT", lifetime=timeout)
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            asn_field = txt.split("|")[0].strip()
            if asn_field:
                result = f"AS{asn_field}" if not asn_field.startswith("AS") else asn_field
                _ASN_CACHE[ip] = result
                return result
    except Exception:
        pass

    # Fallback: try socket-based whois (no external library)
    try:
        result = _cymru_whois_lookup(ip)
        _ASN_CACHE[ip] = result
        return result
    except Exception as exc:
        logger.debug("ASN lookup failed for %s: %s", ip, exc)
        _ASN_CACHE[ip] = None
        return None


def _cymru_whois_lookup(ip: str) -> str | None:
    """ASN lookup via Team Cymru whois socket (fallback, no DNS library needed)."""
    with socket.create_connection(("whois.cymru.com", 43), timeout=3) as sock:
        sock.sendall(f" -f {ip}\n".encode())
        data = b""
        while chunk := sock.recv(4096):
            data += chunk
    for line in data.decode(errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("AS"):
            continue
        parts = line.split("|")
        if parts:
            asn = parts[0].strip()
            if asn and asn.isdigit():
                return f"AS{asn}"
            if asn.startswith("AS"):
                return asn
    return None


def _is_private_ip(ip: str) -> bool:
    """Return True for loopback, link-local, and RFC-1918 addresses."""
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Traceroute parser
# ---------------------------------------------------------------------------

# Regex: matches lines like "  1  192.168.1.1  1.234 ms"
# and "  3  * * *" (non-responsive hop)
_HOP_RE = re.compile(
    r"^\s*(\d+)\s+"           # hop number
    r"(?:\*|\(?([\d.]+)\)?)"  # IP or *
    r"(?:\s+([\d.]+)\s*ms)?"  # optional RTT
)


def parse_traceroute_output(output: str, destination: str) -> RouteObservation:
    """Parse the stdout of a standard traceroute(1) call into a RouteObservation."""
    hops: list[RouteHop] = []
    seen_hops: set[int] = set()

    for line in output.splitlines():
        m = _HOP_RE.match(line)
        if not m:
            continue
        hop_n = int(m.group(1))
        if hop_n in seen_hops:
            continue  # traceroute prints 3 probes per hop; take first
        seen_hops.add(hop_n)

        ip = m.group(2) or None
        rtt = float(m.group(3)) if m.group(3) else None
        hops.append(RouteHop(hop_number=hop_n, ip=ip, rtt_ms=rtt))

    return RouteObservation(destination=destination, hops=hops)


# ---------------------------------------------------------------------------
# RouteTracker
# ---------------------------------------------------------------------------


class RouteTracker:
    """Runs traceroute and tracks path stability per destination.

    Typical use::

        tracker = RouteTracker(resolve_asn=True)
        events = tracker.observe("8.8.8.8")
        # events is [] on first run (baseline stored)
        # subsequent calls return RouteChangeEvent objects for any deviation
    """

    def __init__(
        self,
        resolve_asn: bool = False,
        traceroute_bin: str = "traceroute",
        max_hops: int = 30,
        probes: int = 1,
        timeout: int = 5,
    ) -> None:
        self.resolve_asn = resolve_asn
        self.traceroute_bin = traceroute_bin
        self.max_hops = max_hops
        self.probes = probes
        self.timeout = timeout
        # destination → baseline RouteObservation
        self._baselines: dict[str, RouteObservation] = {}

    # ── Public API ────────────────────────────────────────────────────────

    def observe(self, destination: str) -> list[RouteChangeEvent]:
        """Run traceroute to *destination* and return any change events.

        First call for a destination stores the baseline and returns [].
        Subsequent calls compare against the baseline.
        """
        obs = self._run_traceroute(destination)
        if obs is None:
            return []

        if self.resolve_asn:
            self._enrich_asns(obs)

        if destination not in self._baselines:
            self._baselines[destination] = obs
            logger.info("Route baseline stored for %s (%d hops)", destination, len(obs.hops))
            return []

        return self._compare(self._baselines[destination], obs)

    def update_baseline(self, destination: str, obs: RouteObservation) -> None:
        """Manually override the stored baseline (e.g. after confirming a legitimate route change)."""
        self._baselines[destination] = obs

    def get_baseline(self, destination: str) -> RouteObservation | None:
        return self._baselines.get(destination)

    # ── Internals ─────────────────────────────────────────────────────────

    def _run_traceroute(self, destination: str) -> RouteObservation | None:
        cmd = [
            self.traceroute_bin,
            "-m", str(self.max_hops),
            "-q", str(self.probes),
            "-w", str(self.timeout),
            "-n",  # numeric output (no DNS reverse lookups)
            destination,
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.max_hops * self.timeout + 10,
            )
            return parse_traceroute_output(result.stdout, destination)
        except FileNotFoundError:
            logger.error("traceroute binary not found: %s", self.traceroute_bin)
        except subprocess.TimeoutExpired:
            logger.warning("traceroute timed out for %s", destination)
        except Exception as exc:
            logger.error("traceroute failed for %s: %s", destination, exc)
        return None

    def _enrich_asns(self, obs: RouteObservation) -> None:
        for hop in obs.hops:
            if hop.ip is not None:
                hop.asn = lookup_asn(hop.ip)

    def _compare(
        self, baseline: RouteObservation, observed: RouteObservation
    ) -> list[RouteChangeEvent]:
        events: list[RouteChangeEvent] = []

        baseline_ips = baseline.responding_ips
        observed_ips = observed.responding_ips

        # Hop count change
        if len(baseline.hops) != len(observed.hops):
            events.append(
                RouteChangeEvent(
                    destination=observed.destination,
                    kind=RouteChangeKind.HOP_COUNT_CHANGED,
                    baseline=baseline,
                    observed=observed,
                    details={
                        "baseline_hops": len(baseline.hops),
                        "observed_hops": len(observed.hops),
                    },
                )
            )

        # Hop sequence change (Jaccard on responding IPs)
        if baseline_ips and observed_ips:
            b_set = set(baseline_ips)
            o_set = set(observed_ips)
            jaccard = len(b_set & o_set) / len(b_set | o_set)
            if jaccard < 0.7:
                new_hops = sorted(o_set - b_set)
                events.append(
                    RouteChangeEvent(
                        destination=observed.destination,
                        kind=RouteChangeKind.HOP_SEQUENCE_CHANGED,
                        baseline=baseline,
                        observed=observed,
                        details={
                            "jaccard": round(jaccard, 3),
                            "new_hops": new_hops,
                            "dropped_hops": sorted(b_set - o_set),
                        },
                    )
                )

        # New ASN in path (only if ASN enrichment was done)
        if self.resolve_asn:
            baseline_asns = set(baseline.asns)
            observed_asns = set(observed.asns)
            novel_asns = observed_asns - baseline_asns
            if novel_asns:
                events.append(
                    RouteChangeEvent(
                        destination=observed.destination,
                        kind=RouteChangeKind.NEW_ASN_IN_PATH,
                        baseline=baseline,
                        observed=observed,
                        details={"new_asns": sorted(novel_asns)},
                    )
                )

        return events

    def check_asymmetry(
        self,
        forward: RouteObservation,
        reverse: RouteObservation,
        jaccard_threshold: float = 0.5,
    ) -> RouteChangeEvent | None:
        """Compare forward and reverse paths; return an event if significantly asymmetric.

        Mild asymmetry is normal on the internet. Flag only when the Jaccard
        similarity of responding IPs falls below *jaccard_threshold*.
        """
        fwd_ips = set(forward.responding_ips)
        rev_ips = set(reverse.responding_ips)

        if not fwd_ips or not rev_ips:
            return None

        jaccard = len(fwd_ips & rev_ips) / len(fwd_ips | rev_ips)
        if jaccard < jaccard_threshold:
            return RouteChangeEvent(
                destination=forward.destination,
                kind=RouteChangeKind.ASYMMETRIC_PATH,
                baseline=forward,
                observed=reverse,
                details={
                    "forward_ips": sorted(fwd_ips),
                    "reverse_ips": sorted(rev_ips),
                    "jaccard": round(jaccard, 3),
                },
            )
        return None
