from peerwatch.parser import NormalisedData
from peerwatch.peer_store import Peer, PeerStore


def scan(
    mac: str = "AA:BB:CC:DD:EE:FF",
    ip: str = "192.168.1.10",
    os: str = "Linux",
    os_candidates: dict[str, int] | None = None,
    ports: list[int] | None = None,
    services: dict[int, str] | None = None,
    **kwargs,
) -> NormalisedData:
    """Build a NormalisedData instance with sensible defaults.

    os_candidates defaults to {os: 96} — matching a single confident nmap pick
    and ensuring the candidate-set comparison path is exercised (not the fallback).
    ports and services are paired: override both or neither.
    """
    if os_candidates is None:
        os_candidates = {os: 96}
    if ports is None:
        ports = [22, 80]
    if services is None:
        services = {22: "ssh-OpenSSH", 80: "http-Apache"}
    return NormalisedData(
        mac_address=mac,
        ipv4=ip,
        os=os,
        os_candidates=os_candidates,
        open_ports=sorted(ports),
        services=services,
        **kwargs,
    )


def warm_up(store: PeerStore, baseline: NormalisedData, n: int = 6) -> Peer:
    """Feed `baseline` into `store` n times and return the resulting Peer.

    n=6 (default) performs: 1 create + 5 updates → scan_count=6.
    The next call to add_or_update_peer is the first that scores anomalies
    (guard: scan_count < BASELINE_MIN_SCANS=5 is False at scan_count=6).

    The returned Peer has suspicion_score == 0.0 because identical scans
    produce no fingerprint changes and warmup suppresses scoring anyway.
    """
    peer = None
    for _ in range(n):
        peer = store.add_or_update_peer(baseline)
    assert peer is not None
    return peer
