from peerwatch.parser import NormalisedData
from peerwatch.peer_store import UNKNOWN_KEY


def _normalise_mac(mac: str | None) -> str | None:
    if not mac or mac == UNKNOWN_KEY:
        return None
    return mac


def _extract_ips(data: NormalisedData) -> set[str]:
    ips = set()
    if data.ipv4 and data.ipv4 != UNKNOWN_KEY:
        ips.add(data.ipv4)
    if data.ipv6 and data.ipv6 != UNKNOWN_KEY:
        ips.add(data.ipv6)
    return ips


def _jaccard_similarity(a: set, b: set) -> float:
    union = a | b
    return len(a & b) / len(union) if union else 1.0
