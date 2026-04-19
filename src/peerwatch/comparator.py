import logging
from collections import defaultdict
from datetime import datetime

from pydantic import BaseModel

from peerwatch.peer_store import PeerStore


class Comparator:
    """Temporal drift analyser over a populated PeerStore.

    Summarises per-peer identity events recorded during scan ingestion,
    providing a human-readable view of which devices have changed and how.
    """

    class PeerDriftSummary(BaseModel):
        mac_address: str | None
        ips: list[str]
        scan_count: int
        suspicion_score: float
        event_counts: dict[str, int]
        first_seen: datetime | None
        last_seen: datetime | None

    def __init__(self, peer_store: PeerStore):
        self.peer_store = peer_store

    def summarise(self) -> list["Comparator.PeerDriftSummary"]:
        summaries = []
        for peer in self.peer_store.peers.values():
            event_counts: dict[str, int] = defaultdict(int)
            timestamps: list[datetime] = []
            for event in peer.identity_history:
                event_counts[event.event] += 1
                timestamps.append(event.timestamp)

            summaries.append(
                self.PeerDriftSummary(
                    mac_address=peer.mac_address,
                    ips=sorted(peer.ips),
                    scan_count=peer.scan_count,
                    suspicion_score=round(peer.suspicion_score, 2),
                    event_counts=dict(event_counts),
                    first_seen=min(timestamps) if timestamps else None,
                    last_seen=max(timestamps) if timestamps else None,
                )
            )

        return sorted(summaries, key=lambda s: s.suspicion_score, reverse=True)

    def print_report(self) -> None:
        summaries = self.summarise()
        width = 80
        lines = [
            "",
            "=" * width,
            f"Temporal Drift Report  ({len(summaries)} peers)",
            "=" * width,
        ]
        for s in summaries:
            label = s.mac_address or "volatile/no-mac"
            ips = ", ".join(s.ips) if s.ips else "no IP"
            lines.append(f"  {label}  [{ips}]")
            lines.append(f"  scans={s.scan_count}  suspicion={s.suspicion_score}")
            notable = {k: v for k, v in s.event_counts.items() if k != "peer_created"}
            if notable:
                for event, count in sorted(notable.items()):
                    lines.append(f"    {event}: {count}x")
            else:
                lines.append("    (no anomalies recorded)")
        logging.info("\n".join(lines))
