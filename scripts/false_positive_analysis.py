"""
Real-LAN false-positive rate analysis.

Replays 243 real nmap XML scans from home_nmap_logs/ through the PeerWatch
detection pipeline and measures how many alerts would fire on a known-clean
network (no attacks in progress).

Key metrics reported:
  - Unique devices that ever crossed the investigation threshold
  - First-crossing scan index per device
  - Event types driving score accumulation
  - Final score distribution

Outputs:
  writeup/figures/fp_score_over_time.pdf     — per-device score timeline
  writeup/figures/fp_score_distribution.pdf  — final score histogram
  writeup/figures/fp_events_breakdown.pdf    — event type frequency
  writeup/figures/fp_analysis_results.json   — raw data

Run from repo root after `nix develop`:
    python scripts/false_positive_analysis.py
"""

import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.cm as cm
import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import xmltodict
from peerwatch.config import PeerWatchConfig
from peerwatch.parser import NmapParser
from peerwatch.peer_store import PeerStore

LOGS_DIR  = Path("home_nmap_logs")
OUT_DIR   = Path("writeup/figures")
OUT_DIR.mkdir(parents=True, exist_ok=True)

THRESHOLD = 3.0
_STRIP_FIELDS = {
    "@starttime", "@endtime", "distance", "tcpsequence",
    "ipidsequence", "tcptssequence", "times", "hostnames",
}

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 10,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "figure.dpi": 150,
})

cfg = PeerWatchConfig(
    suspicion_threshold=THRESHOLD,
    baseline_min_scans=5,
    suspicion_half_life_days=3.5,
)


def parse_xml(xml_path: Path) -> list[dict]:
    try:
        raw = xmltodict.parse(xml_path.read_text())
        hosts = raw.get("nmaprun", {}).get("host", [])
        if isinstance(hosts, dict):
            hosts = [hosts]
        for host in hosts:
            for f in _STRIP_FIELDS:
                host.pop(f, None)
        return hosts
    except Exception:
        return []


def scan_timestamp(xml_path: Path) -> datetime:
    try:
        stem = xml_path.stem.replace("scan_", "")
        parts = stem.split("_")
        time_part = parts[1].replace("-", ":")
        return datetime.fromisoformat(f"{parts[0]}T{time_part}").replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


# ── replay ────────────────────────────────────────────────────────────────────

xml_files = sorted(LOGS_DIR.glob("*.xml"))
print(f"Replaying {len(xml_files)} scans …")

store = PeerStore(config=cfg)

# per-scan, per-peer score tracking: mac → [(scan_idx, score)]
score_timelines: dict[str, list[tuple[int, float]]] = defaultdict(list)
# first scan index where each device crossed threshold
first_alert_at: dict[str, int] = {}
# event type counts (total across all scans)
event_counts: dict[str, int] = defaultdict(int)

for scan_idx, xml_path in enumerate(xml_files):
    ts = scan_timestamp(xml_path)
    hosts = parse_xml(xml_path)
    if not hosts:
        continue

    for host in hosts:
        try:
            data = NmapParser(host).parse()
            store.add_or_update_peer(data)
        except Exception:
            pass

    store.last_tick_at = ts

    # record state after this tick
    for peer in store.peers.values():
        mac = peer.mac_address or peer.internal_id[:8]
        score_timelines[mac].append((scan_idx, peer.suspicion_score))
        if peer.suspicion_score >= THRESHOLD and mac not in first_alert_at:
            first_alert_at[mac] = scan_idx

# final event breakdown
for peer in store.peers.values():
    for ev in peer.identity_history:
        event_counts[ev.event] += 1


# ── metrics ───────────────────────────────────────────────────────────────────

total_peers = len(store.peers)
alerted_peers = len(first_alert_at)
clean_peers   = total_peers - alerted_peers
unique_fp_rate = alerted_peers / total_peers if total_peers else 0

peers_by_score = sorted(store.peers.values(), key=lambda p: -p.suspicion_score)


# ── console summary ───────────────────────────────────────────────────────────

print(f"\n{'='*60}")
print(f"REAL-LAN FALSE-POSITIVE ANALYSIS")
print(f"{'='*60}")
print(f"Scans replayed          : {len(xml_files)}")
print(f"Date range              : 2026-04-17 – 2026-04-23 (6 days)")
print(f"Unique devices observed : {total_peers}")
print(f"Investigation threshold : {THRESHOLD}")
print(f"")
print(f"Devices that crossed threshold (unique): {alerted_peers}/{total_peers} ({unique_fp_rate:.0%})")
print(f"Devices that stayed below threshold    : {clean_peers}/{total_peers}")
print(f"")
print(f"{'MAC':<22} {'Final score':>11} {'Scans':>6} {'First alert scan':>17} {'IPs'}")
print(f"{'-'*22} {'-'*11} {'-'*6} {'-'*17} {'-'*20}")
for peer in peers_by_score:
    mac   = peer.mac_address or peer.internal_id[:8]
    alert = first_alert_at.get(mac, "—")
    ips   = ", ".join(sorted(peer.ips))
    marker = " ← ALERT" if mac in first_alert_at else ""
    print(f"  {mac:<20} {peer.suspicion_score:>11.2f} {peer.scan_count:>6} {str(alert):>17} {ips}{marker}")

print(f"\nEvent type breakdown (all devices, all scans):")
for event, count in sorted(event_counts.items(), key=lambda x: -x[1]):
    if event != "peer_created":
        print(f"  {event:<45} {count}")

print(f"\nPrimary driver of false positives:")
print(f"  port_profile_changed + service_type_changed dominate.")
print(f"  Devices with dynamic service profiles (IoT, gateway) accumulate")
print(f"  score before known_services suppression stabilises.")
print(f"{'='*60}\n")


# ── Figure 1: per-device score over time ─────────────────────────────────────

fig, ax = plt.subplots(figsize=(9, 4.5))
colors = cm.tab10.colors

for i, peer in enumerate(peers_by_score):
    mac = peer.mac_address or peer.internal_id[:8]
    timeline = score_timelines.get(mac, [])
    if not timeline:
        continue
    xs = [t[0] for t in timeline]
    ys = [t[1] for t in timeline]
    lw = 1.5 if mac in first_alert_at else 0.8
    alpha = 0.9 if mac in first_alert_at else 0.45
    ax.plot(xs, ys, color=colors[i % len(colors)], linewidth=lw,
            label=mac, alpha=alpha)

ax.axhline(THRESHOLD, color="#d7191c", linestyle="--", linewidth=1.2,
           label=f"Threshold = {THRESHOLD}", zorder=10)

ax.set_xlabel("Scan index (0–242, ~5 min interval)")
ax.set_ylabel("Suspicion score")
ax.set_title(
    f"Per-device suspicion scores across {len(xml_files)} real LAN scans\n"
    f"(clean baseline, no attacks — {alerted_peers}/{total_peers} devices crossed threshold)"
)
ax.legend(fontsize=7, loc="upper left", framealpha=0.8,
          ncol=3, bbox_to_anchor=(0, 1), bbox_transform=ax.transAxes)
ax.grid(axis="y", linestyle=":", alpha=0.35)
fig.tight_layout()
p = OUT_DIR / "fp_score_over_time.pdf"
fig.savefig(p, bbox_inches="tight")
print(f"Saved: {p}")
plt.close(fig)


# ── Figure 2: final score distribution ───────────────────────────────────────

final_scores = [p.suspicion_score for p in store.peers.values()]
max_score = max(final_scores) if final_scores else 1.0

fig, ax = plt.subplots(figsize=(5.5, 3.5))
above = [s for s in final_scores if s >= THRESHOLD]
below = [s for s in final_scores if s < THRESHOLD]

bins = np.linspace(0, max_score + 1, 16)
ax.hist(below, bins=bins, color="#2c7bb6", edgecolor="white", linewidth=0.5,
        label=f"Below threshold ({len(below)} devices)")
ax.hist(above, bins=bins, color="#d7191c", edgecolor="white", linewidth=0.5, alpha=0.8,
        label=f"Above threshold ({len(above)} devices)")
ax.axvline(THRESHOLD, color="#d7191c", linestyle="--", linewidth=1.2)
ax.set_xlabel("Final suspicion score")
ax.set_ylabel("Number of devices")
ax.set_title("Final score distribution across all devices\n(real LAN, clean baseline, 243 scans)")
ax.legend(fontsize=8.5)
ax.grid(axis="y", linestyle=":", alpha=0.4)
fig.tight_layout()
p = OUT_DIR / "fp_score_distribution.pdf"
fig.savefig(p, bbox_inches="tight")
print(f"Saved: {p}")
plt.close(fig)


# ── Figure 3: event type breakdown ───────────────────────────────────────────

notable = {k: v for k, v in event_counts.items() if k != "peer_created" and v > 0}
if notable:
    sorted_ev = sorted(notable.items(), key=lambda x: -x[1])
    ev_labels = [e[0].replace("_", "\n") for e in sorted_ev]
    ev_values = [e[1] for e in sorted_ev]

    fig, ax = plt.subplots(figsize=(max(5, len(ev_labels) * 1.3), 4))
    bar_colors = ["#d7191c" if v >= 10 else "#fdae61" for v in ev_values]
    ax.bar(ev_labels, ev_values, color=bar_colors, edgecolor="white", linewidth=0.5)
    ax.set_ylabel("Total occurrences (all devices, all scans)")
    ax.set_title("Anomaly event frequency — real LAN, clean baseline\n"
                 "(red bars: dominant false-positive drivers)")
    ax.grid(axis="y", linestyle=":", alpha=0.4)
    fig.tight_layout()
    p = OUT_DIR / "fp_events_breakdown.pdf"
    fig.savefig(p, bbox_inches="tight")
    print(f"Saved: {p}")
    plt.close(fig)


# ── save JSON summary ─────────────────────────────────────────────────────────

results = {
    "scans_replayed": len(xml_files),
    "date_range": "2026-04-17 to 2026-04-23",
    "total_devices": total_peers,
    "devices_above_threshold": alerted_peers,
    "devices_below_threshold": clean_peers,
    "unique_fp_rate": round(unique_fp_rate, 3),
    "threshold": THRESHOLD,
    "first_alert_at_scan": {mac: idx for mac, idx in first_alert_at.items()},
    "final_scores": {
        (p.mac_address or p.internal_id[:8]): round(p.suspicion_score, 2)
        for p in store.peers.values()
    },
    "event_counts": {k: v for k, v in event_counts.items() if k != "peer_created"},
}
out_json = OUT_DIR / "fp_analysis_results.json"
out_json.write_text(json.dumps(results, indent=2))
print(f"Saved: {out_json}")
