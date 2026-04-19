# Fleet-Level Anomaly Correlation — Design Doc

## Problem

PeerWatch currently analyses each peer in isolation. A coordinated attack affecting
multiple devices simultaneously produces N independent medium-confidence alerts rather
than one high-confidence fleet event. This makes the following attacks harder to detect:

- **ARP poisoning campaign** — attacker poisons the ARP cache of several hosts at once;
  each host shows a `mac_conflict` or `arp_spoofing_detected` event, but score per peer
  may stay below the investigation threshold.
- **VLAN hopping / man-in-the-middle** — route paths change for multiple peers
  simultaneously; each fires `route_hop_change` individually.
- **Coordinated fingerprint normalisation** — an attacker carefully mirrors baseline
  fingerprints on multiple devices; small per-peer deltas add up to a clear pattern
  fleet-wide.
- **Network infrastructure replacement** — a switch or gateway is swapped; every peer
  behind it shows simultaneous TTL or route changes, which individually look like noise.

The current design also means the LLM agent sees one peer at a time and cannot reason
about fleet context.


## Goals

1. Detect temporal clustering: N peers with anomaly events within the same scan window.
2. Classify the cluster by attack type using event co-occurrence patterns.
3. Boost per-peer suspicion scores when a peer's events match a fleet pattern.
4. Surface a single fleet-level alert summarising the cluster.
5. Pass fleet context to the LLM agent so it can reason about coordinated behaviour.


## Non-Goals

- Real-time streaming correlation (we are scan-tick based, not packet-stream based).
- Graph-based lateral movement tracking (out of scope for thesis).
- Persistent cross-tick cluster identity (clusters are re-evaluated each tick).


## Design

### 1. FleetCorrelator

New class `src/peerwatch/fleet_correlator.py`.

```
FleetCorrelator(peer_store: PeerStore, config: PeerWatchConfig)
    .analyse() -> list[FleetEvent]
```

Called once per daemon tick, after `Comparator` runs and before `SuspiciousAgent`.

#### Input

The full `PeerStore`. For each peer, inspect `identity_history` entries added since
the last saved tick (tracked via a watermark timestamp stored in `PeerStore`).

#### Algorithm

**Step 1 — collect recent events**

For each peer, collect identity events with `timestamp >= tick_start`. Group by
`event` field.

```
recent: dict[event_type, list[(peer_id, timestamp, details)]]
```

**Step 2 — pattern matching**

Apply a set of named patterns (see table below). Each pattern specifies:
- Required event types (must all appear)
- Minimum peer count (`min_peers`, default 2)
- Time window (`window_seconds`, default = scan interval)
- Suspicion boost applied to each matching peer

| Pattern name          | Required events                              | Min peers | Score boost |
|-----------------------|----------------------------------------------|-----------|-------------|
| `arp_poisoning`       | `arp_spoofing_detected`                      | 2         | +2.0        |
| `route_shift`         | `route_hop_change` or `new_asn_in_path`      | 3         | +1.5        |
| `os_normalisation`    | `os_family_changed`                          | 3         | +1.5        |
| `identity_sweep`      | `identity_shift` or `full_identity_change`   | 2         | +2.0        |
| `service_sweep`       | `service_type_changed`                       | 4         | +1.0        |
| `ttl_shift`           | `ttl_deviation`                              | 3         | +1.5        |

Patterns are evaluated independently; a peer can match multiple patterns.

**Step 3 — emit FleetEvents**

For each matched pattern, emit one `FleetEvent`:

```python
class FleetEvent(BaseModel):
    pattern: str                  # e.g. "arp_poisoning"
    peer_ids: list[str]
    ips: list[str]
    event_count: int
    window_start: datetime
    window_end: datetime
    suspicion_boost: float        # applied to each matched peer
    description: str              # human-readable summary
```

**Step 4 — apply score boosts**

For each matched peer in each `FleetEvent`, call:

```python
peer_store.add_suspicion(peer_id, fleet_event.suspicion_boost, reason=fleet_event.pattern)
```

`add_suspicion` is a new thin wrapper on `Peer.suspicion_score +=` that also appends
an `identity_history` event of type `fleet_correlation_boost` so the LLM sees it.

### 2. PeerStore changes

- Add `last_tick_at: datetime | None` to `PeerStore`. Set at end of each `run_pipeline()`
  tick. Used by `FleetCorrelator` as the event window start.
- Add `add_suspicion(peer_id, delta, reason)` method.

### 3. SuspiciousAgent changes

When `FleetEvent`s are present, pass them in the investigation context:

```python
agent.investigate_all(fleet_events=fleet_events)
```

The agent formats fleet events into the prompt alongside per-peer history:

```
FLEET CONTEXT
-------------
Pattern: arp_poisoning
Affected peers: 3 (192.168.1.10, 192.168.1.22, 192.168.1.45)
Window: 2026-04-19T14:00:00Z – 14:05:00Z

This peer's events occurred in the same scan window as 2 other ARP spoofing
events on the subnet. Consider coordinated attack.
```

### 4. Fleet alert output

`daemon.py` writes a separate fleet alert record to `alerts/fleet_alerts.jsonl`:

```json
{
  "ts": "...",
  "pattern": "arp_poisoning",
  "peer_ids": ["...", "..."],
  "ips": ["192.168.1.10", "192.168.1.22"],
  "event_count": 6,
  "suspicion_boost": 2.0,
  "description": "3 peers fired arp_spoofing_detected within one scan window"
}
```


## Integration into daemon tick

```
nmap → ingest → Comparator
                    ↓
             FleetCorrelator.analyse()   ← NEW
                    ↓ FleetEvents
             apply score boosts          ← NEW
                    ↓
             SuspiciousAgent (with fleet context)
                    ↓
             write_alert + write_fleet_alert
                    ↓
             Remediator
```


## Config additions

```json
"fleet_min_window_seconds": 300,
"fleet_arp_min_peers": 2,
"fleet_route_min_peers": 3,
"fleet_os_min_peers": 3,
"fleet_identity_min_peers": 2,
"fleet_service_min_peers": 4,
"fleet_ttl_min_peers": 3
```

All default to the values in the pattern table above.


## Simulation tests

Add `tests/simulation/test_fleet_simulation.py` with scenarios:

| Scenario | Attack | Expected pattern |
|----------|--------|-----------------|
| F1 | ARP poisoning: 3 peers simultaneously get wrong MAC in ARP reply | `arp_poisoning` |
| F2 | Gateway swap: all peers show route hop change in same tick | `route_shift` |
| F3 | OS normalisation: attacker mimics baseline but slips on 4 peers | `os_normalisation` |
| F4 | Identity sweep: 2 peers show full identity change simultaneously | `identity_sweep` |

Each scenario: inject events directly into `PeerStore`, run `FleetCorrelator.analyse()`,
assert correct pattern fires and score boosts applied.


## Files to create / modify

| File | Change |
|------|--------|
| `src/peerwatch/fleet_correlator.py` | New — `FleetCorrelator`, `FleetEvent` |
| `src/peerwatch/peer_store.py` | Add `last_tick_at`, `add_suspicion()` |
| `src/peerwatch/agent.py` | Accept `fleet_events` kwarg, inject into prompt |
| `src/peerwatch/config.py` | Add fleet threshold fields |
| `daemon.py` | Call `FleetCorrelator`, pass events to agent, write fleet alerts |
| `config.example.json` | Document new fields |
| `tests/simulation/test_fleet_simulation.py` | New — F1–F4 scenarios |
| `prompts/suspicious_agent.txt` | Add fleet context section |


## Open questions

1. **Cross-tick persistence** — should a cluster that spans two ticks (partial events
   in tick N, rest in tick N+1) be merged? Simplest answer: no. Re-evaluate fresh each
   tick. Revisit if false negatives emerge in testing.

2. **Score boost cap** — should fleet boosts be capped to avoid runaway scores on
   noisy networks? Proposal: cap total fleet boost per peer per tick at +4.0.

3. **Threshold for LLM escalation** — fleet-boosted peers may cross the 3.0 threshold
   that would not have crossed it individually. This is the intended behaviour.
   Confirm with simulation tests that FPR stays low.
