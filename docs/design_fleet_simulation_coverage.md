# Fleet Simulation — Full Coverage Design Doc

## Current state

`tests/simulation/test_fleet_simulation.py` has 7 tests (F1–F7).

| Test | Pattern | What it covers |
|------|---------|----------------|
| F1 | `arp_poisoning` | 3 peers, boost applied, event recorded |
| F2 | `route_shift` | 4 peers, event_count correct |
| F3 | `os_normalisation` | 3 peers, boost amount correct |
| F4 | `identity_sweep` | via `full_identity_shift`, peer_ids correct |
| F5 | — | single peer below min_peers → no pattern |
| F6 | — | boost cap across two patterns |
| F7 | — | first-tick no-op (last_tick_at is None) |

## Coverage gaps

### 1. Uncovered patterns

`service_sweep` and `ttl_shift` have no tests. `identity_sweep` is only tested
via `full_identity_shift`; the pattern also matches `identity_conflict_detected`
but that OR branch is untested.

### 2. Window boundary

No test verifies that events recorded *before* `last_tick_at` are excluded from
fleet matching. An off-by-one in the `>=` comparison would silently include stale
events from previous ticks, producing false fleet detections on warm restarts.

### 3. Threshold integration (Scenario D closure)

The key thesis claim for fleet correlation is: a peer that individually stays
*below* the 3.0 investigation threshold can be pushed *above* it when the same
anomaly occurs fleet-wide. No test currently exercises this path end-to-end
(i.e. peers at score ~1.5 + fleet boost → crosses threshold).

This directly closes the Scenario D gap noted in the benchmark: cross-device
identity conflict produces a score of ≥1.0 per peer individually, which is
below the threshold. When two devices show identity conflict simultaneously,
`identity_sweep` fires and boosts both by +2.0, reaching ≥3.0.

### 4. Partial fleet match

No test verifies that non-matching peers in a mixed store are *not* boosted.
If the boost logic iterates `store.peers` instead of `matching_peer_ids`, all
peers would be affected — a silent bug.

### 5. Multiple events per peer within a window

`event_count` on `FleetEvent` should reflect how many pattern events fired
across all matching peers, not just how many peers matched. No test fires the
same event type more than once per peer.

### 6. Empty tick (no events in window)

`last_tick_at` is set but no events were recorded this tick. Should return an
empty list without error. Currently untested — distinct from F7 (which has no
`last_tick_at` at all).

### 7. FleetEvent field correctness

No test does a complete field check on a `FleetEvent`: that `window_start <
window_end`, that `ips` contains the IPs of matched peers only, that
`description` mentions the peer count and event types.


## New scenarios

### F8 — Service sweep

**Attack:** attacker installs backdoor services on 4 hosts simultaneously;
each host's port fingerprint changes service type on a known port.

**Setup:** 4 peers warmed up; inject `service_type_changed` on each.

**Assertions:**
- `service_sweep` pattern fires
- All 4 peer_ids in the FleetEvent
- Each peer's score increased by +1.0

---

### F9 — TTL shift (infrastructure MITM)

**Attack:** a MITM device is inserted between the scanner and 3 hosts,
slightly altering observed TTLs as packets transit an extra hop.

**Setup:** 3 peers warmed up; inject `ttl_deviation` on each.

**Assertions:**
- `ttl_shift` pattern fires
- Boost of +1.5 applied to each peer

---

### F10 — Identity sweep via `identity_conflict_detected`

**Attack:** 2 peers each resolve an identity conflict (same IP, different MAC)
in the same tick — indicative of ARP cache manipulation affecting device
resolution, not just TTL or OS.

**Setup:** 2 peers; inject `identity_conflict_detected` (not `full_identity_shift`).

**Assertions:**
- `identity_sweep` fires (verifies the OR branch: `identity_conflict_detected`
  is in the pattern's event_types set alongside `full_identity_shift`)
- Both peers boosted by +2.0

---

### F11 — Window boundary: stale events excluded

**Attack simulation:** events from a previous tick (before `last_tick_at`) must
not contribute to fleet detection.

**Setup:** 3 peers; inject `arp_spoofing_detected` with timestamp
`last_tick_at - 1 second` (stale). Then inject `arp_spoofing_detected` with
current timestamp on only 1 peer.

**Assertions:**
- `arp_poisoning` does NOT fire (only 1 peer has an in-window event;
  min_peers=2 not met)
- Verifies the `e.timestamp >= window_start` filter is correct

---

### F12 — Threshold crossing via fleet boost (Scenario D closure)

**Attack:** two devices show simultaneous identity conflicts — each scores
~1.0 individually (below the 3.0 investigation threshold), but the fleet
boost tips both over.

**Setup:** 2 peers with `fleet_identity_min_peers=2`. Use `add_or_update_peer`
to generate a real `identity_conflict_detected` event on both peers so the
score accumulates naturally (not via `_inject_event`). Verify score is below
threshold before fleet analysis.

**Assertions:**
- Both peers below 3.0 before `FleetCorrelator.analyse()`
- `identity_sweep` fires
- Both peers above 3.0 after fleet boost
- Confirms fleet correlation is the mechanism that makes Scenario D detectable

---

### F13 — Partial fleet match: non-matching peers unaffected

**Setup:** 5 peers warmed up; inject `arp_spoofing_detected` on only 3 of them.
`fleet_arp_min_peers=2`.

**Assertions:**
- `arp_poisoning` fires with `peer_ids` containing exactly the 3 matching peers
- The 2 non-matching peers have no `fleet_correlation_boost` event
- The 2 non-matching peers' scores are unchanged

---

### F14 — Multiple events per peer: event_count accuracy

**Setup:** 2 peers; inject `arp_spoofing_detected` twice on each (4 total
events). `fleet_arp_min_peers=2`.

**Assertions:**
- `arp_poisoning` fires
- `fe.event_count == 4`
- Score boost is still +2.0 per peer (boost is per-peer, not per-event)

---

### F15 — Empty tick: no events recorded

**Setup:** store with `last_tick_at` set; peers warmed up but no new events
injected after `last_tick_at`.

**Assertions:**
- `FleetCorrelator.analyse()` returns `[]`
- No peer scores change

---

### F16 — FleetEvent field completeness

**Setup:** F1-equivalent (3 peers, `arp_poisoning`).

**Assertions (exhaustive field check):**
- `fe.window_start < fe.window_end`
- `set(fe.peer_ids) == {p.internal_id for p in peers}`
- `set(fe.ips) == {ip for p in peers for ip in p.ips}`
- `fe.event_count == 3`
- `fe.suspicion_boost == 2.0`
- `"arp_poisoning"` in `fe.description`
- `"3"` in `fe.description` (peer count mentioned)


## Summary table

| Test | Pattern(s) | New coverage |
|------|-----------|--------------|
| F8 | `service_sweep` | Previously untested pattern |
| F9 | `ttl_shift` | Previously untested pattern |
| F10 | `identity_sweep` | OR branch via `identity_conflict_detected` |
| F11 | — | Window boundary: stale events excluded |
| F12 | `identity_sweep` | Threshold crossing — Scenario D closure |
| F13 | `arp_poisoning` | Non-matching peers are not boosted |
| F14 | `arp_poisoning` | `event_count` reflects multi-event peers |
| F15 | — | Empty-tick returns empty list |
| F16 | `arp_poisoning` | All FleetEvent fields verified |


## Files to change

| File | Change |
|------|--------|
| `tests/simulation/test_fleet_simulation.py` | Add F8–F16 |
| `TODO.md` | Mark Scenario D closure item done after F12 passes |

No changes needed to `FleetCorrelator` or `PeerStore` — all gaps are test gaps,
not implementation gaps (except F11 which may expose a real boundary bug).
