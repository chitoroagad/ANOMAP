# PeerWatch TODO

## Done
- [x] Make useful peer store to have baseline of peers to compare new measurements against
- [x] Make peer store compare incoming peer data
- [x] Replace embedding-based comparison with structured comparisons
  - OS family: categorical equality check
  - Ports: Jaccard similarity (threshold 0.6)
  - Services: per-port protocol type check (ignores version changes)
- [x] Per-port `service_type_changed` events with old/new service in details
- [x] Suppress oscillating service false positives via `known_services` per port

---

## Phase 1 — Strengthen Core nmap Pipeline

- [x] **Tune suspicion parameters**
  - Validated against 86 scans/device: port Jaccard stays 1.0 for stable devices; Jaccard 0.6 threshold is correct
  - Added comments to constants explaining the empirical basis

- [x] **Add suspicion decay**
  - Exponential decay: suspicion halves every 3.5 days (`SUSPICION_HALF_LIFE_DAYS`), ~6% remaining after 2 weeks
  - Applied per-scan based on elapsed time since `last_seen_at`

- [x] **Baseline warmup period**
  - First 5 scans (`BASELINE_MIN_SCANS`) build baseline; events are recorded but not scored
  - Eliminates false positives from noisy iOS/randomized-MAC devices with ephemeral ports

- [x] **Handle volatile/MAC-less peers**
  - `evict_stale_volatile_peers()` removes MAC-less peers inactive for 24 h (`VOLATILE_PEER_TTL_HOURS`)
  - Also fixed `is_volatile` bug: was `True if mac else False` (backwards), now `mac is None`

- [x] **Wire up comparator.py to the main pipeline**
  - Refactored `Comparator` to structural temporal drift analyser over a populated `PeerStore`
  - `print_report()` called in `main.py` before agent investigation

- [x] **Check if service on a port matches expected protocol**
  - `_check_port_protocol_mismatches()` checks well-known ports (22→ssh, 80→http, 5432→postgresql, etc.)
  - Fires once per port via `flagged_port_mismatches`; adds +3.0 suspicion (`PORT_PROTOCOL_MISMATCH_SUSPICION`)

---

## Phase 2 — Additional Data Sources

### tcpdump / Passive Packet Capture
- [x] TTL consistency checker
  - `ingest_ttl_observation(ip, ttl)` — builds median-based baseline (TTL_BASELINE_MIN_SAMPLES=5),
    snaps to OS default (64/128/255), flags deviations > 15 with +2.0 suspicion
  - `snap_ttl_to_os_default()` / `ttl_to_os_hint()` helpers in `packet_capture.py`
- [x] IP ID sequence anomaly detection
  - `ingest_ip_id_observation(ip, ip_id)` — detects sequential pattern then flags jumps
    > IP_ID_JUMP_THRESHOLD (5000) as spoofing indicator (+1.0)
  - `_detect_sequential_ip_ids()` uses median delta; random IDs (Linux) stay silent
- [x] Passive TCP/IP stack fingerprinting
  - `ingest_tcp_fingerprint(ip, window_size, tcp_options, mss)` — infers OS via
    penalty-weighted signature matching; flags contradiction with nmap OS (+2.0)
  - `infer_os_from_tcp_fingerprint()` in `packet_capture.py` with known profiles
    for Linux, Windows, macOS
- [x] ARP monitoring
  - `ingest_arp_observation(ip, mac)` — compares claimed MAC against known peer MAC;
    fires `arp_spoofing_detected` event + 3.0 suspicion (highest single-event score)
  - `PassiveCaptureObserver` + `SniffCaptureLoop` in `packet_capture.py` for live capture

### traceroute / Path Analysis
- [x] Route stability tracker
  - `RouteTracker.observe(destination)` runs traceroute and compares against baseline
  - `ingest_route_change(ip, destination, hops, change_kind)` scores peer (+1.0 / +1.5)
  - `known_routes` dict on each Peer stores per-destination hop sequence
- [x] ASN consistency checks
  - `lookup_asn(ip)` via Team Cymru DNS (`origin.asn.cymru.com`) with whois fallback
  - `RouteChangeKind.NEW_ASN_IN_PATH` fires when novel ASN appears in path (+1.5)
- [x] Asymmetric route detection
  - `RouteTracker.check_asymmetry(forward, reverse)` — Jaccard on responding IPs;
    flags paths with similarity < 0.5 as `ASYMMETRIC_PATH`

---

## Phase 3 — Detection Intelligence

- [x] **LLM-based anomaly explanation**
  - `SuspiciousAgent._analyse()` formats full peer context (fingerprint + event history) and calls local Ollama LLM
  - Returns structured `AgentDecision` (severity, explanation, recommended scans); executes scans; writes JSON report to `reports/`
  - Prompt in `prompts/suspicious_agent.txt`; wired into `main.py` via `agent.investigate_all()`

- [x] **Correlation across peers**
  - `FleetCorrelator` detects coordinated attacks across multiple peers in one scan tick
  - 6 named patterns: `arp_poisoning`, `route_shift`, `os_normalisation`, `identity_sweep`, `service_sweep`, `ttl_shift`
  - Applies configurable suspicion boosts (capped at `fleet_boost_cap`) and records `fleet_correlation_boost` events
  - Fleet context injected into LLM prompt so agent can reason about coordinated attacks
  - `alerts/fleet_alerts.jsonl` — separate audit trail for fleet events
  - 7 simulation tests covering F1–F4 attack scenarios, below-threshold guard, boost cap, and first-tick no-op

- [x] **MAC spoofing detection**
  - `VENDOR_OS_COMPATIBILITY` maps constrained vendor keywords (Apple, Raspberry Pi, Microsoft…) to expected OS families
  - `_check_mac_vendor_os_mismatch()` runs post-warmup, fires once per peer (`flagged_vendor_mismatch` guard), adds +2.0 suspicion
  - Records `mac_vendor_os_mismatch` event with vendor, expected families, observed families

---

## Phase 4 — Data & Validation

- [x] **Collect labeled dataset**
  - 11 labelled simulation scenarios (A–J + clean) serve as ground-truth benchmark data
  - `scripts/benchmark.py` exports per-scenario records to `data/benchmark_results.jsonl`
  - Labels: scenario ID, name, attack type, should_detect, final score, detected, events fired

- [x] **Simulate attack scenarios for testing**
  - `tests/simulation/test_simulation.py` scenarios A–I cover:
    IP spoofing, service backdoor, MAC spoofing, cross-device conflict,
    OS fingerprint-only spoof, multi-port takeover, IoT botnet, incremental compromise,
    service mimicry evasion (documented detection limit)
  - Each scenario tied to a CVE / MITRE ATT&CK reference with score breakdown comments

- [x] **Benchmark comparison approaches**
  - `scripts/benchmark.py` — runs all scenarios, computes TP/FP/TN/FN, precision, recall, F1, FPR
  - Phase 1+3 (nmap structured): precision=1.00, recall=1.00, F1=1.00, FPR=0.00 on simulation set
  - Known undetected attacks: D (cross-device conflict, needs Phase 2), E (OS-only below threshold), I (service mimicry — documented limit)
  - Hybrid (structured + embeddings) deferred: embedder.py exists but embedding approach replaced by structured comparison due to superior determinism and lower latency

---

## Phase 5 — Production & Architecture

- [x] **Persistent storage**
  - JSON-on-disk snapshot via `PeerStore.save()` / `PeerStore.load()`
  - All peer state persists: suspicion scores, known_services, TTL baselines, SSH/SSL anchors, identity history
  - `ingested_scan_files` set prevents double-ingest on reload

- [x] **Daemon / scheduler**
  - `daemon.py` runs nmap on a configurable interval (`scan_interval_minutes`)
  - Injection demo path: drop crafted XML into `data/raw/`, picked up on next tick
  - Graceful SIGINT/SIGTERM shutdown

- [x] **Alert output**
  - `alerts/alerts.jsonl` — one JSON record per alert (ts, peer_id, ip, mac, score, severity, events, explanation, recommended_actions)

- [x] **Config file**
  - `src/peerwatch/config.py` — Pydantic model with all thresholds, weights, and daemon settings
  - `config.example.json` documents every field with defaults

- [x] **Scan rate limiting**
  - `min_scan_interval_minutes` enforced in daemon main loop
  - RFC 1918 check warns (with 5 s abort window) if subnet is public

---

## Phase 6 — Thesis Writing (highest priority)

- [ ] **Write the thesis**
  - Abstract, introduction, related work, methodology, evaluation, conclusion — all placeholder/empty
  - Core argument to make: structured fingerprint comparison + passive capture + fleet correlation + LLM explanation outperforms simple ARP monitoring (arpwatch)
  - Sections needed: motivation, architecture overview, detection pipeline (Phases 1–3), fleet correlation, evaluation, limitations, future work

- [ ] **Real-world evaluation on live traffic**
  - Run daemon against an actual home/lab network for several hours with known-clean devices
  - Record false positive rate — simulation F1=1.00 says nothing about clean-traffic FPR
  - Document what the tool produces on normal traffic to answer the inevitable reviewer question

- [ ] **Comparison against existing tools**
  - arpwatch: detects MAC-IP mapping changes only — no OS/service/route/TTL signals
  - Show at least one attack scenario (e.g. scenario A ARP poisoning) that both tools catch, and one (e.g. scenario B service backdoor) that only PeerWatch catches
  - Framing: PeerWatch adds multi-layer evidence accumulation; arpwatch is single-signal

- [ ] **Document known detection limits**
  - Scenario E (OS fingerprint spoofing below threshold): by design, single-signal below 3.0 is not flagged
  - Scenario I (service mimicry): not detected — attacker mirrors exact service fingerprint, structured comparison has no signal
  - Fleet correlation for scenario D: cross-device conflict needs Phase 2 passive data to reach threshold in isolation; fleet boost helps when multiple peers are targeted

---

## Phase 7 — Code Quality

- [ ] **Fix `_resolve_conflict` survivor selection bug**
  - `peer_store.py` line ~824: `max(peers, key=lambda p: p.is_volatile)` picks the *more* volatile peer as survivor — should be `not p.is_volatile` to prefer the confirmed-MAC peer
  - Remove the `print("Check this as it might be broken")` debug statements

- [ ] **Replace `print()` with `logging` throughout**
  - `peer_store.py`: `save()` and `load()` both call `print()` alongside `logging.info()`
  - `agent.py`: `investigate_all()`, `investigate()` use `print()` for progress output
  - `comparator.py`: `print_report()` writes directly to stdout — should be `logging.info` so output goes to the daemon log file

- [ ] **Graceful Ollama fallback**
  - If Ollama is unreachable, `SuspiciousAgent` logs a warning but the investigation silently returns the fallback `AgentDecision`
  - Add a rule-based severity assignment as explicit fallback: score ≥ 7 → high, ≥ 4 → medium, else low
  - Log clearly when fallback is active so operators know LLM analysis is degraded

---

## Phase 8 — Detection Improvements

- [ ] **DHCP fingerprinting**
  - DHCP option order and the set of requested options are OS-specific signatures independent of TCP/IP stack
  - Add `ingest_dhcp_observation(ip, option_order, requested_params)` to `PeerStore`
  - Infer OS from DHCP fingerprint (use fingerbank or a small local table); cross-reference with nmap OS
  - Mismatch adds ~+2.0 suspicion — same weight as TCP fingerprint mismatch
  - Requires passive capture (scapy filter: `port 67 or port 68`)

- [ ] **Fleet simulation coverage for scenario D**
  - Scenario D (cross-device identity conflict) currently scores ≥ 1.0 — below the 3.0 threshold
  - Add a fleet simulation test that drives two peers into identity conflict simultaneously and verifies `identity_sweep` fires and boosts both peers above threshold
