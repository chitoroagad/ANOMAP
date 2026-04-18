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

<!-- - [ ] **Correlation across peers** -->
<!--   - If multiple peers show simultaneous fingerprint shifts, it may indicate a network event, not spoofing -->
<!--   - Fleet-level anomaly grouping to reduce false positives -->

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

- [ ] **Daemon / scheduler**
  - Run nmap scans on a configurable interval automatically
  - Queue new scan results without blocking

- [ ] **Alert output**
  - Currently just prints to stdout
  - Add structured alert output: JSON log, syslog, or webhook

- [ ] **Config file**
  - Hardcoded thresholds and suspicion increments should be configurable
  - YAML/TOML config for subnet targets, scan interval, alert thresholds

- [ ] **Scan rate limiting**
  - Overly frequent nmap scans can disrupt network operations
  - Enforce minimum scan intervals and warn when targets are outside local subnet

# Further Ideas
- [ ] Look into a computer hijacking another connected computer's connection to gain access to network
- [ ] Create features out of scanned RTTs and compare them across time
