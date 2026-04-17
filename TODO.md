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

- [ ] **LLM-based anomaly explanation**
  - Feed suspicious peer identity_history into an LLM to generate human-readable incident reports
  - Stub exists in main.py (say_hi_test); needs real prompt and integration with PeerStore output

- [ ] **Correlation across peers**
  - If multiple peers show simultaneous fingerprint shifts, it may indicate a network event, not spoofing
  - Fleet-level anomaly grouping to reduce false positives

- [ ] **MAC spoofing detection**
  - Current system trusts MAC as ground truth — but MACs can be spoofed
  - Cross-reference MAC OUI vendor against observed OS/device type (e.g. Apple MAC + Linux OS = suspicious)
  - Use passive fingerprint (tcpdump) as a second opinion on identity

---

## Phase 4 — Data & Validation

- [ ] **Collect labeled dataset**
  - Without labeled spoofing examples, can't measure precision/recall
  - Options: simulate spoofing in a lab network, CTF datasets, public IP spoofing datasets

- [ ] **Simulate attack scenarios for testing**
  - IP spoofing (same IP, different MAC)
  - MAC spoofing (same MAC, different OS/ports)
  - Service change (legitimate: upgrade; illegitimate: backdoor added)
  - Full identity takeover (new device, same IP+MAC)

- [ ] **Benchmark comparison approaches**
  - Structured (current) vs hybrid (structured + embeddings for service banners)
  - Metric: false positive rate on real scan data, detection rate on simulated attacks

---

## Phase 5 — Production & Architecture

- [ ] **Persistent storage**
  - PeerStore currently lives in memory; add SQLite or JSON-on-disk persistence
  - Required for long-running daemon and reboot survival; known_services must also persist

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
