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
- [ ] TTL consistency checker
  - For each known peer, track expected TTL; deviations suggest spoofing or routing changes
  - TTL fingerprinting: Linux defaults 64, Windows 128, Cisco 255
- [ ] IP ID sequence anomaly detection
  - Spoofed packets often have non-sequential or random IP ID fields
  - Collect IP ID sequences per source IP and flag statistical outliers
- [ ] Passive TCP/IP stack fingerprinting
  - Window size, TCP options order, and MSS are OS-specific and hard to fake
  - Cross-reference against nmap active OS detection in PeerStore
- [ ] ARP monitoring
  - Watch for ARP replies that don't match known MAC→IP mappings in PeerStore
  - ARP spoofing is a direct precursor to MITM — this is a high-value signal

### traceroute / Path Analysis
- [ ] Route stability tracker
  - Maintain expected hop sequence per destination
  - Sudden route changes (different ASN, new intermediate hop) are suspicious
- [ ] ASN consistency checks
  - Map each hop's IP to its ASN (Team Cymru BGP lookup or offline data)
  - Flag if a peer's traffic starts traversing unexpected ASNs
- [ ] Asymmetric route detection
  - Significant asymmetry between forward and reverse paths can indicate spoofing

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
