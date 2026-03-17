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

- [ ] **Tune suspicion parameters**
  - Current values (OS +2.0, port drift +0.5, service change +1.0) are reasonable but untested
  - Validate against real scan data; adjust Jaccard threshold (0.6) based on observed variance

- [ ] **Add suspicion decay**
  - Suspicion only accumulates, never decays — a legitimate OS upgrade makes a device permanently suspicious
  - Implement time-based decay (e.g. suspicion halves after N days of clean scans)

- [ ] **Baseline warmup period**
  - First N scans of a new peer should build a baseline, not trigger anomaly detection
  - Only start scoring after baseline is stable (low variance across k scans)

- [ ] **Handle volatile/MAC-less peers**
  - Peers without a MAC live in the volatile pool forever
  - Add TTL / eviction policy for volatile peers with no recent activity

- [ ] **Wire up comparator.py to the main pipeline**
  - Currently unused; temporal drift analysis is valuable signal
  - Integrate scan-over-scan delta reporting into main.py

- [ ] **Check if service on a port matches expected protocol**
  - Is the service on port 22 actually SSH? Banner grabbing / protocol verification
  - Mismatches are strong indicators of backdoors; complements the current service type check

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
