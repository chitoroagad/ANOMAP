# PeerWatch

Autonomous network anomaly detection for home and small-office subnets.
PeerWatch fingerprints devices via nmap, tracks device identity over time across
three independent signal layers, detects coordinated attacks across the fleet,
and triggers an LLM-backed investigation when suspicion crosses a threshold —
optionally blocking offenders via iptables.

No cloud dependency. No managed switching required. Runs on any Linux.

---

## How it works

Each scan tick runs a full detection pipeline:

1. **Active scan** — nmap `-sV -O` scan of the configured subnet (XML → JSON)
2. **Ingest** — scan files parsed and fed into `PeerStore` (keyed by MAC address)
3. **Passive capture** — Scapy listener tracks ARP replies, TTL baselines, TCP stack fingerprints, and route paths between scans
4. **Fleet correlation** — `FleetCorrelator` detects co-temporal anomaly patterns across multiple peers in the same tick window
5. **Investigate** — peers above the suspicion threshold are passed to `SuspiciousAgent` (Phi-4 via Ollama, falls back to rule-based scoring)
6. **Remediate** — high-severity peers above the block floor are blocked via iptables (`dry_run` by default)

Suspicion scores decay exponentially (half-life: 3.5 days by default).
A warmup period of 5 scans records baselines before scoring begins.

---

## Quick start

### Prerequisites

**Nix with flakes enabled.** Add to `~/.config/nix/nix.conf` or `/etc/nix/nix.conf`:

```
experimental-features = nix-command flakes
```

On NixOS: `nix.settings.experimental-features = ["nix-command" "flakes"];`

**Ollama** with Phi-4 pulled:

```sh
ollama serve
ollama pull phi4
```

The daemon falls back to rule-based severity if Ollama is unreachable — no features are disabled.

### Installation

```sh
git clone https://github.com/chitoroagad/peerwatch
cd peerwatch
nix develop

cp config.example.json config.json
# Edit config.json — at minimum set subnet and never_block
```

### Minimum config.json

```json
{
  "subnet": "192.168.1.0/24",
  "never_block": ["192.168.1.1", "192.168.1.X"]
}
```

Always add your gateway IP and the monitoring host's own IP to `never_block`
before enabling `enforce` mode.

### Run

```sh
# Production daemon — requires root for nmap OS detection
sudo python daemon.py
sudo python daemon.py --config /path/to/config.json

# One-shot (loads data/processed/*.json, runs comparator + agent once)
python main.py
```

**Injection demo:** drop a crafted nmap XML into `data/raw/` between scans —
the daemon picks it up on the next tick via `convert_pending_xml()`.

---

## Configuration

All fields are optional; omitted fields use the defaults shown.

| Field                       | Default          | Meaning                                                    |
| --------------------------- | ---------------- | ---------------------------------------------------------- |
| `subnet`                    | `192.168.1.0/24` | Subnet to scan                                             |
| `scan_interval_minutes`     | `5`              | Scan cadence                                               |
| `min_scan_interval_minutes` | `2`              | Rate-limit floor (prevents overlapping scans)              |
| `suspicion_threshold`       | `3.0`            | Score that triggers LLM investigation                      |
| `block_confidence_floor`    | `5.0`            | Minimum score to trigger a block                           |
| `model`                     | `phi4:latest`    | Ollama model name                                          |
| `remediation_mode`          | `dry_run`        | `dry_run` / `confirm` / `enforce`                          |
| `never_block`               | `[]`             | IPs/MACs never blocked — **always include gateway + self** |
| `baseline_min_scans`        | `5`              | Warmup scans before scoring begins                         |
| `suspicion_half_life_days`  | `3.5`            | Exponential decay half-life                                |
| `block_ttl_hours`           | `24`             | Auto-unblock TTL                                           |

---

## Suspicion scoring

### Phase 1 — nmap active scan

| Event                                                  | Score       |
| ------------------------------------------------------ | ----------- |
| OS family changed                                      | +2.0        |
| Full identity shift (OS + ports + services all change) | +2.0        |
| Service type changed on known port                     | +1.0 / port |
| Port profile drifted (Jaccard < 0.6)                   | +0.5        |
| MAC conflict (same IP, different MAC)                  | +0.5        |
| Identity collision                                     | +1.0        |
| Port/protocol mismatch (e.g. HTTP on port 22)          | +3.0        |

### Phase 2 — passive capture

| Event                                          | Score |
| ---------------------------------------------- | ----- |
| TTL deviation > 15 from established baseline   | +2.0  |
| ARP reply claims wrong MAC for known peer      | +3.0  |
| TCP fingerprint implies different OS than nmap | +2.0  |
| IP ID counter jump (sequential device only)    | +1.0  |
| Route hop sequence changed                     | +1.0  |
| New ASN in traceroute path                     | +1.5  |

### Phase 3 — detection intelligence

| Event                                                       | Score                        |
| ----------------------------------------------------------- | ---------------------------- |
| MAC OUI vendor contradicts nmap OS (e.g. Apple MAC + Linux) | +2.0                         |
| SSH host key fingerprint changed on known port              | +3.0                         |
| SSL/TLS certificate fingerprint changed on known port       | +2.0                         |
| Fleet correlation boost (coordinated attack pattern)        | +1.0–+2.0 (capped +4.0/tick) |

---

## Fleet correlation

`FleetCorrelator` fires when ≥ N peers show the same anomaly class within one
tick window and boosts each affected peer's score.

| Pattern            | Trigger event(s)                                      | Min peers | Boost |
| ------------------ | ----------------------------------------------------- | --------- | ----- |
| `arp_poisoning`    | `arp_spoofing_detected`                               | 2         | +2.0  |
| `identity_sweep`   | `full_identity_shift` or `identity_conflict_detected` | 2         | +2.0  |
| `route_shift`      | `route_changed`                                       | 3         | +1.5  |
| `os_normalisation` | `os_family_changed`                                   | 3         | +1.5  |
| `ttl_shift`        | `ttl_deviation`                                       | 3         | +1.5  |
| `service_sweep`    | `service_type_changed`                                | 4         | +1.0  |

Fleet context is injected into the LLM prompt so the agent reasons about
coordinated attacks, not just isolated per-peer anomalies.
A boost cap (default 4.0/tick) prevents adversarial score inflation.

---

## Remediation

`Remediator` evaluates each investigation report against five guards.
All must pass before a block is issued:

1. IP/MAC not in `never_block`
2. `suspicion_score >= block_confidence_floor` (default 5.0)
3. `severity == "high"`
4. At least one IP available for the peer
5. No active block already exists for this IP

Blocks insert iptables `INPUT DROP` + `OUTPUT DROP` rules and expire
automatically after `block_ttl_hours`.
All decisions — including dry-run non-executions — are written to
`blocks/blocks.jsonl` for audit.

**The LLM is not in the authorisation path.** Enforcement is purely rule-based.

`enforce` mode silently downgrades to `dry_run` if not running as root.

### Enforcement modes

| Mode      | Behaviour                                                |
| --------- | -------------------------------------------------------- |
| `dry_run` | Logs what would happen; no iptables calls (safe default) |
| `confirm` | Prints the command and waits for operator `y/N`          |
| `enforce` | Executes iptables rules immediately; requires root       |

---

## Reading alerts

**Per-device alerts** (`alerts/alerts.jsonl`):

```json
{
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "ips": ["192.168.1.42"],
  "suspicion_score": 4.5,
  "severity": "medium",
  "explanation": "OS family changed from Linux to Windows...",
  "recommended_actions": ["Re-scan device", "Verify physically"]
}
```

**Fleet alerts** (`alerts/fleet_alerts.jsonl`):

```json
{
  "pattern": "arp_poisoning",
  "ips": ["192.168.1.10", "192.168.1.11"],
  "suspicion_boost": 2.0,
  "description": "2 peers fired arp_spoofing_detected in the same tick"
}
```

A fleet alert means a coordinated attack is likely. Each affected device also
receives an individual alert with fleet context included in the LLM explanation.

---

## Output files

| Path                           | Contents                                                                   |
| ------------------------------ | -------------------------------------------------------------------------- |
| `data/peer_store.json`         | Full device identity store snapshot (atomically written each tick)         |
| `alerts/alerts.jsonl`          | Per-peer investigation alerts (JSON Lines)                                 |
| `alerts/fleet_alerts.jsonl`    | Fleet-level pattern alerts (JSON Lines)                                    |
| `blocks/blocks.jsonl`          | Remediation audit log — all block decisions including dry-run (JSON Lines) |
| `reports/investigation_*.json` | Full LLM investigation reports with follow-up scan output                  |
| `logs/daemon.log`              | All log output from all pipeline stages                                    |

---

## Tests

```sh
nix develop
pytest
```

222 tests. No network access, root privileges, or running Ollama required.
All agent and remediation tests mock subprocess and LLM calls.

| Scope                                      | Tests |
| ------------------------------------------ | ----- |
| `PeerStore` and fingerprint comparison     | 28    |
| Attack scenarios A–I (Phase 1 active scan) | 39    |
| Fleet correlation F1–F16                   | 16    |
| Phase 2 passive capture signals            | 33    |
| Rule-based agent fallback                  | 12    |
| Remediation guard chain and modes          | 19    |
| Parser, comparator, persistence            | 33    |
| Config, decay, embedder                    | 22    |

Coverage: 67% overall; low coverage in `agent.py` (25%) and `route_tracker.py`
(30%) reflects code paths that require live Ollama or real network interfaces.

---

## Project layout

```
daemon.py                    production entry point — periodic scan loop
main.py                      one-shot entry point
config.example.json          all config fields with defaults documented
src/peerwatch/
  parser.py                  nmap XML host → NormalisedData
  peer_store.py              device identity store + fingerprint comparison + passive ingest
  comparator.py              temporal drift analyser (read-only, logs report)
  packet_capture.py          Phase 2: passive observation models + Scapy capture loop
  route_tracker.py           Phase 2: traceroute path stability + Team Cymru ASN lookup
  fleet_correlator.py        Phase 3: coordinated attack detection across peers
  agent.py                   SuspiciousAgent — LLM investigation + rule-based fallback
  remediation.py             autonomous blocking via iptables (dry_run / confirm / enforce)
  config.py                  Pydantic config model — all thresholds and weights
  embedder.py                embedding helpers (unused in main pipeline)
  util.py                    shared helpers
prompts/
  suspicious_agent.txt       LLM system prompt (includes Fleet Context Guide)
tests/
  simulation/
    test_simulation.py       Phase 1+2 attack scenarios A–I (CVE/ATT&CK referenced)
    test_phase2_passive.py   Phase 2 passive capture signal tests
    test_fleet_simulation.py Fleet correlation scenarios F1–F16
  test_agent_fallback.py
  test_comparator.py
  test_config.py
  test_decay.py
  test_parser.py
  test_peer_store.py
  test_persistence.py
  test_phase3.py
  test_remediation.py
scripts/                     one-off scripts (false_positive_analysis.py, etc.)
writeup/                     thesis source (Typst — nix develop .#writeup)
```

---

## Extending

**Add a scoring event:** define detection logic in `_compare_fingerprints()` or
`_check_incoming_fingerprint()` in `src/peerwatch/peer_store.py`, add the score
increment, and add a test.

**Add a fleet pattern:** one tuple in `_PATTERNS` in `src/peerwatch/fleet_correlator.py`
and one `int` field in `PeerWatchConfig` in `src/peerwatch/config.py`.
No other files need changes.

**Add a passive capture signal:** new `_observe_*()` method in
`src/peerwatch/packet_capture.py`, registered in the dispatch loop.
Results feed `PeerStore` via the existing `ingest_*()` interface.

---

## Writeup

The thesis is written in Typst. To compile:

```sh
nix develop .#writeup
typst compile writeup/main.typ writeup/main.pdf
```
