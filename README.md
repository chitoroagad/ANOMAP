# PeerWatch

Autonomous network anomaly detection for local subnets. PeerWatch fingerprints devices via nmap, tracks device identity over time, detects coordinated attacks across the fleet, and triggers an LLM-backed investigation when suspicion crosses a threshold — optionally blocking offenders via iptables.

## How it works

Each scan tick runs a full detection pipeline:

1. **Scan** — nmap active scan of the configured subnet (XML → JSON)
2. **Ingest** — new scan files parsed and fed into `PeerStore` (keyed by MAC)
3. **Compare** — `Comparator` checks for temporal drift across all peers
4. **Passive capture** — scapy listener watches for ARP spoofing, TTL anomalies, TCP fingerprint mismatches, and route changes between scans
5. **Fleet correlation** — `FleetCorrelator` detects coordinated attack patterns across multiple peers in the same tick window
6. **Investigate** — peers above the suspicion threshold are passed to `SuspiciousAgent` (LLM via Ollama, falls back to rule-based)
7. **Remediate** — high-severity peers above the block floor are blocked via iptables (`dry_run` by default)

Suspicion scores decay exponentially (half-life: 3.5 days). A warmup period of 5 scans records baselines before scoring begins.

## Quick start

```sh
# 1. Enter dev shell
nix develop

# 2. Configure
cp config.example.json config.json
# Edit config.json — set subnet, model, never_block (include your gateway + self)

# 3. Run Ollama (separate terminal)
ollama run phi4

# 4. Start daemon (requires root for nmap OS detection)
sudo python daemon.py
```

Injection demo: drop a crafted nmap XML into `data/raw/` between scans — the daemon picks it up on the next tick.

### One-shot mode

```sh
# Loads data/processed/*.json, runs comparator + agent once
python main.py
```

## Requirements

- Python 3.11+ (via Nix flake)
- nmap in PATH, run as root for `-O` OS detection
- Ollama with `phi4:latest` — or set `model` in `config.json` to another local model
- scapy for passive capture (optional — capture is skipped if unavailable)
- Root/sudo for iptables enforcement

## Configuration

Copy `config.example.json` to `config.json`. All fields are optional; omitted fields use defaults.

| Field | Default | Meaning |
|---|---|---|
| `subnet` | `192.168.1.0/24` | Subnet to scan |
| `scan_interval_minutes` | `5` | Interval between nmap scans |
| `min_scan_interval_minutes` | `2` | Rate-limit floor |
| `suspicion_threshold` | `3.0` | Score that triggers LLM investigation |
| `model` | `phi4:latest` | Ollama model name |
| `remediation_mode` | `dry_run` | `dry_run` / `confirm` / `enforce` |
| `block_confidence_floor` | `5.0` | Min score required to trigger a block |
| `block_ttl_hours` | `24` | Auto-unblock after this many hours |
| `never_block` | `["192.168.1.1"]` | IPs/MACs exempt from blocking — add your gateway and self |
| `baseline_min_scans` | `5` | Warmup scans before scoring begins |
| `suspicion_half_life_days` | `3.5` | Exponential decay period |

## Suspicion scoring

### Phase 1 — nmap active scan

| Event | Score |
|---|---|
| OS family changed | +2.0 |
| Full identity shift (OS + ports + services) | +2.0 |
| Service type changed on known port | +1.0 / port |
| Port profile drifted (Jaccard < 0.6) | +0.5 |
| MAC conflict (same IP, different MAC) | +0.5 |
| Identity collision | +1.0 |
| Port/protocol mismatch (e.g. HTTP on port 22) | +3.0 |

### Phase 2 — passive capture

| Event | Score |
|---|---|
| TTL deviation > 15 from baseline | +2.0 |
| ARP reply claims wrong MAC for known peer | +3.0 |
| TCP fingerprint implies different OS than nmap | +2.0 |
| IP ID counter jump (sequential device only) | +1.0 |
| Route hop sequence changed | +1.0 |
| New ASN in traceroute path | +1.5 |

### Phase 3 — detection intelligence

| Event | Score |
|---|---|
| MAC OUI vendor contradicts nmap OS | +2.0 |
| SSH host key fingerprint changed | +3.0 |
| SSL/TLS certificate fingerprint changed | +2.0 |
| Fleet correlation boost | +1.0–+2.0 (capped at +4.0/tick) |

## Fleet correlation

`FleetCorrelator` fires when ≥ N peers show the same anomaly within one tick window and boosts each affected peer's score.

| Pattern | Trigger | Min peers | Boost |
|---|---|---|---|
| `arp_poisoning` | `arp_spoofing_detected` | 2 | +2.0 |
| `identity_sweep` | `full_identity_shift` or `identity_conflict_detected` | 2 | +2.0 |
| `route_shift` | `route_changed` | 3 | +1.5 |
| `os_normalisation` | `os_family_changed` | 3 | +1.5 |
| `ttl_shift` | `ttl_deviation` | 3 | +1.5 |
| `service_sweep` | `service_type_changed` | 4 | +1.0 |

Fleet context is injected into the LLM prompt so the agent reasons about coordinated attacks, not just isolated per-peer anomalies.

## Remediation

`Remediator` runs after `SuspiciousAgent` each tick. All four guards must pass before a block is issued:

1. IP/MAC not in `never_block`
2. `suspicion_score >= block_confidence_floor` (default 5.0)
3. `severity == "high"`
4. No active block already exists for this IP

Blocks are iptables `INPUT` + `OUTPUT` DROP rules. They expire automatically after `block_ttl_hours`. All decisions are appended to `blocks/blocks.jsonl` for audit. The LLM is **not** in the authorization path — enforcement is purely rule-based.

`enforce` mode silently downgrades to `dry_run` if not running as root.

## Output files

| Path | Contents |
|---|---|
| `alerts/alerts.jsonl` | Per-peer investigation alerts (one JSON record per line) |
| `alerts/fleet_alerts.jsonl` | Fleet-level pattern alerts |
| `blocks/blocks.jsonl` | Remediation audit log |
| `reports/` | Full LLM investigation JSON reports |
| `data/peer_store.json` | Persistent device identity store |
| `logs/daemon.log` | All log output |

## Tests

```sh
pytest
```

143 tests covering Phase 1–3 detection scenarios (A–I), passive capture, fleet correlation (F1–F16), parser, and peer store. `PYTHONPATH` is configured via `pyproject.toml`.

## Project layout

```
daemon.py                   production entry point — periodic scan loop
main.py                     one-shot entry point
config.example.json         all config fields with defaults
src/peerwatch/
  parser.py                 nmap XML host → NormalisedData
  peer_store.py             device identity store + fingerprint comparisons
  comparator.py             temporal drift analyser (read-only, logs report)
  packet_capture.py         Phase 2: passive observation models + scapy loop
  route_tracker.py          Phase 2: traceroute stability + Team Cymru ASN lookup
  fleet_correlator.py       Phase 3: coordinated attack detection
  agent.py                  SuspiciousAgent — LLM investigation + rule-based fallback
  remediation.py            autonomous blocking via iptables
  config.py                 Pydantic config model
prompts/
  suspicious_agent.txt      LLM system prompt
tests/
  simulation/
    test_simulation.py      Phase 1+2 attack scenarios A–I (CVE/ATT&CK referenced)
    test_phase2_passive.py  Phase 2 passive capture unit tests
    test_fleet_simulation.py fleet correlation scenarios F1–F16
writeup/                    thesis source (Typst — nix develop .#writeup)
```

## Architecture notes

- `PeerStore` keys by MAC; MAC-less (volatile) devices key by IP and are evicted after `volatile_peer_ttl_hours`
- `known_services` per port suppresses oscillating nmap fingerprint false positives
- `SuspiciousAgent` uses LangChain + Ollama with `format="json"` for grammar-constrained output
- `PeerStore.last_tick_at` is stamped at the end of each tick and persisted, used by `FleetCorrelator` as the event window start
