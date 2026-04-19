# PeerWatch — CLAUDE.md

Autonomous network anomaly detection tool. Fingerprints subnet devices via nmap, tracks identity over time in `PeerStore`, detects coordinated attacks via fleet-level correlation, and triggers LLM investigation when the suspicion threshold is crossed.

## Project layout

```
daemon.py                   production entry point — periodic scan loop
main.py                     one-shot entry point (legacy, still works)
config.json                 runtime config (copy from config.example.json)
config.example.json         all config fields with defaults documented
src/peerwatch/
  parser.py                 nmap XML host → NormalisedData
  peer_store.py             device identity store + fingerprint comparisons + passive ingest
  comparator.py             structural temporal drift analyser over PeerStore (logs report)
  packet_capture.py         Phase 2: passive observation models + scapy capture loop
  route_tracker.py          Phase 2: traceroute path stability + Team Cymru ASN lookup
  fleet_correlator.py       Phase 3: coordinated attack detection across multiple peers
  agent.py                  SuspiciousAgent — LLM investigation + rule-based fallback
  remediation.py            autonomous blocking via iptables (dry_run / confirm / enforce)
  config.py                 Pydantic config model — all thresholds and weights
  embedder.py               embedding helpers (unused in main pipeline)
  util.py                   shared helpers
prompts/
  suspicious_agent.txt      LLM system prompt (fleet context guide included)
data/
  raw/                      nmap XML (not committed)
  processed/                nmap JSON (not committed)
  peer_store.json           persistent PeerStore snapshot (not committed)
alerts/
  alerts.jsonl              per-peer investigation alerts (not committed)
  fleet_alerts.jsonl        fleet-level pattern alerts (not committed)
blocks/
  blocks.jsonl              remediation audit log (not committed)
reports/                    LLM investigation JSON reports (not committed)
logs/
  daemon.log                all logging output (not committed)
tests/
  simulation/
    test_simulation.py      Phase 1+2 attack scenarios A–I (CVE/ATT&CK referenced)
    test_phase2_passive.py  Phase 2 passive capture unit tests
    test_fleet_simulation.py fleet correlation scenarios F1–F16
  test_parser.py
  test_peer_store.py
  test_phase3.py
  test_embedder.py
scripts/                    one-off scripts (benchmark.py, etc.)
docs/                       design docs for implemented features
writeup/                    thesis in Typst (main.typ)
```

## Dev environment

Nix flake — `nix develop` for Python shell, `nix develop .#writeup` for Typst.

Requires Ollama running locally. Default model: `phi4:latest` (14B).
If Ollama is unavailable the agent falls back to rule-based severity assignment.

## Run

```sh
# Production daemon (requires root for nmap OS detection)
sudo python daemon.py
sudo python daemon.py --config /path/to/config.json

# One-shot (loads data/processed/*.json, runs comparator + agent)
python main.py
```

Injection demo — drop a crafted nmap XML into `data/raw/` between scans;
the daemon picks it up on the next tick via `convert_pending_xml()`.

## Test

```sh
pytest
```

143 tests. `PYTHONPATH` set to `src/` via `pyproject.toml`.

## Config

All thresholds, weights, and daemon settings live in `config.py` as a Pydantic
model. Copy `config.example.json` to `config.json` and adjust. Unset fields use
defaults. Key fields:

| Field | Default | Meaning |
|---|---|---|
| `subnet` | `192.168.1.0/24` | Subnet to scan |
| `scan_interval_minutes` | `5` | How often to run nmap |
| `min_scan_interval_minutes` | `2` | Rate-limit floor |
| `suspicion_threshold` | `3.0` | Score that triggers LLM investigation |
| `model` | `phi4:latest` | Ollama model |
| `remediation_mode` | `dry_run` | `dry_run` / `confirm` / `enforce` |
| `block_confidence_floor` | `5.0` | Min score to trigger a block |
| `never_block` | `[]` | IPs/MACs never blocked (add gateway + self) |

## Suspicion scoring

### Phase 1 — nmap active scan
| Event | Score |
|---|---|
| OS family changed | +2.0 |
| Full identity shift (OS + ports + services) | +2.0 |
| Service type changed on known port | +1.0/port |
| Port profile drifted (Jaccard < 0.6) | +0.5 |
| MAC conflict (same IP, different MAC) | +0.5 |
| Identity collision | +1.0 |
| Port/protocol mismatch (e.g. HTTP on port 22) | +3.0 |

### Phase 2 — passive capture
| Event | Score |
|---|---|
| TTL deviation > 15 from established baseline | +2.0 |
| ARP reply claims wrong MAC for known peer | +3.0 |
| TCP fingerprint implies different OS than nmap | +2.0 |
| IP ID counter jump (sequential device only) | +1.0 |
| Route hop sequence changed | +1.0 |
| New ASN in traceroute path | +1.5 |

### Phase 3 — detection intelligence
| Event | Score |
|---|---|
| MAC OUI vendor contradicts nmap OS (e.g. Apple MAC + Linux) | +2.0 |
| SSH host key fingerprint changed on known port | +3.0 |
| SSL/TLS certificate fingerprint changed on known port | +2.0 |
| Fleet correlation boost (coordinated attack pattern) | +1.0–+2.0 (capped at +4.0/tick) |

Investigation triggered at `suspicion_score ≥ 3.0`.

## Fleet correlation patterns

`FleetCorrelator` runs each tick after ingestion, before `SuspiciousAgent`.
A pattern fires when ≥ N peers show the same anomaly event within one tick window.

| Pattern | Trigger event(s) | Min peers | Boost |
|---|---|---|---|
| `arp_poisoning` | `arp_spoofing_detected` | 2 | +2.0 |
| `identity_sweep` | `full_identity_shift` or `identity_conflict_detected` | 2 | +2.0 |
| `route_shift` | `route_changed` | 3 | +1.5 |
| `os_normalisation` | `os_family_changed` | 3 | +1.5 |
| `ttl_shift` | `ttl_deviation` | 3 | +1.5 |
| `service_sweep` | `service_type_changed` | 4 | +1.0 |

Fleet context is injected into the LLM prompt so the agent reasons about
coordinated attacks, not just isolated per-peer anomalies.

## Remediation

`Remediator` runs after `SuspiciousAgent` each tick. Guards (all must pass):
1. IP/MAC not in `never_block`
2. `suspicion_score >= block_confidence_floor` (default 5.0)
3. `severity == "high"`
4. No active block already exists for this IP

Blocks are iptables INPUT+OUTPUT DROP rules with a configurable TTL
(`block_ttl_hours`, default 24h). Auto-unblocked on TTL expiry. All decisions
written to `blocks/blocks.jsonl` for audit. The LLM is NOT in the
authorization path — enforcement is purely rule-based.

`enforce` mode requires root; silently downgrades to `dry_run` otherwise.

## Architecture notes

- `PeerStore` keys devices by MAC; MAC-less (volatile) devices key by IP
- `known_services` per port suppresses oscillating nmap fingerprint false positives
- Suspicion decays exponentially: halves every 3.5 days (`suspicion_half_life_days`)
- Warmup period: first 5 scans (`baseline_min_scans`) record events but don't score
- `Comparator` reads the full `PeerStore` and logs a drift report; does not mutate state
- `SuspiciousAgent` calls LLM via LangChain + Ollama with `format="json"` for grammar-constrained output; falls back to rule-based severity if Ollama is unavailable
- `PeerStore.last_tick_at` is stamped at end of each tick and persisted; used by `FleetCorrelator` as the event window start
- Embedder (`embedder.py`) exists but structured comparison replaced the embedding-based approach
