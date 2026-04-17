# PeerWatch — CLAUDE.md

Autonomous network anomaly detection tool. Fingerprints subnet devices via nmap, tracks identity over time in `PeerStore`, triggers LLM investigation when suspicion threshold crossed.

## Project layout

```
main.py                     entry point
src/peerwatch/
  parser.py                 nmap XML host → NormalisedData
  peer_store.py             device identity store + fingerprint comparisons + Phase 2 ingest
  comparator.py             structural temporal drift analyser over PeerStore
  packet_capture.py         Phase 2: passive observation models + scapy capture loop
  route_tracker.py          Phase 2: traceroute path stability + Team Cymru ASN lookup
  agent.py                  SuspiciousAgent — LLM-driven investigation + reports
  embedder.py               embedding helpers (currently unused in main pipeline)
  util.py                   shared helpers
prompts/                    LLM system prompts (loaded at startup)
data/
  raw/                      nmap XML (not committed)
  processed/                nmap JSON (not committed)
reports/                    investigation JSON output (not committed)
logs/                       app.log (not committed)
tests/
  simulation/               attack scenario simulation tests (Phase 1 + Phase 2)
  test_parser.py
  test_peer_store.py
  test_embedder.py
scripts/                    one-off scripts
writeup/                    thesis in Typst
```

## Dev environment

Nix flake — `nix develop` for Python shell, `nix develop .#writeup` for Typst.

Requires Ollama running locally. Default model: `phi4-mini:latest`.

## Run

```sh
python main.py        # loads data/processed/*.json, runs comparator, investigates suspicious peers
```

Convert raw nmap XML → JSON first:
```sh
python -c "import main; main.jsonify(open('data/raw/scan.xml'))"
```

## Test

```sh
pytest
```

`PYTHONPATH` set to `src/` via `pyproject.toml`.

## Key constants (peer_store.py)

| Constant | Value | Meaning |
|---|---|---|
| `BASELINE_MIN_SCANS` | 5 | Warmup period — no scoring until 5 scans seen |
| `SUSPICION_HALF_LIFE_DAYS` | 3.5 | Exponential decay half-life |
| `VOLATILE_PEER_TTL_HOURS` | 24 | Evict MAC-less peers inactive this long |
| `PORT_PROTOCOL_MISMATCH_SUSPICION` | 3.0 | Score added for port/protocol mismatch |

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

Investigation triggered at `suspicion_score ≥ 3.0`.

## Architecture notes

- `PeerStore` keys devices by MAC; MAC-less (volatile) devices key by IP
- `known_services` per port suppresses oscillating nmap fingerprint false positives
- `Comparator` reads the full `PeerStore` and prints a drift report; does not mutate state
- `SuspiciousAgent` calls LLM via LangChain + Ollama, can run follow-up nmap/traceroute/tcpdump
- Embedder (`embedder.py`) exists but structured comparison replaced embedding-based approach
