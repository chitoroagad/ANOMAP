# PeerWatch — Anomaly Detection for Subnets

Autonomous sysadmin tool that fingerprints network devices using `nmap` and detects suspicious changes over time. Devices are tracked in a `PeerStore` — each new scan is compared against the device's known fingerprint and a suspicion score is accumulated when anomalies are found. Peers that cross the suspicion threshold are investigated by an LLM agent which explains the anomaly, runs follow-up scans, and writes a report.

## How it works

```
nmap XML scans
      ↓
  NmapParser          normalises raw nmap output into a structured fingerprint
      ↓
  PeerStore           tracks devices by MAC/IP, compares fingerprints across scans:
                        - OS family change (categorical)
                        - Port set drift (Jaccard similarity)
                        - Service type change per port
                        - Oscillation suppression via known_services
      ↓
  SuspiciousAgent     triggered when suspicion_score ≥ threshold:
                        - LLM explains what changed and why it is suspicious
                        - Recommends and executes follow-up scans (nmap/traceroute/tcpdump)
                        - Writes JSON investigation report to reports/
```

## Setup

### Nix

```sh
nix develop
```

### Pip

```sh
pip install -r _requirements.txt
```

Requires Ollama running locally with a model pulled, e.g.:

```sh
ollama pull phi4-mini
```

## Preparing scan data

Convert nmap XML output to the JSON format expected by `PeerStore` using the `jsonify()` helper in `main.py`, then place the files in `data/processed/`:

```sh
python -c "
import main
with open('data/raw/your_scan.xml') as f:
    main.jsonify(f)
"
```

Or run nmap directly and save as XML:

```sh
nmap -sV -O --osscan-guess -oX scan.xml 192.168.1.0/24
```

## Run

```sh
python main.py
```

This will:
1. Load all JSON files from `data/processed/`
2. Build the `PeerStore` baseline from the first scan of each device
3. Detect anomalies across subsequent scans
4. Investigate any peer with `suspicion_score ≥ 3.0` using the LLM agent
5. Write investigation reports to `reports/`

## Report format

Each investigation produces a JSON file at `reports/investigation_<mac>_<timestamp>.json`:

```json
{
  "peer_id": "...",
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "ips": ["192.168.1.5"],
  "suspicion_score": 4.5,
  "severity": "high",
  "explanation": "The device's OS family changed from Linux to Windows...",
  "recommended_scans": [
    {"type": "nmap", "reason": "Verify current OS and open ports"},
    {"type": "traceroute", "reason": "Check if the network path has changed"}
  ],
  "scan_results": [...],
  "recommended_actions": [
    "Check ARP table for MAC aa:bb:cc:dd:ee:ff",
    "Verify physical device identity at 192.168.1.5"
  ]
}
```

## Suspicion scoring

| Event | Score |
|---|---|
| OS family changed | +2.0 |
| Full identity shift (OS + ports + services all changed) | +2.0 |
| Service type changed on a known port (e.g. SSH → HTTP on port 22) | +1.0 per port |
| Port profile drifted (Jaccard < 0.6) | +0.5 |
| MAC conflict (same IP, different MAC) | +0.5 |
| Identity collision (MAC and IP match different peers) | +1.0 |

Oscillating service names (e.g. nmap alternating between two valid fingerprints on the same port) are suppressed after first detection via `known_services`.

## Project structure

```
main.py                     entry point
src/
  peerwatch/
    parser.py               normalises nmap XML host data → NormalisedData
    peer_store.py           device identity store + fingerprint comparison
    agent.py                LLM investigation agent
    util.py                 shared helpers
data/
  raw/                      nmap XML scans (not committed)
  processed/                nmap JSON scans (not committed)
prompts/                    LLM system prompts
reports/                    investigation output (not committed)
logs/                       app.log (not committed)
tests/
scripts/
writeup/                    thesis writeup (Typst)
```
