# PeerWatch — MEng/MSc Thesis TODO

This document tracks everything needed to turn the current implementation into a
defensible MEng/MSc thesis submission. It is organised by what must be done before
writing, what must be done while writing, and what the writing itself requires.

The central claim to defend:

> **Multi-signal evidence accumulation — combining active nmap fingerprinting,
> passive packet capture, and fleet-level co-occurrence analysis — detects a
> broader class of network spoofing attacks than single-signal ARP monitoring,
> with a comparable false positive rate on clean traffic.**

Everything below serves this claim or the academic scaffolding around it.

---

## T1 — Research Question & Scope (do first)

- [ ] **Write a one-paragraph research question statement**
  - State: what problem, what approach, what claim, what evaluation method
  - Use this as the north star for every decision below
  - Must be falsifiable: "we show X is better than Y by metric Z"
  - Suggested framing: "We evaluate whether multi-signal fingerprint accumulation
    detects spoofing attacks missed by ARP-only monitoring, and whether fleet-level
    co-occurrence reduces the per-peer false positive rate on clean traffic"

- [ ] **Define the threat model explicitly**
  - Attacker has local network access (same subnet)
  - Attacker can forge MAC addresses, ARP replies, and OS fingerprints
  - Attacker cannot modify TCP/IP stack behaviour (rules out Scenario I fully)
  - Attacker does not have physical access to change hardware
  - Out of scope: off-path attacks, WAN-level BGP hijacking, insider threats
  - Write this as a numbered list in the thesis — reviewers check threat models

- [ ] **Fix scope mismatch: the thesis currently describes an ML approach; the
  implementation uses structured heuristics**
  - Decide: is the LLM a "machine learning" component or an "explanation" component?
  - Correct framing: the detection pipeline is entirely rule-based and deterministic;
    the LLM provides structured natural-language triage of fired alerts
  - Update the thesis title to reflect this: drop "Machine Learning techniques"

---

## T2 — Literature Review

The literature review must cover four areas and position PeerWatch within each.
Aim for 20–30 cited works minimum at MSc level.

### T2a — ARP Spoofing & Network Spoofing Detection

- [ ] Read and cite: arpwatch (Leres & Jacobson, 1992) — the baseline to beat
- [ ] Read and cite: Bro/Zeek ARP policy framework (Paxson, 1999; zeek.org)
  — understand what Zeek's `arp-spoofing` policy detects vs. PeerWatch
- [ ] Read and cite: Dynamic ARP Inspection (DAI) in 802.1X — hardware-enforced
  ARP binding; explain why software detection is still needed in environments
  without managed switches
- [ ] Read and cite: ARPDefender, XArp, or any academic ARP IDS paper (search
  IEEE Xplore / ACM DL for "ARP spoofing detection" 2005–2020)
- [ ] Summarise: what signals do existing tools use? (MAC-IP binding only, or more?)
  What attacks do they miss? This sets up PeerWatch's contribution.

### T2b — Network Device Fingerprinting

- [ ] Read and cite: Nmap OS detection (Lyon, 2008 — "Nmap Network Scanning" book
  or the Nmap.org reference) — the technique PeerWatch builds on
- [ ] Read and cite: p0f (Zalewski, 2012, lcamtuf.coredump.cx/p0f3) — passive TCP
  fingerprinting; PeerWatch implements a subset of this
- [ ] Read and cite: Kohno et al. (2005) "Remote Physical Device Fingerprinting" —
  IEEE S&P — clock skew as a persistent device identity signal
- [ ] Read and cite: Aksoy et al. (2017) "Operating System Fingerprinting for
  Virtual Machines" or similar — fingerprinting accuracy limits
- [ ] Read and cite: one paper on DHCP fingerprinting (e.g. Fingerbank, or
  Barbhuiya et al.) — establishes this as a known passive signal
- [ ] Summarise: what features are stable device identity signals? What degrades?
  This justifies the multi-signal approach.

### T2c — Anomaly Detection in Network Security

- [ ] Read and cite: Chandola, Banerjee & Kumar (2009) "Anomaly Detection: A Survey"
  — ACM Computing Surveys — the canonical survey; situate PeerWatch's
  threshold-based scoring within the taxonomy
- [ ] Read and cite: one paper on CUSUM or sequential change detection applied to
  network data (TTL or IP ID) — justifies the baseline + deviation approach
- [ ] Read and cite: Lakhina et al. (2004) "Diagnosing Network-Wide Traffic
  Anomalies" — SIGCOMM — fleet-level anomaly detection precedent
- [ ] Read and cite: one paper using suspicion scoring / evidence accumulation
  (search for "belief accumulation IDS" or "evidence aggregation intrusion detection")
- [ ] Summarise: why is per-peer detection insufficient for coordinated attacks?
  What does the literature say about multi-host correlation? This is the gap
  that fleet correlation fills.

### T2d — LLM / AI in Security Operations

- [ ] Read and cite: one paper on LLM-assisted alert triage or SOC automation
  (search IEEE/ACM 2023–2024 for "LLM security operations" or "GPT SOC")
- [ ] Read and cite: one paper on explainability in security systems (XAI for IDS)
- [ ] Be honest: PeerWatch's LLM component is an explanation layer, not a detection
  layer. Frame it as "reducing analyst cognitive load" with a citation to the
  alert fatigue problem in SOC environments (many papers on this).
- [ ] Summarise: what is the state of the art in AI-assisted security? Where does
  PeerWatch fit? (Likely: simpler than cutting-edge, but more transparent and
  locally deployable)

---

## T3 — Evaluation Design (most important section)

The evaluation must be designed *before* running experiments, not after.
Write the evaluation plan as a section of the thesis first.

### T3a — Baseline Comparison

- [ ] **Implement arpwatch comparison in the benchmark**
  - Install arpwatch: `nix-env -i arpwatch` or equivalent
  - Run arpwatch on the same simulation scenarios (feed it the ARP traffic implied
    by each scenario)
  - Record: which scenarios does arpwatch detect? What is its alert output?
  - Add arpwatch results as a column in `data/benchmark_results.jsonl`
  - Expected result: arpwatch catches Scenario A (ARP poisoning) and nothing else.
    PeerWatch catches A, B, C, F, G, H. This is the core result table.

- [ ] **Add a Zeek comparison (stretch goal — strong if achievable)**
  - Zeek's `policy/protocols/arp/detect-MiTM.zeek` detects ARP-based MITM
  - If Zeek is available in the Nix environment, run it on PCAP replays of
    Scenario A and compare output
  - Even "Zeek detects scenario A only, same as arpwatch" is a useful result

- [ ] **Add per-phase ablation to the benchmark**
  - Add a `phases` parameter to `PeerWatchConfig` that can disable Phase 2/3 scoring:
    - `phases=1`: only nmap structured comparison (Jaccard, OS, service checks)
    - `phases=2`: Phase 1 + passive capture (TTL, ARP, TCP fingerprint, IP ID, route)
    - `phases=3`: Phase 1+2 + fleet correlation (all features, current system)
  - Run `scripts/benchmark.py` for each configuration
  - Show incremental detection improvement: phases=1 catches X/9, phases=2 catches Y/9,
    phases=3 catches Z/9
  - This directly proves the "multi-signal accumulation" claim

### T3b — False Positive Measurement (clean traffic)

- [ ] **Design the clean traffic experiment**
  - Run the daemon against your home network for a minimum of 4 hours
  - All devices must be known-clean (your own devices, no attacks)
  - Record: number of alerts fired, scores, events
  - Repeat 3 times on different days to check consistency
  - Report: FPR = alerts / total scans on clean traffic

- [ ] **Log the experiment conditions**
  - How many devices? (record count each run)
  - How many scan ticks? (record from daemon log)
  - What scan interval? (5 minutes default → ~48 ticks in 4 hours)
  - Device types present (laptop, phone, printer, router — without identifying info)
  - Any expected noise sources (iOS randomised MAC, smart TVs with changing ports)

- [ ] **Run the same clean traffic config for each ablation phase**
  - Check that disabling Phase 2/3 does not increase FPR on clean traffic
  - If Phase 2 increases FPR, that is an important result — document threshold tuning

- [ ] **Report FPR alongside TPR in the results table**
  ```
  | Configuration | Detected/9 | TPR  | FPR (clean) |
  |---------------|------------|------|-------------|
  | arpwatch      | 1/9        | 0.11 | ~0.00       |
  | PeerWatch P1  | X/9        | X.XX | X.XX        |
  | PeerWatch P2  | Y/9        | Y.YY | Y.YY        |
  | PeerWatch P3  | Z/9        | Z.ZZ | Z.ZZ        |
  ```

### T3c — Threshold Sensitivity Analysis

- [ ] **Run the benchmark across a range of suspicion_threshold values**
  - Test: 2.0, 2.5, 3.0, 3.5, 4.0, 5.0
  - For each: record TPR (detected/9) and FPR (alerts on clean traffic)
  - Plot ROC-style curve: TPR vs FPR as threshold varies
  - This justifies the 3.0 default empirically instead of by intuition

- [ ] **Run sensitivity analysis on the key weights**
  - `arp_spoof_suspicion`: vary ±50% from default (3.0 → 1.5, 2.0, 3.0, 4.5)
  - `port_jaccard_threshold`: vary 0.4, 0.5, 0.6, 0.7, 0.8
  - Report: which parameters most affect TPR/FPR? Are results stable?
  - Conclusion: "results are robust to ±25% parameter variation" (or not — that's
    also a valid finding)

- [ ] **Add a `scripts/sensitivity.py` script**
  - Iterates over parameter combinations, runs benchmark for each
  - Outputs results to `data/sensitivity_results.jsonl`
  - Should complete in under 5 minutes (all in-memory simulation)

### T3d — Fleet Correlation Evaluation

- [ ] **Add fleet-specific scenarios to the benchmark**
  - Currently the benchmark (scenarios A–I) tests per-peer detection only
  - Add 3 fleet scenarios:
    - FL1: ARP poisoning campaign — 3 peers simultaneously (fleet detects, arpwatch misses)
    - FL2: Infrastructure swap — 4 peers show route change (fleet detects, per-peer misses)
    - FL3: Coordinated identity conflict (Scenario D × 2) — shows fleet closes the D gap
  - For each: record (a) score without fleet boost, (b) score with fleet boost,
    (c) whether threshold is crossed in each case

- [ ] **Measure fleet FPR on clean traffic**
  - Count `fleet_alerts.jsonl` entries during the clean traffic runs
  - Expected: zero fleet alerts on clean traffic (no coordinated anomalies)
  - If fleet fires on clean traffic, document why and adjust `fleet_*_min_peers`

---

## T4 — Code Changes to Support Evaluation

These are the minimal code changes needed. Do not over-engineer.

- [ ] **Add `phases` config field to `PeerWatchConfig`**
  - `phases: int = 3` — controls which scoring phases are active
  - In `_check_incoming_fingerprint`: skip Phase 2/3 suspicion additions when
    `self._cfg.phases < 2` / `< 3`
  - In `FleetCorrelator.analyse()`: return early if `cfg.phases < 3`
  - This enables the ablation study without changing the simulation tests

- [ ] **Add arpwatch simulation to `scripts/benchmark.py`**
  - arpwatch detects: new MAC seen for known IP, known MAC seen on new IP
  - Implement `arpwatch_would_detect(scenario_events)` — check if any scenario
    event is `arp_spoofing_detected` or `mac_conflict`
  - Add `arpwatch_detected: bool` field to benchmark output records

- [ ] **Add fleet scenarios to `scripts/benchmark.py`**
  - Implement FL1–FL3 as benchmark scenarios alongside A–I
  - Record per-peer score before/after fleet and whether threshold crossed

- [ ] **Add sensitivity sweep script `scripts/sensitivity.py`**
  - Accepts parameter ranges via CLI or config
  - Runs `benchmark.py` logic for each combination
  - Outputs CSV/JSONL suitable for plotting

- [ ] **Log clean traffic experiment metadata to `data/clean_traffic_log.jsonl`**
  - Daemon should append a record each tick: `{ts, scan_count, peer_count, alert_count, fleet_alert_count}`
  - Enables post-hoc FPR calculation without reading full alert logs

---

## T5 — Thesis Writing

Write sections in this order. Each section is listed with its required content.

### T5a — Abstract (write last, 150–250 words)
- [ ] State the problem (network spoofing detection is hard, existing tools use single signals)
- [ ] State the approach (multi-signal accumulation + fleet correlation)
- [ ] State the main result (detects X/9 scenarios vs arpwatch's 1/9; Y FPR on clean traffic)
- [ ] State the conclusion (multi-signal approach is more effective; fleet correlation adds Z)

### T5b — Introduction (800–1200 words)
- [ ] Motivate the problem: why is device spoofing a threat?
  - ARP spoofing enables MITM attacks on local networks
  - Standard defences (DHCP snooping, DAI) require managed infrastructure
  - Lightweight monitoring tools exist but are single-signal
- [ ] State the gap: existing tools detect ARP anomalies but miss fingerprint,
  service, route, and TTL signals; none correlate across peers
- [ ] State the contributions — as a bullet list, one per contribution:
  1. A multi-signal device fingerprinting system (PeerWatch) integrating active nmap
     scan comparison, passive packet observation, and cryptographic identity anchors
  2. A fleet-level co-occurrence detector that identifies coordinated attacks missed
     by per-peer analysis
  3. An empirical evaluation across 9 simulated attack scenarios and N hours of
     clean traffic, comparing against arpwatch as a baseline
- [ ] State what is NOT claimed: real-time detection, ML-based detection, protection
  against sophisticated evasion (Scenario I), enterprise-scale deployment

### T5c — Background (600–900 words)
- [ ] Explain the ARP protocol and why it is vulnerable (no authentication)
- [ ] Explain nmap OS/service fingerprinting at a level a CS grad can follow
- [ ] Explain passive TCP/IP stack fingerprinting (TTL, window size, IP ID)
- [ ] Explain suspicion scoring as an evidence accumulation pattern (cite Dempster-Shafer
  or Bayesian updating if you want theoretical grounding, or just describe it operationally)
- [ ] Keep this short — background is not a literature review

### T5d — Related Work (800–1200 words)
- [ ] ARP detection tools: arpwatch, Zeek ARP policy, DAI — what they detect, what they miss
- [ ] Network fingerprinting: nmap, p0f, Kohno et al. clock skew — position PeerWatch as
  building on active + passive fingerprinting literature
- [ ] Anomaly detection surveys: Chandola et al. — where threshold-based scoring fits
- [ ] Multi-host / fleet correlation: Lakhina et al. and any other co-occurrence papers —
  establish that per-peer detection is a known limitation, fleet correlation is understudied
  at the LAN level
- [ ] LLM in security: frame as related work, not as PeerWatch's contribution

### T5e — System Design (1500–2500 words) — describe what was built
- [ ] Architecture overview diagram: nmap → ingest → Comparator → FleetCorrelator →
  SuspiciousAgent → Remediator
- [ ] Phase 1: active nmap fingerprinting — what signals are extracted, how
  comparison works, what events fire
- [ ] Phase 2: passive capture — TTL baseline, ARP monitoring, TCP fingerprint,
  IP ID, route tracking — one paragraph each
- [ ] Phase 3: detection intelligence — MAC/vendor cross-reference, SSH/SSL anchors,
  fleet correlation — emphasise fleet correlation as the novel component
- [ ] Suspicion scoring model: how events accumulate, decay formula, warmup period,
  threshold
- [ ] PeerStore persistence and the `last_tick_at` tick window mechanism
- [ ] Do NOT describe the remediation system in depth — one sentence: "the system
  supports optional autonomous blocking; this is outside the scope of the evaluation"

### T5f — Evaluation (2000–3000 words) — the most important section
- [ ] **Experimental setup**: hardware, network, scan interval, number of runs
- [ ] **Simulation methodology**: describe the 9 scenarios (A–I) — each with attack
  type, MITRE ATT&CK reference, and expected detection mechanism. Acknowledge that
  scenarios were designed to test specific detectors (this is a limitation, not a flaw).
- [ ] **Baseline comparison results**: table of TPR/FPR for arpwatch vs PeerWatch P1/P2/P3
- [ ] **Fleet correlation results**: FL1–FL3 scenarios — scores before/after fleet boost,
  whether threshold crossed; compare to per-peer-only detection
- [ ] **Clean traffic FPR**: methodology, run conditions, results per configuration
- [ ] **Threshold sensitivity**: ROC curve or sensitivity table; justify 3.0 default
- [ ] **Known limitations**: Scenario I (service mimicry) is undetected — explain why
  this is a fundamental limit of active fingerprinting, not a bug. Scenario E is below
  threshold by design.
- [ ] **Threats to validity**:
  - Simulation is self-referential: scenarios were written to match detectors
  - Clean traffic dataset is small (one home network, ~8 devices)
  - Thresholds were initially set by intuition; sensitivity analysis shows they are
    not globally optimal
  - No evaluation against a sophisticated attacker who knows the detection approach

### T5g — Discussion (600–900 words)
- [ ] Interpret the results: what does the TPR improvement mean in practice?
- [ ] Discuss the fleet correlation result: under what conditions does it add value?
  (Only when attacks are coordinated; no benefit for single-device attacks)
- [ ] Discuss the LLM component honestly: it does not improve detection; it reduces
  the time an operator spends understanding an alert. Quantify the information density
  improvement (events list vs. natural language explanation).
- [ ] Discuss deployment constraints: requires root for nmap OS detection; passive
  capture requires promiscuous mode; not suitable for large subnets without parallelism
- [ ] Compare to the threat model: what attacker capabilities would defeat PeerWatch?
  (Service mimicry, gradual fingerprint drift below warmup threshold, avoiding ARP)

### T5h — Conclusion (300–500 words)
- [ ] Restate the claim and the main result in 2–3 sentences
- [ ] State what the evaluation showed
- [ ] List 3–4 concrete future work directions:
  1. DHCP fingerprinting as an additional passive signal
  2. Formal probabilistic model for the suspicion score (replace ad-hoc weights)
  3. Real-world dataset collection and threshold derivation from data
  4. User study measuring operator response time with/without LLM triage

### T5i — Artifact Appendix
- [ ] How to install and run PeerWatch (copy from CLAUDE.md, clean up)
- [ ] How to reproduce the benchmark results (`python scripts/benchmark.py`)
- [ ] How to reproduce the sensitivity analysis
- [ ] Link to the repository

---

## T6 — Statistical Rigour

- [ ] **Do not report a single run as a result.** For any number reported in the
  evaluation, either: (a) explain why a single run is deterministic (simulation is,
  so one run is sufficient), or (b) run 3+ times and report mean ± std.

- [ ] **Report confidence intervals on the clean traffic FPR.**
  With 48 ticks per run and 3 runs (144 total), a Wilson confidence interval on
  a 0/144 FPR is [0, 0.025] at 95% — that is a real result.

- [ ] **For the sensitivity analysis**, report which parameters the results are
  sensitive to. If TPR drops from 7/9 to 5/9 when `arp_spoof_suspicion` is halved,
  that is a finding that belongs in the thesis.

- [ ] **Acknowledge the small dataset size in every result discussion.** Do not
  overstate generalisability. "On this network, with these devices, over these runs"
  is honest; "PeerWatch achieves 0% FPR" is not.

---

## T7 — Formatting & Submission

- [ ] **Fix the Typst template**
  - Remove `#lorem(15)` placeholder abstract
  - Set the actual title (remove "Machine Learning techniques")
  - Remove conference metadata (ACM TOG, JACM volume/article numbers) —
    this is a thesis, not a journal submission; use the UCL thesis template or
    a clean academic paper template
  - Add keywords

- [ ] **Figure: system architecture diagram**
  - A single diagram showing the full pipeline is essential
  - Nodes: nmap scan → XML → PeerStore ingest → Comparator → FleetCorrelator →
    SuspiciousAgent → alerts
  - Can be drawn in Typst, Excalidraw, or any tool and imported as SVG/PDF

- [ ] **Figure: detection results table**
  - The comparison table (arpwatch vs PeerWatch P1/P2/P3) must be a formatted
    table in the thesis, not just raw numbers

- [ ] **Figure: threshold sensitivity plot**
  - TPR vs threshold, FPR vs threshold — two lines on one plot
  - Shows the 3.0 threshold is in a reasonable operating region

- [ ] **Check word count**
  - MSc dissertation at UCL CS: typically 10,000–15,000 words
  - MEng project report: typically 8,000–12,000 words
  - Check your department's specific requirements

- [ ] **Bibliography: minimum 20 cited works**
  - Add all papers from T2 to `writeup/refs.bib`
  - Use consistent citation style (ACM format is already configured)

---

## Priority order

If time is short, do these in order and stop when out of time:

1. T1 — fix the research question and scope (1 day)
2. T4 — add `phases` ablation + arpwatch baseline to benchmark (2 days)
3. T3b — clean traffic FPR run × 3 (collect data, 3 evenings)
4. T5e + T5f — system design + evaluation sections (the core of the thesis)
5. T2 — literature review (read and cite while writing T5)
6. T3c — sensitivity analysis (1 day coding + writing)
7. T5b + T5g + T5h — introduction, discussion, conclusion
8. T5c + T5d — background and related work
9. T5a — abstract (write last)
10. T7 — formatting and final checks
