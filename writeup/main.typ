#import "ucl-title.typ": ucl-title-page

// ── UCL title page ─────────────────────────────────────────────────────────────
#set page(
  paper: "a4",
  margin: (x: 2.5cm, top: 3cm, bottom: 3cm),
  numbering: none,
  header: none,
  footer: none,
)

#ucl-title-page(
  logo-path: "ucl_logo.png",
  title: "PeerWatch: Multi-Signal Network Anomaly Detection for Local Area Networks",
  subtitle: none,
  date: "TODO: Day Month Year",
  author: "Darius Chitoroaga",
  degree: "MEng Computer Science",
  supervisor: "TODO: Supervisor's Name",
  distribution: "open",
)

#pagebreak()

// ── Paper body ─────────────────────────────────────────────────────────────────
#set page(
  paper: "a4",
  margin: (x: 2cm, top: 2.5cm, bottom: 2.5cm),
  numbering: "1",
  header: context {
    set text(size: 8pt)
    if counter(page).get().first() > 1 [
      #grid(
        columns: (1fr, 1fr),
        align(left)[Chitoroaga — PeerWatch],
        align(right)[UCL MEng Computer Science],
      )
      #line(length: 100%, stroke: 0.4pt + gray)
    ]
  },
  footer: context {
    set text(size: 8pt)
    align(center)[#counter(page).display("1")]
  },
)

#set text(font: "Linux Libertine O", size: 10pt, lang: "en")
#set par(justify: true, leading: 0.65em, spacing: 1.2em)

// Heading styles
#show heading.where(level: 1): it => {
  v(1.4em, weak: true)
  set text(size: 11pt, weight: "bold")
  upper(it)
  v(0.6em, weak: true)
}
#show heading.where(level: 2): it => {
  v(1.2em, weak: true)
  set text(size: 10.5pt, weight: "bold")
  it
  v(0.4em, weak: true)
}
#show heading.where(level: 3): it => {
  v(0.8em, weak: true)
  set text(size: 10pt, weight: "bold", style: "italic")
  it
  v(0.3em, weak: true)
}

#set heading(numbering: "1.1.1")

// Table header bold + bottom rule
#show table.cell.where(y: 0): strong
#set table(
  stroke: (x, y) => if y == 0 { (bottom: 0.7pt + black) },
)

// ── Abstract (full width before columns) ───────────────────────────────────────
#block(
  width: 100%,
  inset: (x: 1.5em, y: 0.8em),
  stroke: (left: 2pt + black),
  fill: luma(248),
)[
  #text(weight: "bold")[Abstract — ]
  // TODO: Write abstract last. Required: problem statement, approach, main result (TPR/FPR numbers), conclusion.
]

#v(1em)

// ── Two-column body ────────────────────────────────────────────────────────────
#columns(2, gutter: 1.5em)[

  = Introduction

  Local area networks are built on protocols that were designed for trusted environments.
  The Address Resolution Protocol (ARP), which maps IP addresses to MAC addresses on a
  subnet, carries no authentication mechanism: any host can broadcast an ARP reply claiming
  any IP-to-MAC binding it chooses @rfc826.
  An attacker with access to a local network can therefore impersonate another device
  silently, redirecting traffic through a machine they control — a man-in-the-middle (MitM)
  attack that enables credential theft, session hijacking, and traffic inspection without
  any indication to the victim or the network administrator @arpspoofing.

  The standard hardware-enforced defences against ARP spoofing — Dynamic ARP Inspection
  (DAI) and DHCP snooping — require managed layer-2 switches that maintain a trusted
  binding table @dai.
  These features are absent from commodity home and small-office routers, the same
  environments where monitoring is often most needed and least configured.
  Software-based tools such as arpwatch @arpwatch fill this gap by passively observing ARP
  traffic and alerting when a MAC-to-IP mapping changes.
  However, arpwatch and similar tools operate on a single signal: the ARP binding.
  An attacker who does not forge ARP replies — for example, one who exploits a compromised
  device, replaces a physical device, or gradually migrates a service to a new host — is
  invisible to ARP-only monitors.

  A more robust approach is to treat device identity as a composite of many independent
  signals: the operating system inferred from TCP/IP stack behaviour, the set of open ports,
  the services running on those ports, the time-to-live (TTL) of outgoing packets, the
  route traffic takes through the network, and the cryptographic identity anchors that
  high-value services such as SSH and TLS expose.
  Significant drift in any of these signals, or the co-occurrence of smaller drifts across
  signals, indicates that the device behind an IP address may not be the device that was
  previously observed there.
  When the same anomaly pattern appears simultaneously across multiple devices on the subnet,
  the probability of a coordinated attack — rather than a routine configuration change —
  rises substantially.
  No lightweight, locally-deployable tool currently integrates all of these signals or
  performs fleet-level co-occurrence analysis.

  This paper presents *PeerWatch*, a daemon that implements multi-signal device fingerprint
  accumulation for LAN spoofing detection.
  PeerWatch runs periodically on a single monitoring host, performs active nmap scans of
  the subnet @nmap, maintains a persistent identity store for each discovered device, and
  scores incoming scan results against the stored baseline.
  A passive packet capture layer supplements the active scan with TTL consistency checks,
  ARP reply monitoring, TCP stack fingerprinting, and IP ID sequence analysis @p0f.
  A fleet correlator runs each tick to identify patterns where multiple peers exhibit the
  same anomaly simultaneously; such co-occurrence adds a configurable suspicion boost and
  is reported to the operator in a dedicated alert log.
  When a device's accumulated suspicion score crosses a configurable threshold, a
  locally-run large language model produces a structured natural-language triage of the
  evidence, reducing the cognitive load on the operator who must decide whether to
  investigate further @alertfatigue.

  The contributions of this work are:

  + *A multi-signal device fingerprinting system* that integrates active nmap scan
    comparison (OS family, port Jaccard similarity, per-port service type, protocol
    mismatches), passive packet observation (TTL baseline, ARP monitoring, TCP fingerprint,
    IP ID sequence, route path stability), and cryptographic identity anchors (SSH host key
    and TLS certificate fingerprint tracking).

  + *A fleet-level co-occurrence detector* that identifies coordinated attack patterns —
    such as simultaneous ARP poisoning of multiple peers or a subnet-wide route shift —
    that are missed or under-scored by per-device analysis alone.

  + *An empirical evaluation* across nine simulated attack scenarios drawn from MITRE
    ATT&CK and CVE-documented techniques, comparing Phase 1 (active scan only), Phase 2
    (active + passive), and Phase 3 (all signals + fleet correlation) against an arpwatch
    baseline, together with a clean-traffic false positive measurement.
  // NOTE: Fill in final TPR/FPR numbers once benchmark runs are complete.

  We do not claim real-time packet-rate detection, protection against a sophisticated
  attacker who can exactly mirror the target device's full fingerprint (Scenario I), or
  suitability for subnets larger than a few hundred hosts without parallelism.
  The detection pipeline is entirely rule-based and deterministic; the LLM component
  provides structured explanation of fired alerts and does not participate in the detection
  decision.
  All scoring logic is transparent and configurable, and the system is designed to run
  without cloud dependencies on hardware a home or small-office administrator already owns.

  The remainder of this paper is structured as follows.
  // NOTE: Fill in section order once all sections are drafted.

  #bibliography(
    "refs.bib",
    title: "References",
    style: "association-for-computing-machinery",
  )

  #colbreak(weak: true)
  #set heading(numbering: "A.a.a")

  = Artifact Appendix
  In this section we show how to reproduce our findings.

] // end columns
