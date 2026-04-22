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
  footer: context {
    set text(size: 8pt)
    align(center)[#counter(page).display("1")]
  },
)

#set text(font: "Linux Libertine O", size: 12pt, lang: "en")
#set par(justify: true, leading: 0.5em, spacing: 1.2em)

// Heading styles
#show heading.where(level: 1): it => {
  v(1.6em, weak: true)
  set text(size: 14pt, weight: "bold")
  upper(it)
  v(1.0em, weak: true)
}
#show heading.where(level: 2): it => {
  v(1.4em, weak: true)
  set text(size: 13pt, weight: "bold")
  it
  v(0.8em, weak: true)
}
#show heading.where(level: 3): it => {
  v(1.0em, weak: true)
  set text(size: 12pt, weight: "bold", style: "italic")
  it
  v(0.6em, weak: true)
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

= Introduction

The typical home network today bears little resemblance to the isolated subnet of a decade ago.
Driven by the proliferation of connected devices, residential and small-office subnets now carry a mixture of
enterprise endpoints, smart home appliances, voice assistants, and networked infrastructure that
receives infrequent security updates and is rarely under active administrative oversight @iotgrowth.
The 2016 Mirai botnet demonstrated at scale that consumer-grade connected devices could be
silently weaponised for coordinated global attacks without their owners' awareness @mirai;
the attack surface in the average home network has only expanded since.
Yet the monitoring tools available to independent administrators have not kept pace with this
expanded threat surface, and this gap motivates the present work.

Local area networks are built on protocols designed for trusted environments.
The Address Resolution Protocol (ARP), which maps IP addresses to MAC addresses
on a subnet, carries no authentication: any host can broadcast an ARP reply
claiming any binding it chooses @rfc826.
An attacker with network access can silently impersonate another device,
redirecting traffic through a machine they control; a man-in-the-middle (MitM)
attack that enables credential theft, session hijacking, and traffic inspection
without alerting the victim or the network administrator @arpspoofing.

The standard hardware-enforced defences against ARP spoofing: Dynamic ARP
Inspection (DAI) and DHCP snooping, require managed layer-2 switches that
maintain a trusted binding table @dai.
These features are absent from commodity home and small-office routers, the
environments where monitoring is often most needed and least configured.
Software-based tools such as arpwatch @arpwatch fill part of this gap by
alerting on changes to ARP bindings, but they operate on a single signal.
An attacker who compromises a device without forging ARP replies, physically
replaces a device, or gradually migrates a service to a new host is entirely
invisible to ARP-only monitors.


A more robust approach treats device identity as a composite of independent
signals: the operating system inferred from TCP/IP stack behaviour, the set of
open ports and running services, the time-to-live (TTL) field of outgoing
packets, the route traffic takes through the network, and the cryptographic
identity anchors that services such as SSH and TLS expose.
Significant drift in any of these signals, or the co-occurrence of smaller
drifts across several signals in the same scan cycle, indicates that the
device behind an IP address may not be the device previously observed there.
When the same anomaly pattern appears simultaneously across multiple hosts, the
probability of a coordinated attack rather than a routine configuration change
rises substantially.
The challenge is calibrating this without drowning operators in noise.
Routine events, a firmware update that alters a device's OS fingerprint, a
DHCP lease renewal that reassigns an IP, or a router reconfiguration that
shifts TTL values, produce observations indistinguishable from an attack in
isolation.
A monitor that fires on every anomaly is quickly ignored, defeating its own
purpose, causing alertfatigue for admins, @alertfatigue; careful evidence accumulation,
signal weighting, and decay are therefore as important as the signals themselves.

Enterprise network detection and response (NDR) platforms such as Darktrace
@darktrace and Cisco Secure Network Analytics @ciscosna provide sophisticated
multi-signal monitoring, but require dedicated appliances, managed
infrastructure, or cloud connectivity that place them beyond the reach of home
and small-office administrators.
Lightweight open-source tools such as arpwatch are deployable on existing
hardware but, as noted, are restricted to a single signal.
Network intrusion detection systems (NIDS) such as Snort @snort and Suricata
@suricata, and the network analysis framework Zeek @zeek, offer deep packet
inspection and protocol analysis but operate on signature matching rather than
per-device identity drift; they are designed for dedicated network taps and do
not maintain a persistent fingerprint model per LAN device.
The gap between these categories of tool is summarised in @tool-comparison.
No open-source, locally-deployable tool currently integrates active device
fingerprinting, passive observation, and fleet-level co-occurrence analysis in
a single monitor.

#figure(
  table(
    columns: (1.6fr, 1fr, 1fr, 1fr, 1fr),
    align: (left, center, center, center, center),
    [*Tool*],
    [*Active scan*],
    [*Passive \ capture*],
    [*Fleet correl.*],
    [*Local deploy*],

    [Darktrace / Cisco SNA],
    [#sym.checkmark],
    [#sym.checkmark],
    [#sym.checkmark],
    [#sym.crossmark],

    [Snort / Suricata],
    [#sym.crossmark],
    [#sym.checkmark],
    [#sym.crossmark],
    [#sym.checkmark],

    [Zeek],
    [#sym.crossmark],
    [#sym.checkmark],
    [#sym.crossmark],
    [#sym.checkmark],

    [arpwatch],
    [#sym.crossmark],
    [#sym.checkmark (ARP only)],
    [#sym.crossmark],
    [#sym.checkmark],

    [*PeerWatch*],
    [#sym.checkmark],
    [#sym.checkmark],
    [#sym.checkmark],
    [#sym.checkmark],
  ),
  caption: [Detection capability comparison across monitoring tools relevant to small-office administrators.],
) <tool-comparison>

This project aims to close that gap, building a tool designed specifically for
the independent administrator who has neither managed switching infrastructure
nor an enterprise security budget.

The threat model assumed throughout this work places the attacker within the
local network — through a compromised device, a rogue wireless association, or
physical access — and grants them the ability to forge ARP replies,
substitute physical devices, or redirect services to attacker-controlled hosts.
The attacker is not assumed to perfectly replicate every observable property of
the target; the detection strategy exploits precisely this constraint.
The monitoring host is assumed to hold a network interface capable of
promiscuous-mode capture and sufficient privilege to run periodic `nmap` scans,
and is itself assumed to be uncompromised.

== Aims and Goals

The _aim_ of this project is to design, implement, and evaluate *PeerWatch*:
an open-source, autonomous network anomaly detection daemon that fingerprints
subnet devices across multiple independent signals, tracks device identity over
time, and flags evidence of spoofing or coordinated attack; deployable on
hardware a home or small-office administrator already owns, with no cloud
dependencies.

The specific _goals_ are:

+ *Active device fingerprinting.* Build a periodic `nmap`-based scan loop @nmap
  that maintains a persistent identity store (`PeerStore`) for each discovered
  device, tracking OS family, open ports, service types, and MAC address.
  Define a scoring engine that accumulates suspicion for detected drift between
  successive scans and decays it exponentially, so stale anomalies do not
  permanently penalise a device.

+ *Passive monitoring layer.* Supplement active scans with live packet capture
  that tracks TTL consistency, monitors ARP replies for binding conflicts,
  performs TCP stack fingerprinting @p0f, and checks route path stability;
  detection signals that require no active probing and that catch attacks leaving
  no nmap-visible trace.

+ *Fleet-level correlation.* Implement a correlator that identifies coordinated
  anomaly patterns across multiple peers within the same scan tick, such as
  simultaneous ARP poisoning of several hosts or a subnet-wide route shift,
  and scores them independently of per-device analysis.

+ *LLM-assisted triage.* Integrate a locally-run large language model that
  produces structured natural-language investigation reports when a device's
  suspicion score crosses a threshold, reducing the cognitive burden on the
  operator who must decide whether to act @alertfatigue.
  Recent advances in locally-runnable models and software allowing models to
  run on commodity hardware via Ollama @ollama have made LLM-assisted triage
  increasingly viable in isolated environments without cloud infrastructure.
  No monitored traffic leaves the subnet, no API key or subscription is required,
  and the system remains functional in air-gapped deployments.
  The LLM explains triggered alerts and does not participate in the detection
  decision itself.
  To prevent indirect prompt injection @promptinjection, the model is never
  given access to raw peer data such as packet payloads, hostnames, or service
  banners; it receives only structured summaries produced by the detection
  pipeline, containing numeric scores, event type labels, and device identifiers.

+ *Empirical evaluation.* Measure detection performance across a suite of
  simulated attack scenarios drawn from MITRE ATT&CK and CVE-documented
  techniques, and characterise the false positive rate under clean traffic.

== Scope

PeerWatch targets subnets of up to approximately 254 hosts (/24 CIDR blocks)
on hardware the administrator already owns: a dedicated monitoring device,
repurposed laptop, or single-board computer.
The following are explicitly outside scope: WAN-level or inter-subnet threats;
decryption of encrypted traffic or deep protocol reconstruction; scalability to
multi-subnet enterprise deployments; and detection of attacks originating from
the monitoring host itself.
The system is designed for deployments where the operator is also the
administrator, home users and small offices, not for SOC environments where
dedicated appliances and analyst teams are available.

== Approach

PeerWatch was developed iteratively across three phases, each adding a new
detection dimension while preserving the correctness of the previous ones.
A key insight shaping the architecture was that each phase was motivated by a
concrete category of attack the previous layer could not detect: ARP-only
monitors are blind to device substitution that bypasses ARP entirely, and
active scan profiles alone cannot catch adversaries who replicate nmap-visible
behaviour while diverging at the packet level.
The interaction between signals also proved more informative than any individual
signal, simultaneous drift in OS fingerprint, TTL baseline, and port profile
within one scan tick is qualitatively different from any single drift in isolation.

*Phase 1* established the core detection loop: periodic `nmap` scans of the
target subnet, a `PeerStore` keyed by MAC address (or IP for MAC-less devices),
and a rule-based scoring engine that compares each scan against the stored
baseline.
When a device's score crosses a configurable threshold, a `SuspiciousAgent`
invokes a locally-run Ollama model for structured JSON triage, falling back to
rule-based severity assignment if the model is unavailable.

*Phase 2* added a passive capture loop running alongside the active scan.
Passive observations: TTL deviation from an established baseline, ARP reply
conflicts, TCP fingerprint inconsistencies, IP ID sequence jumps, and
traceroute path changes, accumulate in per-device observation models and
contribute to the suspicion score independently of the active scan.
This layer catches attacks that exactly mimic a target's nmap-visible profile
but cannot replicate every low-level TCP stack behaviour.

*Phase 3* introduced the `FleetCorrelator`, which runs each tick after
ingestion and before investigation.
It detects patterns where multiple peers exhibit the same anomaly simultaneously,
applies a configurable suspicion boost to each matching device, and injects
fleet-level context into the LLM prompt, so the agent can reason about
coordinated attacks rather than isolated per-device events.
Phase 3 also added SSH host-key and TLS certificate fingerprint tracking as
high-value cryptographic identity anchors.

Throughout, all scoring weights, thresholds, and daemon settings are exposed
through a single Pydantic @pydantic configuration model, keeping the pipeline transparent
and tunable without code changes.
The system is designed for subnets of a few hundred hosts on hardware a home
or small-office administrator already owns; larger deployments would require
scan parallelism.

== Report Structure

Chapter 2 provides the context for this work: background on LAN-layer attack
techniques, a survey of related detection tools, and an introduction to the
key libraries and components on which PeerWatch is built.
Chapter 3 captures the requirements and analyses them into an initial design.
Chapter 4 describes the design and implementation of PeerWatch in detail,
following the three-phase structure above.
Chapter 5 presents the testing strategy and empirical evaluation across the
simulated attack suite and a clean-traffic false-positive measurement.
Chapter 6 concludes with a critical assessment of the results against the
goals set out above, and directions for future work.
// TODO: updated this when finished

= Background and Context

== LAN-Layer Attack Techniques

Understanding the threat landscape PeerWatch targets requires examining how attackers exploit
the trust assumptions embedded in local network protocols.
The attacks described below are not hypothetical: each maps to documented CVEs or MITRE
ATT&CK techniques @mitre and corresponds directly to detection scenarios evaluated in
Chapter 5.

=== ARP Cache Poisoning

The Address Resolution Protocol's trust model was introduced in Chapter 1; this section
examines the attack mechanics in sufficient detail to motivate the detection signals
that follow.

An ARP poisoning attack proceeds in two steps.
The attacker broadcasts gratuitous ARP replies — unsolicited announcements claiming a
particular IP-to-MAC binding — targeting both the victim host and the default gateway.
Because standard operating system ARP implementations update their cache on receipt of
any ARP reply regardless of whether a request was issued @rfc826, both targets update
their routing tables to direct traffic through the attacker's machine.
The attacker, forwarding traffic between victim and gateway while inspecting it, achieves
a man-in-the-middle position transparent to both parties.

From this position an attacker can intercept cleartext credentials, inject content into
unencrypted sessions, or strip TLS by presenting a forged certificate to the victim while
maintaining a legitimate upstream connection.
CVE-2020-25705 (SAD DNS @saddns) demonstrates that IP address ownership cannot be treated
as self-authenticating even without ARP manipulation; ARP poisoning is the local-network
equivalent, documented as MITRE ATT&CK T1557.002 @mitre.

The MAC address change ARP poisoning produces is detectable by tools such as arpwatch.
It is only one observable, however: if the attacker substitutes a device with an identical
MAC — or if the attack proceeds through a compromised device that retains its original
MAC — the ARP signal is entirely clean, and a richer set of observations is required.

=== Device Substitution Without ARP Forgery

A more operationally sophisticated attack replaces or impersonates a device without
disturbing ARP bindings.
The attacker clones the target device's MAC address — trivially accomplished on modern
operating systems — and begins responding to network traffic from attacker-controlled
hardware.
No ARP anomaly is produced; arpwatch observes nothing.

What does change is the device's observable identity at the network stack level.
Different hardware exposes a different TCP/IP stack fingerprint: initial TTL values, IP
identification field patterns, TCP window size, window scaling options, and initial
sequence number generation are determined by the operating system and kernel version,
not the MAC address @nmap.
An attacker running Linux on hardware that previously hosted a Windows IoT device will
produce OS fingerprinting results inconsistent with the stored baseline, a port profile
that may differ, and a TTL baseline that diverges from the established per-device average.

MAC spoofing without OS replication is documented as T1564.006 @mitre.
The limitations of MAC-only monitoring were demonstrated in CVE-2004-0699, where device
identity assumptions were exploited precisely because address-layer credentials were not
backed by any deeper identity verification.

=== Service-Level Impersonation

Where device substitution attacks target the network identity of a host, service-level
attacks target specific services running on it.

*Service backdoors and protocol takeover.*
An attacker who has compromised a device may install additional services, replace existing
ones with attacker-controlled versions, or expose services on non-standard ports.
These produce observable port profile drift: new ports appear in subsequent scans, or
services on known ports change type.
T1543 (Create or Modify System Process) @mitre and US-CERT advisory TA17-181A @uscertTA17
document service persistence techniques used in documented intrusions.
More recent examples include CVE-2024-6387 (regreSSHion @regresshion), a remote code
execution vulnerability in OpenSSH that could enable replacement of a running SSH daemon,
and CVE-2024-4577, where protocol-level service replacement produced detectable
port/protocol mismatches.

*Cryptographic identity anchors.*
SSH servers present a host key fingerprint to clients on each connection; TLS servers
present a certificate fingerprint.
These are high-entropy, asymmetrically generated values that cannot be forged without
the corresponding private key.
A device substitution that replaces an SSH or HTTPS server necessarily exposes a different
fingerprint to any observer who has recorded the original.
This makes host key and certificate tracking qualitatively stronger evidence than
heuristic signals: a determined attacker can tune kernel parameters to approximate an OS
fingerprint, but presenting a valid SSH host key for a device they do not control is
computationally infeasible.

=== Coordinated Fleet Attacks

The attack patterns above are considered in isolation; in practice, targeted intrusions
frequently affect multiple hosts in the same network concurrently.
The distinction matters for detection: a single device showing OS fingerprint drift is
consistent with a firmware update; four devices showing simultaneous OS drift is not.

Fleet-level patterns observable in real intrusions include gateway substitution campaigns
— where the attacker poisons ARP caches across multiple hosts simultaneously to redirect
all subnet traffic — subnet-wide route shifts produced by compromising the default gateway,
and identity sweeps where multiple devices are replaced in the same window to reduce
single-device anomaly visibility.
The 2016 Mirai botnet @mirai is a documented precedent for coordinated compromise of
multiple LAN devices; post-compromise behaviour included systematic service port exposure
consistent with the service sweep pattern.

A critical property of coordinated attacks is that per-device analysis may silently miss
them: if each individual device scores below the investigation threshold, no alert fires.
Fleet-level correlation — detecting that several peers exhibit the same anomaly class
within the same observation window — is the mechanism that closes this gap, and is
described in detail in Section 4.x. // TODO: add cross-ref

=== Evasion and the Attacker's Observable Constraint

The detection strategy throughout PeerWatch rests on the assumption stated in Chapter 1:
an attacker cannot perfectly replicate every observable property of the device they are
impersonating.
This section examines where that assumption is strong and where it is not.

A determined attacker can replicate several signals.
Port profile can be matched by opening the same ports; service type labels can be mimicked
by running compatible stacks; OS fingerprint can be approximated through kernel parameter
tuning — adjusting TCP initial TTL, window size, and timestamp options.
Scenario I in the evaluation (T1036.004 masquerading, CVE-2024-3094) demonstrates this
boundary: an attacker who carefully mirrors the target's service profile produces a
suspicion score of 0.0, a correctly identified limitation of the active-scanning layer.

What is structurally hard to replicate: TTL baselines accumulated over many scan cycles,
where hardware-level routing differences compound; TCP/IP stack microvariances below
the granularity of kernel parameter tuning; IP identification field counter patterns,
which reflect packet generation rate and hardware; and cryptographic identity anchors,
where forging a host key or certificate requires possession of the private key.

The practical consequence is that detection reliability increases with the number of
independent signals covered.
An attacker who evades the nmap OS fingerprint signal may still expose TTL drift;
one who suppresses TTL drift may expose a host key change.
No single evasion technique neutralises all signals simultaneously without perfectly
replicating the target device — which is, by definition, device substitution rather than
impersonation.

#bibliography(
  "refs.bib",
  title: "References",
  style: "association-for-computing-machinery",
)

#colbreak(weak: true)
#set heading(numbering: "A.a.a")

= Artifact Appendix
In this section we show how to reproduce our findings.
