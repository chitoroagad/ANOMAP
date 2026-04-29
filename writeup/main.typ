#import "ucl-title.typ": ucl-title-page
#import "@preview/fletcher:0.5.7" as fletcher: diagram, edge, node

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
  date: "29 April 2026",
  author: "Candidate SWSG5",
  degree: "MEng Computer Science",
  supervisor: "",
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
#set par(justify: true, leading: 0.7em, spacing: 1.7em)

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

#show figure: set block(breakable: true)

#outline()
#pagebreak()

// ── Abstract (full width before columns) ───────────────────────────────────────
#block(
  width: 100%,
  inset: (x: 1.5em, y: 0.8em),
  stroke: (left: 2pt + black),
  fill: luma(248),
)[
  #text(weight: "bold")[Abstract — ]
  Home and small-office networks are increasingly heterogeneous and unmonitored,
  yet the tools available to independent administrators remain limited to
  single-signal monitors such as arpwatch or signature-based intrusion detection
  systems that do not model per-device identity over time.
  An attacker with local network access can substitute a device, poison ARP
  caches, or migrate a service to an attacker-controlled host and remain entirely
  invisible to these tools.

  This project presents PeerWatch, an open-source autonomous network anomaly
  detection daemon that maintains a persistent fingerprint identity per subnet
  device and detects deviation across three independently observable signal
  layers.
  The active scanning layer runs periodic nmap scans, compares OS-candidate
  sets, port-profile Jaccard similarity, and per-port service types against
  stored baselines, and accumulates suspicion using a weighted scoring model
  with exponential decay.
  The passive observation layer supplements active scans with real-time packet
  capture, tracking TTL consistency, ARP reply conflicts, TCP stack
  fingerprinting, and route path stability.
  A fleet correlation layer identifies coordinated attack patterns across multiple peers within
  a scan tick, boosting scores when the same anomaly class co-occurs across
  two or more devices.
  When a device's suspicion score crosses a configurable threshold, a locally
  hosted large language model produces a structured
  investigation report with severity classification and recommended follow-up
  scans; a rule-based fallback ensures operation without any cloud dependency.
  Autonomous remediation via iptables is available under operator-controlled
  enforcement modes.

  Evaluated against nine attack scenarios drawn from MITRE ATT&CK techniques
  and published CVEs, PeerWatch detects seven of nine (78%), with the two
  undetected scenarios representing deliberate calibration choices rather than
  implementation gaps.
  A false-positive analysis over 322 nmap scans of a real home network
  spanning 18 devices yields a false-positive rate of 0%, achieved after
  iterative calibration of OS-oscillation suppression, service-type tracking,
  and visibility-gap guards.
  The fleet correlation layer is validated across 16 scenarios, demonstrating
  that sub-threshold per-device scores become detectable under coordinated
  attack co-occurrence.
  The full test suite comprises 222 automated tests covering all detection
  phases, persistence, and remediation.
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
  techniques, and characterise the false-positive rate under clean traffic.

== Scope <scope>

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

== Approach <approach>

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

- Chapter 2 provides context: background on LAN-layer attack techniques,
  a survey of device fingerprinting approaches and related detection tools,
  evidence accumulation theory, and an introduction to the libraries on which
  PeerWatch is built.
- Chapter 3 captures and analyses the requirements, defines use cases, and
  maps them to the component structure.
- Chapter 4 describes the design and implementation of all five components —
  scan loop, `PeerStore`, passive observation layer, `FleetCorrelator`,
  `SuspiciousAgent`, and `Remediator` — following the three-phase development
  structure introduced above.
- Chapter 5 presents the testing strategy, a false-positive analysis on
  real home-network traffic, evaluation of nine attack scenarios against the
  active-scan pipeline, fleet correlation evaluation across sixteen test scenarios,
  LLM agent and remediation evaluation, performance characterisation, and a
  discussion of limitations and threats to validity.
- Chapter 6 concludes with a summary of contributions, critical evaluation
  against each goal, and directions for future work.

= Background and Context

== LAN-Layer Attack Techniques <lan-layer-attack>

Understanding the threat landscape PeerWatch targets requires examining how attackers exploit
the trust assumptions embedded in local network protocols.
The attacks described below are real-world examples: each maps to documented CVEs or MITRE
ATT&CK techniques @mitre and corresponds directly to detection scenarios evaluated in
Chapter 5.

=== ARP Cache Poisoning

The Address Resolution Protocol's trust model was introduced in Chapter 1; this section
examines the attack mechanics in sufficient detail to motivate the detection signals
that follow.

An ARP poisoning attack proceeds in two steps.
The attacker broadcasts gratuitous ARP replies (unsolicited announcements claiming a
particular IP-to-MAC binding) targeting both the victim host and the default gateway.
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
MAC, or if the attack proceeds through a compromised device that retains its original
MAC; the ARP signal is entirely clean, and a richer set of observations is required.

=== Device Substitution Without ARP Forgery <device-substitution>

A more operationally sophisticated attack replaces or impersonates a device without
disturbing ARP bindings.
The attacker clones the target device's MAC address, trivially accomplished on modern
operating systems, and begins responding to network traffic from attacker-controlled
hardware.
No ARP anomaly is produced; arpwatch observes nothing.

What does change is the device's observable identity at the network stack level.
Different hardware exposes a different TCP/IP stack fingerprint: initial TTL values, IP
identification field patterns, TCP window size, window scaling options, and initial
sequence number generation are determined by the operating system and kernel version,
not the MAC address @nmap.
An attacker running Windows on hardware that previously hosted a Linux IoT device will
produce OS fingerprinting results inconsistent with the stored baseline, a port profile
that may differ, and a TTL baseline that diverges from the established per-device average.

MAC spoofing without OS replication is documented as T1564.006 @mitre.
The limitations of MAC-only monitoring were demonstrated in CVE-2004-0699 @cve-2004-0699, where device
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
and CVE-2024-4577 @cve-2024-4577, where protocol-level service replacement produced
detectable port/protocol mismatches.

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

=== Coordinated Fleet Attacks <fleet-attacks>

The attack patterns above are considered in isolation; in practice, targeted intrusions
frequently affect multiple hosts in the same network concurrently.
The distinction matters for detection: a single device showing OS fingerprint drift is
consistent with a firmware update; four devices showing simultaneous OS drift is not.

Fleet-level patterns observable in real intrusions include gateway substitution campaigns, where
the attacker poisons ARP caches across multiple hosts simultaneously to redirect
all subnet traffic, subnet-wide route shifts produced by compromising the default gateway,
and identity sweeps where multiple devices are replaced in the same window to reduce
single-device anomaly visibility.
The 2016 Mirai botnet @mirai is a documented precedent for coordinated compromise of
multiple LAN devices; post-compromise behaviour included systematic service port exposure
consistent with the service sweep pattern.

A critical property of coordinated attacks is that per-device analysis may silently miss
them: if each individual device scores below the investigation threshold, no alert fires.
Fleet-level correlation (detecting that several peers exhibit the same anomaly class
within the same observation window) is the mechanism that closes this gap, and is
described in detail in @fleet-correlator.

=== Evasion and the Attacker's Observable Constraint <evasion>

The detection strategy throughout PeerWatch rests on the assumption stated in Chapter 1:
an attacker cannot perfectly replicate every observable property of the device they are
impersonating.
This section examines where that assumption is strong and where it is not.

A determined attacker can replicate several signals.
Port profile can be matched by opening the same ports; service type labels can be mimicked
by running compatible stacks; OS fingerprint can be approximated through kernel parameter
tuning — adjusting TCP initial TTL, window size, and timestamp options.
Scenario I // Cross Reference here
in the evaluation (T1036.004 masquerading @mitre, CVE-2024-3094 @cve-2024-3094) demonstrates this
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
replicating the target device; which is, by definition, device substitution rather than
impersonation.

== Device Fingerprinting <device-fingerprinting>

Device fingerprinting derives a stable identity for a networked host from observable
protocol behaviour, without relying on self-reported credentials.
This section surveys the techniques PeerWatch draws on, their mechanisms, and their
limitations.
@design-implementation describes how each is implemented within the pipeline.

=== Active Fingerprinting

Active fingerprinting sends crafted probe packets to a target and analyses the responses.
Nmap's OS detection engine @nmap sends a battery of TCP, UDP, and ICMP probes designed
to elicit responses that vary by operating system implementation: a SYN to an open port,
a SYN to a closed port, a FIN to an open port, and several ICMP variants, each exposing
differences in TCP initial sequence number generation, window size and scaling, timestamp
option presence, don't-fragment bit handling, and IP identification field behaviour.
The response profile is matched against a database of approximately 5,000 OS fingerprints;
a confident match returns the OS family and version, a low-confidence match returns the
closest candidates with a probability score.

Beyond OS family, the set of open ports constitutes a stable per-device identity vector.
Jaccard similarity: the size of the intersection divided by the size of the union of
two port sets, quantifies drift between successive scans.
A score below a configurable threshold (0.6 by default) flags meaningful port profile
change.
Service version detection supplements this: nmap's banner-grabbing identifies the
service type on each open port, catching cases where the port number is unchanged but
the responding application is not.

Active fingerprinting has well-known limitations.
Root privilege is required to send raw packets; probe traffic is visible to network
monitors; and OS detection accuracy degrades in virtualised or containerised environments
where the guest stack is partially masked by the hypervisor.
Most importantly for this work, OS fingerprint can be partially spoofed through kernel
parameter tuning, adjusting TCP initial TTL, window size, and timestamp options, as
established in @evasion. These limitations motivate the passive layer described next.

=== Passive Fingerprinting

Passive fingerprinting derives OS and behavioural signals from traffic already on the
wire, without sending probes.
The p0f tool @p0f pioneered this approach: SYN packets from TCP initiators expose the
sender's TTL, TCP window size, window scaling factor, maximum segment size, timestamp
echo, and IP option fields: a profile that differs reliably across OS families without
any active interaction.

The most operationally significant passive signal for per-device identity tracking is
the TTL baseline.
Each OS family initialises outgoing packets with a characteristic TTL (Linux: 64,
Windows: 128, Cisco IOS: 255); after traversing a fixed number of hops to the monitoring
host, the observed value is stable for a given device.
A single TTL observation is unreliable, routing changes and transient variation exist,
but a per-device baseline accumulated over many observations is robust.
Deviation of more than 15 from the established baseline is a reliable indicator of
either a routing path change or a device substitution.

The IP identification field provides a complementary signal.
Older Linux kernels and many embedded devices generate sequential IP ID values, producing
a monotonically increasing counter visible in captured packets.
Modern Linux and Windows randomise the field.
A transition from sequential to random generation, or a counter jump inconsistent with
the device's observed packet rate, indicates a stack change.

Passive observation has a structural advantage: it cannot easily be suppressed by an
attacker without controlling all outgoing traffic from the compromised device.
Its limitation is the inverse: devices generating no observable traffic are invisible,
and promiscuous-mode capture requires the monitoring interface to see the relevant frames.

=== Cryptographic Identity Anchors

Cryptographic identity anchors are high-entropy, asymmetrically generated values that
services expose on connection and that cannot be forged without the corresponding
private key.

SSH servers generate a host key pair at installation time and present the public key
fingerprint to every connecting client.
TLS servers present a certificate fingerprint (the hash of the DER-encoded certificate)
on each connection.
Both values are stable across reboots and software updates; they change only on explicit
reconfiguration or reinstallation.
A device substitution that replaces an SSH or HTTPS server necessarily exposes a
different fingerprint to any observer who recorded the original, making key or
certificate change near-certain evidence of server substitution rather than routine
maintenance.

The qualitative difference from heuristic signals is significant.
OS fingerprint, TTL, and port profile can all be partially spoofed through configuration;
presenting a valid SSH host key for a device the attacker does not control requires
breaking RSA or ECDSA — computationally infeasible.
A single host key change event therefore carries far more evidential weight than a
single OS fingerprint drift.

Internet-scale infrastructure monitoring tools such as Censys @censys apply the same
principle across the public internet, indexing SSH and TLS fingerprints to track
infrastructure changes and detect certificate substitution.
PeerWatch applies the technique at LAN granularity, where the baseline is per-device
and changes are flagged in real time against a persistent identity store.

=== Route Stability and MAC OUI Correlation

*Route stability.*
Traceroute maps the sequence of IP hops between the monitoring host and a target device.
For a LAN device with a fixed default gateway, this path is constant; a new intermediate
hop or changed hop count indicates a routing table manipulation or gateway substitution,
consistent with the fleet patterns described in @fleet-attacks.
Team Cymru's IP-to-ASN mapping @teamcymru attributes each hop to an autonomous system;
a new ASN in the path indicates traffic leaving via an unexpected upstream provider.

*MAC OUI correlation.*
The first three octets of a MAC address identify the hardware vendor registered with the
IEEE (the Organizationally Unique Identifier).
Cross-checking OUI vendor against nmap-detected OS family catches a class of substitution
neither signal alone would flag: an Apple OUI combined with a Linux OS detection indicates
the claimed hardware identity is inconsistent with the network stack behaviour.

This signal carries elevated false-positive risk.
MAC address randomisation, enabled by default in iOS 14+ and Android 10+, assigns
locally-administered addresses per network, making OUI attribution unreliable for
mobile devices.
Virtual machine adapters expose hypervisor vendor OUIs legitimately inconsistent with
the guest OS.
OUI correlation is therefore treated as a supporting signal rather than a primary
detection trigger.

== Related Work and Tool Survey <related-work-and-tools>

@lan-layer-attack established the attack landscape and @device-fingerprinting the detection signals.
This section surveys existing tools and research, explains why each fails to address
the gap PeerWatch targets, and positions PeerWatch within the literature.
The capability comparison in @tool-comparison provides a structured summary; this
section provides the qualitative analysis behind it.

=== Enterprise Network Detection and Response

Enterprise NDR platforms represent the most capable end of the monitoring spectrum.
Darktrace @darktrace builds unsupervised machine learning baselines per device, detecting
anomalous behaviour relative to each device's individual norm, a conceptual approach
similar in spirit to PeerWatch's per-device identity tracking.
Cisco Secure Network Analytics @ciscosna analyses NetFlow traffic metadata to detect
volumetric and behavioural anomalies across managed infrastructure.
Both platforms offer genuine multi-signal detection with documented effectiveness
against advanced persistent threats in enterprise environments.

The gap they do not address is deployment model, not technical capability.
Darktrace requires cloud connectivity for model updates and investigation tooling, and
its detection logic is proprietary and not user-inspectable.
Cisco Secure Network Analytics requires Cisco managed switching infrastructure or a
cloud licence.
Neither platform runs on commodity hardware; neither is available without enterprise
licensing.
The threat model they address (enterprise perimeter, managed infrastructure, dedicated
security operations staff) differs substantially from the one PeerWatch targets.

=== Network Intrusion Detection Systems (NIDS)

Snort @snort and Suricata @suricata are signature-based NIDS that evaluate each packet
or flow against a rule set.
They are effective at detecting known attack patterns against published rule sets and
are widely deployed in enterprise and research networks.
Their fundamental limitation here is that they maintain no per-device identity model:
each packet is evaluated in isolation against static rules.
Snort can detect ARP spoofing if an ARP rule is deployed, but has no concept of "this
device previously ran Windows and now runs Linux", the drift-based detection that
characterises PeerWatch's approach.

Zeek @zeek is a more flexible protocol analysis framework that supports custom scripting
for detection logic.
A sufficiently motivated operator could script per-device fingerprint tracking in Zeek,
but this is not available out of the box and requires deep domain expertise; Zeek's
deployment model also assumes a dedicated high-throughput network tap rather than the
edge hardware SOHO (Small Office/Home Office) administrators own.
No maintained open-source Zeek module provides the LAN-device identity-drift detection
PeerWatch implements.

All three are fundamentally *reactive*: they detect known or statistically anomalous
patterns against a current observation.
None accumulates a persistent per-device fingerprint baseline that enables temporal
identity drift to be measured across scan cycles.

=== Single-Signal Lightweight Tools

Arpwatch @arpwatch monitors ARP bindings and alerts on new or changed IP-to-MAC mappings.
It is lightweight, reliable, and well-suited to the SOHO deployment model.
Its limitation is precisely what @device-substitution establishes: it is blind to device
substitution that does not disturb ARP bindings, to service-level impersonation, and
to coordinated attack patterns that unfold above the ARP layer.
XarpS and similar tools share this scope.

Hardware-enforced equivalents, Dynamic ARP Inspection and DHCP snooping @dai, are
more robust for the ARP signal specifically but require managed layer-2 switching
infrastructure absent from SOHO deployments.

Every existing lightweight tool covers a single signal.
The design space for a multi-signal, locally-deployable, open-source LAN identity
monitor combining active scanning, passive capture, and fleet correlation is
effectively vacant.

=== Academic Work on Device Fingerprinting

A substantial body of academic work addresses device *type* identification from passive
network observations.
IoT Sentinel @iotsentinel identifies IoT device types from DHCP fingerprints and network
flow metadata, enabling automatic policy enforcement on home routers.
Related work uses DNS query patterns, flow statistics, and protocol behaviour to
distinguish device categories for network management and access control.

This work is related but addresses a different question.
Classification asks: *what type of device is this?*
Identity drift detection asks: *is this the same device as before?*
A classifier is not sensitive to identity drift: a compromised device replicating its
device type's traffic profile would be correctly classified while going undetected, and
a substitution that preserves device type would be invisible.
The two approaches are complementary rather than competitive.

Statistical anomaly detection: flow entropy analysis, traffic volume baselines,
protocol distribution modelling, underpins commercial NDR systems and has a deep
research literature @lakhina2004.
These operate at aggregate traffic level, making them sensitive to volumetric shifts
but not to low-and-slow device substitution that preserves traffic volume while
changing device identity.

Direct prior work on per-device multi-signal identity drift detection in open-source
LAN monitoring is, to the author's knowledge, sparse.
This gap is the primary motivation for PeerWatch.

=== LLM-Assisted Security Triage

The application of large language models to security operations has grown rapidly since
the emergence of capable instruction-following models.
Commercial products including Microsoft Copilot for Security @mscopilot and Google Security Operations @googlesecurity
incorporate LLMs for alert summarisation, threat intelligence synthesis, and first-pass
triage of SIEM events, targeting the alert fatigue problem @alertfatigue that afflicts
security operations teams at scale.

Deploying LLMs in security contexts introduces a specific risk: indirect prompt
injection @promptinjection.
Where an LLM processes data originating from an adversary controlled source,
packet payloads, device-reported hostnames, service banners, an attacker can embed
instructions that manipulate the model's output.
Greshake et al. demonstrate this against several deployed LLM-integrated applications, // Fix reference
including cases where injected instructions cause the model to suppress or distort its
report to the user.
In a network monitoring context the threat is direct: a compromised device could craft
hostnames or service banners that cause the triage LLM to downplay the anomaly it is
investigating; more importantly, since PeerWatch runs with elevated privileges prompt injection could
even compromise a machine.

PeerWatch addresses this with an architectural boundary described in @scope: the
LLM receives only structured summaries from the detection pipeline: numeric scores,
event type labels, device identifiers, never raw packet payloads or device-supplied
strings.
The model operates in an explanation role, producing a structured investigation report;
it plays no part in the detection or scoring decision.
This design adds interpretability without introducing a new attack surface.

== Tools and Libraries <tools-and-libraries>

This section introduces non-obvious tool choices and the rationale behind each.
Per the scope stated in @approach, PeerWatch targets hardware a SOHO administrator
already owns; tool selection reflects that constraint throughout.

=== Active Scanning: nmap

Nmap @nmap is the active scanning engine for all device discovery and fingerprinting.
The choice warrants justification against two faster alternatives.

Masscan @masscan is capable of scanning the entire IPv4 address space in under six minutes but
performs only port discovery: it carries no OS fingerprint database, no service version
detection, and produces no OS confidence scores.
On a /24 subnet scanned every five minutes, scan speed is irrelevant; fingerprint depth
is not.
ZMap @zmap is an internet-scale single-packet scanner with the same limitation.
Both tools are optimised for breadth; nmap is optimised for depth, which is what
per-device identity tracking requires.

Nmap's value in this context is threefold.
Its OS detection engine matches response profiles against a database of approximately
5,000 fingerprints, returning both a matched OS family and a confidence score that
PeerWatch records alongside the result.
Service version detection via banner-grabbing identifies the application behind each
open port, enabling service-type drift to be detected independently of port number.
Structured XML output carries host metadata, port state, service attributes, and OS
match candidates in a single machine-readable document, which PeerWatch's parser
(`src/peerwatch/parser.py`) consumes directly rather than relying on a thin wrapper
library: full control over confidence fields and timing data is preserved.

=== Passive Capture: Scapy

Passive fingerprinting requires live packet capture with per-field access to ARP, IP,
and TCP headers.
Four Python libraries were evaluated.

*Raw libpcap via ctypes.*
Libpcap @libpcap is the standard C library for low-level packet capture on POSIX
systems; it provides a file descriptor over a network interface in promiscuous mode
and a BPF (Berkeley Packet Filter) compilation interface for pushing kernel-level
packet filters to the capture path.
BPF filters are boolean expressions over packet fields (i.e.,
`arp or (tcp and not port 22)`) that are compiled to a bytecode program executed
in the kernel before any packet reaches userspace, reducing the volume of data
Python must handle.
Accessing libpcap from Python requires ctypes, the standard library module for
calling C shared libraries via foreign function interface without writing a C
extension.
The combination provides maximum throughput but demands significant boilerplate:
manual struct layout, pointer arithmetic, and per-protocol field extraction.
Appropriate for a production high-throughput capture engine, but not for a research
implementation where correctness and readability matter more than throughput on a LAN at the scale
we are targeting.

*Pyshark.*
Pyshark @pyshark wraps tshark @wireshark — the command-line version of Wireshark,
a widely used protocol analyser — as a subprocess, feeding it packets and
deserialising its JSON output per packet.
The subprocess boundary introduces external process overhead and serialisation cost
on every packet; suitable for offline PCAP (packet capture file) analysis, not for
real-time per-packet processing in a daemon loop.

*Dpkt.*
Dpkt @dpkt is efficient for offline PCAP file parsing with a clean Python API, but
its live capture support is limited, and it is less expressive than scapy for protocol
composition or custom layer access patterns.

*Scapy.*
Scapy @scapy is a Python-native packet library where each protocol layer is a
first-class Python object, and field access is direct
(`pkt[ARP].psrc`, `pkt[IP].ttl`, `pkt[TCP].window`) exactly what passive
fingerprinting requires.
It supports BPF filter compilation at the capture level, limiting what reaches
Python-level handling.
Scapy is established in security research with broad protocol coverage and active
maintenance.
The expressiveness advantage over alternatives outweighs the modest throughput
overhead at LAN traffic volumes.

=== LLM Integration: Ollama, Phi-4, and LangChain

Three related choices form the LLM integration layer.

*Ollama* @ollama is a local inference server that runs quantised open-weights models
on commodity hardware via a REST API compatible with the OpenAI client interface.
It was selected over direct cloud API providers (OpenAI, Anthropic) because network
monitoring context, even in summarised form, must not leave the monitored subnet.
An air-gapped deployment must remain functional with no outbound connections; Ollama
satisfies this constraint without code changes.

*Phi-4* (Microsoft, 14B parameters) is the default model.
At 4-bit quantisation it requires approximately 8 GB of RAM, within reach of a dedicated
monitoring device the administrator already owns.
It was selected over Llama 3 8B (lower resource requirement but weaker structured JSON
output reliability observed during development) and Mistral 7B (similar tradeoff) on
the basis of structured output quality and instruction-following consistency, both
critical for producing well-formed `InvestigationReport` JSON on every invocation.
The MIT licence is compatible with the project's open-source goals.
The model is configurable; any Ollama-supported model can be substituted via
`config.json`.

*LangChain* @langchain provides the `format="json"` grammar-constrained generation
interface, ensuring the model produces valid JSON regardless of content, enabling
direct deserialisation into a typed Pydantic schema.
The alternative of raw HTTP to Ollama's `/api/generate` endpoint was rejected because
LangChain's structured output handling, retry logic, and streaming/non-streaming
abstraction are non-trivial to reimplement correctly; the investigation report schema
is validated against a Pydantic model on deserialisation, and the integration between
LangChain's structured output and Pydantic's validation is the key value.
If Ollama is unavailable, `SuspiciousAgent` falls back to rule-based severity
assignment without invoking LangChain, the dependency is isolated to the LLM path.

=== Configuration and Validation: Pydantic

All scoring weights, thresholds, and daemon settings are declared in a single Pydantic
`PeerWatchConfig` model @pydantic.
Pydantic was chosen over plain dicts or dataclasses for three reasons: automatic type
coercion (a JSON string `"3.0"` is coerced to `float` transparently), field-level
validation with informative error messages on misconfiguration (a user who sets
`suspicion_threshold: "high"` receives an immediate type error rather than a runtime
crash deep in the scoring engine), and self-documenting field types and defaults.

The `config.example.json` pattern documents all fields with their defaults; users copy
it to `config.json` and override only what they need.
`model_validate` handles partial configs, unset fields use the declared defaults.
Every component that consumes a threshold receives it from the same config object,
eliminating scattered magic numbers and the risk of drift between independently
maintained constants.

== Evidence Accumulation and Anomaly Scoring <evidence-accumulation>

The signals described in @device-fingerprinting are individually noisy: a single TTL deviation
is consistent with a transient routing change; a single OS fingerprint shift is
consistent with a firmware update.
Turning noisy per-signal observations into reliable detection requires a principled
accumulation model.
This section establishes the theoretical basis; @design-implementation describes the implementation.
=== Weighted Scoring

Not all signals carry equal evidential weight.
A changed SSH host key is near-certain evidence of server substitution; a Jaccard
port profile drift below 0.6 is consistent with routine service changes.
Assigning uniform weight to all signals would cause low-evidence events to dominate
the score when they fire frequently, drowning higher-confidence signals in noise.

Axelsson @axelsson demonstrates that in intrusion detection systems the false-positive
rate of individual signals has an outsized effect on overall system utility: even at
high true-positive rates, a signal with a 1% false-positive rate will produce more
false alerts than true ones on a typical network where attacks are rare.
The practical implication is that signal weights should reflect each signal's
discriminative power: its ability to distinguish attack from benign change in the
target deployment.
PeerWatch assigns weights by evidential strength: cryptographic anchor changes (+3.0
for port/protocol mismatch, +3.0 for SSH host key change) carry far more weight than
heuristic signals (+0.5 for Jaccard drift, +0.5 for MAC conflict) that fire routinely
under legitimate operation.

=== Signal Compositing

Independent signals with low individual discriminative power can be combined to achieve
high discriminative power.
If two signals each have a 10% false-positive rate and fire independently, the joint
probability of both firing simultaneously on a benign event is approximately 1%,
a tenfold reduction in false-positive rate with no loss of true-positive rate for attacks
that trigger both.

This compositing effect is the formal justification for PeerWatch's threshold design:
an OS fingerprint drift alone may not cross the investigation threshold; OS drift
combined with TTL deviation and port profile change in the same tick reaches the
threshold while remaining unlikely under benign conditions.
Treating signals as independent is a conservative approximation, in reality, correlated
signals (e.g., OS change and TTL change both caused by device substitution) provide
less additional evidence than independent signals would, so the approach underestimates
joint evidence rather than overstating it.

=== Exponential Decay and the Cold-Start Period

A device that triggers anomaly events during a legitimate firmware update should not
remain permanently penalised once the update is complete and the new baseline is stable.
Exponential decay, where the suspicion score halves every $T$ days, implements a
forgetting mechanism: unreinforced anomalies fade over time without a hard reset.
Event-window approaches that reset scores after a fixed period produce cliff effects
(a device near the window boundary retains full score; one just past it retains none);
continuous decay avoids this discontinuity.
The half-life parameter (`suspicion_half_life_days`, default 3.5 days) is tunable
to the deployment context.

The cold-start problem, first observed in recommender systems and fraud detection,
applies directly to device identity tracking.
A device seen for the first time has no baseline; scoring drift against a single
observation produces high false-positive rates on legitimate newly-discovered devices.
PeerWatch withholds scoring for the first `baseline_min_scans` observations (default 5),
recording events without contributing to the suspicion score until a stable baseline
is established.

=== Threshold Calibration

The investigation threshold determines the operating point on the precision-recall
curve.
Lowering the threshold increases true-positive rate at the cost of false-positive rate;
raising it reduces false alerts at the risk of missed detections.
Axelsson @axelsson shows that for realistic base rates of attacks on a typical network,
even modest false-positive rates render a detection system impractical; an alert that
fires ten times per day on a clean network will be ignored within a week, eliminating
any security value.

Threshold calibration is therefore not a parameter to set once and forget but a
deployment-specific tradeoff between operator tolerance for false alarms and the
acceptable miss rate for real attacks.
@testing characterises PeerWatch's operating point empirically under both simulated
attack traffic and clean-traffic conditions, providing the data an operator needs to
adjust the threshold for their specific environment.

This chapter has established the foundations on which PeerWatch is built.
@lan-layer-attack defined the threat landscape — the attack techniques that existing
single-signal tools cannot detect and that motivate a multi-signal approach.
@device-fingerprinting surveyed the fingerprinting signals available to a locally-deployed monitor,
from active nmap probing to passive TCP stack observation and cryptographic anchors.
@related-work-and-tools positioned PeerWatch against existing tools and research, identifying the
vacant design space it occupies.
@tools-and-libraries and @evidence-accumulation introduced the tools the implementation relies on and the
theoretical basis for combining their outputs into a coherent scoring model.
@requirements-and-analysis translates this context into a structured requirements specification and
analyses it into an initial design.

= Requirements and Analysis <requirements-and-analysis>

== Detailed Problem Statement <problem-statement>

The introduction established that existing tools fail to detect device substitution
and service-level impersonation attacks on home and small-office networks.
This section states the precise technical problem an implementation must solve:
the specific uncertainties, constraints, and failure modes from which the
requirements in @requirements Section 3.2 are derived.

The system must detect when a device observed at a given MAC or IP address in a
previous scan is no longer the same physical or logical device.
It must do this without external ground truth: at runtime there is no oracle to
confirm whether a fingerprint change represents a firmware update or an attack.
Detection is therefore probabilistic, evidence accumulates across scan cycles
until a configurable confidence threshold is crossed, at which point investigation
is triggered.
The goal is not to prove an attack has occurred, but to surface sufficient evidence
that an operator or autonomous rule can act on it with an acceptable false positive
rate.
This distinguishes the problem from signature-based intrusion detection, which
matches observations against known attack patterns; PeerWatch detects drift against
a self-built per-device baseline regardless of whether the underlying technique
appears in any signature database.

Several classes of legitimate event produce observations indistinguishable from
attacks in isolation.
A firmware update changes OS fingerprint and may change port profile and TTL
baseline.
A DHCP lease renewal reassigns an IP, potentially to a different device.
A service restart or version upgrade changes the service banner and may open or
close ports transiently.
MAC address randomisation, enabled by default in modern mobile operating systems,
breaks MAC-keyed identity continuity for mobile devices.
A router reconfiguration shifts TTL values and route paths simultaneously for all
subnet devices.
These events define the false-positive ceiling: any signal that fires on them
without corroboration or weighting will produce an alert rate that renders the
system unusable in practice @axelsson.
Evidence accumulation, signal weighting, and score decay are therefore
requirements rather than optional refinements, they are the mechanism by which
the system remains useful under legitimate network activity.

The deployment target imposes hard operational constraints.
Nmap OS detection requires root privilege to send raw socket probes; promiscuous-mode
packet capture requires root and a network interface that can see subnet broadcast
traffic.
Neither constraint can be mitigated in software.
Nmap scanning a /24 subnet takes between 15 and 60 seconds depending on host density
and scan depth; the minimum tick interval is bounded below by this figure.
Passive capture is continuous while active scans are periodic: passive observations
must be attributed to the device identity established by the most recent active scan,
and devices that generate no outgoing traffic between scans are invisible to passive
observation.
There is no managed switching infrastructure, SNMP feed (Simple Network Management
Protocol — device telemetry polling), NetFlow export (per-flow traffic metadata
generated by managed routers and switches), or SPAN port (Switched Port Analyser —
a switch feature that mirrors all traffic from one port to a dedicated monitoring
port) available; the monitoring host sees only traffic visible on its local interface
and subnet broadcasts.

Per-device threshold analysis has a structural failure mode: a coordinated attack
affecting multiple devices simultaneously, each producing insufficient evidence to
cross the per-device threshold individually, will produce no alert.
Lowering the per-device threshold to catch such attacks would generate unacceptable
false positives under legitimate fleet-wide events, a router reconfiguration shifts
TTL values for all devices at once.
Fleet-level correlation is therefore a first-class detection requirement rather than
a sensitivity adjustment.
It requires a bounded tick window within which events from multiple peers are
co-evaluated; the window start is the previous tick timestamp, and only events
recorded after that timestamp are eligible for fleet pattern matching.

Two architectural constraints emerge from the problem domain before any design
decisions are made.
First, the LLM must not receive adversarially-controlled data.
Device-reported hostnames, service banners, and packet payloads are attacker-
controllable strings that, if passed to the model, expose it to indirect prompt
injection @promptinjection, a compromised device could craft its hostname to
cause the LLM to suppress or misclassify the alert investigating it.
LLM input must therefore be restricted to data derived entirely by the detection
pipeline: numeric scores, event type labels drawn from a fixed enum, and device
identifiers assigned by PeerWatch, not reported by the device.
Second, autonomous blocking carries irreversibility risk: an incorrectly blocked
device may take a legitimate service offline.
The decision to block must be governed by deterministic rule-based guards that LLM
output cannot override; the model's severity classification may be one guard among
several, but the guard logic itself must be purely rule-based.

== Requirements <requirements>

The requirements below are derived directly from the constraints identified in
@problem-statement.
Functional requirements specify what the system must do; non-functional requirements
specify properties the implementation must exhibit.
Requirements are numbered for traceability: Chapter 4 references them when describing
design decisions, and @testing references them when describing test coverage.


=== Functional Requirements

#figure(
  table(
    columns: (auto, 1fr),
    align: (left, left),
    [*ID*], [*Requirement*],

    table.hline(stroke: 0pt),
    table.cell(colspan: 2)[*A — Device Discovery and Identity Tracking*],

    [FR1],
    [The system shall periodically scan a configurable IPv4 /24 subnet using nmap,
      discovering active hosts and recording OS family, open TCP/UDP ports, service
      types, and MAC address per host.],

    [FR2],
    [Device identity shall be persisted across daemon restarts in a structured store
      keyed by MAC address; devices that expose no MAC address shall be keyed by IP
      address.],

    [FR3],
    [On each scan, the system shall compare each device's current fingerprint against
      its stored baseline and emit a typed identity event for each detected drift.],

    [FR4],
    [Each identity event shall carry a configurable numeric weight; the device's
      suspicion score shall be the weighted sum of accumulated events subject to
      exponential decay between ticks.],

    [FR5],
    [The system shall maintain a per-device known-services table; events for service
      fingerprint changes on ports where oscillation has been previously observed shall
      be suppressed.],

    [FR6],
    [Scoring shall be withheld for the first $N$ observations of a newly discovered
      device (configurable `baseline_min_scans`); events shall be recorded but shall
      not contribute to the suspicion score during this warmup period.],

    table.hline(stroke: 0pt),
    table.cell(colspan: 2)[*B — Passive Monitoring*],

    [FR7],
    [The system shall run a continuous passive packet capture loop in parallel with
      active scans, monitoring: (a) ARP reply binding conflicts; (b) per-device TTL
      deviation from an accumulated baseline; (c) TCP stack fingerprint inconsistency;
      (d) IP identification field counter anomalies.],

    [FR8],
    [The system shall track route path stability per device via periodic traceroute;
      each hop shall be attributed to an autonomous system; changes in hop sequence or
      ASN membership shall emit identity events.],

    [FR9],
    [The system shall track SSH host key and TLS certificate fingerprints per service
      port; a change in fingerprint on a previously observed port shall emit an identity
      event.],

    table.hline(stroke: 0pt),
    table.cell(colspan: 2)[*C — Fleet Correlation*],

    [FR10],
    [After each scan tick, the system shall evaluate identity events recorded since
      the previous tick across all peers; where $≥ N$ peers exhibit the same event
      class (pattern-dependent threshold), a fleet pattern shall fire and a configurable
      score boost shall be applied to each matching peer.],

    table.hline(stroke: 0pt),
    table.cell(colspan: 2)[*D — LLM-Assisted Triage*],

    [FR11],
    [When a device's suspicion score reaches or exceeds a configurable threshold, the
      system shall invoke a locally-running LLM via Ollama and request a structured JSON
      investigation report.],

    [FR12],
    [The system shall remain fully operational if Ollama is unavailable; a rule-based
      severity assignment shall be substituted for the LLM report without loss of
      detection capability.],

    [FR13 <fr13>],
    [The LLM prompt shall contain only data derived by the detection pipeline: numeric
      suspicion score, event type labels from a fixed enum, system-assigned device
      identifiers, and timestamp. Raw packet payloads, device-supplied hostnames, service
      banners, and any other attacker-reachable strings shall not appear in the prompt.],

    table.hline(stroke: 0pt),
    table.cell(colspan: 2)[*E — Remediation*],

    [FR14],
    [The system shall support autonomous remediation via iptables INPUT and OUTPUT DROP
      rules for devices that satisfy all blocking guards.],

    [FR15],
    [All four of the following guards must pass before a block is applied: (a) IP and
      MAC not in `never_block`; (b) suspicion score $≥$ `block_confidence_floor`;
      (c) severity == "high"; (d) no active block already exists for this IP.],

    [FR16],
    [Three remediation modes shall be supported: `dry_run` (log decision only),
      `confirm` (prompt operator before applying), `enforce` (apply rule immediately).],

    [FR17],
    [Blocks shall expire after a configurable TTL; expired rules shall be removed on
      each tick. All block decisions including dry-run outcomes shall be written to an
      append-only audit log before any rule is applied or withheld.],

    table.hline(stroke: 0pt),
    table.cell(colspan: 2)[*F — Configuration*],

    [FR18],
    [All thresholds, event weights, decay parameters, scan interval, remediation mode,
      and model selection shall be configurable via a single JSON file without code
      changes.],
  ),
  caption: [Functional requirements.],
  kind: "requirements",
  supplement: "Table",
) <fr-table>

=== Non-Functional Requirements

#figure(
  table(
    columns: (auto, 1fr, auto),
    align: (left, left, left),
    [*ID*], [*Requirement*], [*Category*],

    [NFR1],
    [The system shall run on hardware with $≥$ 4 GB RAM with no dedicated appliance
      or managed switching infrastructure required.],
    [Deployment],

    [NFR2],
    [No outbound internet connectivity shall be required at runtime; the system shall
      be fully functional in an air-gapped environment.],
    [Deployment],

    [NFR3],
    [The LLM prompt construction path shall contain no dynamic interpolation of
      device-supplied strings, satisfying FR13 by construction rather than by policy.],

    [Security],

    [NFR4],
    [All remediation decisions shall be written to the audit log before any iptables
      rule is applied or withheld; no silent blocking shall occur.],
    [Auditability],

    [NFR5],
    [The scan interval shall be bounded below by a configurable rate-limit floor to
      prevent subnet flooding regardless of operator configuration.],
    [Performance],

    [NFR6],
    [The detection and scoring pipeline shall operate independently of LLM
      availability, satisfying FR12 without degraded detection coverage.],
    [Reliability],

    [NFR7],
    [The test suite shall require no live network access; all detection scenarios
      shall be exercisable via simulated scan sequences injected directly into
      PeerStore.],
    [Testability],

    [NFR8],
    [The system shall build device baselines autonomously from a cold start with no
      operator-supplied initial configuration beyond the target subnet.],
    [Usability],
  ),
  caption: [Non-functional requirements.],
  kind: "requirements",
  supplement: "Table",
) <nfr-table>

== Use Cases <use-cases>

Four actors interact with the system.  The *Network Administrator* is the human operator: they
configure PeerWatch, review investigation reports, approve or reject remediation actions in
`confirm` mode, and consult the audit log.  The *PeerWatch Daemon* is the primary automated
actor: it drives the scan loop, ingests passive observations, performs fingerprint comparison,
and coordinates all downstream components.  *Ollama* is an external actor: a local LLM service
invoked by the daemon when suspicion crosses the investigation threshold; it is never invoked
directly by the administrator.  *iptables* is a system actor that receives firewall rule commands
from the Remediator component.

@tbl-usecases lists all ten identified use cases.  Full specifications for the three most
security-critical cases (UC4, UC3, UC7) appear in @appendix-usecases.

#figure(
  table(
    columns: (auto, 1fr, auto),
    align: (center, left, center),
    table.header([*ID*], [*Use Case*], [*Primary Actor*]),
    [UC1], [Run periodic subnet scan], [Daemon],
    [UC2], [Ingest passive observations], [Daemon],
    [UC3], [Compare fingerprint against baseline], [Daemon],
    [UC4], [Trigger LLM investigation], [Daemon],
    [UC5], [View investigation report], [Administrator],
    [UC6], [Configure parameters], [Administrator],
    [UC7], [Approve remediation block], [Administrator],
    [UC8], [Review audit log], [Administrator],
    [UC9], [Inject crafted nmap XML], [Administrator],
    [UC10], [Auto-expire block on TTL], [Daemon],
  ),
  caption: [Identified use cases.],
  kind: "requirements",
  supplement: "Table",
) <tbl-usecases>

UC4 (_Trigger LLM investigation_) is architecturally the most constrained use case.  The daemon
passes only sanitised, structured fields (suspicion score, event list, and fingerprint delta)
to the agent prompt; raw packet payloads and peer-supplied strings are never forwarded.
This design directly mitigates the indirect prompt-injection risk identified in NFR3
@promptinjection.  UC7 (_Approve remediation block_) is exercised only in `confirm` mode; in
`dry_run` mode it reduces to a no-op, and in `enforce` mode it is bypassed entirely by the
daemon.  UC9 (_Inject crafted nmap XML_) is included as an explicit use case because the injection
interface (dropping a file into `data/raw/` between ticks) forms the basis of both the attack
simulation test suite and the manual demonstration scenario described in @testing.

== Analysis <analysis>

The requirements established what the system must do; this section analyses them to extract the
information structures the system must store, the components that must exist to satisfy each
requirement group, and the key architectural decisions that constrain the design before
implementation begins.  These decisions are elaborated further in @design-implementation.

=== Data Model <data-model>

The central entity is a *Peer*: a device that has been observed on the subnet in at least one
scan.  A Peer record accumulates identity evidence across scan cycles: it is not a snapshot of
a single observation but a longitudinal model of a device's expected behaviour.

Stable devices (those whose nmap output includes a MAC address) are keyed by MAC address, since
IP addresses are volatile: a DHCP lease renewal or router reboot can legitimately reassign an IP
to a different device, which would cause a MAC-keyed system to raise a false positive only for
the new device, not the old one.  Devices that nmap reports without a MAC (typically off-subnet
hosts or devices that suppress ARP) are keyed by IP address and flagged as volatile; identity
continuity guarantees for these peers are weaker by design.

@tbl-datamodel summarises the fields maintained per Peer and the requirement group (@fr-table) each field
satisfies.

#figure(
  table(
    columns: (auto, 1fr, auto),
    align: (left, left, center),
    table.header([*Field*], [*Description*], [*FR group*]),
    [`mac`], [Primary key for stable devices; `None` for volatile peers], [A],
    [`ip`], [Last observed IP address; primary key for volatile peers], [A],
    [`os_family`], [Operating system family inferred by nmap], [B],
    [`open_ports`], [Set of open TCP/UDP ports from most recent scan], [B],
    [`known_services`],
    [Per-port service type baseline (suppresses oscillation)],
    [B],

    [`ttl_baseline`],
    [Mean TTL observed in passive capture; used for deviation scoring],
    [C],

    [`tcp_fingerprint`],
    [Passive OS fingerprint from TCP stack behaviour (p0f model)],
    [C],

    [`route_path`], [Ordered hop sequence from last traceroute], [C],
    [`ssh_key_hash`],
    [SHA-256 of SSH host key on port 22 (or configured port)],
    [B],

    [`tls_cert_hash`], [SHA-256 of TLS certificate on known TLS ports], [B],
    [`mac_oui_vendor`], [OUI vendor string derived from MAC prefix], [B],
    [`suspicion_score`],
    [Accumulated weighted evidence score; decays over time],
    [D, E],

    [`baseline_scans`], [Count of scans completed; gates warmup period], [A],
    [`scan_history`], [Ordered list of `ScanRecord` snapshots], [A, B],
  ),
  caption: [Peer entity fields and the requirement groups they satisfy.],
  kind: "requirements",
  supplement: "Table",
) <tbl-datamodel>

Three supporting entities complete the model.  A *ScanRecord* is an immutable snapshot of one
tick: it stores the timestamp, the list of anomaly events fired, and the score delta applied.
A *FleetAlert* records a coordinated-pattern detection: the pattern name, the set of peer
identifiers involved, the boost applied, and the tick timestamp.  A *RemediationBlock* is the
audit record for one iptables rule: the target IP and MAC, the issue time, the expiry time, the
triggering severity, and the score at the time of issue.  An *InvestigationReport* stores the
structured JSON output of one LLM invocation: the peer identifier, severity verdict, rationale
text, and recommended action.  None of these supporting entities reference each other; they are
all associated to their parent Peer by MAC or IP key, keeping the model flat and easy to
serialise to JSON.

=== Component Identification <components>

@tbl-components maps each functional requirement group to the source module responsible for
satisfying it.  The mapping guided the initial module decomposition and is reflected directly in
the `src/peerwatch/` package structure.

#figure(
  table(
    columns: (auto, auto, 1fr),
    align: (center, left, left),
    table.header([*FR group*], [*Module(s)*], [*Responsibility*]),
    [A],
    [`daemon.py`, `parser.py`],
    [Periodic nmap invocation, XML ingestion, tick coordination],

    [B],
    [`peer_store.py`, `comparator.py`],
    [Device identity storage, fingerprint comparison, drift scoring],

    [C],
    [`packet_capture.py`, `route_tracker.py`],
    [Passive TTL/TCP observation, traceroute path tracking],

    [D],
    [`fleet_correlator.py`],
    [Cross-peer coordinated pattern detection, score boosting],

    [E],
    [`agent.py`],
    [LLM triage invocation, rule-based fallback severity assignment],

    [F],
    [`remediation.py`],
    [iptables rule management, block TTL, audit logging],

    [—],
    [`config.py`],
    [Pydantic configuration model, threshold and weight validation],
  ),
  caption: [Functional requirement groups mapped to implementation modules.],
  kind: "requirements",
  supplement: "Table",
) <tbl-components>

The daemon coordinates all modules but contains no detection logic itself; it is responsible
only for scheduling, calling `convert_pending_xml()` to ingest any injected nmap files, and
advancing the tick.  This separation means each detection component can be unit-tested in
isolation without running the full scan loop, which is important given that live nmap scans
require root and network access.

=== Key Design Decisions <design-decisions>

Three decisions made during analysis have the broadest impact on the rest of the design.  Each
was reached by considering alternatives against the requirements and constraints established
above.

*MAC-primary keying.*  The alternative was to key peers by IP address.  IP-keyed identity breaks
immediately on DHCP lease renewal: if `192.168.1.42` is reassigned from a printer to a laptop,
an IP-keyed store would score the laptop for not looking like the printer.  A hostname-keyed
approach was also considered, but hostname resolution requires DNS, which is not always present
or reliable on small-office networks, and hostnames can be spoofed as readily as IP addresses.
MAC addresses are hardware-assigned and stable across reboots, making them the strongest
available identity anchor at layer 2.  The MAC-spoofing case, where an attacker clones a
victim's MAC, is explicitly detected as an identity collision event (FR8) rather than
suppressed.

*Additive score accumulation with exponential decay.*  An event-threshold model, fire an
investigation on the first tick any single event exceeds a fixed magnitude, would satisfy
FR13 at low implementation cost, but would violate NFR1 (false-positive rate).
Axelsson's analysis of base-rate effects in intrusion detection @axelsson shows that even
a 99% accurate binary classifier produces predominantly false positives on a network where
attacks are rare; accumulating evidence across multiple ticks raises the posterior probability
of a genuine attack before triggering investigation.
Exponential decay (score halves every 3.5 days by default) prevents stale low-confidence events
from permanently biasing the score of a peer that was suspicious six months ago and has been
well-behaved since.  The cold-start warmup period (first five scans, configurable) records
events without scoring them, establishing a baseline before the decay clock starts.

*LLM as triage advisor, not decision-maker.*  An alternative design placed the LLM in the
authorisation path: the agent would both assess severity and issue the iptables command.
This was rejected on two grounds. First, auditability: FR18 requires a complete audit trail; LLM reasoning
is non-deterministic and cannot be reproduced from the audit record alone. Second, reliability:
if Ollama is unavailable, the system must still function; rule-based severity assignment serves
as the fallback, and the remediation guards are purely deterministic.  The adopted design keeps
the LLM solely in the investigation path: it produces a structured JSON report that a human or
the rule-based guards can act on, but it never issues a system call.

@design-implementation describes the implementation of each component in detail, starting with the daemon
scan loop and progressing through the detection pipeline in the order data flows through it.

= Design and Implementation <design-implementation>


== System Architecture <system-architecture>

PeerWatch is a single daemon process (`daemon.py`) executing a periodic tick loop.
Each tick is an atomic, sequential pipeline: it scans the subnet, ingests results into the
device identity store, drains the passive observation queue, runs fleet-level correlation,
triggers LLM investigation for peers whose suspicion score crosses the threshold, and applies
or expires remediation blocks.
The sequential tick model eliminates inter-component race conditions: no component reads state
that another is concurrently writing, and the full system state is reproducible from the
persisted `peer_store.json` at any tick boundary.

@fig-arch shows the data flow between components.
Solid-bordered boxes are Python modules; dashed-bordered boxes are external processes or
files.
Italicised labels denote components outside the Python process boundary.
`PeerStore` (shaded) is the central mutable state shared by all detection phases.

#figure(
  diagram(
    node-stroke: 0.5pt,
    node-corner-radius: 3pt,
    node-inset: 6pt,
    spacing: (1.2em, 1.2em),

    // Active scan path
    node(
      (0, 0),
      text(size: 9pt, style: "italic")[nmap],
      name: <nmap>,
      fill: luma(245),
      stroke: (dash: "dashed"),
    ),
    node((1, 0), text(size: 9pt)[`parser.py`], name: <parser>),
    node(
      (2, 0),
      text(size: 9pt, weight: "bold")[PeerStore],
      name: <ps>,
      fill: luma(225),
    ),
    node((3, 0), text(size: 9pt)[`fleet_correlator`], name: <fc>),
    node((4, 0), text(size: 9pt)[`agent.py`], name: <agent>),
    node((5, 0), text(size: 9pt)[`remediation.py`], name: <rem>),
    node(
      (6, 0),
      text(size: 9pt, style: "italic")[iptables],
      name: <ipt>,
      fill: luma(245),
      stroke: (dash: "dashed"),
    ),

    // Passive capture path
    node(
      (0, 1),
      text(size: 9pt, style: "italic")[scapy thread],
      name: <scapy>,
      fill: luma(245),
      stroke: (dash: "dashed"),
    ),
    node((1, 1), text(size: 9pt)[Queue], name: <queue>),
    node(
      (2, 1),
      text(size: 9pt, style: "italic")[peer_store.json],
      name: <json>,
      fill: luma(245),
      stroke: (dash: "dashed"),
    ),

    // Active pipeline
    edge(<nmap>, <parser>, "->"),
    edge(<parser>, <ps>, "->"),
    edge(<ps>, <fc>, "->"),
    edge(<fc>, <agent>, "->"),
    edge(<agent>, <rem>, "->"),
    edge(<rem>, <ipt>, "->"),

    // Passive ingestion
    edge(<scapy>, <queue>, "->"),
    edge(<queue>, <ps>, "->"),

    // Persistence
    edge(<ps>, <json>, "<->"),
  ),
  caption: [PeerWatch component data-flow diagram. Dashed boxes are external to the Python process. `PeerStore` is the central identity state updated by both ingestion paths.],
) <fig-arch>

*Tick pipeline.* Each tick executes the following steps in order:

+ *Rate-limit check.* If the previous tick completed fewer than `min_scan_interval_minutes`
  ago, the tick is skipped to prevent scan storms during slow nmap runs.
+ *XML injection drain.* `convert_pending_xml()` processes any crafted nmap XML files dropped
  into `data/raw/` since the last tick and writes the converted JSON to `data/processed/`.
  This is the test injection interface (UC9).
+ *nmap scan.* The daemon invokes nmap as a subprocess with `-O -sV -oX`; the resulting XML
  is parsed by `parser.py` into a list of `NormalisedData` records.
+ *Active ingest.* `add_or_update_peer()` is called once per host returned by nmap,
  comparing each against its stored fingerprint and accumulating anomaly events and score
  deltas.
+ *Passive drain.* Observations accumulated by the background capture thread since the last
  tick are drained from the inter-thread queue and applied to peer records via the
  corresponding `PeerStore` ingestion methods.
+ *Fleet correlation.* `FleetCorrelator.analyse()` examines events across all peers and
  applies coordinated-pattern score boosts.
+ *Investigation.* For each peer whose `suspicion_score` meets or exceeds
  `suspicion_threshold`, `SuspiciousAgent.investigate()` is called.
+ *Remediation.* `Remediator.evaluate()` checks guard conditions for each peer and
  `act()` issues or skips iptables blocks; `unblock_expired()` removes blocks whose TTL
  has elapsed.
+ *Persist.* `peer_store.save()` serialises the full store to `peer_store.json`.

*Thread model.* The passive capture layer (`packet_capture.py`) is implemented as a
self-contained background component and is fully functional as a library; however, it is
not yet started by `daemon.py` in the current release — the daemon tick runs only the
active-scan pipeline (steps 1–4 and 6–9).
The architecture below describes the intended integration, which is the natural next step
for deployment.
When wired in, passive packet capture cannot share the main thread because scapy's
`sniff()` is a blocking call: a single `threading.Thread(daemon=True)` would be started
once at daemon startup (before the first tick), running the capture loop indefinitely.
(`daemon=True` means the thread exits automatically when the main process exits, with no
explicit join required.)
Inter-thread communication uses a `queue.Queue`: the capture thread enqueues observation
records and the main thread drains the queue at step 5 of each tick.
All `PeerStore` ingestion methods acquire a `threading.Lock` (@peer-store), so passive
observations drained on the main thread and any future concurrent callers are safe.

*Persistence model.* `PeerStore` serialises to `peer_store.json` via Pydantic's
`model_dump()` at the end of each tick.
The file is loaded at daemon startup if it exists, allowing the daemon to resume from prior
state after a restart without discarding accumulated suspicion evidence.
`PeerStore.last_tick_at` is persisted alongside the peer data; `FleetCorrelator` uses it as
the event-window start to avoid re-triggering fleet patterns from events that fired in a
previous session.

*Configuration injection.* All components receive a single `Config` instance constructed at
startup.
No module reads configuration from a global variable; each takes `config` as a constructor
argument.
This makes every component independently testable with a minimal config object, without
touching the filesystem or invoking nmap.

The following sections describe the design and implementation of each component in the order
data flows through the pipeline.

== Scan Loop and Data Ingestion <scan-loop>

`daemon.py` is the entry point and tick coordinator.
It contains no detection logic: its responsibilities are scheduling, nmap subprocess
management, file I/O, and dispatching each tick's results to the pipeline modules.
This separation means the entire detection pipeline can be exercised in tests by calling
`run_pipeline()` directly with pre-supplied JSON files, without invoking nmap or touching
the network.

=== nmap Invocation

Each tick invokes nmap as a subprocess:

```python
subprocess.run(
    ["nmap", "-sV", "-O", "--osscan-guess", "-oX", str(output_path), subnet],
    capture_output=True, text=True, timeout=300,
)
```

Three flags drive the identity model.
`-sV` enables service and version detection, populating the per-port service strings that
PeerStore uses for service-drift comparison.
`-O` enables OS detection, which requires root; if the daemon runs without elevated
privileges, `os_candidates` will be empty for every host and OS-drift events will never
fire.
`--osscan-guess` instructs nmap to emit all plausible OS candidates, not only its top
pick — this is what makes the `os_candidates` multi-entry dictionary possible and is
therefore essential to the false-positive suppression described in @peer-store.

A 300-second timeout guards against unresponsive hosts stalling the scan loop.
Non-zero nmap exit codes are logged but do not abort the daemon: a failed scan produces
no new JSON file, so the pipeline runs on the previous tick's data with no new ingestion,
and the loop continues.

=== XML to JSON Conversion and Field Stripping

`jsonify_xml()` parses nmap's XML output using `xmltodict` — a lightweight Python library
that maps XML element hierarchies to Python dicts — and writes a cleaned JSON file
to `data/processed/`.
Before writing, a set of volatile fields is removed from each host record:

```python
_STRIP_FIELDS = {
    "@starttime", "@endtime", "distance", "tcpsequence",
    "ipidsequence", "tcptssequence", "times", "hostnames",
}
```

These fields change on every scan (TCP ISN sequencing counters, scan timestamps, and
round-trip time measurements) but carry no persistent identity signal.
Retaining them would inject noise into fingerprint comparisons and inflate the stored JSON
with data that cannot distinguish a firmware update from an impersonation.
Stripping happens at conversion time, so the fields are absent from both the on-disk JSON
and the structures ingested by PeerStore.

=== The Injection Interface

`convert_pending_xml()` polls `data/raw/` for XML files that do not yet have a JSON
counterpart in `data/processed/`:

```python
def convert_pending_xml(output_dir: Path) -> None:
    for xml_path in RAW_DIR.glob("*.xml"):
        json_equiv = output_dir / (xml_path.stem + ".json")
        if not json_equiv.exists():
            logging.info(f"New XML detected: {xml_path.name}")
            jsonify_xml(xml_path, output_dir)
```

Any XML file dropped into `data/raw/` between ticks is converted and ingested in the
next tick, without requiring root access or a live network.
This interface is the basis of the entire attack simulation test suite described in
@testing: crafted nmap XML files representing spoofed devices, ARP poisoning scenarios,
and service impersonation attacks can be injected and processed under controlled
conditions.
The injection check runs before the live nmap scan each tick, ensuring manually supplied
files are processed in the same tick they appear.

=== NormalisedData and the os_candidates Design

`NmapParser` transforms one xmltodict host record into a `NormalisedData` Pydantic model.
Most fields are straightforward extractions; the `os_candidates` field warrants attention:

```python
candidates: dict[str, int] = {}
for match in osmatches:
    accuracy = int(match.get("@accuracy", 0))
    for osclass in match.get("osclass", []):
        family = osclass.get("@vendor") or osclass.get("@osfamily")
        if family:
            candidates[family] = max(candidates.get(family, 0), accuracy)
```

nmap returns multiple `osmatch` entries ordered by descending accuracy.
Rather than recording only the top-ranked family, `NmapParser` iterates all entries and
builds a dict mapping each OS family to its best accuracy score across all matches
i.e., `{"Linux": 96, "Google": 93}` for an Android device.
This representation matters because nmap's top pick is not deterministic: slight variation
in TCP response timing between scans can cause it to reorder "Linux" and "Microsoft
Windows" as the top result for the same device.
If PeerStore compared only the top candidate, this reordering would fire an OS-change
event on every other scan.
By comparing candidate sets (@peer-store), PeerStore fires only when the union of known
candidates and newly observed candidates diverges, which is robust to nmap's
non-determinism.

Port extraction handles two xmltodict edge cases: when nmap reports exactly one open port,
xmltodict returns a dict rather than a list, so `_extract_ports()` normalises both forms.
Service strings are constructed as `name + "-" + product` where both are present
(e.g.,\ `ssh-OpenSSH`), falling back to whichever is available.
`open_ports` is sorted before storage so that Jaccard distance computation in PeerStore
is independent of scan ordering.

=== Ingestion Tracking, Rate Limiting, and Shutdown

`PeerStore.ingested_scan_files` is a set of JSON filenames that have already been
processed.
`run_pipeline()` filters `data/processed/*.json` against this set before ingesting,
ensuring that daemon restarts do not replay historical scans and that each injected file
is ingested exactly once.
The set is persisted with `peer_store.json` at the end of each tick.

The rate-limit guard compares the elapsed time since `last_scan_at` against
`min_scan_interval_minutes` (default 2 minutes).
If a slow scan overlaps its scheduled successor, the next tick is deferred rather than
stacked, preventing two nmap processes from running concurrently.

Graceful shutdown is handled by registering SIGINT and SIGTERM handlers that set a
`shutdown` boolean flag.
The inter-tick sleep is implemented as `_sleep_interruptible`, which wakes every second
to check the flag.
The daemon therefore always completes its current tick, including persisting `peer_store.json`,
before exiting — ensuring no partially-applied score increments are lost on SIGTERM.

== Device Identity Store and Fingerprint Comparison <peer-store>

`PeerStore` is the central mutable state of the system.
It maintains a longitudinal model of each observed device, accumulates anomaly evidence
across scan cycles, and exposes ingestion methods for all five detection signals.
All public methods that mutate peer state acquire a `threading.Lock`, since the passive
capture thread calls ingestion methods concurrently with the main thread's active-scan
ingestion.

=== Peer Model and Identity Keying

Each device is represented by a `Peer` record keyed by an internal UUID.
Two auxiliary indexes provide fast lookup: `mac_to_id` maps normalised MAC address to
UUID, and `ip_to_id` maps IP address to UUID.
Stable devices, those whose nmap output includes a MAC address, are registered in both
indexes; volatile (MAC-less) devices appear only in `ip_to_id` and carry an `is_volatile`
flag.

`add_or_update_peer()` resolves which peer a new scan result belongs to by querying both
indexes and branching on the number of candidates found:

- *Zero candidates* — the device is new; `_create_peer()` is called.
  The first scan's service types are preloaded into `known_services` so day-one
  observations do not immediately trigger service-change events.
- *One candidate* — the existing peer is updated. Suspicion decay is applied first,
  then fingerprint comparison, then the peer record is refreshed.
- *Multiple candidates* — the MAC index and IP index resolved to different peer records,
  indicating a possible identity collision; `_resolve_conflict()` is invoked.

=== Fingerprint Comparison Engine

`_compare_fingerprints()` evaluates four checks in sequence and returns a
`FingerprintComparison` record containing the events that fired and an overall similarity
score.

*OS comparison via candidate-set intersection.*
Rather than comparing the single top-ranked OS pick, the comparison uses the full set of
OS family names across all `osmatch` entries:

```python
prev_families = _os_candidate_families(prev)
curr_families = _os_candidate_families(incoming)
os_match = bool(prev_families & curr_families)
if not os_match:
    events.append("os_family_changed")
```

This choice is motivated by nmap's non-determinism: a device at 95% confidence for both
"Sony" and "Linux" may flip its top-ranked entry between scans depending on TCP response
timing.
Set intersection is stable under this jitter: `os_family_changed` fires only when the
candidate sets are genuinely disjoint, i.e., no previously observed OS family appears in
the new scan at all.

*Port-set Jaccard similarity.*
Open port sets are compared as:
$ J(A, B) = lr(|A inter B|) / lr(|A union B|) $
With $A$ and $B$ being the previous and incoming port sets. A result below `port_jaccard_threshold`
(default 0.6) fires `port_profile_changed` (+0.5).
Empty unions are excluded from comparison to avoid penalising devices behind a firewall
that intermittently suppresses all ports.

*Service type comparison on shared ports.*
Only the first token of nmap's service string is compared: `ssh` from `ssh-OpenSSH`,
`http` from `http-nginx`.
Version upgrades within the same protocol family are therefore not flagged — only a
genuine protocol change on a port (e.g., `ssh` → `http`) triggers
`service_type_changed` (+1.0 per port).
Comparison is limited to `shared_ports = prev_ports & curr_ports`; a port present in
only one scan is captured by the Jaccard check, not here.

*Full identity shift.*
A composite event that fires when all three dimensions change simultaneously: OS families
disjoint, Jaccard below 0.4, and at least one service type changed or no shared ports at
all.
This is the primary device-substitution signal (+2.0) and is designed to be robust
against the single-signal false positives that motivated the multi-signal approach.

The overall similarity score used for logging and drift reporting (not for triggering
events) is:
$ s = 0.5 dot.op s_"OS" + 0.3 dot.op J + 0.2 dot.op s_"svc" $
where $s_"OS" = lr(|F_"prev" inter F_"curr"|) / lr(|F_"prev" union F_"curr"|)$ is the
Jaccard similarity of the two OS candidate-family sets (not a binary flag, so partial
overlap (e.g., one family in common out of three) gives a score between 0 and 1);
$J$ is the port-set Jaccard from the previous check; and $s_"svc"$ is the fraction of
shared ports whose service type was unchanged
($s_"svc" = 1 - lr(|"changed ports"|) / lr(|"shared ports"|)$, or 1.0 when there are no
shared ports).

=== False-Positive Suppression

Seven distinct mechanisms address recurring false-positive patterns.
The first three are structural design choices; the remaining four target specific
nmap artefacts identified through empirical testing on real traffic (@sec-fp-analysis).

*`known_services` bidirectional oscillation suppression.*
`Peer.known_services` is a per-port set of service type strings that have been observed
at least once.
Before recording a `service_type_changed` event, the incoming service type is checked
against this set:

```python
new_type = new_svc.split("-")[0] if new_svc else ""
if new_type in prev.known_services.get(port, set()):
    # oscillation — silently re-merge and skip
    continue
```

If the type has been seen before, the event is silently skipped and the old type is
re-added to the set.
Critically, when `service_type_changed` does fire for the first time, _both_ the old
and new service types are written to `known_services`, not only the new type.
This ensures the oscillation is suppressed in both directions: a port cycling
`icslap` → `upnp` → `icslap` fires once (on the first `icslap` → `upnp` transition),
then silently absorbs all subsequent reversals.

*Warmup period.*
For the first `baseline_min_scans` scans (default 5), anomaly events are recorded in
`identity_history` but the suspicion score is not incremented.
This prevents a device first observed mid-configuration from entering the store with
artificially elevated score.

*One-shot guards.*
`flagged_port_mismatches: set[int]` and `flagged_vendor_mismatch: bool` are set when a
port-protocol mismatch or MAC OUI/OS mismatch is first detected and prevent those checks
from re-scoring on every subsequent tick.
Both fields are persisted in the peer snapshot, so the guards survive daemon restarts.

*Port-protocol mismatch.*
`WELL_KNOWN_PORT_PROTOCOLS` maps nine well-known ports to the set of service types
legitimately expected on them: port 22 expects `ssh`, port 80 expects `http`, and so on.
Any other service type detected on these ports fires `port_protocol_mismatch` (+3.0),
the highest single-event score in the system, reflecting that running a non-standard
service on a well-known port is a strong indicator of a backdoor or replacement device.
Port 443 deliberately includes both `https` and `http` since nmap may report `http` when
TLS termination is handled transparently by a proxy.
Service identifications of `tcpwrapped` (where nmap could not determine the protocol) are
excluded from comparison and never written to `known_services`, since `tcpwrapped` is an
nmap visibility gap rather than a real service identity.

*MAC OUI vendor versus OS family.*
`VENDOR_OS_COMPATIBILITY` maps vendor name substrings to the set of OS families
compatible with that hardware.
A device with an Apple-registered MAC but a Linux OS fingerprint fires
`mac_vendor_os_mismatch` (+2.0).
Generic NIC vendors (Intel, Realtek, ASUSTek) are intentionally absent from the
table: commodity PC hardware can run any OS, so flagging it would produce a high false
positive rate.
Only vendors with a strongly constrained hardware ecosystem (Apple, Raspberry Pi,
Microsoft Xbox, Sony, Amazon) are included.
Matching uses substring search (`keyword in vendor.lower()`) to handle vendor string
variations in nmap output.
An additional guard suppresses the mismatch when the peer's `known_os_families` set
already contains a vendor-compatible family — indicating that nmap's OS probe is
oscillating between readings rather than observing a genuine hardware contradiction.

*`known_os_families` oscillation suppression.*
Nmap's OS detection heuristic is sensitive to service-level response variation on the
same device: a Windows machine running UPnP/SSDP may match `Microsoft` on one scan and
`Fortinet` or `Polycom` on the next, depending on which UPnP response is in flight at
probe time.
`Peer.known_os_families` accumulates every OS candidate family ever observed for a peer.
`os_family_changed` is suppressed when the incoming OS candidates intersect this set;
the first genuine encounter with each family still fires, but repeated oscillation
between known families is absorbed silently.

*Visibility-gap guards for port and identity checks.*
`port_profile_changed` and `full_identity_shift` are suppressed when either the
previous or current scan has no visible ports.
An empty port set indicates an nmap visibility gap (the device is firewalled or
temporarily offline), not a substitution attack; comparing it against a populated
port set via Jaccard would always yield 0.0 and trigger a false alert.

=== Scoring and Exponential Decay <scoring-and-exponential-decay>

Suspicion score is additive across events and ticks.
Decay is applied at the start of each `add_or_update_peer()` call, before comparison:

```python
peer.suspicion_score *= 0.5 ** (elapsed_days / self._cfg.suspicion_half_life_days)
```

Applying decay _before_ scoring means a peer that has been clean for a month arrives at
the comparison with near-zero prior evidence; new events are therefore not amplified by
stale history.
The default half-life is 3.5 days: a score of 3.0 (the investigation threshold) decays
below 1.0 in approximately one week of clean scans.

@tbl-score-weights summarises the score increments for all active-scan events.

#figure(
  table(
    columns: (1fr, auto),
    align: (left, center),
    table.header([*Event*], [*Score*]),
    [`os_family_changed`], [+2.0],
    [`full_identity_shift`], [+2.0],
    [`mac_vendor_os_mismatch`], [+2.0],
    [`service_type_changed`], [+1.0 per port],
    [`identity_conflict_detected`], [+1.0],
    [`port_profile_changed`], [+0.5],
    [`mac_conflict`], [+0.5],
    [`port_protocol_mismatch`], [+3.0],
  ),
  caption: [Active-scan suspicion score increments. Passive-capture and fleet events are covered in @passive-layer and @fleet-correlator.],
  kind: "requirements",
  supplement: "Table",
) <tbl-score-weights>

=== Conflict Resolution, Volatile Peers, and Persistence

*Identity conflict resolution.*
When `add_or_update_peer()` resolves multiple candidate IDs (MAC and IP map to different
peer records) `_resolve_conflict()` selects a survivor and merges the losers into it.
Survivor selection prefers the non-volatile (MAC-confirmed) peer; among equally volatile
candidates, the higher scan count wins, favouring the record with more accumulated
evidence.
`_merge_peers()` transfers history, IP set, `known_services`, and score from loser to
survivor before deleting the loser record.
The conflict records `identity_conflict_detected` (+1.0) on the survivor.

This situation arises in two scenarios: a MAC-spoofing attack where the attacker takes a
known IP without cloning the MAC (the IP maps to the victim's peer, the attacker's MAC
maps to no peer, collision at the IP boundary), and a legitimate DHCP reassignment where
an IP previously held by peer A is now claimed by a new device with a different MAC.
The system treats both conservatively: score is incremented and investigation is triggered
if the threshold is reached, leaving the operator to distinguish the cases.

*Volatile peer eviction.*
MAC-less peers not observed within `volatile_peer_ttl_hours` are removed by
`evict_stale_volatile_peers()`, called once per tick after ingestion.
This bounds memory growth on subnets with high DHCP churn where off-subnet hosts
transiently appear without MAC addresses.

*Persistence.*
`PeerStore.save()` writes a versioned JSON snapshot containing all peer records,
`ingested_scan_files`, and `last_tick_at`.
`PeerStore.load()` rebuilds the `mac_to_id` and `ip_to_id` indexes from the peer data
rather than storing them separately, ensuring index consistency on load.
A `_SNAPSHOT_VERSION` integer guards against loading snapshots from an incompatible
schema — a mismatch logs a warning and starts a fresh store rather than attempting
migration.

*Comparator.*
`Comparator` is a read-only reporter that takes a populated `PeerStore`, aggregates
event counts per peer into `PeerDriftSummary` records, sorts them by suspicion score
descending, and logs a formatted drift table to the daemon log.
It contains no detection logic and makes no mutations; it is called once per tick after
ingestion to provide a human-readable audit trail independently of the alert output.

== Passive Observation Layer <passive-layer>

The passive observation layer collects network signals continuously between nmap scans,
providing four detection channels that active scanning cannot deliver: TTL baseline
deviation, ARP spoofing, TCP stack fingerprint contradiction, and IP ID counter anomaly.
A fifth channel, route path stability, runs on demand via traceroute.

=== Architecture and Testability

The layer is split into two halves that share no direct dependency.
The first half consists of typed observation dataclasses ,`TTLObservation`,
`ARPObservation`, `TCPFingerprintObservation`, and `IPIDObservation`, that are plain
Python `@dataclass`s with no scapy import.
The second half is the capture machinery: `PassiveCaptureObserver` and
`SniffCaptureLoop`.

This separation is the key testability decision for Phase 2.
Because the observation types are scapy-free, the full test suite for passive detection
injects typed observations directly into `PeerStore.ingest_*()` without requiring a
live network interface, elevated privileges, or scapy installed.
A test that verifies ARP spoofing detection simply constructs an `ARPObservation` with
a conflicting MAC and calls `peer_store.ingest_arp_observation()` — no packet capture
involved.

`PassiveCaptureObserver` wires the two halves.
It maintains four callback lists and exposes `on_ttl()`, `on_arp()`,
`on_tcp_fingerprint()`, and `on_ip_id()` registration methods.
`process_packet()` parses a raw scapy packet into the appropriate observation type and
dispatches to all registered callbacks.
The daemon registers one callback per type that routes observations to the corresponding
`PeerStore.ingest_*()` method.

`SniffCaptureLoop` wraps scapy's `sniff()` in a daemon thread:

```python
sniff(
    iface=self.iface,
    filter=self.bpf_filter,   # "ip or arp"
    prn=self.observer.process_packet,
    store=False,
    timeout=timeout,
)
```

The BPF filter `"ip or arp"` is applied at kernel level before any Python code runs,
discarding non-IP, non-ARP traffic without waking the Python interpreter.
`store=False` discards packets after processing, preventing unbounded memory
accumulation in long-running sessions.
The thread is a daemon thread so it exits automatically when the main process ends,
without requiring an explicit stop call.

=== Per-Signal Capture

*TTL baseline and deviation.*
Real-world TTL values observed in packets are always less than or equal to the device's
origin TTL, since each router along the path decrements the field by one.
`snap_ttl_to_os_default()` exploits this property to recover the plausible origin:

```python
_TTL_THRESHOLDS = [64, 128, 255]   # Linux/macOS, Windows, Cisco

def snap_ttl_to_os_default(raw_ttl: int) -> int:
    for threshold in _TTL_THRESHOLDS:
        if raw_ttl <= threshold:
            return threshold
    return _TTL_THRESHOLDS[-1]
```

An observed TTL of 60 snaps to 64 (four-hop Linux host); 120 snaps to 128 (eight-hop
Windows host).
PeerStore builds a per-peer TTL baseline from the first `ttl_baseline_min_samples`
observations, using the median to resist outlier packets, then snaps to an OS default.
Once established, any observation deviating by more than `ttl_deviation_threshold`
(default 15) fires `ttl_deviation` (+2.0).
A deviation of this magnitude cannot be explained by a route-length change alone —
it implies a different OS-family origin TTL or an injected packet with a forged TTL.

*ARP spoofing detection.*
Only ARP reply packets (`op == 2`, is-at) are processed.
Each reply's claimed IP-to-MAC binding is checked against the confirmed MAC stored in
PeerStore for that IP.
A discrepancy fires `arp_spoofing_detected` (+3.0), the highest-weight passive signal.
This directly detects the attack described in @lan-layer-attack: an attacker broadcasting gratuitous
ARP replies to redirect subnet traffic through a machine they control.

*TCP passive fingerprint.*
TCP SYN packets are fingerprinted passively: SYN-only (`SYN` flag set, `ACK` not set)
because the SYN carries the initiating device's native TCP stack options unmodified.
A SYN-ACK would reflect the responding server's preferences, not the device being
monitored.
Three OS profiles are maintained in `TCP_FINGERPRINT_PROFILES`, drawn from p0f and
nmap OS templates @p0f:

```python
"Linux": {
    "option_signatures": [
        ["MSS", "SACK", "TS", "NOP", "WScale"],
        ["MSS", "NOP", "NOP", "TS", "NOP", "WScale", "SACK"],
    ],
    "window_hint": range(14600, 65536),
    "ttl": 64,
},
```

`infer_os_from_tcp_fingerprint()` scores each profile against the observed option-kind
sequence: +1.0 per option present in both signature and observation, −0.5 per expected
option absent, −0.3 per extra option present; +1.0 bonus for exact window size match,
+0.5 for window in range.
A minimum score of 2.0 is required to suppress guesses on sparse input.
The inferred OS is cross-referenced against the peer's nmap `os_candidates` set via a
family mapping (e.g.,\ `"Linux"` covers both `"Linux"` and `"Android"` in nmap output).
A contradiction fires `tcp_fingerprint_mismatch` (+2.0).

*IP ID counter anomaly.*
The IP Identification header field is a 16-bit counter.
Older operating systems (and Windows) maintain a single global counter that increments
monotonically; modern Linux assigns a random value per connection.
`_detect_sequential_ip_ids()` distinguishes the two behaviours by examining the median
per-step delta across a sample window:

```python
deltas = [(samples[i+1] - samples[i]) % 65536 for i in range(len(samples) - 1)]
return statistics.median(deltas) <= 100
```

A median delta of ≤ 100 is characteristic of a global counter; large irregular deltas
indicate random assignment.
Only peers classified as sequential have their subsequent IP IDs monitored for anomalous
jumps; flagging random-ID peers would produce pure noise.
Modular arithmetic handles the 16-bit wrap-around at 65535→0.

=== Route Tracking and ASN Enrichment

`RouteTracker` runs traceroute to a target address and maintains a per-destination
baseline hop sequence.
The subprocess is invoked with `-n` (no DNS reverse lookups, for speed), `-q 1` (one
probe per hop rather than the default three), and a timeout derived from the maximum hop
count:

```
traceroute -n -q 1 -w 5 -m 30 <destination>
```

The output parser deduplicates the three probe lines traceroute emits by default using
a `seen_hops` set, taking only the first responding IP per hop number.
Silent hops (`* * *`) are recorded as `RouteHop` entries with `ip=None`.

`_compare()` evaluates three change types:
- *Hop count change*: total hop count differs.
- *Hop sequence change*: Jaccard similarity of responding-IP sets falls below 0.7, a
  tighter threshold than the port Jaccard (0.6) because legitimate route changes are
  less frequent than port profile variations.
- *New ASN in path*: an autonomous system number appears in the observed path that was
  not present in the baseline.
Any of these fires `route_changed` (+1.0 for hop changes, +1.5 for new ASN).

ASN resolution uses Team Cymru's DNS-based BGP origin service @teamcymru.
The query format is a reverse-octet DNS TXT lookup:
`<reversed-octets>.origin.asn.cymru.com`.
Two resolvers are tried in order: `dns.resolver` (fast, requires the `dnspython`
package) and a raw socket whois connection to `whois.cymru.com:43` (no external
dependency).
Results are cached in-process in `_ASN_CACHE` to avoid repeated lookups for the same
hop IP across ticks.
RFC-1918 and loopback addresses are skipped — private-network hops have no public ASN.

A new ASN appearing in a traceroute path is a high-confidence signal for a BGP prefix
hijack or an MITM device inserted as a routing hop: both introduce an autonomous system
boundary not present in the established baseline.

== Fleet Correlation <fleet-correlator>

Per-peer fingerprint comparison detects that _a_ device has changed; it cannot determine
whether multiple devices changed _simultaneously_.
`FleetCorrelator` addresses this gap by examining the full event log across all peers
within a single tick window and firing coordinated-pattern detections when several peers
show the same anomaly type concurrently.
It runs after all per-peer ingestion is complete and before `SuspiciousAgent`, so that
investigation prompts already contain fleet context.

=== Tick Window and Event Collection

`analyse()` opens a window from `peer_store.last_tick_at` to the current time.
On the first tick `last_tick_at` is `None` and the method returns immediately with no
events: there is no prior baseline to define a window boundary.

Event collection builds a `recent` mapping of peer ID to the list of event type strings
fired since `window_start`:

```python
recent: dict[str, list[str]] = {}
for peer_id, peer in self._store.peers.items():
    events_in_window = [
        e.event for e in peer.identity_history
        if e.timestamp >= window_start
    ]
    if events_in_window:
        recent[peer_id] = events_in_window
```

Using `last_tick_at` as the boundary rather than `now() - scan_interval` is deliberate.
`last_tick_at` is persisted in `peer_store.json` at the end of every tick; on daemon
restart it is reloaded from the snapshot.
Events that fired before the restart have timestamps earlier than the loaded
`last_tick_at` and are therefore excluded from the next tick's window.
A wall-clock interval would have no such anchor and would re-process historical events
on every restart.

=== Pattern Matching, Boost Cap, and Fleet Context

The pattern registry is a flat list of 4-tuples: name, trigger event set, min-peers
config attribute, and base boost:

```python
_PATTERNS = [
    ("arp_poisoning",    frozenset({"arp_spoofing_detected"}), "fleet_arp_min_peers", 2.0),
    ("identity_sweep",   frozenset({"identity_conflict_detected", "full_identity_shift"}), "fleet_identity_min_peers", 2.0),
    ("route_shift",      frozenset({"route_changed"}), "fleet_route_min_peers", 1.5),
    ("os_normalisation", frozenset({"os_family_changed"}), "fleet_os_min_peers", 1.5),
    ("ttl_shift",        frozenset({"ttl_deviation"}), "fleet_ttl_min_peers", 1.5),
    ("service_sweep",    frozenset({"service_type_changed"}), "fleet_service_min_peers", 1.0),
]
```

A peer "hits" a pattern if it fired at least one event in the trigger set during the
current window.
A pattern fires if the number of hitting peers meets or exceeds its `min_peers`
threshold.
The `frozenset` semantics produce OR matching within a pattern: `identity_sweep`
triggers on either `full_identity_shift` or `identity_conflict_detected` because a
fleet-wide device-substitution attack may produce either event depending on whether the
attacker clones the victim's MAC.
Min-peer thresholds differ by pattern: `arp_poisoning` requires only 2 peers (an
attacker targeting a gateway and one host is sufficient), while `service_sweep` requires
4 (a scan-wide service change is only suspicious at scale).
All thresholds are configurable so operators can tune them for their subnet size.

Boost application is capped per peer per tick.
A `boost_applied` dict tracks cumulative boost received this tick; each pattern's
contribution is clipped to the remaining headroom:

```python
headroom = max(0.0, cap - boost_applied.get(pid, 0.0))
actual_boost = min(boost, headroom)
```

The default cap is 4.0.
Without it, a peer matching all six patterns in a single tick would accumulate 9.5 in
fleet boosts alone, immediately triggering a remediation block on what may be a
coincidental co-occurrence of routine events.
The cap ensures fleet boosts amplify existing per-peer evidence rather than substitute
for it.
Each boost is recorded as a `fleet_correlation_boost` event on the peer via
`PeerStore.add_suspicion()`, preserving a full audit trail of the scoring decision.

`FleetEvent` objects serve two purposes after `analyse()` returns.
The daemon appends each to `fleet_alerts.jsonl` for persistent audit.
All events are also passed to `SuspiciousAgent.investigate_all(fleet_events=...)` so
the LLM prompt includes the coordination context: pattern name, number of peers
involved, and the list of affected IPs.
Without this injection, each peer's investigation would be independent and the
simultaneous co-occurrence, the very signal that distinguishes a coordinated attack
from a coincidental configuration change, would be invisible to the agent.

== LLM-Assisted Investigation <agent>

`SuspiciousAgent` is invoked after fleet correlation completes.
It runs a four-step investigation pipeline for each peer whose suspicion score meets or
exceeds `suspicion_threshold`, produces a structured JSON report, and optionally feeds
cryptographic anchor results back into `PeerStore`.
The LLM is strictly in the triage path: it produces a severity verdict and
recommendations, but it never issues system calls and is never in the authorisation path
for remediation.

=== Investigation Pipeline

`investigate_all()` selects peers with `score >= threshold`, builds a per-peer lookup
of any `FleetEvent` objects that include that peer, and calls `investigate()` for each.
A single peer investigation proceeds in four steps:

+ `_analyse()` — format peer context into a prompt, invoke the LLM, parse the JSON
  response into an `AgentDecision`.
+ `_build_auto_identity_checks()` — append `ssh_hostkey` and `ssl_cert` scan
  recommendations for any peer with SSH or HTTPS ports open, regardless of what the
  LLM recommended.
+ `_execute_scans()` — execute each recommended scan type; some results feed back into
  `PeerStore`.
+ `_write_report()` — serialise the full `InvestigationReport` to
  `reports/investigation_<mac>_<timestamp>.json`.

=== Prompt Design and Injection Prevention

`_format_peer_context()` constructs the human-turn message passed to the LLM.
The included fields are: MAC address, IP set, suspicion score, OS fields from the latest
`NormalisedData`, all OS candidates with accuracy scores, device vendor string, open
ports, current services dict, per-port `known_services` history, and the timestamped
event history with structured detail dicts.
When fleet events are present, a labelled `FLEET CONTEXT` section is appended with the
pattern name, affected peer count and IPs, and the window timestamps.

What the prompt deliberately excludes is equally important.
Raw packet payloads, nmap service banner strings, DNS hostnames, and any other
unstructured data originating from the network are not forwarded.
The `details` dicts in `IdentityEvent` records contain only structured fields
(`port=22`, `old_service="ssh"`, `new_service="http"`) not raw wire data.
This is the primary mitigation for indirect prompt injection @promptinjection: an
attacker cannot craft a service banner or hostname that alters the LLM's severity
verdict, because those strings never appear in the prompt.

The system prompt in `prompts/suspicious_agent.txt` includes a Fleet Context Guide
section that explicitly instructs the model to increase severity when a fleet pattern is
present and to name the pattern in its explanation.
This structured instruction, rather than relying on the LLM to infer the significance
of fleet data from raw peer lists, produces more consistent severity calibration across
different model versions.

=== LLM Integration, Output Schema, and Fallback

The LLM client is initialised with:

```python
self.llm = init_chat_model(
    model, model_provider="ollama", temperature=0, format="json"
)
```

`temperature=0` produces deterministic outputs for identical inputs, making
investigations reproducible and making it easier to distinguish model-introduced variance
from genuine signal changes.
`format="json"` enables Ollama's grammar-constrained decoding, which forces the model
to emit syntactically valid JSON regardless of how verbose its base response tendency
is.
`_strip_code_fence()` handles the residual case where a model wraps its JSON in a
markdown code block despite the constraint.

The expected response is validated into `AgentDecision`:

```python
class AgentDecision(BaseModel):
    explanation: str
    severity: str          # "low" | "medium" | "high"
    recommended_scans: list[ScanRecommendation]
    recommended_actions: list[str]
```

where each `ScanRecommendation` carries a `type` (one of `nmap`, `traceroute`,
`tcpdump`) and a `reason` string.

Any exception during the LLM call, Ollama unavailable, JSON parse failure, network
timeout, routes to `_rule_based_fallback()`.
The fallback assigns severity by score thresholds (below 4.0 → low, 4.0–7.0 → medium,
above 7.0 → high) and inspects the set of fired events to select relevant scan
recommendations: a peer that fired `arp_spoofing_detected` receives a tcpdump recommendation.
The explanation is prefixed `[Rule-based fallback — LLM unavailable]` so operators can
distinguish fallback reports from LLM-produced ones.
This ensures FR15 (investigation always completes) regardless of whether Ollama is
running.

=== Automated Follow-up Scans and Cryptographic Anchors

`_build_auto_identity_checks()` adds `ssh_hostkey` and `ssl_cert` recommendations to
every investigation that involves a peer with SSH or HTTPS ports open, unconditionally:

```python
# Always run cryptographic identity checks for peers with SSH/HTTPS ports open
# — these catch service-mimicry evasion that LLM may not know to request.
auto_checks = self._build_auto_identity_checks(peer, decision.recommended_scans)
all_recs = list(decision.recommended_scans) + auto_checks
```

This is hardcoded detection logic outside the LLM path.
A sophisticated attacker can construct a device that perfectly mimics the victim's OS
fingerprint, port profile, MAC address, and TTL baseline.
What it cannot spoof without the victim's private key is the SSH host key fingerprint.
Cryptographic anchors are therefore the highest-confidence identity check available, and
deferring their execution to LLM discretion would create an evasion path.

`_execute_scans()` dispatches to five scan types.
`nmap` re-scans the target and re-ingests the result into `PeerStore` via
`NmapParser` and `add_or_update_peer()`, keeping the stored fingerprint current after
investigation.
`traceroute` and `tcpdump` run as subprocesses; their output is recorded in the report
but does not mutate `PeerStore`.
`ssh_hostkey` runs `nmap --script ssh-hostkey`, regex-parses all `SHA256:...`
fingerprints from the script output, and calls `peer_store.ingest_ssh_hostkeys()`.
On first call the fingerprints are stored as the trusted baseline; on subsequent calls
any difference fires `ssh_host_key_changed` (+3.0 to suspicion score).
The scan result output is annotated with `[KEY CHANGED on ports [22]]` when a change is
detected, making the signal visible in the report without requiring the reader to compare
raw nmap XML.
`ssl_cert` follows the same pattern using `nmap --script ssl-cert` and
`peer_store.ingest_ssl_cert()`, firing `ssl_cert_changed` (+2.0) on fingerprint change.

The choice of Phi-4 14B as the default model reflects a balance between
reasoning quality and local inference speed.
During development, Mistral 7B and Llama 3.1 8B were evaluated on the same
multi-signal investigation prompts; both produced correct severity verdicts on single-
event cases but showed weaker reasoning on composite cases where OS change, port drift,
and fleet context occurred simultaneously.
Phi-4 consistently named the relevant attack pattern and produced fleet-aware
explanations.
Running locally via Ollama means no investigation data leaves the monitored subnet,
satisfying the air-gap requirement and eliminating the latency and availability risk of
an external API.

== Autonomous Remediation <remediation>

`Remediator` is the final stage of each tick.
It receives an `InvestigationReport` from `SuspiciousAgent`, evaluates a deterministic
guard chain, and — if all guards pass — issues or logs an iptables block.
The LLM is not in the authorisation path: the severity field in the report informs guard
3, but a rule check, not the LLM, decides whether to act.

=== Guard Chain and Enforcement Modes

`evaluate()` applies five guards in sequence; all must pass before a `BlockAction` is
constructed and returned:

+ *Never-block whitelist.* Both IP and MAC are checked against `never_block`, a
  `frozenset` built once at `Remediator.__init__()` from config.
  Operators should include the gateway and the monitoring host itself.
  Frozenset membership is O(1) and immutable after construction.
+ *Score floor.* `suspicion_score >= block_confidence_floor` (default 5.0).
  This is intentionally above the 3.0 investigation threshold: a peer must accumulate
  further evidence after triggering LLM investigation before becoming block-eligible.
+ *Severity gate.* `severity.lower() == "high"`.
  The comparison is a deterministic string check against the `InvestigationReport`
  field; the LLM (or fallback) populates that field, but it cannot bypass the other
  four guards.
+ *No active block.* `_is_active_block()` scans `blocks.jsonl` for records where
  `executed=True`, `unblocked_at=None`, and `expires_at > now` for the same IP.
  Prevents double-blocking a peer whose block has not yet expired.
+ *IP available.* At least one IP must be resolvable from the peer record; volatile
  peers with no confirmed IP are skipped.

When all guards pass, `evaluate()` constructs a `BlockAction` containing the two
iptables command sequences and an expiry timestamp:

```python
block_cmds = [
    ["iptables", "-I", "INPUT",  "-s", ip, "-j", "DROP"],
    ["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
]
expires_at = now + timedelta(hours=cfg.block_ttl_hours)
```

`-I` (insert) places the DROP rule at the head of the chain, preventing a downstream
ACCEPT rule from overriding it.
Both INPUT and OUTPUT chains are targeted to block inbound traffic from the suspect
device and prevent any outbound exfiltration to it.

`act()` dispatches to one of three mode handlers.
Root privilege is checked once at `__init__()`: if `enforce` mode is requested but
`os.geteuid() != 0`, the mode is silently downgraded to `dry_run` with an error log
entry.
The downgrade is unconditional — not retried per call — so misconfigured deployments
fail safely rather than intermittently.

- *`dry_run`* (default): logs the would-be iptables commands and appends a
  `BlockRecord(executed=False)` to `blocks.jsonl`.
  No system state is modified.
- *`confirm`*: prints the block candidate — IP, score, reason, expiry, and the exact
  commands — to stdout and calls `input("Execute? [y/N]")`.
  `EOFError` and `KeyboardInterrupt` both default to `"n"`, ensuring that
  non-interactive sessions (SSH without a TTY, piped input) never accidentally confirm
  a block.
  A `"y"` response delegates to `_enforce()`.
- *`enforce`*: runs the iptables commands via `subprocess.run()`, appends
  `BlockRecord(executed=True)` on success or `BlockRecord(executed=False)` on failure.

The `reason` field stored in `BlockRecord` is built from the last five identity events
on the peer, falling back to the first 120 characters of the LLM explanation.
It is human-readable context for the audit log and is never passed to iptables.

=== Block TTL, Audit Log, and Atomic Rewrite

`unblock_expired()` is called at the end of each daemon tick, after `act()`.
It reads all records from `blocks.jsonl`, identifies those where
`executed=True`, `unblocked_at=None`, and `expires_at <= now`, runs the stored
`unblock_cmds`, stamps `unblocked_at = now`, and rewrites the file.

The JSONL file uses two write strategies depending on the operation.
Appending a new record uses `_append_record()` — a single-line write that cannot
produce a partial file.
Updating existing records (to set `unblocked_at`) requires a full rewrite;
`_rewrite_records()` performs this atomically:

```python
with tempfile.NamedTemporaryFile(mode="w", dir=dir_, delete=False, suffix=".tmp") as tmp:
    for record in records:
        tmp.write(record.model_dump_json() + "\n")
tmp_path.replace(self._blocks_path)
```

`Path.replace()` is an atomic rename on POSIX systems: if the daemon is terminated
between the write and the rename, `blocks.jsonl` is left intact and the orphaned `.tmp`
file is harmless.
Without this guarantee, a crash during rewrite could truncate the audit log, causing
`_is_active_block()` to miss an active block entry on the next tick and issue a
duplicate block.

Together, the guard chain and TTL expiry implement the complete block lifecycle:
a peer transitions from eligible → blocked (or dry-run logged) → auto-unblocked at TTL
expiry, with every decision — including declined `confirm` prompts and downgraded
`dry_run` records — written to `blocks.jsonl` as a tamper-evident append-only audit
trail.

== Configuration and Extensibility <configuration>

All thresholds, weights, and operational parameters are consolidated in a single
`PeerWatchConfig` Pydantic model defined in `config.py`.
Every field carries a typed default and an inline `description` kwarg that doubles as
schema documentation:

```python
port_jaccard_threshold: float = Field(
    default=0.6,
    description="Minimum Jaccard similarity between port sets before flagging drift",
)
remediation_mode: Literal["dry_run", "confirm", "enforce"] = Field(
    default="dry_run",
    description="dry_run: log only | confirm: prompt | enforce: execute (requires root)",
)
```

`PeerWatchConfig` inherits from `BaseModel`, not `BaseSettings`: there is no environment
variable resolution.
Configuration is always loaded from an explicit JSON file path via `load_config()`,
which handles three cases — `None` or missing file returns a fresh instance with all
defaults; a present file is parsed with `json.load()` and validated through
`PeerWatchConfig(**data)`.
Pydantic validation runs at construction time, so a misconfigured file (wrong type,
`remediation_mode: "auto"`, negative threshold) raises a `ValidationError` before the
daemon starts rather than at the point of first use.
The `Literal` constraint on `remediation_mode` is a particularly useful type-level
guard: it makes three semantically distinct operating modes an exhaustive, validated
enum rather than a convention-dependent string.

All components receive the config instance as a constructor argument; there is no global
config state.
`PeerStore`, `FleetCorrelator`, `Remediator`, and `SuspiciousAgent` each hold a
reference to the same `PeerWatchConfig` object, which means tuning a threshold in
`config.json` and restarting the daemon propagates the change everywhere without
modifying any detection logic.

Adding a new passive or active detection signal follows a three-step extension path.
First, define the event name string and call `peer.record_event()` with it at the
detection site in `peer_store.py`.
Second, add a typed `float` field to `PeerWatchConfig` with a conservative default and
description.
Third, add a scoring case in `_check_incoming_fingerprint()` (or the relevant
`ingest_*()` method) that reads the new weight from `self._cfg`.
No changes to `FleetCorrelator` or `SuspiciousAgent` are required unless the new signal
warrants a fleet pattern — in which case a single tuple is added to the `_PATTERNS`
list in `fleet_correlator.py` alongside the corresponding `int` min-peers field in
config.
This separation of signal definitions, weights, and pipeline orchestration keeps the
system extensible without requiring broad refactors.

= Testing and Evaluation <testing>

== Testing Strategy and Approach <testing-strategy>

Testing an intrusion detection system against live attacks is not feasible in a
controlled setting: it requires root privileges, a live network, real attacker
tooling, and produces results that cannot be independently reproduced.
PeerWatch's injection interface (@scan-loop) was designed to address this constraint
directly.
`NormalisedData` is the canonical input to the entire detection pipeline; it is a
plain Pydantic model that can be constructed in Python without invoking nmap,
touching the network, or holding any special privileges.
Any scan sequence, legitimate or adversarial, can be replayed deterministically
by feeding a sequence of `NormalisedData` records to `add_or_update_peer()`.

The test suite is organised into three categories.

*Unit tests* exercise individual components in isolation.
Each test constructs minimal inputs, calls one method, and asserts a single
outcome.
Components covered: `NmapParser`, `PeerStore` fingerprint comparison, suspicion
decay, persistence round-trip, `Comparator`, `PeerWatchConfig` validation,
agent rule-based fallback, and remediation guard chain.
None of these tests invoke a subprocess, open a network connection, or require
Ollama.

*Simulation tests* replay multi-scan sequences representing documented attack
patterns against a live `PeerStore` instance.
A baseline device is warmed up by feeding the same `NormalisedData` record six
times, placing the store past the `baseline_min_scans = 5` cold-start threshold
with `suspicion_score = 0.0`, and then one or more attack scans are injected.
The test asserts the resulting score and the specific events that fired.
Three simulation suites cover each detection phase:
Phase 1 (active-scan anomalies, scenarios A–I), Phase 2 (passive observation
signals), and Phase 3 (fleet correlation patterns F1–F16).

*Test infrastructure.*
`tests/simulation/factories.py` provides two helpers.
`scan()` builds a `NormalisedData` with sensible defaults
(`os="Linux"`, ports `[22, 80]`, services `{22: "ssh-OpenSSH", 80: "http-Apache"}`)
overridable by keyword argument.
`warm_up(store, baseline, n=6)` feeds the baseline six times so the next call is
the first that scores anomalies, the returned peer has `suspicion_score == 0.0`
because identical scans produce no fingerprint changes and warmup suppresses
scoring anyway.
`pytest.approx()` is used throughout for float score comparisons, since
floating-point accumulation across multiple increments makes exact equality
assertions brittle.
`PYTHONPATH = ["src"]` is configured via `pyproject.toml`, so no package installation
step is required to run the suite.

*Real-LAN evaluation.*
In addition to the simulation suite, PeerWatch was run continuously against a
home LAN for six days, producing 322 nmap scans at
approximately five-minute intervals.
These scans were replayed through the detection pipeline offline to measure
false-positive behaviour on a known-clean network.
The results of this evaluation (18 devices observed, none of which crossed the
investigation threshold) are analysed in @sec-fp-analysis and visualised in
@fig-fp-score-over-time and @fig-fp-score-distribution. _Note that one device reached very close to the
detection threshold, only not crossing due to decay._

#figure(
  image("figures/fp_score_over_time.pdf", width: 100%),
  caption: [Per-device suspicion scores across 243 real LAN scans (clean baseline,
    no attacks in progress). Devices above the dashed investigation threshold line
    represent false positives. Bold traces are devices that crossed threshold; faint
    traces stayed below.],
) <fig-fp-score-over-time>

#figure(
  image("figures/fp_score_distribution.pdf", width: 72%),
  caption: [Distribution of final suspicion scores across all 18 observed devices
    after 322 scans. No device crossed the investigation threshold.],
) <fig-fp-score-distribution>

*What automated tests do not cover.*
Three areas fall outside automated test coverage and are discussed in @sec-fp-analysis:
LLM output quality (The model choice is not a core contribution);
actual iptables rule insertion (subprocess is mocked; manually verified);
and timing-dependent passive signals (TTL baseline, IP ID counter) which are
tested via injected values rather than real packet captures.

== False-Positive Analysis on Real Traffic <sec-fp-analysis>

To measure false-positive rate under real conditions, 322 nmap XML scans collected
over six days on a home LAN were replayed offline through
the full detection pipeline.
No attacks were in progress during collection; every alert that fires is a false
positive by construction.

*Setup.*
Scans were taken at approximately five-minute intervals using the same nmap flags as
the production daemon.
The replay script feeds each scan through `NmapParser` → `add_or_update_peer()` in
timestamp order, preserving the temporal structure of the data.
The suspicion threshold and all scoring weights were left at their production defaults
(`threshold = 3.0`, `suspicion_half_life_days = 3.5`).

*Results.*
Of 18 unique devices observed across 322 scans, zero crossed the investigation
threshold, a false-positive rate of 0%.
All devices stayed strictly below 3.0 for the entire six-day window
(@fig-fp-score-over-time, @fig-fp-score-distribution).
The highest final score was 2.99 (device C4:9D:ED:32:A1:D1), reflecting two
one-time events that were subsequently suppressed by the mechanisms described below.

*Root causes and fixes.*
The initial implementation produced false positives on 7 of 17 devices (41%).
Each root cause was identified by replaying event histories and inspecting raw nmap
XML at the triggering scans.
Four targeted suppression mechanisms were added iteratively and are described in full
in @peer-store (False-Positive Suppression): `tcpwrapped` exclusion,
visibility-gap guards for port and identity checks, `known_os_families` oscillation
suppression, and bidirectional `known_services` recording.
@tab-fp-progression shows the reduction in false-positive rate across each fix.

#figure(
  table(
    columns: (auto, auto, auto),
    align: (left, center, center),
    table.header([Fix applied], [FP devices], [FP rate]),
    [None (initial)], [7 / 17], [41%],
    [+ tcpwrapped exclusion and one-sided Jaccard guard], [2 / 17], [12%],
    [+ known\_os\_families and full\_identity\_shift guard], [1 / 18], [6%],
    [+ bidirectional service-type suppression], [0 / 18], [*0%*],
  ),
  caption: [False-positive rate reduction across successive fixes on the 322-scan
    real-LAN trace. Device count grew from 17 to 18 as the trace was extended.],
) <tab-fp-progression>

*Limitations.*
The dataset spans a single home LAN with 18 devices over six days.
Enterprise deployments with a larger and more diverse device population may surface
new nmap artefacts not present in this trace.
All four fixes are conservative: each suppresses only events with a clear
artefact explanation, and suppression is bounded — the first genuine observation
of each new OS family or service type still fires.
Neither `known_os_families` nor bidirectional `known_services` adds configuration
surface; both are populated automatically from observed data.

== Attack Scenario Evaluation <sec-attack-scenarios>

=== Methodology

Each scenario follows the same injection protocol: a baseline device is
warmed up by feeding six identical `NormalisedData` records to
`add_or_update_peer()`, placing the peer past the five-scan cold-start window
with `suspicion_score = 0.0`.
One to three attack scans are then injected, and the resulting score and event
set are verified.
No live network access, root privileges, or Ollama instance are required,
the injection interface (@scan-loop) makes every scenario deterministically
reproducible in CI.

Scenarios A–I cover the nine distinct attack patterns in the simulation suite.
Two scenarios (E, I) are negative calibration tests: they verify that PeerWatch
does _not_ alert on attacks it is designed to leave below threshold, confirming
the system does not hair-trigger.

#figure(
  table(
    columns: (auto, auto, auto, auto, auto),
    align: (left, left, center, center, left),
    table.header([ID], [Attack], [Score], [Detected], [Primary events]),
    [A],
    [IP Spoofing / ARP Poisoning],
    [5.0],
    [#sym.checkmark],
    [`full_identity_shift`, `mac_conflict`],

    [B],
    [Service Backdoor],
    [4.0],
    [#sym.checkmark],
    [`service_type_changed`, `port_protocol_mismatch`],

    [C],
    [MAC Spoofing / OS Mismatch],
    [4.5],
    [#sym.checkmark],
    [`os_family_changed`, `full_identity_shift`],

    [D],
    [Cross-Device Identity Conflict],
    [≥1.0],
    [via fleet],
    [`identity_conflict_detected`],

    [E], [OS Fingerprint Spoofing (neg.)], [2.0], [—], [`os_family_changed`],
    [F],
    [Multi-Port Protocol Takeover],
    [8.0],
    [#sym.checkmark],
    [`port_protocol_mismatch` ×2],

    [G],
    [IoT Botnet Enrollment],
    [3.0],
    [#sym.checkmark],
    [`port_protocol_mismatch`],

    [H],
    [Incremental Compromise (3 scans)],
    [6.5],
    [#sym.checkmark],
    [`os_family_changed`, `port_profile_changed`, `port_protocol_mismatch`],

    [I], [Service Mimicry Evasion (neg.)], [0.0], [—], [none],
  ),
  caption: [Suspicion scores and detection outcome for scenarios A–I.
    Scores are post-warmup and without decay (deterministic replay).
    Threshold = 3.0.],
) <tab-scenarios>

@fig-scenario-scores visualises these scores against the investigation threshold.

#figure(
  image("figures/scenario_scores.pdf", width: 100%),
  caption: [Suspicion scores for attack scenarios A–I (post-warmup, single tick
    except H which accumulates over three scans).
    Blue bars are detected; red bars are correctly-below-threshold negatives.
    Dashed line is the investigation threshold (3.0).],
) <fig-scenario-scores>

=== Scenario Walkthrough

*Scenario A — IP Spoofing / ARP Poisoning (score 5.0).*
Models CVE-2020-25705 @saddns (off-path IP spoofing) and T1557.002
(ARP Cache Poisoning @mitre).
The attacker responds to the victim's IP with a different MAC, different OS
family, and completely different port set.
`add_or_update_peer()` resolves by IP, finds the existing peer, and compares
fingerprints: OS families are disjoint (+2.0), Jaccard({22,80},{3389,445}) = 0.0
< 0.6 (+0.5), and all three dimensions differ simultaneously (+2.0).
`_update_peer()` then detects the MAC mismatch and adds +0.5 directly.
Total: 5.0.
The four-signal combination makes this one of the most reliable detections in
the suite, an attacker would need to clone the MAC, spoof the OS fingerprint,
and replicate the port profile exactly to evade all four checks simultaneously.

*Scenario B — Service Backdoor (score 4.0).*
Models T1543 (Create or Modify System Process) @mitre and TA17-181A (NotPetya lateral
movement via port 445 with unexpected protocol) @uscertTA17.
Post-compromise implant binds to port 22, replacing sshd with an HTTP beacon.
`_check_port_protocol_mismatches()` identifies `http` on port 22 (expected: `ssh`)
and fires `port_protocol_mismatch` (+3.0), the highest single-event weight.
`service_type_changed` (+1.0) fires concurrently.
The `flagged_port_mismatches` guard prevents the +3.0 from accumulating on every
subsequent scan, so repeat injections leave the score unchanged at 4.0.

*Scenario C — MAC Spoofing / OS Mismatch (score 4.5).*
Models CVE-2004-0699 @cve-2004-0699 (Cisco 802.1X bypass via spoofed MAC) and
T1564.006 (Hide Artifacts: Run Virtual Instance) @mitre.
Attacker clones a Windows workstation's MAC onto a Linux attack box.
The MAC resolves to the known peer, but OS candidates (`{Linux}` vs `{Microsoft}`)
are disjoint and port sets share nothing.
Score breakdown: `os_family_changed` +2.0, `port_profile_changed` +0.5,
`full_identity_shift` +2.0 = 4.5.
`service_type_changed` does not fire — comparison only covers shared ports,
and there are none.

*Scenario D — Cross-Device Identity Conflict (score ≥ 1.0, detected via fleet).*
Models T1465 (Rogue Wi-Fi Access Points) @mitre and CVE-2019-11477 @cve-2019-11477
(SACK Panic used to DoS a device so an attacker can claim its identity).
Attacker simultaneously presents the MAC of device A and the IP of device B,
triggering `_resolve_conflict()` and `identity_conflict_detected` (+1.0).
Alone this score is below threshold.
In the full system, fleet correlation pattern `identity_sweep` (@fleet-correlator)
fires when two peers show `identity_conflict_detected` in the same tick, boosting
each by +2.0.
Scenario F12 in the fleet suite demonstrates this closure: both peers cross 3.0
purely through fleet correlation, with neither crossing individually.
This is the intended design: the single-signal floor avoids false positives from
routine IP reassignment, while the fleet boost catches coordinated identity abuse.

*Scenario E — OS Fingerprint Spoofing, negative (score 2.0).*
Models T1014 (Rootkit: kernel-level OS fingerprint manipulation) @mitre.
Attacker manipulates TCP stack to make a Linux host fingerprint as Windows while
leaving ports and services unchanged.
`os_family_changed` fires (+2.0), but without port or service corroboration the
score stays at 2.0, below threshold.
This is a deliberate calibration point.
The multi-signal accumulation design (@evidence-accumulation) is motivated
precisely by this scenario: OS fingerprinting is unreliable enough on real hardware
(as confirmed by the FP analysis in @sec-fp-analysis) that an OS change alone
should not trigger investigation.
An operator can lower the threshold to 2.0 to catch Scenario E, but the FP
analysis shows this would alert on every device with UPnP-driven OS oscillation.

*Scenario F — Multi-Port Protocol Takeover (score 8.0).*
Models CVE-2024-6387 (regreSSHion, unauthenticated RCE in OpenSSH ≤ 9.7) @regresshion
and CVE-2024-4577 (PHP CGI argument injection, CVSS 9.8) @cve-2024-4577.
After RCE, attacker replaces two services simultaneously: sshd on port 22 with
an HTTP beacon and the web server on port 80 with an SMTP listener.
Two `service_type_changed` events (+1.0 each) and two `port_protocol_mismatch`
events (+3.0 each) fire in a single scan, yielding the highest score in the suite
at 8.0.
The `flagged_port_mismatches` guard records both ports after the first scan, so
repeat scans do not accumulate further.

*Scenario G — IoT Botnet Enrollment (score 3.0).*
Models CVE-2024-7029 @cve-2024-7029 (AVTECH IP camera command injection, CISA KEV)
and CVE-2023-1389 @cve-2023-1389 (TP-Link Archer AX21 injection used in Mirai campaigns) @mirai.
Mirai-family implant opens port 22 with an HTTP-based C2 beacon alongside the
camera's existing HTTP and RTSP ports.
Port-set Jaccard({80,554},{22,80,554}) = 2/3 ≈ 0.67 > 0.6, so
`port_profile_changed` does not fire.
The sole detection is `port_protocol_mismatch` on port 22 (`http-bot` seen,
`ssh` expected), which alone exactly hits the threshold at +3.0.
This scenario demonstrates that `port_protocol_mismatch` catches stealthy port
additions that the Jaccard threshold would silently pass.

*Scenario H — Incremental Compromise over three scans (score 6.5).*
Models CVE-2024-3400 @cve-2024-3400 (Palo Alto PAN-OS OS command injection, CVSS 10.0,
CISA Emergency Directive 24-02) and CVE-2023-20198 @cve-2023-20198 (Cisco IOS XE
web UI privilege escalation, CVSS 10.0).
No single scan crosses the threshold; evidence accumulates across three ticks:

#figure(
  image("figures/scenario_h_progression.pdf", width: 72%),
  caption: [Scenario H — incremental compromise score progression.
    Each scan adds a distinct anomaly signal; threshold is crossed on scan 3.],
) <fig-scenario-h>

After warmup: scan 1 shifts OS family (Cisco → Linux, +2.0, score 2.0 — below
threshold). Scan 2 drops a management port and adds a backdoor port; Jaccard
drops below 0.6 (+0.5, score 2.5 — still below threshold). Scan 3 replaces sshd
on port 22 with an HTTP C2 agent: `service_type_changed` (+1.0) and
`port_protocol_mismatch` (+3.0) fire, bringing total to 6.5.
The temporal accumulation model (@scoring-and-exponential-decay) is the enabling
mechanism: each sub-threshold observation is retained and compounds.
An attacker who spaces these steps across multiple half-lives would see the score
decay between changes, quantifying the evasion cost in units of time.

*Scenario I — Service Mimicry Evasion, negative (score 0.0).*
Models CVE-2024-3094 @cve-2024-3094 (XZ Utils / liblzma backdoor injected into sshd)
and T1036.004 (Masquerade Task or Service) @mitre.
Attacker replaces OpenSSH with Dropbear SSH, a legitimate alternative that also
identifies as `ssh` on port 22.
nmap reports `ssh-Dropbear` instead of `ssh-OpenSSH`; PeerWatch compares only
the first token (`ssh` = `ssh`), so no change is detected.
Score: 0.0.
This is a documented detection limit, not a calibration failure.
The design choice to compare protocol types rather than implementation identifiers
is what suppresses Scenario E false positives (a genuine OS upgrade leaves the
service token unchanged) and the service oscillation FPs described in @peer-store.
Catching Scenario I would require comparing implementation fingerprints
(banner strings, protocol negotiation sequences), a Phase 2 passive-capture
capability outside the scope of the active-scan pipeline.

=== Operating Point Analysis

Of the nine scenarios, seven are detected (78%), and two are correctly left
below threshold by design.
The two undetected scenarios represent opposite ends of the evasion spectrum:
Scenario E (score 2.0) requires only one weak signal and is deliberately
below threshold to contain FP rate; Scenario I (score 0.0) requires the
attacker to stay within the same protocol family and is a fundamental limit
of nmap service-type comparison.

Combining Scenarios E and B, OS fingerprint spoofing _and_ a service backdoor,
would yield 2.0 + 4.0 = 6.0, well above threshold.
The practical evasion requirement is therefore not "avoid any single signal"
but "avoid _all_ detectable signals simultaneously", which requires the attacker
to replicate the exact OS family, port set, and service types of the target device.

== Fleet Correlation Evaluation <sec-fleet-eval>

Per-peer detection cannot distinguish a lone anomalous device from a coordinated
multi-host attack: both produce the same per-peer score.
`FleetCorrelator.analyse()` addresses this by examining the full event log
across all peers after each ingestion tick and firing a boost when ≥N peers show
the same anomaly class within the tick window.
The 16 fleet scenarios (F1–F16) test this layer in isolation by injecting events
directly via `_inject_event()`, removing any dependency on the per-peer detection
pipeline.

=== Pattern Catalogue

Six coordination patterns are defined.
@tbl-fleet-patterns lists each pattern's trigger event(s), minimum-peer
threshold, and score boost; the implementation is described in @fleet-correlator.

#figure(
  table(
    columns: (auto, 1fr, auto, auto),
    align: (left, left, center, center),
    table.header([*Pattern*], [*Trigger event(s)*], [*Min peers*], [*Boost*]),
    [`arp_poisoning`], [`arp_spoofing_detected`], [2], [+2.0],
    [`identity_sweep`],
    [`full_identity_shift` or `identity_conflict_detected`],
    [2],
    [+2.0],

    [`route_shift`], [`route_changed`], [3], [+1.5],
    [`os_normalisation`], [`os_family_changed`], [3], [+1.5],
    [`ttl_shift`], [`ttl_deviation`], [3], [+1.5],
    [`service_sweep`], [`service_type_changed`], [4], [+1.0],
  ),
  caption: [Fleet correlation patterns, trigger events, minimum co-occurrence
    threshold, and suspicion boost per matching peer.],
) <tbl-fleet-patterns>

`service_sweep` carries the lowest boost (+1.0) and the highest minimum-peer
count (4) because `service_type_changed` is the most common per-peer event;
the per-peer `known_services` oscillation suppression does not extend to fleet
co-occurrence, so the threshold is raised at the fleet level to compensate.
`arp_poisoning` and `identity_sweep` carry the highest boost (+2.0) because
ARP spoofing and identity conflicts are structurally improbable as coincidental
simultaneous events across unrelated devices.

=== Positive Detection (F1–F4, F8–F10)

Scenarios F1–F4 and F8–F10 verify that each pattern fires correctly when the
minimum-peer threshold is met.

/ F1 - ARP Poisoning Campaign: Three peers simultaneously show `arp_spoofing_detected`.
  `arp_poisoning` fires; all three peer IDs appear in `FleetEvent.peer_ids`;
  each peer receives a +2.0 boost and a `fleet_correlation_boost` event in its
  identity history.
  This models a coordinated ARP cache poisoning attack (T1557.002) @mitre against
  multiple subnet hosts in the same tick.

/ F2 - Gateway Swap (Route Shift): Four peers show `route_changed` after a switch or gateway is replaced.
  `route_shift` fires with `event_count == 4` and boost +1.5 per peer.
  This models infrastructure-level adversary-in-the-middle insertion (T1557) @mitre,
  where a physical or virtual device is interposed transparently between the scanner
  and the monitored hosts.

/ F3 - OS Normalisation: Three peers show `os_family_changed` in the same tick.
  `os_normalisation` fires with boost +1.5.
  This models an attacker selectively altering TCP/IP stack fingerprints on multiple
  devices to blend them into a uniform OS profile, reducing the distinctiveness of
  each individual host as a detection evasion technique.

/ F4 - Identity Sweep: Two peers show `full_identity_shift` simultaneously.
  `identity_sweep` fires with boost +2.0 per peer and the matched peer IDs equal
  exactly the two injected peers.

/ F8 - Service Sweep: Four peers show `service_type_changed` in the same tick.
  Models coordinated backdoor service installation across multiple hosts (T1543) @mitre.
  `service_sweep` fires with boost +1.0; the four-peer threshold ensures a
  routine fleet-wide service restart does not trigger this pattern.

/ F9 - TTL Shift (Infrastructure MITM): Three peers show `ttl_deviation` simultaneously.
  `ttl_shift` fires with boost +1.5.
  Models MITM device insertion that adds a transparent forwarding hop and shifts
  the observed IP TTL for all downstream hosts (T1557) @mitre.

/ F10 - Identity Sweep via Conflict: Two peers show `identity_conflict_detected` rather than `full_identity_shift`.
  `identity_sweep` fires with boost +2.0, verifying the OR-branch in the pattern
  definition: either trigger event is sufficient.
  This is relevant because coordinated device-substitution attacks may manifest as
  either a clean identity shift or a MAC/IP conflict, depending on whether the
  attacker reuses the victim's IP address.

=== Scenario D Closure — F12

@sec-attack-scenarios established that a single `identity_conflict_detected`
event yields a per-peer score of \~1.0, safely below the 3.0 investigation
threshold.
F12 demonstrates how fleet correlation closes this detection gap.

Two peers are pre-set to `suspicion_score = 1.0` and each receives an
`identity_conflict_detected` event in the same tick.
Before fleet analysis both remain below threshold.
`FleetCorrelator.analyse()` detects the `identity_sweep` pattern and applies
a +2.0 boost to each peer, bringing both to 3.0 — exactly at the investigation
threshold.

#figure(
  image("figures/fleet_boost_f12.pdf", width: 72%),
  caption: [F12 — Scenario D closure. Per-peer score (1.0) lies below the
    investigation threshold until fleet correlation applies the identity_sweep
    boost (+2.0), crossing the threshold for both peers simultaneously.],
) <fig-fleet-f12>

This separation of concerns is deliberate.
A standalone `identity_conflict_detected` at score 1.0 can arise from a DHCP
lease conflict or an ARP entry collision during normal network operation.
The fleet boost fires only when two or more peers exhibit the same event in the
same tick, a co-temporal constraint that eliminates the coincidental-collision
explanation and raises the minimum evidence bar for investigation to the fleet
level.

=== Guard Mechanisms (F5, F6, F7, F11)

Four properties of the guard layer are verified independently.

/ F5 — Min-peers gate: A single peer fires `arp_spoofing_detected` with `fleet_arp_min_peers=2`.
  No fleet pattern fires; no `fleet_correlation_boost` event is recorded.
  This prevents isolated gratuitous ARP replies, which are standard network
  behaviour (e.g., a host announcing its IP after a link change), from triggering
  a fleet alert.

/ F6 — Boost cap: A peer simultaneously matches both `arp_poisoning` (+2.0) and `identity_sweep`
  (+2.0) patterns.
  With `fleet_boost_cap=2.5`, the first pattern's boost is applied in full (2.0)
  and the second is clipped to 0.5, for a total of 2.5.
  The cap prevents an attacker from engineering multiple simultaneous fleet patterns
  to push a peer's score arbitrarily high in a single tick — fleet boosts amplify
  per-peer evidence rather than substitute for it.

/ F7 — First-tick window: `last_tick_at` is `None` (system not yet through its first tick).
  `analyse()` returns an empty list immediately without inspecting any events.
  No fleet pattern can fire before the event window is established, preventing
  spurious alerts on startup when `PeerStore` may be partially populated.

/ F11 — Staleness exclusion: Three peers each have an `arp_spoofing_detected` event timestamped one second
  before `last_tick_at`; one peer also has a current in-window event.
  Only the single current event falls inside the window, so only one peer qualifies
  (below `min_peers=2`) and no pattern fires.
  This verifies that the `>=` boundary comparison correctly excludes events that
  pre-date the current tick, preventing prior-tick anomalies from re-triggering
  fleet patterns indefinitely (fleet echo).

=== Targeting Precision and Edge Cases

/ F13 — Partial fleet match: Five peers exist in the store; three receive `arp_spoofing_detected` and two
  do not.
  `arp_poisoning` fires; `FleetEvent.peer_ids` contains exactly the three matching
  peers; the two unaffected peers' scores are unchanged and carry no
  `fleet_correlation_boost` event.
  This confirms that fleet boosts are surgically applied to contributing peers only,
  with no collateral score inflation on innocent co-located devices.

/ F14 — Multi-fire event count: Each of two peers fires `arp_spoofing_detected` twice (four events total).
  `FleetEvent.event_count == 4` captures the intensity of the attack signal for
  operator reporting.
  The per-peer boost remains +2.0 regardless of event count — score is not
  multiplied by firing frequency, so a rapidly oscillating sensor cannot inflate
  the score arbitrarily.

/ F15 — Empty tick: `last_tick_at` is set (not the first tick) but no events were recorded after it.
  `analyse()` returns `[]` cleanly.
  This is the expected steady-state between attack events and confirms that fleet
  analysis imposes no overhead when the network is quiet.

/ F16 — FleetEvent field completeness: A full field audit of a `FleetEvent` produced by a real `analyse()` call:
  `peer_ids` matches the three injected peers; `ips` is sorted and complete;
  `event_count == 3`; `suspicion_boost == 2.0`; `window_start` equals
  `store.last_tick_at`; `window_end` falls within the test's timing bounds;
  `description` contains both the peer count and the trigger event name.
  These fields are consumed by the daemon's `fleet_alerts.jsonl` audit log and
  by the `SuspiciousAgent` prompt template, so field completeness is a functional
  correctness requirement.

=== Discussion

Fleet correlation adds a multiplicative detection capability orthogonal to
per-peer accumulation.
Attacks that individually produce sub-threshold scores, such as the identity
conflict in Scenario D, become detectable when they co-occur across $≥N$ peers
within a single tick.

Three properties bound the fleet layer's behaviour.
The min-peers threshold prevents individual anomalous events from triggering
fleet patterns; the minimum is pattern-specific and tunable via `PeerWatchConfig`.
The boost cap (default 4.0 per tick, overridden to 2.5 in F6) ensures that
fleet evidence amplifies rather than replaces per-peer evidence: a device with
no per-peer signal cannot be pushed to the investigation threshold by fleet
correlation alone.
The tick window prevents fleet echo: anomalies that fired in prior ticks do not
re-trigger patterns in subsequent ticks.

Fleet events are passed to `SuspiciousAgent.investigate_all()` so the LLM
receives explicit coordinated-attack context.
The system prompt's Fleet Context Guide section instructs the model to raise
severity when a fleet pattern is present, producing more consistent severity
classification across Phi-4 model versions.

Adding a new coordination pattern requires one tuple in the `_PATTERNS` list
in `fleet_correlator.py` and one corresponding `int` field in `PeerWatchConfig`,
with no changes to `PeerStore`, `SuspiciousAgent`, or the daemon loop.

== LLM Agent Evaluation <sec-agent-eval>

`SuspiciousAgent` is invoked after fleet correlation each tick for every peer
whose `suspicion_score` meets or exceeds the investigation threshold.
The evaluation covers three aspects: structured output reliability, the
rule-based fallback when Ollama is unavailable, and automatic identity checks.

=== Structured Output and Fleet-Aware Severity

The agent calls Phi-4 @ollama via LangChain @langchain with `temperature=0`
and Ollama's `format="json"` grammar constraint.
The grammar constraint forces the model to produce a JSON token stream,
eliminating the class of failures where the model wraps its answer in prose or
markdown fences.
A `_strip_code_fence()` post-processor handles the residual case where
a model revision re-introduces fences.

The system prompt (@agent) specifies a fixed four-field schema:
`explanation` (plain-English summary), `severity` (`low` / `medium` / `high`),
`recommended_scans` (typed list), and `recommended_actions` (string list).
The severity guide instructs the model to assign `high` for structural identity
signals (OS family changed, full identity shift, MAC conflict) and `low` for
ephemeral port changes.
A Fleet Context Guide section, appended when fleet events are present, instructs
the model to raise severity and name the fleet pattern in its explanation.
During manual evaluation of the nine attack scenarios (@sec-attack-scenarios),
Phi-4 consistently assigned `high` severity to Scenarios B, C, F, G, and H,
and `medium` to Scenario D prior to fleet correlation, matching the expected
calibration in each case.

=== Rule-Based Fallback

When Ollama is unreachable or the LLM invocation raises an exception, the agent
falls back to `_rule_based_fallback()` without propagating the error to the
daemon.
The fallback assigns severity by score alone and recommends scans by event type.
Twelve tests in `test_agent_fallback.py` verify this path independently of any
running Ollama instance.

#figure(
  table(
    columns: (auto, auto, 1fr),
    align: (left, left, left),
    table.header([*Condition*], [*Severity*], [*Added scan type*]),
    [`score ≥ 7.0`], [`high`], [—],
    [`score ≥ 4.0`], [`medium`], [—],
    [`score < 4.0`], [`low`], [—],
    [`route_changed` or `ttl_deviation` in history], [—], [`traceroute`],
    [`arp_spoofing_detected` or `ttl_deviation`], [—], [`tcpdump`],
    [always], [—], [`nmap`],
  ),
  caption: [Rule-based fallback severity thresholds and event-driven scan
    recommendations. Severity and scan type rules are applied independently.],
) <tbl-fallback>

The thresholds (7.0 → high, 4.0 → medium) are deliberately conservative
relative to the investigation threshold (3.0): a peer that barely crosses the
threshold receives `low` severity, nudging the operator to monitor rather than
act, while a peer at 7.0 (Scenario F) receives `high` immediately.
This is the same calibration used by the LLM prompt's severity guide, so
fallback and LLM outputs are consistent when evidence is unambiguous.

=== Automatic Identity Checks

After the LLM (or fallback) returns its `recommended_scans`, the agent
appends `ssh_hostkey` and `ssl_cert` checks automatically for any peer with
an open SSH or HTTPS port, regardless of whether the LLM requested them.
This implements the cryptographic identity anchoring described in
@agent without relying on the LLM's awareness of which ports are open.
Results are parsed by `_parse_ssh_fingerprints()` and
`_parse_ssl_cert_fingerprint()` and fed back to `PeerStore.ingest_ssh_hostkeys()`
and `PeerStore.ingest_ssl_cert()`, so subsequent ticks benefit from the updated
baseline.
Changed fingerprints are annotated directly in the `ScanResult.output` field
(e.g., `[KEY CHANGED on ports [22]]`) for operator-readable audit trails.

=== Prompt Injection Resistance

All data inserted into the LLM prompt (MAC address, IP list, event history,
service map, fleet context) is derived from structured `PeerStore` fields, not
from raw packet payloads or device-supplied strings.
Device hostnames and banner strings are not included in the prompt.
The grammar-constrained output schema further limits the attack surface: even
if a device managed to inject adversarial text into an event detail field, the
model's output is validated against the fixed `AgentDecision` schema before use.
A validation failure falls through to the rule-based fallback, which does not
read LLM output at all.

== Remediation Evaluation <sec-remediation-eval>

`Remediator` runs after `SuspiciousAgent` each tick, evaluating each
`InvestigationReport` against a five-guard chain before issuing a block.
Nineteen tests in `test_remediation.py` verify the guard chain, mode
behaviour, and TTL expiry logic.

=== Guard Chain

@tbl-remediation-guards lists each guard in evaluation order.
A peer that fails any guard produces no block action for that tick.

#figure(
  table(
    columns: (auto, 1fr, auto),
    align: (left, left, left),
    table.header([*Guard*], [*Condition*], [*Failure result*]),
    [Never-block whitelist], [`ip` or `mac` in `never_block`], [skip],
    [Score floor],
    [`suspicion_score < block_confidence_floor` (default 5.0)],
    [skip],

    [Severity gate], [`severity ≠ "high"`], [skip],
    [IP availability], [no IP address recorded for peer], [skip],
    [Duplicate block],
    [active (executed, non-expired) block already exists for this IP],
    [skip],
  ),
  caption: [Remediation guard chain. Guards are evaluated in order; failure at
    any guard prevents the block action from being issued.],
) <tbl-remediation-guards>

The score floor (default 5.0) is intentionally higher than the investigation
threshold (3.0) because the investigation threshold triggers LLM analysis,
which is cheap, while a block is a disruptive network action with operational
consequences.
A peer must accumulate substantial multi-signal evidence before autonomous
blocking is authorised.
The severity gate (`severity == "high"`) means the LLM (or fallback) must
also classify the anomaly as high before a block fires; a fleet-boosted peer
that the LLM rates `medium` will be investigated but not blocked.

The duplicate-block guard reads `blocks.jsonl` to check whether an active,
executed, non-expired record already exists for the target IP.
An expired block (past `expires_at`) does not count as active, allowing
re-evaluation after TTL expiry.

=== Enforcement Modes

Three modes control whether `iptables` commands are executed.

#figure(
  table(
    columns: (auto, 1fr, auto),
    align: (left, left, left),
    table.header([*Mode*], [*Behaviour*], [*`executed` field*]),
    [`dry_run`], [Log commands; write record; no subprocess], [`False`],
    [`confirm`],
    [Print commands; prompt operator y/n; execute if confirmed],
    [`True` / `False`],

    [`enforce`],
    [Execute `iptables -I INPUT/OUTPUT DROP` immediately],
    [`True`],
  ),
  caption: [Remediation enforcement modes and their effect on block execution.],
) <tbl-remediation-modes>

`enforce` mode requires root or `CAP_NET_ADMIN`.
If `enforce` is configured but the daemon is not running as root,
`Remediator.__init__()` silently downgrades to `dry_run` and logs an error —
the system remains safe without crashing.
Two iptables rules are inserted per block: `INPUT DROP` (drops inbound traffic)
and `OUTPUT DROP` (drops outbound traffic to the target), preventing both
receipt and transmission.

=== TTL Auto-Unblock

`unblock_expired()` is called once per daemon tick after investigation.
It reads `blocks.jsonl`, identifies records where `executed=True`,
`unblocked_at=None`, and `expires_at <= now`, runs the stored `unblock_cmds`
(`iptables -D` variants), stamps `unblocked_at`, and atomically rewrites
`blocks.jsonl` via a `tempfile` rename.
The atomic rewrite prevents a half-written file from corrupting the audit log
if the daemon is interrupted.
Default block TTL is 24 hours (`block_ttl_hours`), configurable per deployment.

All block decisions — including dry-run non-executions and operator-declined
confirms — are written to `blocks.jsonl` so the full remediation history is
available for audit independent of whether iptables was invoked.
The LLM is not in the authorisation path: remediation decisions are
purely rule-based.

== Performance <sec-performance>

PeerWatch is designed for operation on a single /24 subnet (up to 254 hosts)
with a default scan interval of five minutes.
This section characterises the computational cost of the three pipeline stages.

=== Ingest Throughput

Replaying the 322-scan real-traffic corpus used in the FP analysis
(@sec-fp-analysis) completes in approximately 2.7 seconds of wall-clock time
on the development machine (\~2.4 s CPU time).
This includes XML parsing via `xmltodict`, `NmapParser` normalisation,
`PeerStore.add_or_update_peer()` for all 18 devices, fingerprint comparison,
`known_os_families` and `known_services` set updates, and figure generation.
Per-scan ingest averages ~8 ms, well within the 5-minute scan interval budget.

`PeerStore` keys devices by MAC address in a Python `dict`, providing O(1)
lookup and update per device regardless of fleet size.
The passive observation queue and identity history lists grow linearly with
events but are bounded in practice by the scan interval: a /24 subnet
produces at most 254 new scan results per tick.

=== Test Suite Runtime

The full test suite of 222 tests — covering all three pipeline phases,
fleet correlation, persistence, and remediation — runs in under 0.5 seconds.
This reflects that all tests operate on in-memory `PeerStore` instances
with injected synthetic data, with no network I/O or subprocess calls (mocked
in agent and remediation tests).
Fast test execution supports tight development iteration without requiring a
running Ollama instance or root privileges.

=== Active Scan Latency

The dominant latency term is nmap itself.
A service-version and OS-detection scan (`nmap -sV -O --osscan-guess`)
of a /24 subnet typically completes in 30–90 seconds, depending on host
count, network latency, and OS detection probe retries.
This is accommodated by the configurable `scan_interval_minutes` (default 5)
and enforced minimum `min_scan_interval_minutes` (default 2), which rate-limits
the daemon against accidentally overlapping consecutive scans.
Fleet correlation, LLM invocation, and remediation evaluation each add less
than one second of overhead per tick in the absence of Ollama latency;
Phi-4 inference on a local GPU averages 3–8 seconds per investigation report.

== Limitations and Threats to Validity <sec-limitations>

=== Offline Replay and Decay Calibration

The FP analysis in @sec-fp-analysis replays 322 scans sequentially in a
single Python process.
Suspicion decay is computed against `peer.last_seen_at`, which is set to
`datetime.now()` (wall-clock time) at each update call.
Because the replay completes in ~2.7 seconds, the wall-clock elapsed time
between any two consecutive ingest calls is on the order of milliseconds,
and the exponential decay function yields effectively zero decay.
This means the offline replay represents a worst-case accumulation scenario:
events that would have partially decayed over days of real operation instead
compound fully.
The zero false-positive rate reported in @sec-fp-analysis is therefore a
conservative result — decay makes the deployed system less sensitive to
event accumulation, not more.

=== nmap OS Fingerprint Instability

nmap OS detection depends on TCP/IP stack probes and service banner matching,
both of which are sensitive to ephemeral factors: UPnP service response
variants, transient port availability during the scan window, and probe
timing.
The UPnP oscillation observed on device C4:9D during FP analysis
(@sec-fp-analysis) is an instance of this class: the same physical device
produces different OS candidate sets across scans depending on which UPnP
endpoint responds first.
The `known_os_families` accumulation mechanism (@peer-store) addresses this,
but it does not eliminate the underlying instability: it suppresses the
scoring consequence of oscillations between already-known families.
Attacks that manipulate only the OS fingerprint (Scenario E) are deliberately
left below threshold for this reason.

=== Single-Subnet Scope

PeerWatch monitors one subnet configured at startup.
`FleetCorrelator` correlates events only within that subnet's `PeerStore`.
A coordinated attack spanning multiple subnets would appear as isolated
per-peer anomalies in each subnet's instance, without fleet-level amplification.
Multi-subnet deployment would require either a shared `PeerStore` or a
federation layer aggregating per-subnet `FleetCorrelator` outputs — both
outside the current scope.

=== Absence of a Ground-Truth Attack Dataset

The attack evaluation in @sec-attack-scenarios uses synthetic event injection
against controlled `PeerStore` instances.
No ground-truth dataset of real subnet intrusions with known attacker activity
is available for validation.
The nine attack scenarios are constructed from published CVE and ATT&CK
technique descriptions, but their representativeness of real attacker behaviour
on LAN segments is unverifiable without a controlled intrusion testbed.

=== LLM Non-Determinism

Phi-4 is invoked with `temperature=0`, which maximises output determinism
for a given model version, but the model's weights and sampling behaviour
may change across Ollama updates.
Severity classification is therefore not strictly reproducible across
model versions.
The rule-based fallback (@sec-agent-eval) provides a deterministic lower bound
on system behaviour, and the structured output schema constrains the output
space, but the explanation text and borderline severity assignments (e.g., a
score of 3.5 that the LLM rates `medium` vs `low`) remain version-dependent.

=== Scan Interval Blind Spot

PeerWatch's detection is contingent on the attacker's changes persisting across
at least one nmap scan.
An attacker who exploits a vulnerability, alters the device's fingerprint, and
reverts all changes within a single scan interval (default five minutes) will
not be detected by the active-scan pipeline.
Passive capture (Phase 2) reduces this blind spot for TTL and ARP signals,
which are observable in real time, but service-type and OS-family changes
remain visible only at scan boundaries.

= Conclusions and Evaluation

== Summary of Contributions

This project set out five goals in @approach.
All five were delivered.

*Active device fingerprinting.*
`PeerStore` maintains a persistent identity record per device, keyed by MAC
address (or IP for MAC-less volatile devices).
The fingerprint comparison engine detects OS-family drift via candidate-set
intersection, port-set drift via Jaccard similarity, and service-type changes
on a per-port basis.
`known_os_families` accumulation suppresses nmap OS oscillation caused by UPnP
service response variance, eliminating the class of false positives observed
during real-traffic validation.
Scores decay exponentially with a 3.5-day half-life, preventing stale anomalies
from permanently penalising a device after a legitimate change.
The false-positive rate on a 322-scan, 18-device real-traffic corpus reached 0%.

*Passive monitoring layer.*
Six additional signals supplement active scans: TTL consistency against a
per-peer baseline, ARP reply conflict detection, TCP stack fingerprinting,
IP ID counter jump analysis, route hop sequence tracking, and ASN enrichment
via Team Cymru @teamcymru.
Each signal is observable at wire speed without active probing and catches
attacks that leave no nmap-visible trace between scan intervals.

*Fleet-level correlation.*
`FleetCorrelator` examines the full event log across all peers after each
ingestion tick.
Six coordination patterns with configurable minimum-peer thresholds fire when
the same anomaly class co-occurs across multiple hosts within the tick window.
A boost cap prevents adversarial score inflation; a staleness boundary prevents
prior-tick events from re-triggering patterns.
The 16-scenario fleet test suite (F1–F16) validates all patterns and guard
mechanisms, with F12 demonstrating the central property: two peers whose
individual scores of 1.0 are below the investigation threshold both cross 3.0
purely through fleet correlation when their events are co-temporal.

*LLM-assisted triage.*
`SuspiciousAgent` invokes Phi-4 @ollama via LangChain @langchain with
grammar-constrained JSON output and `temperature=0`.
Fleet context is injected into the prompt when coordination patterns are active.
A rule-based fallback covers Ollama-unavailable deployments with deterministic
severity and scan recommendations.
Automatic SSH host-key and TLS certificate checks are appended after every
investigation, independent of the LLM's output.
No monitored traffic leaves the subnet; no cloud dependency or API key is
required; the system remains functional in air-gapped deployments.

*Empirical evaluation.*
Nine attack scenarios (A–I) drawn from MITRE ATT\&CK @mitre techniques and
published CVEs cover the full range of observable attacker behaviours: ARP
poisoning, device substitution, service backdoor, incremental compromise, and
service-mimicry evasion.
Seven of nine scenarios are detected (78%); two are correctly left below
threshold by design, representing calibration choices rather than
implementation gaps.
222 automated tests cover all three detection phases, fleet correlation,
persistence, and remediation.

== Critical Evaluation

*Multi-signal accumulation is the core design insight.*
No single signal is sufficient.
Scenario E (OS fingerprint spoof alone, score 2.0) and Scenario I (service
mimicry alone, score 0.0) are individually below threshold, but combining OS
spoofing with a service backdoor (Scenarios E + B) yields 6.0.
The evasion requirement is not "avoid any single signal" but "avoid all
detectable signals simultaneously", which requires the attacker to replicate
the exact OS family, port set, and service types of the target device.
The fleet layer adds a further constraint: a coordinated attacker who manages
to keep each device's per-peer score below threshold is still detectable when
the same anomaly class appears across multiple peers in the same tick.

*The false-positive calibration problem was harder than anticipated.*
The progression from 41% to 0% FP rate across four iterative fixes reflects
that nmap OS detection is more variable on real hardware than synthetic test
data suggests.
The root cause, UPnP service response variant determines which OS candidate
set nmap produces for the same physical device, required understanding
nmap's fingerprinting internals to diagnose and resolve.
The `known_os_families` accumulation mechanism is the most technically
consequential design decision made during implementation:
a first-pass implementation that scored every OS oscillation as suspicious
would have been unusable on real networks.

*Fitness for purpose.*
PeerWatch fills a genuine gap in the tool landscape (@tool-comparison):
it is the only locally-deployable, open-source monitor that combines active
fingerprinting, passive capture, and fleet-level correlation without requiring
managed switching infrastructure or cloud connectivity.
arpwatch @arpwatch monitors a single ARP signal; NIDS tools such as Snort
@snort and Suricata @suricata detect content-layer threats rather than
device-identity drift; enterprise platforms such as Darktrace @darktrace match
or exceed PeerWatch's capabilities but require infrastructure that places them
beyond the scope of the target deployment context.
Within its stated scope (subnets of up to 254 hosts, operated by an
independent administrator on existing hardware) the system is fit for purpose.

*Known limitations.*
The scan interval blind spot is fundamental: an attacker who exploits a
vulnerability and reverts all changes within the scan interval is invisible
to the active-scan pipeline.
Passive capture reduces this for TTL and ARP signals but not for service-type
or OS-family changes.
The single-subnet scope limits fleet correlation to within one /24 block;
a coordinated attack spanning multiple subnets appears as isolated per-peer
anomalies in each instance.
The absence of a ground-truth attack dataset (@sec-limitations) means the
78% detection rate is measured against synthetic scenarios rather than recorded
real-world intrusions.

== Future Work

Three directions offer the clearest return on further development effort.

*Agentic investigation loop.*
The current pipeline is one-shot: the LLM analyses evidence, recommends scans,
and the agent executes them in sequence.
A tighter loop would have the LLM emit structured action suggestions
(e.g. `{"action": "traceroute", "target": "192.168.1.5"}`) that a trusted
executor runs, with results ingested back into the passive pipeline as new
evidence before the next tick's analysis.
The LLM would remain outside the execution path entirely, the no-LLM-in-authorisation-path
invariant is preserved, but investigation would become
adaptive: a route anomaly triggers a targeted traceroute whose output updates
the route tracker; a service change triggers a certificate fetch whose
fingerprint is compared to the stored baseline.
The seed of this pattern already exists in `_build_auto_identity_checks()`,
which appends SSH and TLS checks unconditionally after the LLM step.

#figure(
  diagram(
    node-stroke: 0.5pt,
    node-corner-radius: 3pt,
    node-inset: 6pt,
    spacing: (3em, 2em),

    node(
      (0, 0),
      text(size: 9pt, weight: "bold")[PeerStore],
      name: <ps>,
      fill: luma(225),
    ),
    node(
      (2, 0),
      text(size: 9pt)[`agent.py` (LLM)],
      name: <agent>,
    ),
    node(
      (2, 1),
      align(center, text(
        size: 9pt,
      )[Trusted Executor \ #text(size: 8pt, style: "italic")[(proposed)]]),
      name: <exec>,
      fill: luma(245),
      stroke: (dash: "dashed"),
    ),
    node(
      (0, 1),
      align(center, text(size: 9pt)[`route_tracker` / \ `packet_capture`]),
      name: <passive>,
    ),

    edge(<ps>, <agent>, "->", text(size: 8pt)[evidence]),
    edge(<agent>, <exec>, "->", text(size: 8pt)[action JSON]),
    edge(<exec>, <passive>, "->", text(size: 8pt)[results]),
    edge(<passive>, <ps>, "->", text(size: 8pt)[new evidence]),
  ),
  caption: [
    Proposed agentic investigation loop.
    The LLM emits structured action suggestions (e.g.,\ `{"action": "traceroute", "target": "…"}`);
    a trusted executor runs them and feeds results back into the passive pipeline as new evidence before the next tick.
    The LLM remains outside the execution path.
    Dashed box is a proposed new component.
  ],
) <fig-agentic-loop>

*Sub-protocol fingerprinting.*
Scenario I (service mimicry, score 0.0) exploits the design decision to compare
protocol-type tokens rather than implementation identifiers.
Tracking SSH banner strings (`ssh-OpenSSH` vs `ssh-Dropbear`) or TLS
handshake parameters (cipher suites, extension ordering) in the passive capture
layer would close this gap at the cost of higher baseline churn on devices that
rotate banners across versions.
A `known_implementations` set analogous to `known_services` and
`known_os_families` would provide the same oscillation-suppression mechanism
at the implementation level.

*Keeping pace with evolving attacks and protocol changes.*
PeerWatch's detection model is anchored to nmap's fingerprint vocabulary and
the fixed set of scoring events defined at implementation time.
Both surfaces drift: nmap's OS detection database is updated with each release,
meaning a device's reported OS family may change across nmap versions even
with no hardware change; new attack techniques may exploit protocol features
or port behaviours that the current scoring weights do not capture.
The fleet correlation patterns were derived from the MITRE ATT\&CK @mitre
technique catalogue as it stood at time of writing; new coordinated attack
patterns documented in future ATT\&CK updates would require corresponding
entries in `_PATTERNS`.
Two mechanisms would help the system remain current without manual intervention.
First, periodic re-baselining: a scheduled mode that treats the current observed
state as the new ground truth after a quiescence period, absorbing legitimate
fleet-wide changes (firmware updates, OS upgrades) without accumulating
false-positive score.
Second, a pattern update feed: the `_PATTERNS` list and scoring weights are
already externalised through `PeerWatchConfig`; a community-maintained
configuration file distributed alongside nmap signatures would allow operators
to pull updated detection rules without modifying code.
Networking protocol evolution poses a similar challenge.
IPv6 adoption on home subnets changes the identity keying assumptions
(MAC-based keying remains valid but requires SLAAC and DHCPv6 awareness);
encrypted DNS and QUIC reduce the passive-capture signal available from
clear-text protocol exchanges.
Adapting the passive layer to these changes is a natural extension of the
Phase 2 architecture, which was designed for per-signal modularity precisely
to allow new capture rules to be added without disturbing existing ones.

== Closing Remarks

The central premise of this project holds: an attacker constrained to a local
network who wishes to evade multi-signal fingerprint monitoring must
simultaneously replicate the target device's OS family, port profile, service
types, TTL baseline, route path, and cryptographic identifiers.
The intersection of these constraints is narrow enough that realistic attacks
leave detectable traces in at least one signal, and the evidence-accumulation
model ensures that individually sub-threshold signals compound into a detectable
score over time.
The most instructive part of the project was not the detection logic itself but
the false-positive calibration work: the gap between expected and observed nmap
behaviour on real hardware drove the design decisions that make the system
deployable in practice rather than only in simulation.

#bibliography(
  "refs.bib",
  title: "References",
  style: "association-for-computing-machinery",
)

#colbreak(weak: true)
#set heading(numbering: "A.a.a")

= System Manual <system-manual>

This appendix provides the technical information needed to build, configure,
run, test, and extend PeerWatch.

== Prerequisites

*Nix (with flakes and new CLI enabled).*
PeerWatch uses a Nix flake for reproducible development environments.
Nix must be installed with the `nix-command` and `flakes` experimental features
enabled.
Add the following to `~/.config/nix/nix.conf` (user) or `/etc/nix/nix.conf`
(system):

```
experimental-features = nix-command flakes
```

On NixOS, set `nix.settings.experimental-features = ["nix-command" "flakes"]`
in your system configuration.

*Ollama.*
LLM-assisted investigation requires Ollama running locally with the
`phi4:latest` model pulled:

```sh
ollama serve          # start the Ollama daemon
ollama pull phi4      # download Phi-4 (~9 GB)
```

The daemon falls back to rule-based severity assignment if Ollama is
unreachable; no features are disabled.

*Root / capability requirements.*
nmap OS detection (`-O`) requires raw socket access.
Passive capture via Scapy requires `CAP_NET_RAW`.
iptables enforcement requires `CAP_NET_ADMIN`.
Run the daemon as root, or grant the specific capabilities to the Python
interpreter.

== Development Environment

Two Nix dev shells are provided in `flake.nix`.

```sh
nix develop           # Python shell with all dependencies + nmap
nix develop .#writeup # Typst shell for compiling the writeup
```

The default shell provisions a Python 3 environment with all runtime
dependencies (`langchain`, `langchain-ollama`, `scapy`, `pydantic`,
`python-nmap`, `xmltodict`, `matplotlib`, `pytest`) via `nixpkgs`.
No `pip install` is required; the Nix shell is self-contained.

After entering the shell, run tests with:

```sh
pytest
```

`pyproject.toml` sets `pythonpath = ["src"]` and `testpaths = ["tests"]`,
so no additional environment variables are needed.

== Configuration

Copy the example config and edit for your deployment:

```sh
cp config.example.json config.json
```

Key fields:

#figure(
  table(
    columns: (auto, auto, 1fr),
    align: (left, left, left),
    table.header([*Field*], [*Default*], [*Meaning*]),
    [`subnet`], [`192.168.1.0/24`], [Subnet to scan],
    [`scan_interval_minutes`], [`5`], [Scan cadence],
    [`min_scan_interval_minutes`], [`2`], [Rate-limit floor],
    [`suspicion_threshold`], [`3.0`], [Score that triggers LLM investigation],
    [`block_confidence_floor`], [`5.0`], [Minimum score to trigger a block],
    [`model`], [`phi4:latest`], [Ollama model name],
    [`remediation_mode`], [`dry_run`], [`dry_run` / `confirm` / `enforce`],
    [`never_block`],
    [`[]`],
    [IPs/MACs never blocked — add gateway and monitoring host],

    [`baseline_min_scans`], [`5`], [Warmup scans before scoring begins],
    [`suspicion_half_life_days`], [`3.5`], [Exponential decay half-life],
    [`block_ttl_hours`], [`24`], [Auto-unblock TTL],
  ),
  caption: [Key `config.json` fields. All fields are optional; unset fields use the defaults shown.],
) <tbl-config>

Always add your gateway IP and the monitoring host's own IP to `never_block`
to prevent self-blocking under `enforce` mode.

== Running

```sh
# Production daemon — requires root for nmap OS detection
sudo python daemon.py
sudo python daemon.py --config /path/to/config.json

# One-shot run (loads data/processed/*.json, runs comparator + agent)
python main.py
```

The daemon logs to `logs/daemon.log` and stdout.
Investigation reports are written to `reports/` as timestamped JSON files.
Fleet alerts are appended to `alerts/fleet_alerts.jsonl`.
Block decisions (including dry-run non-executions) are appended to
`blocks/blocks.jsonl`.

*Injection demo.*
Drop a crafted nmap XML file into `data/raw/` between scans.
The daemon calls `convert_pending_xml()` at the start of each tick and
ingests the file as if it were a real scan result.

== Persistence Files

#figure(
  table(
    columns: (auto, 1fr),
    align: (left, left),
    table.header([*File*], [*Contents*]),
    [`data/peer_store.json`],
    [Full `PeerStore` snapshot — peers, identity histories, known services, suspicion scores],

    [`alerts/alerts.jsonl`],
    [Per-peer `InvestigationReport` records (JSON Lines)],

    [`alerts/fleet_alerts.jsonl`],
    [`FleetEvent` records from each tick (JSON Lines)],

    [`blocks/blocks.jsonl`],
    [`BlockRecord` audit log — all block decisions including dry-run and declined confirms (JSON Lines)],

    [`logs/daemon.log`], [Structured log output from all pipeline stages],
  ),
  caption: [Persistent output files. None are committed to version control.],
) <tbl-persistence>

`peer_store.json` is written atomically at the end of each tick via a
`tempfile` rename, so an interrupted daemon leaves the previous snapshot
intact.

== Extending the System

*Adding a scoring event.*
Define the event string and add detection logic in
`_compare_fingerprints()` or `_check_incoming_fingerprint()` in
`src/peerwatch/peer_store.py`.
Add the corresponding score increment to the scoring block in
`_check_incoming_fingerprint()`.
Add a test in `tests/test_peer_store.py` or the appropriate simulation file.

*Adding a fleet pattern.*
Add one tuple to the `_PATTERNS` list in `src/peerwatch/fleet_correlator.py`:

```python
("pattern_name", frozenset({"trigger_event"}), "config_field_name", boost_amount),
```

Add the corresponding `int` field to `PeerWatchConfig` in
`src/peerwatch/config.py` with a sensible default.
Add a test scenario to `tests/simulation/test_fleet_simulation.py`.
No other files require modification.

*Adding a passive capture signal.*
Add a new `_observe_*()` method in `src/peerwatch/packet_capture.py`
following the pattern of existing methods (`_observe_ttl`, `_observe_arp`,
etc.).
Register it in the `PacketCapture` dispatch loop.
The signal feeds into `PeerStore` via the existing passive ingest interface
(`PeerStore.ingest_*()` methods).

= User Manual <user-manual>

This appendix covers everything needed to install, configure, and operate
PeerWatch as a network administrator.
No programming knowledge is required beyond basic command-line familiarity.

== Installation

```sh
# 1. Clone the repository
git clone https://github.com/chitoroagad/peerwatch
cd peerwatch

# 2. Enter the Nix development shell
#    Requires Nix with flakes enabled (see System Manual, @system-manual)
nix develop

# 3. Create your config file
cp config.example.json config.json
```

Open `config.json` in a text editor and set at minimum:

```json
{
  "subnet": "192.168.1.0/24",
  "never_block": ["192.168.1.1", "192.168.1.X"]
}
```

Replace `192.168.1.0/24` with your subnet and add your gateway IP and the
IP of the machine running PeerWatch to `never_block`.

== Starting the Daemon

```sh
sudo python daemon.py
```

Root is required for nmap OS detection.
On first start, PeerWatch runs a baseline period of 5 scans before scoring
begins — anomaly events are recorded, but no alerts are generated during this
warmup.
You will see log lines in `logs/daemon.log` confirming each scan:

```
INFO  Scan complete: 12 hosts discovered
INFO  No suspicious peers found.
```

Leave the daemon running continuously.
It rescans every 5 minutes by default (configurable via
`scan_interval_minutes`).

== Reading Alerts

When a device's suspicion score crosses 3.0, PeerWatch writes an alert to
`alerts/alerts.jsonl` and a JSON investigation report to `reports/`.

*Per-device alerts* (`alerts/alerts.jsonl`) — one JSON object per line:

```json
{
  "peer_id": "...",
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "ips": ["192.168.1.42"],
  "suspicion_score": 4.5,
  "severity": "medium",
  "explanation": "OS family changed from Linux to Windows...",
  "recommended_actions": ["Re-scan device", "Verify physically"]
}
```

Key fields:

#figure(
  table(
    columns: (auto, 1fr),
    align: (left, left),
    table.header([*Field*], [*Meaning*]),
    [`severity`],
    [`low` — monitor; `medium` — investigate; `high` — likely compromise],

    [`suspicion_score`],
    [Accumulated weighted anomaly score; decays over time if no new events fire],

    [`explanation`],
    [LLM natural-language summary of what changed and why it is suspicious],

    [`recommended_actions`], [Concrete steps the LLM recommends],
    [`recommended_scans`],
    [Follow-up scans the agent ran automatically (nmap, traceroute, tcpdump)],
  ),
  caption: [Key fields in a per-device investigation alert.],
) <tbl-alert-fields>

*Fleet alerts* (`alerts/fleet_alerts.jsonl`) — fired when the same anomaly
class appears simultaneously across multiple devices:

```json
{
  "pattern": "arp_poisoning",
  "peer_ids": ["...", "..."],
  "ips": ["192.168.1.10", "192.168.1.11", "192.168.1.12"],
  "suspicion_boost": 2.0,
  "description": "3 peers fired arp_spoofing_detected in the same tick"
}
```

A fleet alert means a coordinated attack is likely.
Each affected device also receives an individual alert with the fleet context
included in the LLM explanation.

== Remediation

By default PeerWatch runs in `dry_run` mode: it logs what it _would_ do but
takes no action.
To enable blocking, set `remediation_mode` in `config.json`:

- `"dry_run"` — safe default; logs only
- `"confirm"` — prints the iptables command and prompts `y/N` before executing
- `"enforce"` — executes iptables blocks immediately; requires root

A device is only blocked when *all* of the following are true:
`suspicion_score ≥ 5.0`, `severity == "high"`, the IP is not in
`never_block`, and no active block already exists.

Blocks expire automatically after 24 hours (`block_ttl_hours`).
All block decisions — including dry-run non-executions — are recorded in
`blocks/blocks.jsonl` for audit.

*Important:* always include your gateway and the monitoring host's own IP
in `never_block` before enabling `enforce` mode.

== Tuning

#figure(
  table(
    columns: (auto, 1fr),
    align: (left, left),
    table.header([*Symptom*], [*Adjustment*]),
    [Too many alerts on benign devices],
    [Raise `suspicion_threshold` (default 3.0); check if a device has UPnP — its OS score may oscillate during the warmup period before `known_os_families` stabilises],

    [Attacks not detected fast enough],
    [Lower `suspicion_threshold`; reduce `scan_interval_minutes`; note: lower threshold increases false-positive risk],

    [Blocks firing too aggressively],
    [Raise `block_confidence_floor` (default 5.0); add stable devices to `never_block`],

    [Score not decaying between incidents],
    [Reduce `suspicion_half_life_days` (default 3.5); lower values make the system more reactive to change but less persistent about past anomalies],

    [Warmup period too long],
    [Reduce `baseline_min_scans` (default 5); minimum recommended value is 3],
  ),
  caption: [Common operational issues and configuration adjustments.],
) <tbl-tuning>

== Output File Reference

#figure(
  table(
    columns: (auto, 1fr),
    align: (left, left),
    table.header([*File*], [*What to look at*]),
    [`logs/daemon.log`],
    [Live daemon status; scan completions; LLM errors; iptables actions],

    [`alerts/alerts.jsonl`],
    [Per-device investigation alerts; `severity` and `explanation` are the key fields],

    [`alerts/fleet_alerts.jsonl`],
    [Coordinated-attack detections; check `pattern` and `ips`],

    [`reports/investigation_*.json`],
    [Full LLM investigation reports with follow-up scan output],

    [`blocks/blocks.jsonl`],
    [Complete block audit log; `executed` field distinguishes dry-run from real blocks],
  ),
  caption: [Output files and what to read in each.],
) <tbl-output-files>

= Evaluation Data <appendix-eval-data>

== False-Positive Event Breakdown

@fig-fp-events-breakdown shows the breakdown of event types that fired across
the 322-scan real-traffic corpus used in the FP analysis (@sec-fp-analysis).
Five events fired in total across 18 devices; none accumulated to the 3.0
investigation threshold.

#figure(
  image("figures/fp_events_breakdown.pdf", width: 72%),
  caption: [Event-type breakdown across the 322-scan FP corpus.
    Five events fired in total: two `service_type_changed`, two
    `os_family_changed`, one `port_profile_changed`.
    All were suppressed from scoring by `known_services`,
    `known_os_families`, or the port-visibility guard respectively.],
) <fig-fp-events-breakdown>

== Test Suite Coverage

@tbl-test-breakdown lists the 222 automated tests by file and class.
All tests run without network access, root privileges, or a running Ollama
instance; agent and remediation tests mock subprocess and LLM calls.

#figure(
  table(
    columns: (auto, auto, auto),
    align: (left, right, right),
    table.header([*Source module*], [*Stmts*], [*Coverage*]),
    [`peerwatch/config.py`], [51], [100%],
    [`peerwatch/__init__.py`], [5], [100%],
    [`peerwatch/fleet_correlator.py`], [58], [98%],
    [`peerwatch/embedder.py`], [42], [95%],
    [`peerwatch/util.py`], [16], [94%],
    [`peerwatch/peer_store.py`], [492], [87%],
    [`peerwatch/remediation.py`], [160], [84%],
    [`peerwatch/parser.py`], [184], [90%],
    [`peerwatch/comparator.py`], [41], [66%],
    [`peerwatch/packet_capture.py`], [151], [50%],
    [`peerwatch/agent.py`], [299], [25%],
    [`peerwatch/route_tracker.py`], [178], [30%],
    table.cell(colspan: 2)[*Total (1677 stmts)*], [*67%*],
  ),
  caption: [Test suite coverage by source module (222 tests, `pytest --cov`).
    `agent.py` and `route_tracker.py` have low coverage because their
    primary code paths require a live Ollama instance, root privileges,
    or real network interfaces — all absent in the CI environment.],
) <tbl-test-breakdown>

= Project Plan <project-plan>

@tbl-project-plan shows the planned schedule across the eight-month project
period (October 2025 – May 2026).
The project was structured in three implementation phases, each adding a new
detection dimension, with evaluation and writeup running in parallel from
March onwards.

#let filled() = table.cell(fill: luma(80))[]
#let empty() = table.cell(fill: white)[]

#figure(
  table(
    columns: (2.2fr, 1fr, 1fr, 1fr, 1fr, 1fr, 1fr, 1fr, 1fr),
    align: (
      left,
      center,
      center,
      center,
      center,
      center,
      center,
      center,
      center,
    ),
    stroke: 0.4pt,
    table.header(
      [*Task*],
      [*Oct*],
      [*Nov*],
      [*Dec*],
      [*Jan*],
      [*Feb*],
      [*Mar*],
      [*Apr*],
      [*May*],
    ),

    table.cell(colspan: 9, fill: luma(230))[*Background and Requirements*],
    [Literature survey],
    filled(),
    filled(),
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    [Requirements capture],
    empty(),
    filled(),
    filled(),
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    [Tool selection and setup],
    empty(),
    filled(),
    filled(),
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),

    table.cell(colspan: 9, fill: luma(230))[*Phase 1 — Active Scanning*],
    [nmap scan loop and XML ingest],
    empty(),
    empty(),
    filled(),
    filled(),
    empty(),
    empty(),
    empty(),
    empty(),
    [`PeerStore` and identity keying],
    empty(),
    empty(),
    filled(),
    filled(),
    empty(),
    empty(),
    empty(),
    empty(),
    [Scoring engine and decay],
    empty(),
    empty(),
    empty(),
    filled(),
    filled(),
    empty(),
    empty(),
    empty(),
    [Phase 1 test suite],
    empty(),
    empty(),
    empty(),
    filled(),
    filled(),
    empty(),
    empty(),
    empty(),

    table.cell(colspan: 9, fill: luma(230))[*Phase 2 — Passive Observation*],
    [Scapy capture loop],
    empty(),
    empty(),
    empty(),
    empty(),
    filled(),
    filled(),
    empty(),
    empty(),
    [TTL, ARP, TCP fingerprint signals],
    empty(),
    empty(),
    empty(),
    empty(),
    filled(),
    filled(),
    empty(),
    empty(),
    [Route tracking and ASN lookup],
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    filled(),
    empty(),
    empty(),
    [Phase 2 test suite],
    empty(),
    empty(),
    empty(),
    empty(),
    filled(),
    filled(),
    empty(),
    empty(),

    table.cell(
      colspan: 9,
      fill: luma(230),
    )[*Phase 3 — Fleet Correlation and Agent*],
    [`FleetCorrelator` and patterns],
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    filled(),
    filled(),
    empty(),
    [`SuspiciousAgent` and Ollama],
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    filled(),
    filled(),
    empty(),
    [Remediation module],
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    filled(),
    empty(),
    [Phase 3 test suite],
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    filled(),
    filled(),
    empty(),

    table.cell(colspan: 9, fill: luma(230))[*Evaluation*],
    [Attack scenario evaluation],
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    filled(),
    filled(),
    [False-positive analysis],
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    filled(),
    filled(),
    [Performance characterisation],
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    filled(),

    table.cell(colspan: 9, fill: luma(230))[*Writeup*],
    [Chapter 1–2 (intro, background)],
    empty(),
    filled(),
    filled(),
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    [Chapter 3 (requirements)],
    empty(),
    empty(),
    filled(),
    filled(),
    empty(),
    empty(),
    empty(),
    empty(),
    [Chapter 4 (design/implementation)],
    empty(),
    empty(),
    empty(),
    filled(),
    filled(),
    filled(),
    empty(),
    empty(),
    [Chapter 5 (evaluation)],
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    filled(),
    filled(),
    [Chapter 6 and appendices],
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    filled(),
    [Review and submission],
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    empty(),
    filled(),
  ),
  caption: [Project plan. Dark cells indicate planned active work periods.
    Implementation phases are sequential; writeup runs in parallel
    from November onwards.],
) <tbl-project-plan>

*Milestones:*

#table(
  columns: (auto, 1fr),
  stroke: none,
  inset: (y: 3pt),
  [M1 — End of November 2025:],
  [Requirements finalised; tool stack selected; development environment configured.],

  [M2 — End of January 2026:],
  [Phase 1 complete; `PeerStore` and scoring engine passing full test suite.],

  [M3 — End of February 2026:],
  [Phase 2 complete; passive capture signals integrated and tested.],

  [M4 — End of March 2026:],
  [Phase 3 complete; fleet correlation, LLM agent, and remediation implemented.],

  [M5 — End of April 2026:],
  [Evaluation complete; false-positive rate and attack scenario results measured.],

  [M6 — Mid-May 2026:], [Writeup submitted.],
)

= Interim Report <interim-report>


== Progress Summary

Phase 1 of the project is complete.
The core detection pipeline — periodic nmap scanning, persistent device identity
storage, fingerprint comparison, and suspicion scoring — is implemented and
tested.

The following deliverables are in place:

- *`PeerStore`*: a MAC-keyed in-memory identity store with JSON persistence.
  Each peer record holds its current fingerprint (OS candidates, open ports,
  service map), full identity event history, and a floating-point suspicion score.
  Volatile devices (those that cannot be fingerprinted to a stable MAC address)
  are keyed by IP and flagged separately.

- *nmap scan loop*: `daemon.py` drives periodic `nmap -sV -O --osscan-guess`
  scans of the configured subnet.
  Raw XML output is converted to normalised JSON, deduplicated, and ingested
  into `PeerStore` via `add_or_update_peer()`.
  The daemon supports a configurable scan interval with a rate-limit floor to
  prevent overlapping scans.

- *Fingerprint comparison engine*: `_compare_fingerprints()` detects four
  categories of drift: OS family change (candidate-set intersection),
  port-profile drift (Jaccard similarity), service-type change on known ports,
  and port/protocol mismatch.
  Weighted scoring with exponential decay is implemented via `PeerWatchConfig`.

- *`SuspiciousAgent`* (basic): LLM investigation via Phi-4 / Ollama is working
  end-to-end.
  A rule-based fallback is implemented for offline deployments.

- *Test suite*: 89 tests covering `PeerStore`, the comparison engine,
  `NmapParser`, configuration, persistence, and all nine active-scan attack
  scenarios (A–I).
  All pass.

Chapters 1 and 2 of the writeup are drafted.
Chapter 3 (requirements) is approximately 70% complete.

== Problems Encountered

*nmap OS fingerprint instability.*
The most significant challenge encountered during Phase 1 was the instability
of nmap's OS detection on real hardware.
During early testing against a home network, several devices produced different
OS candidate sets across consecutive scans with no hardware changes, causing
the scoring engine to fire `os_family_changed` spuriously.
The root cause was traced to UPnP service response variance: when a device's
UPnP endpoint responds with an `icslap`-type header, nmap's fingerprint database
matches it to Fortinet/Vonage/Polycom OS families; when it responds with a
`upnp-Microsoft IIS httpd` header, the match is Windows.
The same physical device switches between these depending on which endpoint
handles the probe first.

The initial implementation treated every OS candidate set as a single
normalised string, which made this oscillation appear as a genuine identity
change.
The fix was to represent OS candidates as a set of strings and compare via
intersection: if the incoming and stored candidate sets share any family token,
no OS change is reported.
This required revisiting the `NormalisedData` schema and the `PeerStore`
ingestion logic, adding approximately three days of unplanned work.

*Embedding-based comparison abandoned.*
An early design explored using sentence embeddings to compare device
fingerprints, treating each fingerprint as a natural-language description and
computing cosine similarity.
This was motivated by the hope that embeddings would generalise across minor
nmap vocabulary changes without explicit field-by-field rules.
In practice, embedding similarity was too coarse: semantically similar
fingerprints (e.g., "Linux 4.x" vs "Linux 5.x") scored identically to
genuinely different ones at the threshold required to suppress legitimate
version changes.
The approach was replaced by the current structured comparison engine, which
gives precise control over which fields trigger which events and at what
thresholds.
The embedder module (`embedder.py`) remains in the codebase but is unused in
the main detection pipeline.

*Config proliferation.*
As more scoring weights and threshold parameters were added, maintaining them
as constructor arguments became unwieldy.
A Pydantic `PeerWatchConfig` model was introduced in week 8 to centralise all
thresholds, weights, and daemon settings with type validation and JSON
serialisation.
This required refactoring all existing components to accept a config parameter,
adding approximately two days of unplanned work, but the result is a cleaner
architecture that will simplify Phase 2 and Phase 3 integration.

== Revised Schedule

The Phase 1 work took approximately one week longer than planned, primarily due
to the OS fingerprint instability investigation.
This does not affect the overall project timeline: the float in the evaluation
phase (originally planned as four weeks) absorbs the delay.
The revised schedule advances Phase 2 start to mid-January and compresses the
passive capture implementation from six weeks to five, which is achievable
given that the Scapy capture loop infrastructure is simpler than the nmap
pipeline it mirrors.

#figure(
  table(
    columns: (2fr, auto, auto, auto),
    align: (left, center, center, left),
    table.header([*Phase*], [*Original end*], [*Revised end*], [*Status*]),
    [Background and requirements], [Nov 2025], [Nov 2025], [Complete],
    [Phase 1 — Active scanning],
    [Jan 2026],
    [Jan 2026],
    [Complete (1 week slip absorbed)],

    [Phase 2 — Passive observation], [Feb 2026], [Feb 2026], [On track],
    [Phase 3 — Fleet and agent], [Mar 2026], [Mar 2026], [Not started],
    [Evaluation], [Apr 2026], [Apr 2026], [Not started],
    [Writeup and submission], [May 2026], [May 2026], [Chapters 1–2 drafted],
  ),
  caption: [Revised project schedule as of January 2026.],
) <tbl-revised-schedule>

== Plan for Remainder of Project

*Phase 2 (January–February 2026).*
Implement the passive observation layer using Scapy.
Target signals: TTL baseline tracking, ARP reply conflict detection, TCP stack
fingerprinting against p0f-style heuristics, IP ID counter monitoring, and
route path stability via traceroute with Team Cymru ASN enrichment.
Each signal will be implemented as an independent `_observe_*()` method and
tested in isolation before integration.

*Phase 3 (February–March 2026).*
Implement `FleetCorrelator` for coordinated attack detection, extend
`SuspiciousAgent` with fleet context injection and automated follow-up scans,
and implement the `Remediator` with iptables enforcement and TTL-based
auto-unblock.

*Evaluation (March–April 2026).*
Run the active-scan attack scenario suite (A–I) against the full three-phase
pipeline, conduct false-positive analysis on real home-network traffic, and
characterise performance.

*Writeup (ongoing).*
Complete Chapters 3–6 alongside implementation; target one chapter draft per
phase completion.

= Use Case Specifications <appendix-usecases>

Full specifications for the three most security-critical use cases identified
in @use-cases.

== UC3 — Compare Fingerprint Against Baseline

#table(
  columns: (auto, 1fr),
  stroke: none,
  inset: (y: 4pt),
  [*Use case ID*], [UC3],
  [*Name*], [Compare fingerprint against baseline],
  [*Primary actor*], [Daemon],
  [*Trigger*],
  [A new nmap scan result is ingested for a device already present in `PeerStore`],

  [*Preconditions*],
  [Device has completed the baseline warmup period (`baseline_min_scans` scans recorded). `PeerStore` holds a prior fingerprint for the device's MAC address.],

  [*Main flow*],
  [
    1. Daemon calls `PeerStore.add_or_update_peer(data)` with the new `NormalisedData`.
    2. `_compare_fingerprints()` computes OS-candidate-set intersection, port-set Jaccard similarity, per-port service-type delta, and port/protocol mismatch.
    3. For each detected drift event, `record_event()` appends an `IdentityEvent` to the peer's history.
    4. Weighted scoring increments `suspicion_score`; `known_services` and `known_os_families` suppress re-scoring on already-seen transitions.
    5. If `suspicion_score >= suspicion_threshold`, the peer is marked for investigation.
  ],

  [*Alternative flows*],
  [
    - *No drift detected*: no events recorded; score unchanged.
    - *MAC conflict*: `_resolve_conflict()` fires `identity_conflict_detected` and merges or displaces the ghost peer.
    - *Volatile device*: comparison proceeds with IP as key; MAC-based deduplication skipped.
  ],

  [*Postconditions*],
  [Peer record updated with new fingerprint, events, and score. If score crossed threshold, peer is in the investigation queue for the current tick.],
)

== UC4 — Trigger LLM Investigation

#table(
  columns: (auto, 1fr),
  stroke: none,
  inset: (y: 4pt),
  [*Use case ID*], [UC4],
  [*Name*], [Trigger LLM investigation],
  [*Primary actor*], [Daemon],
  [*Trigger*],
  [`peer.suspicion_score >= suspicion_threshold` at the end of a tick],

  [*Preconditions*],
  [Fleet correlation has completed for the current tick. Ollama is running (or rule-based fallback is acceptable).],

  [*Main flow*],
  [
    1. `SuspiciousAgent.investigate_all(fleet_events)` iterates over all peers above threshold.
    2. For each peer, `_format_peer_context()` builds a structured prompt from fingerprint, event history, known services, and fleet context (if any fleet events reference this peer).
    3. The prompt is sent to Phi-4 via LangChain with `temperature=0` and `format="json"`.
    4. The response is validated against `AgentDecision` schema: `explanation`, `severity`, `recommended_scans`, `recommended_actions`.
    5. `_build_auto_identity_checks()` appends `ssh_hostkey` and `ssl_cert` checks for any peer with open SSH or HTTPS ports, independent of the LLM output.
    6. Recommended scans are executed (`nmap`, `traceroute`, `tcpdump`, `ssh_hostkey`, `ssl_cert`).
    7. An `InvestigationReport` is written to `reports/` and appended to `alerts/alerts.jsonl`.
  ],

  [*Alternative flows*],
  [
    - *Ollama unavailable*: `_analyse()` catches the exception and calls `_rule_based_fallback()`, which assigns severity by score threshold and recommends scans by event type. Investigation proceeds without LLM output.
    - *Schema validation failure*: falls through to rule-based fallback.
    - *No suspicious peers*: method returns immediately; no reports written.
  ],

  [*Postconditions*],
  [Investigation report on disk. `alerts/alerts.jsonl` updated. Scan results (including any changed SSH keys or TLS certificates) ingested back into `PeerStore`.],

  [*Security note*],
  [Raw packet payloads, hostnames, and peer-supplied banner strings are never included in the LLM prompt. All prompt data is derived from structured `PeerStore` fields to mitigate indirect prompt injection @promptinjection.],
)

== UC7 — Approve Remediation Block

#table(
  columns: (auto, 1fr),
  stroke: none,
  inset: (y: 4pt),
  [*Use case ID*], [UC7],
  [*Name*], [Approve remediation block],
  [*Primary actor*], [Administrator],
  [*Trigger*],
  [`Remediator.evaluate()` returns a non-`None` `BlockAction` in `confirm` mode],

  [*Preconditions*],
  [All five guards cleared: IP/MAC not in `never_block`; `suspicion_score >= block_confidence_floor`; `severity == "high"`; IP available; no active block for this IP. `remediation_mode == "confirm"`.],

  [*Main flow*],
  [
    1. `Remediator.act()` prints the target IP, suspicion score, reason string, expiry time, and the exact iptables commands to stdout.
    2. Administrator reads the prompt and types `y` to confirm or `N` (or Enter) to decline.
    3. On confirmation: iptables `INPUT DROP` and `OUTPUT DROP` rules are inserted for the target IP. A `BlockRecord` with `executed=True` is appended to `blocks/blocks.jsonl`.
    4. On decline: a `BlockRecord` with `executed=False` is appended to `blocks/blocks.jsonl` for audit purposes.
  ],

  [*Alternative flows*],
  [
    - *EOF / keyboard interrupt at prompt*: treated as decline; block is not executed.
    - *`dry_run` mode*: UC7 reduces to a no-op — `act()` logs the would-be commands and writes `executed=False` without prompting.
    - *`enforce` mode*: UC7 is bypassed — block is executed immediately without operator interaction.
    - *iptables failure*: `_run_cmds()` logs the error; `BlockRecord` written with `executed=False`.
  ],

  [*Postconditions*],
  [Block decision recorded in `blocks/blocks.jsonl` regardless of outcome. If executed, block is active until `expires_at`; `unblock_expired()` removes the iptables rules on the next tick after TTL expiry.],

  [*Security note*],
  [The LLM is not in the authorisation path. The decision to block is made purely by the rule-based guard chain; the LLM severity classification is one input to that chain, but the chain itself is deterministic.],
)

= Source Code <source-code>

The full source code is available at:

#align(center)[`https://github.com/chitoroagad/peerwatch`]

The commit pinned to this submission is noted below.
Repository structure follows the layout described in @system-manual.

#table(
  columns: (auto, 1fr),
  stroke: none,
  inset: (y: 3pt),
  [*Submission commit*], [`a3035aa21e6c72cd37c89cb8e49b6961730c8c44`],
  [*Language*], [Python 3.13],
  [*Test command*],
  [`nix develop && pytest` (222 tests, no network or root required)],

  [*Writeup command*],
  [`nix develop .#writeup && typst compile writeup/main.typ`],
)
