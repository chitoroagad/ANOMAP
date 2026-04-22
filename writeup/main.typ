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
The limitations of MAC-only monitoring were demonstrated in CVE-2004-0699 @mitre, where device
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

=== Coordinated Fleet Attacks <fleet-attacks>

The attack patterns above are considered in isolation; in practice, targeted intrusions
frequently affect multiple hosts in the same network concurrently.
The distinction matters for detection: a single device showing OS fingerprint drift is
consistent with a firmware update; four devices showing simultaneous OS drift is not.

Fleet-level patterns observable in real intrusions include gateway substitution campaigns
, where the attacker poisons ARP caches across multiple hosts simultaneously to redirect
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
described in detail in Section 4.x. // TODO: add cross-ref

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
in the evaluation (T1036.004 masquerading, CVE-2024-3094) demonstrates this
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
Chapter 4 describes how each is implemented within the pipeline.
// TODO: add cross refernce

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
Team Cymru's IP-to-ASN mapping attributes each hop to an autonomous system; a new ASN
in the path indicates traffic leaving via an unexpected upstream provider.
// TODO: Add references here.

*MAC OUI correlation.*
The first three octets of a MAC address identify the hardware vendor registered with the
IEEE (the Organizationally Unique Identifier). // TODO: reference
Cross-checking OUI vendor against nmap-detected OS family catches a class of substitution
neither signal alone would flag: an Apple OUI combined with a Linux OS detection indicates
the claimed hardware identity is inconsistent with the network stack behaviour.

This signal carries elevated false positive risk.
MAC address randomisation, enabled by default in iOS 14+ and Android 10+, assigns
locally-administered addresses per network, making OUI attribution unreliable for
mobile devices.
Virtual machine adapters expose hypervisor vendor OUIs legitimately inconsistent with
the guest OS.
OUI correlation is therefore treated as a supporting signal rather than a primary
detection trigger.

== Related Work and Tool Survey

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
XarpS and similar tools share this scope.  // TODO: reference

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
research literature. // TODO: Reference
These operate at aggregate traffic level, making them sensitive to volumetric shifts
but not to low-and-slow device substitution that preserves traffic volume while
changing device identity.

Direct prior work on per-device multi-signal identity drift detection in open-source
LAN monitoring is, to the author's knowledge, sparse.
This gap is the primary motivation for PeerWatch.

=== LLM-Assisted Security Triage

The application of large language models to security operations has grown rapidly since
the emergence of capable instruction-following models.
Commercial products including Microsoft Copilot for Security and Google Chronicle AI // TODO: Reference
incorporate LLMs for alert summarisation, threat intelligence synthesis, and first-pass
triage of SIEM events, targeting the alert fatigue problem @alertfatigue that afflicts
security operations teams at scale.

Deploying LLMs in security contexts introduces a specific risk: indirect prompt
injection @promptinjection.
Where an LLM processes data originating from an adversarially controlled source,
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

#bibliography(
  "refs.bib",
  title: "References",
  style: "association-for-computing-machinery",
)

#colbreak(weak: true)
#set heading(numbering: "A.a.a")

= Artifact Appendix
In this section we show how to reproduce our findings.
