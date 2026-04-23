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

== Tools and Libraries

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
BPF filters are boolean expressions over packet fields (i.e.
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
maintenance.  // TODO: maybe reference
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

== Evidence Accumulation and Anomaly Scoring

The signals described in @device-fingerprinting are individually noisy: a single TTL deviation
is consistent with a transient routing change; a single OS fingerprint shift is
consistent with a firmware update.
Turning noisy per-signal observations into reliable detection requires a principled
accumulation model.
This section establishes the theoretical basis; Chapter 4 describes the implementation. // TODO: cross-reference

=== Weighted Scoring

Not all signals carry equal evidential weight.
A changed SSH host key is near-certain evidence of server substitution; a Jaccard
port profile drift below 0.6 is consistent with routine service changes.
Assigning uniform weight to all signals would cause low-evidence events to dominate
the score when they fire frequently, drowning higher-confidence signals in noise.

Axelsson @axelsson demonstrates that in intrusion detection systems the false positive
rate of individual signals has an outsized effect on overall system utility: even at
high true positive rates, a signal with a 1% false positive rate will produce more
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
If two signals each have a 10% false positive rate and fire independently, the joint
probability of both firing simultaneously on a benign event is approximately 1%,
a tenfold reduction in false positive rate with no loss of true positive rate for attacks
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
observation produces high false positive rates on legitimate newly-discovered devices.
PeerWatch withholds scoring for the first `baseline_min_scans` observations (default 5),
recording events without contributing to the suspicion score until a stable baseline
is established.

=== Threshold Calibration

The investigation threshold determines the operating point on the precision-recall
curve.
Lowering the threshold increases true positive rate at the cost of false positive rate;
raising it reduces false alerts at the risk of missed detections.
Axelsson @axelsson shows that for realistic base rates of attacks on a typical network,
even modest false positive rates render a detection system impractical; an alert that
fires ten times per day on a clean network will be ignored within a week, eliminating
any security value.

Threshold calibration is therefore not a parameter to set once and forget but a
deployment-specific tradeoff between operator tolerance for false alarms and the
acceptable miss rate for real attacks.
Chapter 5 characterises PeerWatch's operating point empirically under both simulated  // TODO: Cross-reference
attack traffic and clean-traffic conditions, providing the data an operator needs to
adjust the threshold for their specific environment.

This chapter has established the foundations on which PeerWatch is built.
Section 2.1 defined the threat landscape — the attack techniques that existing
single-signal tools cannot detect and that motivate a multi-signal approach.
Section 2.2 surveyed the fingerprinting signals available to a locally-deployed monitor,
from active nmap probing to passive TCP stack observation and cryptographic anchors.
Section 2.3 positioned PeerWatch against existing tools and research, identifying the
vacant design space it occupies.
Sections 2.4 and 2.5 introduced the tools the implementation relies on and the
theoretical basis for combining their outputs into a coherent scoring model.
Chapter 3 translates this context into a structured requirements specification and
analyses it into an initial design.

= Requirements and Analysis

== Problem Statement

The introduction established that existing tools fail to detect device substitution
and service-level impersonation attacks on home and small-office networks.
This section states the precise technical problem an implementation must solve:
the specific uncertainties, constraints, and failure modes from which the
requirements in Section 3.2 are derived.  // TODO: cross-reference

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
These events define the false positive ceiling: any signal that fires on them
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

#bibliography(
  "refs.bib",
  title: "References",
  style: "association-for-computing-machinery",
)

#colbreak(weak: true)
#set heading(numbering: "A.a.a")

= Artifact Appendix
In this section we show how to reproduce our findings.
