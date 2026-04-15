"""
Simulation tests: sequences of nmap scans representing real attack patterns.

Each scenario is tied to a documented CVE or MITRE ATT&CK technique and verifies
that PeerWatch raises the correct events and crosses the suspicion threshold (≥ 3.0).
Scores were verified empirically against the live PeerStore before these tests were written.

Scenario summary:
  A — IP Spoofing / ARP Poisoning        CVE-2020-25705, T1557.002    score: 5.0
  B — Service Backdoor                    T1543, US-CERT TA17-181A     score: 4.0
  C — MAC Spoofing / OS Mismatch          CVE-2004-0699, T1564.006     score: 4.5
  D — Cross-Device Identity Conflict      T1465, CVE-2019-11477         score: ≥ 1.0
  E — OS Fingerprint Spoofing (neg.)      T1014                         score: 2.0 (below threshold)
  F — Multi-Port Protocol Takeover        CVE-2024-6387, CVE-2024-4577  score: 8.0
  G — IoT Botnet Enrollment               CVE-2024-7029, CVE-2023-1389  score: 3.0
  H — Network Appliance Incremental       CVE-2024-3400, CVE-2023-20198 score: 6.5 (over 3 scans)
  I — Service Mimicry Evasion (neg.)      CVE-2024-3094, T1036.004      score: 0.0 (undetected)
"""

import pytest

from peerwatch.peer_store import Peer, PeerStore

from .factories import scan, warm_up

THRESHOLD = 3.0


# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------


def assert_events_fired(peer: Peer, *events: str) -> None:
    fired = {e.event for e in peer.identity_history}
    for event in events:
        assert event in fired, f"Expected event '{event}' not fired; got {fired}"


def assert_events_not_fired(peer: Peer, *events: str) -> None:
    fired = {e.event for e in peer.identity_history}
    for event in events:
        assert event not in fired, f"Event '{event}' fired unexpectedly"


def assert_score_above(peer: Peer, threshold: float = THRESHOLD) -> None:
    assert peer.suspicion_score >= threshold, (
        f"suspicion_score={peer.suspicion_score:.2f} did not reach {threshold}"
    )


def assert_score_below(peer: Peer, threshold: float = THRESHOLD) -> None:
    assert peer.suspicion_score < threshold, (
        f"suspicion_score={peer.suspicion_score:.2f} unexpectedly reached {threshold}"
    )


def assert_event_details(peer: Peer, event: str, **expected_kv) -> None:
    matches = [e for e in peer.identity_history if e.event == event]
    assert matches, f"No '{event}' event found in identity_history"
    for e in matches:
        for key, val in expected_kv.items():
            if key in e.details:
                assert e.details[key] == val, (
                    f"Event '{event}': expected {key}={val!r}, got {e.details[key]!r}"
                )


# ---------------------------------------------------------------------------
# Scenario A — IP Spoofing / ARP Poisoning
#
# Attack: Attacker runs arpspoof to answer for the victim's IP with a
# different MAC address and completely different OS/port fingerprint.
# nmap sees the same IP responding from a new device.
#
# References:
#   CVE-2020-25705 (SAD DNS) — off-path IP spoofing as a core attack mechanism.
#     Demonstrates that IP ownership is not self-authenticating.
#   MITRE ATT&CK T1557.002 — ARP Cache Poisoning (documented MITM precursor).
#
# PeerStore path: ip_to_id matches victim (1 candidate) → single-candidate update.
#   _check_incoming_fingerprint sees OS + port changes → os_family_changed,
#   port_profile_changed, full_identity_shift.
#   _update_peer detects MAC mismatch → mac_conflict (+0.5 directly to score).
#
# Score breakdown:
#   mac_conflict       +0.5
#   os_family_changed  +2.0
#   port_profile_changed +0.5
#   full_identity_shift +2.0
#   ─────────────────────────
#   Total              5.0
# ---------------------------------------------------------------------------


class TestIPSpoofing:
    @pytest.fixture
    def store(self):
        return PeerStore()

    @pytest.fixture
    def victim_baseline(self):
        return scan(
            mac="AA:BB:CC:DD:EE:FF",
            ip="192.168.1.10",
            os="Linux",
            os_candidates={"Linux": 96},
            ports=[22, 80],
            services={22: "ssh-OpenSSH", 80: "http-Apache"},
        )

    def test_warmup_produces_zero_suspicion(self, store, victim_baseline):
        peer = warm_up(store, victim_baseline)
        assert peer.suspicion_score == pytest.approx(0.0)

    def test_single_attack_scan_crosses_threshold(self, store, victim_baseline):
        warm_up(store, victim_baseline)

        attacker = scan(
            mac="DE:AD:BE:EF:00:01",  # different MAC
            ip="192.168.1.10",        # same IP — triggers lookup of victim peer
            os="Windows",
            os_candidates={"Microsoft": 95},
            ports=[3389, 445],
            services={3389: "rdp-ms-rdp", 445: "microsoft-ds"},
        )
        peer = store.add_or_update_peer(attacker)

        assert_score_above(peer)
        assert peer.suspicion_score == pytest.approx(5.0)

    def test_correct_events_fired(self, store, victim_baseline):
        warm_up(store, victim_baseline)

        attacker = scan(
            mac="DE:AD:BE:EF:00:01",
            ip="192.168.1.10",
            os="Windows",
            os_candidates={"Microsoft": 95},
            ports=[3389, 445],
            services={3389: "rdp-ms-rdp", 445: "microsoft-ds"},
        )
        peer = store.add_or_update_peer(attacker)

        assert_events_fired(
            peer,
            "mac_conflict",
            "os_family_changed",
            "port_profile_changed",
            "full_identity_shift",
        )

    def test_peer_survives_in_store(self, store, victim_baseline):
        warm_up(store, victim_baseline)

        attacker = scan(
            mac="DE:AD:BE:EF:00:01",
            ip="192.168.1.10",
            os="Windows",
            os_candidates={"Microsoft": 95},
            ports=[3389, 445],
            services={3389: "rdp-ms-rdp", 445: "microsoft-ds"},
        )
        store.add_or_update_peer(attacker)

        assert len(store.peers) == 1, "Peer must not be evicted after an attack scan"


# ---------------------------------------------------------------------------
# Scenario B — Service Backdoor (Port Protocol Mismatch)
#
# Attack: Post-compromise implant binds to port 22, replacing the SSH daemon
# with a C2 beacon. nmap fingerprints port 22 as an HTTP service, not SSH.
#
# References:
#   MITRE ATT&CK T1543 — Create or Modify System Process.
#     Attackers replace or wrap sshd to establish persistence on a known port.
#   US-CERT TA17-181A (NotPetya) — lateral movement via port 445 running
#     unexpected protocols. Same pattern: well-known port, wrong service.
#
# PeerStore path: single-candidate update.
#   _check_port_protocol_mismatches detects port 22 ∉ {"ssh"} → port_protocol_mismatch.
#   Flagged in peer.flagged_port_mismatches to prevent repeated scoring.
#
# Score breakdown:
#   service_type_changed (ssh → http, port 22)  +1.0
#   port_protocol_mismatch (port 22 ∉ {"ssh"})  +3.0
#   ─────────────────────────────────────────────────
#   Total                                         4.0
# Both events fire on the first attack scan. On repeat scans: service stays "http"
# so service_type_changed is silent, and flagged_port_mismatches deduplicates
# port_protocol_mismatch — score stays at 4.0.
# ---------------------------------------------------------------------------


class TestServiceBackdoor:
    MAC = "BB:CC:DD:EE:FF:00"
    IP = "192.168.1.20"

    @pytest.fixture
    def store(self):
        return PeerStore()

    @pytest.fixture
    def baseline(self):
        return scan(
            mac=self.MAC,
            ip=self.IP,
            ports=[22, 80, 443],
            services={22: "ssh-OpenSSH", 80: "http-Apache", 443: "https-nginx"},
        )

    @pytest.fixture
    def attack_scan(self):
        return scan(
            mac=self.MAC,
            ip=self.IP,
            ports=[22, 80, 443],
            services={22: "http-c2backdoor", 80: "http-Apache", 443: "https-nginx"},
        )

    def test_warmup_produces_zero_suspicion(self, store, baseline):
        peer = warm_up(store, baseline)
        assert peer.suspicion_score == pytest.approx(0.0)

    def test_single_attack_scan_crosses_threshold_exactly(
        self, store, baseline, attack_scan
    ):
        warm_up(store, baseline)
        peer = store.add_or_update_peer(attack_scan)

        # service_type_changed (ssh→http) +1.0 + port_protocol_mismatch +3.0 = 4.0
        assert peer.suspicion_score == pytest.approx(4.0)

    def test_port_protocol_mismatch_event_fired(self, store, baseline, attack_scan):
        warm_up(store, baseline)
        peer = store.add_or_update_peer(attack_scan)

        # Both events fire: the service changed (ssh→http) AND the new service is wrong
        assert_events_fired(peer, "service_type_changed", "port_protocol_mismatch")

    def test_event_details_identify_port_and_service(
        self, store, baseline, attack_scan
    ):
        warm_up(store, baseline)
        peer = store.add_or_update_peer(attack_scan)

        assert_event_details(peer, "port_protocol_mismatch", port=22)
        mismatch = next(
            e for e in peer.identity_history if e.event == "port_protocol_mismatch"
        )
        assert mismatch.details["actual"] == "http-c2backdoor"
        assert "ssh" in mismatch.details["expected"]

    def test_mismatch_only_scored_once_per_port(self, store, baseline, attack_scan):
        """flagged_port_mismatches must prevent the score accumulating on repeat scans."""
        warm_up(store, baseline)
        store.add_or_update_peer(attack_scan)
        peer = store.add_or_update_peer(attack_scan)  # second identical attack scan

        mismatch_events = [
            e for e in peer.identity_history if e.event == "port_protocol_mismatch"
        ]
        assert len(mismatch_events) == 1
        # score from first attack: service_type_changed +1.0 + port_protocol_mismatch +3.0 = 4.0
        # second attack: mismatch deduped, service unchanged → no additional score
        assert peer.suspicion_score == pytest.approx(4.0)


# ---------------------------------------------------------------------------
# Scenario C — MAC Spoofing / OS and Port Profile Mismatch
#
# Attack: Attacker clones a Windows workstation's MAC address onto a Linux
# attack box. The MAC matches the known peer, but the OS family and port
# profile are completely different.
#
# References:
#   CVE-2004-0699 — Cisco 802.1X bypass via crafted Ethernet frames with a
#     spoofed MAC; classic demonstration that MAC is a weak authenticator.
#   MITRE ATT&CK T1564.006 — Hide Artifacts: Run Virtual Instance.
#     VMs and containers commonly present spoofed MACs to impersonate known devices.
#
# PeerStore path: mac_to_id matches known Windows peer (1 candidate).
#   OS candidates are disjoint → os_family_changed.
#   Jaccard([3389,445,139], [22,80,8080]) = 0/6 = 0.0 < 0.6 → port_profile_changed.
#   No shared ports → full_identity_shift (OS disjoint + Jaccard < 0.4 + no shared ports).
#
# Score breakdown:
#   os_family_changed    +2.0
#   port_profile_changed +0.5
#   full_identity_shift  +2.0
#   ──────────────────────────
#   Total                4.5
# ---------------------------------------------------------------------------


class TestMACSpoofing:
    WINDOWS_MAC = "CC:DD:EE:FF:00:11"
    IP = "192.168.1.30"

    @pytest.fixture
    def store(self):
        return PeerStore()

    @pytest.fixture
    def windows_baseline(self):
        return scan(
            mac=self.WINDOWS_MAC,
            ip=self.IP,
            os="Windows",
            os_candidates={"Microsoft": 98},
            ports=[3389, 445, 139],
            services={
                3389: "rdp-ms-rdp",
                445: "microsoft-ds",
                139: "netbios-ssn",
            },
        )

    def test_warmup_produces_zero_suspicion(self, store, windows_baseline):
        peer = warm_up(store, windows_baseline)
        assert peer.suspicion_score == pytest.approx(0.0)

    def test_single_attack_scan_crosses_threshold(self, store, windows_baseline):
        warm_up(store, windows_baseline)

        linux_attacker = scan(
            mac=self.WINDOWS_MAC,  # cloned MAC
            ip=self.IP,
            os="Linux",
            os_candidates={"Linux": 95},
            ports=[22, 80, 8080],
            services={22: "ssh-OpenSSH", 80: "http-nginx", 8080: "http-panel"},
        )
        peer = store.add_or_update_peer(linux_attacker)

        assert_score_above(peer)
        assert peer.suspicion_score == pytest.approx(4.5)

    def test_correct_events_fired(self, store, windows_baseline):
        warm_up(store, windows_baseline)

        linux_attacker = scan(
            mac=self.WINDOWS_MAC,
            ip=self.IP,
            os="Linux",
            os_candidates={"Linux": 95},
            ports=[22, 80, 8080],
            services={22: "ssh-OpenSSH", 80: "http-nginx", 8080: "http-panel"},
        )
        peer = store.add_or_update_peer(linux_attacker)

        assert_events_fired(
            peer, "os_family_changed", "port_profile_changed", "full_identity_shift"
        )

    def test_no_service_type_change_when_no_shared_ports(
        self, store, windows_baseline
    ):
        # Windows and Linux port sets are disjoint — service_type_changed requires
        # shared ports, so it must not fire here.
        warm_up(store, windows_baseline)

        linux_attacker = scan(
            mac=self.WINDOWS_MAC,
            ip=self.IP,
            os="Linux",
            os_candidates={"Linux": 95},
            ports=[22, 80, 8080],
            services={22: "ssh-OpenSSH", 80: "http-nginx", 8080: "http-panel"},
        )
        peer = store.add_or_update_peer(linux_attacker)

        assert_events_not_fired(peer, "service_type_changed")


# ---------------------------------------------------------------------------
# Scenario D — Cross-Device Identity Conflict (Rogue AP / Device Swap)
#
# Attack: Attacker simultaneously claims the MAC of device A and the IP of
# device B — e.g., a rogue access point that impersonates two known devices
# at once to position itself as a MITM.
#
# References:
#   MITRE ATT&CK T1465 — Rogue Wi-Fi Access Points.
#     A rogue AP clones the legitimate MAC/BSSID to intercept traffic.
#   CVE-2019-11477 (SACK Panic) — used to DoS a legitimate device so that
#     an attacker can claim its identity on the network post-crash.
#
# PeerStore path: mac_to_id[attacker_mac] → peer_A AND ip_to_id[victim_B_ip] → peer_B
#   → two candidates → _resolve_conflict → identity_conflict_detected (+1.0).
#   (This path required fixing the pass→continue bug in _resolve_conflict.)
#
# Note: this scenario alone scores ~1.5 (below threshold). In the full system
# it combines with Phase 2 passive packet analysis (TTL anomalies, ARP monitoring)
# to cross 3.0. Documented here to prove the detection fires correctly.
# ---------------------------------------------------------------------------


class TestCrossDeviceConflict:
    MAC_A = "AA:BB:CC:DD:EE:FF"
    IP_A = "192.168.1.10"
    MAC_B = "BB:CC:DD:EE:FF:00"
    IP_B = "192.168.1.20"

    @pytest.fixture
    def store_with_two_devices(self):
        store = PeerStore()
        device_a = scan(mac=self.MAC_A, ip=self.IP_A, os="Linux")
        device_b = scan(mac=self.MAC_B, ip=self.IP_B, os="Windows",
                        os_candidates={"Microsoft": 95},
                        ports=[3389], services={3389: "rdp-ms-rdp"})
        warm_up(store, device_a)
        warm_up(store, device_b)
        return store

    def test_two_devices_established(self, store_with_two_devices):
        assert len(store_with_two_devices.peers) == 2

    def test_identity_conflict_fires(self, store_with_two_devices):
        store = store_with_two_devices
        # Attacker: MAC of A (known) + IP of B (known to different peer) → conflict
        attacker = scan(mac=self.MAC_A, ip=self.IP_B, os="Linux")
        survivor = store.add_or_update_peer(attacker)

        assert_events_fired(survivor, "identity_conflict_detected")

    def test_peers_merged_not_deleted(self, store_with_two_devices):
        """The _resolve_conflict bug fix (pass→continue) must leave the survivor intact."""
        store = store_with_two_devices
        attacker = scan(mac=self.MAC_A, ip=self.IP_B, os="Linux")
        store.add_or_update_peer(attacker)

        assert len(store.peers) == 1, (
            "Conflict resolution must leave exactly one survivor, not delete all peers"
        )

    def test_score_increases_after_conflict(self, store_with_two_devices):
        store = store_with_two_devices
        attacker = scan(mac=self.MAC_A, ip=self.IP_B, os="Linux")
        survivor = store.add_or_update_peer(attacker)

        assert survivor.suspicion_score >= 1.0


# ---------------------------------------------------------------------------
# Scenario E — OS Fingerprint Spoofing Alone (negative / calibration test)
#
# Attack: Attacker manipulates the TCP/IP stack (e.g., via a rootkit or
# scapy-based packet crafting) to make a Linux host fingerprint as Windows,
# while keeping the same ports and services unchanged.
#
# References:
#   MITRE ATT&CK T1014 — Rootkit: kernel-level OS fingerprint manipulation
#     is a rootkit-class technique used to evade OS-specific detection rules.
#
# PeerWatch detection:
#   os_family_changed fires → +2.0. Ports and services are identical → no
#   further events. Final score 2.0 < 3.0 threshold.
#
# This is intentional: a single OS-fingerprint anomaly is suspicious but not
# conclusive on its own. PeerWatch is calibrated to require corroborating
# evidence (port/service changes) before alerting. Documenting this negative
# case proves the threshold is not hair-trigger.
# ---------------------------------------------------------------------------


class TestOSFingerprintSpoofingAlone:
    MAC = "EE:FF:00:11:22:33"
    IP = "192.168.1.50"

    @pytest.fixture
    def store(self):
        return PeerStore()

    @pytest.fixture
    def linux_baseline(self):
        return scan(
            mac=self.MAC,
            ip=self.IP,
            os="Linux",
            os_candidates={"Linux": 96},
            ports=[22, 80],
            services={22: "ssh-OpenSSH", 80: "http-Apache"},
        )

    def test_warmup_produces_zero_suspicion(self, store, linux_baseline):
        peer = warm_up(store, linux_baseline)
        assert peer.suspicion_score == pytest.approx(0.0)

    def test_os_change_alone_does_not_cross_threshold(self, store, linux_baseline):
        warm_up(store, linux_baseline)

        # Same ports and services — only OS family changes
        windows_spoof = scan(
            mac=self.MAC,
            ip=self.IP,
            os="Windows",
            os_candidates={"Microsoft": 94},
            ports=[22, 80],
            services={22: "ssh-OpenSSH", 80: "http-Apache"},
        )
        peer = store.add_or_update_peer(windows_spoof)

        assert peer.suspicion_score == pytest.approx(2.0)
        assert_score_below(peer)

    def test_os_family_changed_fires(self, store, linux_baseline):
        warm_up(store, linux_baseline)

        windows_spoof = scan(
            mac=self.MAC,
            ip=self.IP,
            os="Windows",
            os_candidates={"Microsoft": 94},
            ports=[22, 80],
            services={22: "ssh-OpenSSH", 80: "http-Apache"},
        )
        peer = store.add_or_update_peer(windows_spoof)

        assert_events_fired(peer, "os_family_changed")

    def test_port_profile_unchanged_no_event(self, store, linux_baseline):
        warm_up(store, linux_baseline)

        windows_spoof = scan(
            mac=self.MAC,
            ip=self.IP,
            os="Windows",
            os_candidates={"Microsoft": 94},
            ports=[22, 80],
            services={22: "ssh-OpenSSH", 80: "http-Apache"},
        )
        peer = store.add_or_update_peer(windows_spoof)

        assert_events_not_fired(peer, "port_profile_changed", "full_identity_shift")


# ---------------------------------------------------------------------------
# Scenario F — Multi-Port Protocol Takeover (Extensive Backdoor Deployment)
#
# Attack: After gaining RCE, the attacker simultaneously replaces two well-known
# services with C2 implants: sshd on port 22 becomes an HTTP beacon, and the
# web server on port 80 is replaced with an SMTP listener acting as a covert
# channel. Both mismatches are detected in a single nmap scan.
#
# References:
#   CVE-2024-6387 (regreSSHion, 2024) — unauthenticated RCE in OpenSSH ≤ 9.7.
#     CVSS 8.1. Exploiting this gives shell access, after which the attacker
#     can replace sshd with a C2 beacon on the same port.
#   CVE-2024-4577 (PHP CGI argument injection, 2024) — CVSS 9.8, RCE on PHP
#     servers. Post-exploitation, web server replaced with reverse-shell listener.
#
# PeerStore path: both ports are shared → service_type_changed fires per port;
#   port_protocol_mismatch fires for each because the new protocol types are
#   not in WELL_KNOWN_PORT_PROTOCOLS[port].
#
# Score breakdown:
#   service_type_changed (ssh→http, port 22)   +1.0
#   port_protocol_mismatch (port 22, ssh→http) +3.0
#   service_type_changed (http→smtp, port 80)  +1.0
#   port_protocol_mismatch (port 80, http→smtp)+3.0
#   ──────────────────────────────────────────────
#   Total                                        8.0
# ---------------------------------------------------------------------------


class TestMultiPortProtocolTakeover:
    MAC = "FF:00:11:22:33:44"
    IP = "192.168.1.60"

    @pytest.fixture
    def store(self):
        return PeerStore()

    @pytest.fixture
    def baseline(self):
        return scan(
            mac=self.MAC,
            ip=self.IP,
            ports=[22, 80],
            services={22: "ssh-OpenSSH", 80: "http-Apache"},
        )

    def test_warmup_produces_zero_suspicion(self, store, baseline):
        peer = warm_up(store, baseline)
        assert peer.suspicion_score == pytest.approx(0.0)

    def test_dual_protocol_takeover_score(self, store, baseline):
        warm_up(store, baseline)

        attack = scan(
            mac=self.MAC,
            ip=self.IP,
            ports=[22, 80],
            services={22: "http-c2agent", 80: "smtp-postfix"},
        )
        peer = store.add_or_update_peer(attack)

        assert peer.suspicion_score == pytest.approx(8.0)

    def test_both_mismatches_recorded(self, store, baseline):
        warm_up(store, baseline)

        attack = scan(
            mac=self.MAC,
            ip=self.IP,
            ports=[22, 80],
            services={22: "http-c2agent", 80: "smtp-postfix"},
        )
        peer = store.add_or_update_peer(attack)

        mismatch_events = [
            e for e in peer.identity_history if e.event == "port_protocol_mismatch"
        ]
        mismatch_ports = {e.details["port"] for e in mismatch_events}
        assert mismatch_ports == {22, 80}

    def test_both_service_type_changes_recorded(self, store, baseline):
        warm_up(store, baseline)

        attack = scan(
            mac=self.MAC,
            ip=self.IP,
            ports=[22, 80],
            services={22: "http-c2agent", 80: "smtp-postfix"},
        )
        peer = store.add_or_update_peer(attack)

        svc_change_events = [
            e for e in peer.identity_history if e.event == "service_type_changed"
        ]
        changed_ports = {e.details["port"] for e in svc_change_events}
        assert changed_ports == {22, 80}

    def test_repeat_scan_does_not_accumulate(self, store, baseline):
        """Both ports are flagged after first attack — score must not grow on repeat."""
        warm_up(store, baseline)

        attack = scan(
            mac=self.MAC,
            ip=self.IP,
            ports=[22, 80],
            services={22: "http-c2agent", 80: "smtp-postfix"},
        )
        store.add_or_update_peer(attack)
        peer = store.add_or_update_peer(attack)

        assert peer.suspicion_score == pytest.approx(8.0)


# ---------------------------------------------------------------------------
# Scenario G — IoT Device Botnet Enrollment (New Backdoor Port)
#
# Attack: A Mirai-family botnet exploits a command injection vulnerability in
# an IP camera. The implant opens a new port (22) with an HTTP-based C2
# beacon — a non-SSH service on a standard SSH port. The camera's existing
# HTTP and RTSP ports remain unchanged so the port-profile Jaccard stays
# above the 0.6 threshold; only the protocol mismatch check catches this.
#
# References:
#   CVE-2024-7029 (AVTECH IP Camera, 2024) — CVSS 8.7, command injection
#     actively exploited to enroll devices in Mirai-variant botnets.
#     CISA KEV listed September 2024.
#   CVE-2023-1389 (TP-Link Archer AX21, 2023) — CVSS 8.8, unauthenticated
#     command injection used in Mirai botnet campaigns.
#
# PeerStore path:
#   Port profile: Jaccard([80,554], [22,80,554]) = 2/3 ≈ 0.67 > 0.6 → NO alert.
#   Port 22 is new (not shared) → service_type_changed does not fire.
#   _check_port_protocol_mismatches sees port 22 with "http-bot" ∉ {"ssh"} → fires.
#
# This scenario demonstrates that port_protocol_mismatch catches a stealthy
# port addition that the Jaccard threshold alone would miss.
#
# Score breakdown:
#   port_protocol_mismatch (port 22, ssh expected, http-bot seen)  +3.0
#   ───────────────────────────────────────────────────────────────────
#   Total                                                            3.0
# ---------------------------------------------------------------------------


class TestIoTBotnetEnrollment:
    MAC = "00:11:22:33:44:55"
    IP = "192.168.1.70"

    @pytest.fixture
    def store(self):
        return PeerStore()

    @pytest.fixture
    def camera_baseline(self):
        return scan(
            mac=self.MAC,
            ip=self.IP,
            os="Linux",
            os_candidates={"Linux": 90},
            ports=[80, 554],
            services={80: "http-lighttpd", 554: "rtsp-Real"},
        )

    def test_warmup_produces_zero_suspicion(self, store, camera_baseline):
        peer = warm_up(store, camera_baseline)
        assert peer.suspicion_score == pytest.approx(0.0)

    def test_new_backdoor_port_crosses_threshold(self, store, camera_baseline):
        warm_up(store, camera_baseline)

        # Mirai implant opens port 22 running HTTP (not SSH)
        compromised = scan(
            mac=self.MAC,
            ip=self.IP,
            os="Linux",
            os_candidates={"Linux": 90},
            ports=[22, 80, 554],
            services={22: "http-bot", 80: "http-lighttpd", 554: "rtsp-Real"},
        )
        peer = store.add_or_update_peer(compromised)

        assert peer.suspicion_score == pytest.approx(3.0)
        assert_score_above(peer)

    def test_jaccard_alone_would_not_alert(self, store, camera_baseline):
        """Port Jaccard = 0.67 > threshold — the mismatch check is the only signal."""
        warm_up(store, camera_baseline)

        compromised = scan(
            mac=self.MAC,
            ip=self.IP,
            os="Linux",
            os_candidates={"Linux": 90},
            ports=[22, 80, 554],
            services={22: "http-bot", 80: "http-lighttpd", 554: "rtsp-Real"},
        )
        peer = store.add_or_update_peer(compromised)

        assert_events_not_fired(peer, "port_profile_changed")
        assert_events_fired(peer, "port_protocol_mismatch")

    def test_mismatch_event_identifies_port(self, store, camera_baseline):
        warm_up(store, camera_baseline)

        compromised = scan(
            mac=self.MAC,
            ip=self.IP,
            os="Linux",
            os_candidates={"Linux": 90},
            ports=[22, 80, 554],
            services={22: "http-bot", 80: "http-lighttpd", 554: "rtsp-Real"},
        )
        peer = store.add_or_update_peer(compromised)

        assert_event_details(peer, "port_protocol_mismatch", port=22, actual="http-bot")


# ---------------------------------------------------------------------------
# Scenario H — Network Appliance Incremental Compromise (Multi-Scan)
#
# Attack: A network firewall is compromised via a zero-day. The attacker's
# footprint expands across three successive nmap scans, each adding evidence:
#   Scan 1 — OS fingerprint shifts from Cisco to Linux (attacker installs tools)
#   Scan 2 — Port profile changes (management port dropped, backdoor port added)
#   Scan 3 — SSH daemon replaced with C2 beacon on port 22 (threshold crossed)
#
# This scenario is unique: no single scan crosses the threshold; suspicion
# accumulates incrementally, demonstrating PeerWatch's temporal scoring model.
#
# References:
#   CVE-2024-3400 (Palo Alto PAN-OS, 2024) — CVSS 10.0, OS command injection
#     in GlobalProtect. Actively exploited; CISA Emergency Directive 24-02.
#     Post-exploitation: attacker deploys Python backdoor (UPSTYLE), manipulates
#     OS-visible services.
#   CVE-2023-20198 (Cisco IOS XE, 2023) — CVSS 10.0, web UI privilege escalation.
#     Attacker creates local accounts, installs implant; device fingerprint shifts.
#
# Score progression (all post-warmup):
#   After scan 1: os_family_changed                 +2.0  → 2.0 (below threshold)
#   After scan 2: port_profile_changed               +0.5  → 2.5 (below threshold)
#   After scan 3: service_type_changed + port_mismatch +4.0 → 6.5 (threshold crossed)
# ---------------------------------------------------------------------------


class TestNetworkApplianceIncrementalCompromise:
    MAC = "11:22:33:44:55:66"
    IP = "192.168.1.80"

    @pytest.fixture
    def store(self):
        return PeerStore()

    @pytest.fixture
    def cisco_baseline(self):
        return scan(
            mac=self.MAC,
            ip=self.IP,
            os="Cisco",
            os_candidates={"Cisco": 95},
            ports=[22, 80, 443],
            services={22: "ssh-OpenSSH", 80: "http-IOS", 443: "https-IOS"},
        )

    def test_warmup_produces_zero_suspicion(self, store, cisco_baseline):
        peer = warm_up(store, cisco_baseline)
        assert peer.suspicion_score == pytest.approx(0.0)

    def test_scan1_os_shift_below_threshold(self, store, cisco_baseline):
        """OS fingerprint change alone: 2.0 — suspicious but not conclusive."""
        warm_up(store, cisco_baseline)

        scan1 = scan(
            mac=self.MAC, ip=self.IP,
            os="Linux", os_candidates={"Linux": 90},
            ports=[22, 80, 443],
            services={22: "ssh-OpenSSH", 80: "http-IOS", 443: "https-IOS"},
        )
        peer = store.add_or_update_peer(scan1)

        assert peer.suspicion_score == pytest.approx(2.0)
        assert_score_below(peer)
        assert_events_fired(peer, "os_family_changed")

    def test_scan2_port_change_still_below_threshold(self, store, cisco_baseline):
        """After OS shift + port change: 2.5 — still below threshold."""
        warm_up(store, cisco_baseline)

        scan1 = scan(
            mac=self.MAC, ip=self.IP,
            os="Linux", os_candidates={"Linux": 90},
            ports=[22, 80, 443],
            services={22: "ssh-OpenSSH", 80: "http-IOS", 443: "https-IOS"},
        )
        store.add_or_update_peer(scan1)

        scan2 = scan(
            mac=self.MAC, ip=self.IP,
            os="Linux", os_candidates={"Linux": 90},
            ports=[22, 443, 4444],
            services={22: "ssh-OpenSSH", 443: "https-IOS", 4444: "tcpwrapped"},
        )
        peer = store.add_or_update_peer(scan2)

        assert peer.suspicion_score == pytest.approx(2.5)
        assert_score_below(peer)
        assert_events_fired(peer, "port_profile_changed")

    def test_scan3_backdoor_crosses_threshold(self, store, cisco_baseline):
        """Third scan activates backdoor: threshold crossed, investigation triggered."""
        warm_up(store, cisco_baseline)

        scan1 = scan(
            mac=self.MAC, ip=self.IP,
            os="Linux", os_candidates={"Linux": 90},
            ports=[22, 80, 443],
            services={22: "ssh-OpenSSH", 80: "http-IOS", 443: "https-IOS"},
        )
        store.add_or_update_peer(scan1)

        scan2 = scan(
            mac=self.MAC, ip=self.IP,
            os="Linux", os_candidates={"Linux": 90},
            ports=[22, 443, 4444],
            services={22: "ssh-OpenSSH", 443: "https-IOS", 4444: "tcpwrapped"},
        )
        store.add_or_update_peer(scan2)

        scan3 = scan(
            mac=self.MAC, ip=self.IP,
            os="Linux", os_candidates={"Linux": 90},
            ports=[22, 443, 4444],
            services={22: "http-c2agent", 443: "https-IOS", 4444: "tcpwrapped"},
        )
        peer = store.add_or_update_peer(scan3)

        assert peer.suspicion_score == pytest.approx(6.5)
        assert_score_above(peer)

    def test_all_three_event_types_appear(self, store, cisco_baseline):
        warm_up(store, cisco_baseline)

        scan1 = scan(mac=self.MAC, ip=self.IP, os="Linux", os_candidates={"Linux": 90},
                     ports=[22, 80, 443], services={22: "ssh-OpenSSH", 80: "http-IOS", 443: "https-IOS"})
        store.add_or_update_peer(scan1)

        scan2 = scan(mac=self.MAC, ip=self.IP, os="Linux", os_candidates={"Linux": 90},
                     ports=[22, 443, 4444], services={22: "ssh-OpenSSH", 443: "https-IOS", 4444: "tcpwrapped"})
        store.add_or_update_peer(scan2)

        scan3 = scan(mac=self.MAC, ip=self.IP, os="Linux", os_candidates={"Linux": 90},
                     ports=[22, 443, 4444], services={22: "http-c2agent", 443: "https-IOS", 4444: "tcpwrapped"})
        peer = store.add_or_update_peer(scan3)

        assert_events_fired(
            peer,
            "os_family_changed",       # scan 1
            "port_profile_changed",    # scan 2
            "service_type_changed",    # scan 3
            "port_protocol_mismatch",  # scan 3
        )


# ---------------------------------------------------------------------------
# Scenario I — Service Mimicry Evasion (negative / detection limit)
#
# Attack: A sophisticated attacker with root access replaces the OpenSSH
# daemon with Dropbear SSH — a minimal alternative that also identifies as
# SSH on port 22. nmap reports "ssh-Dropbear" instead of "ssh-OpenSSH".
# The service TYPE ("ssh") remains the same, so PeerWatch cannot detect this.
#
# This scenario documents a deliberate detection limit: PeerWatch checks
# protocol TYPE (the first token of the nmap service string), not the
# specific implementation. An attacker who substitutes a same-protocol
# implementation evades detection entirely.
#
# References:
#   CVE-2024-3094 (XZ Utils / liblzma backdoor, 2024) — the backdoor was
#     injected into sshd via a compromised upstream dependency. The patched
#     sshd still identified as SSH, rendering nmap-based detection ineffective.
#     This is precisely the evasion demonstrated here.
#   MITRE ATT&CK T1036.004 — Masquerading: Masquerade Task or Service.
#     Attacker uses a legitimate service name/protocol to avoid detection rules
#     that check for unexpected protocol types.
#
# Score: 0.0 — PeerWatch does not detect this change.
# Mitigation (Phase 2): passive packet capture (tcpdump) and banner/version
# analysis would catch the implementation change even when the type matches.
# ---------------------------------------------------------------------------


class TestServiceMimicryEvasion:
    MAC = "22:33:44:55:66:77"
    IP = "192.168.1.90"

    @pytest.fixture
    def store(self):
        return PeerStore()

    @pytest.fixture
    def linux_baseline(self):
        return scan(
            mac=self.MAC,
            ip=self.IP,
            os="Linux",
            os_candidates={"Linux": 96},
            ports=[22, 80],
            services={22: "ssh-OpenSSH", 80: "http-Apache"},
        )

    def test_warmup_produces_zero_suspicion(self, store, linux_baseline):
        peer = warm_up(store, linux_baseline)
        assert peer.suspicion_score == pytest.approx(0.0)

    def test_dropbear_replacement_undetected(self, store, linux_baseline):
        """Replacing OpenSSH with Dropbear: same protocol type → score stays 0."""
        warm_up(store, linux_baseline)

        # Dropbear SSH: type is still "ssh" — PeerWatch cannot distinguish
        with_dropbear = scan(
            mac=self.MAC,
            ip=self.IP,
            os="Linux",
            os_candidates={"Linux": 96},
            ports=[22, 80],
            services={22: "ssh-Dropbear", 80: "http-Apache"},
        )
        peer = store.add_or_update_peer(with_dropbear)

        assert peer.suspicion_score == pytest.approx(0.0)
        assert_score_below(peer, threshold=THRESHOLD)

    def test_no_events_fired(self, store, linux_baseline):
        warm_up(store, linux_baseline)

        with_dropbear = scan(
            mac=self.MAC,
            ip=self.IP,
            os="Linux",
            os_candidates={"Linux": 96},
            ports=[22, 80],
            services={22: "ssh-Dropbear", 80: "http-Apache"},
        )
        peer = store.add_or_update_peer(with_dropbear)

        assert_events_not_fired(
            peer, "service_type_changed", "port_protocol_mismatch",
            "os_family_changed", "port_profile_changed",
        )

    def test_contrast_with_overt_replacement(self, store, linux_baseline):
        """Same scenario but attacker uses http-c2agent — that IS detected."""
        warm_up(store, linux_baseline)

        overt_backdoor = scan(
            mac=self.MAC,
            ip=self.IP,
            os="Linux",
            os_candidates={"Linux": 96},
            ports=[22, 80],
            services={22: "http-c2agent", 80: "http-Apache"},
        )
        peer = store.add_or_update_peer(overt_backdoor)

        assert_score_above(peer)
        assert_events_fired(peer, "port_protocol_mismatch")
