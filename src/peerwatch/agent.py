import json
import logging
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import xmltodict
from langchain.chat_models import init_chat_model
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel

from peerwatch.parser import NmapParser
from peerwatch.peer_store import Peer, PeerStore

DEFAULT_SUSPICION_THRESHOLD = 3.0
DEFAULT_MODEL = "phi4-mini:latest"
_ANALYSIS_SYSTEM_PROMPT = ""

with open("./prompts/suspicious_agent.txt") as f:
    _ANALYSIS_SYSTEM_PROMPT = f.read()


class ScanRecommendation(BaseModel):
    type: str  # "nmap" | "traceroute" | "tcpdump"
    reason: str


class AgentDecision(BaseModel):
    explanation: str
    severity: str
    recommended_scans: list[ScanRecommendation]
    recommended_actions: list[str]


class ScanResult(BaseModel):
    type: str
    output: str
    error: str | None = None


class InvestigationReport(BaseModel):
    peer_id: str
    mac_address: str | None
    ips: list[str]
    suspicion_score: float
    timestamp: datetime
    severity: str
    explanation: str
    recommended_scans: list[ScanRecommendation]
    scan_results: list[ScanResult]
    recommended_actions: list[str]


class SuspiciousAgent:
    """
    Investigates peers whose suspicion_score crosses a threshold.

    For each suspicious peer:
      1. Formats event history + fingerprint into a prompt
      2. Asks an LLM to explain what happened and recommend scans
      3. Executes recommended scans (nmap/traceroute/tcpdump)
      4. Writes a JSON investigation report to output_dir
    """

    def __init__(
        self,
        peer_store: PeerStore,
        output_dir: str = "./reports",
        model: str = DEFAULT_MODEL,
        threshold: float = DEFAULT_SUSPICION_THRESHOLD,
    ):
        self.peer_store = peer_store
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.threshold = threshold
        self.llm = init_chat_model(model, model_provider="ollama", temperature=0)

    # --------------------
    # Public API
    # --------------------

    def investigate_all(self) -> list[InvestigationReport]:
        """Run investigation on every peer above the suspicion threshold."""
        suspicious = [
            p
            for p in self.peer_store.peers.values()
            if p.suspicion_score >= self.threshold
        ]
        if not suspicious:
            print("No suspicious peers found.")
        return [self.investigate(peer) for peer in suspicious]

    def investigate(self, peer: Peer) -> InvestigationReport:
        """Full investigation pipeline for a single peer."""
        print(
            f"Investigating peer {peer.mac_address or peer.internal_id[:8]} "
            f"(score={peer.suspicion_score:.1f})"
        )

        decision = self._analyse(peer)

        # Always run cryptographic identity checks for peers with SSH/HTTPS ports
        # open — these catch service-mimicry evasion that LLM may not know to request.
        auto_checks = self._build_auto_identity_checks(peer, decision.recommended_scans)
        all_recs = list(decision.recommended_scans) + auto_checks
        scan_results = self._execute_scans(peer, all_recs)

        report = InvestigationReport(
            peer_id=peer.internal_id,
            mac_address=peer.mac_address,
            ips=list(peer.ips),
            suspicion_score=peer.suspicion_score,
            timestamp=datetime.now(timezone.utc),
            severity=decision.severity,
            explanation=decision.explanation,
            recommended_scans=decision.recommended_scans,
            scan_results=scan_results,
            recommended_actions=decision.recommended_actions,
        )

        path = self._write_report(report)
        print(f"  [{report.severity.upper()}] → {path}")
        return report

    # --------------------
    # LLM analysis
    # --------------------

    def _analyse(self, peer: Peer) -> AgentDecision:
        context = self._format_peer_context(peer)
        messages = [
            SystemMessage(content=_ANALYSIS_SYSTEM_PROMPT),
            HumanMessage(content=context),
        ]
        try:
            raw = self.llm.invoke(messages).content.strip()
            data = json.loads(_strip_code_fence(raw))
            return AgentDecision(
                explanation=data["explanation"],
                severity=data.get("severity", "medium"),
                recommended_scans=[
                    ScanRecommendation(**s) for s in data.get("recommended_scans", [])
                ],
                recommended_actions=data.get("recommended_actions", []),
            )
        except Exception as e:
            logging.warning(f"LLM analysis failed for {peer.internal_id}: {e}")
            return AgentDecision(
                explanation="Automated analysis failed — manual review required.",
                severity="medium",
                recommended_scans=[
                    ScanRecommendation(
                        type="nmap", reason="Verify current device state"
                    )
                ],
                recommended_actions=["Review peer event history manually"],
            )

    def _format_peer_context(self, peer: Peer) -> str:
        known_svc_lines = "\n".join(
            f"  port {port}: {', '.join(sorted(svcs))}"
            for port, svcs in sorted(peer.known_services.items())
        )
        event_lines = "\n".join(
            f"  [{e.timestamp.strftime('%H:%M:%S')}] {e.event} {e.details}"
            for e in peer.identity_history
        )
        m = peer.metadata
        return (
            f"MAC: {peer.mac_address or 'unknown'}\n"
            f"IPs: {', '.join(sorted(peer.ips))}\n"
            f"Suspicion score: {peer.suspicion_score}\n"
            f"Is volatile (no confirmed MAC): {peer.is_volatile}\n"
            f"\nCurrent fingerprint:\n"
            f"  OS: {m.os}  version: {m.os_version}  distribution: {m.distribution}\n"
            f"  OS candidates: {m.os_candidates}\n"
            f"  Device vendor (MAC OUI): {m.device_vendor}\n"
            f"  Open ports: {m.open_ports}\n"
            f"  Services: {dict(m.services)}\n"
            f"\nAll service types ever seen per port:\n{known_svc_lines or '  (none)'}\n"
            f"\nEvent history:\n{event_lines or '  (none)'}"
        )

    # --------------------
    # Scan execution
    # --------------------

    def _build_auto_identity_checks(
        self, peer: Peer, already_recommended: list[ScanRecommendation]
    ) -> list[ScanRecommendation]:
        """Return ssh_hostkey / ssl_cert recommendations for open ports not already covered."""
        recommended_types = {r.type for r in already_recommended}
        extra: list[ScanRecommendation] = []

        ssh_ports = [
            p for p, svc in peer.metadata.services.items()
            if isinstance(svc, str) and svc.lower().startswith("ssh")
        ] or ([22] if 22 in peer.metadata.open_ports else [])

        ssl_ports = [
            p for p, svc in peer.metadata.services.items()
            if isinstance(svc, str) and any(k in svc.lower() for k in ("https", "ssl", "tls"))
        ] or ([443] if 443 in peer.metadata.open_ports else [])

        if ssh_ports and "ssh_hostkey" not in recommended_types:
            extra.append(
                ScanRecommendation(
                    type="ssh_hostkey",
                    reason="Auto: verify SSH host key has not changed (service-mimicry check)",
                )
            )
        if ssl_ports and "ssl_cert" not in recommended_types:
            extra.append(
                ScanRecommendation(
                    type="ssl_cert",
                    reason="Auto: verify SSL/TLS certificate has not changed (identity anchor)",
                )
            )
        return extra

    def _execute_scans(
        self, peer: Peer, recommendations: list[ScanRecommendation]
    ) -> list[ScanResult]:
        target = self._pick_target_ip(peer)
        if not target:
            logging.warning(
                f"No IP available for peer {peer.internal_id}, skipping scans"
            )
            return []

        results = []
        for rec in recommendations:
            match rec.type:
                case "nmap":
                    result = self._run_nmap(target, peer)
                case "traceroute":
                    result = self._run_traceroute(target)
                case "tcpdump":
                    result = self._run_tcpdump(target)
                case "ssh_hostkey":
                    result = self._run_ssh_hostkey(target, peer)
                case "ssl_cert":
                    result = self._run_ssl_cert(target, peer)
                case _:
                    logging.warning(f"Unknown scan type requested: {rec.type}")
                    continue
            results.append(result)
        return results

    def _run_nmap(self, ip: str, peer: Peer) -> ScanResult:
        """Re-scan and feed any new results back into PeerStore."""
        try:
            proc = subprocess.run(
                ["nmap", "-sV", "-O", "--osscan-guess", "-oX", "-", ip],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode != 0:
                return ScanResult(type="nmap", output=proc.stdout, error=proc.stderr)

            # Parse and re-ingest so PeerStore stays current
            hosts = xmltodict.parse(proc.stdout).get("nmaprun", {}).get("host", [])
            if isinstance(hosts, dict):
                hosts = [hosts]
            for host in hosts:
                try:
                    data = NmapParser(host).parse()
                    self.peer_store.add_or_update_peer(data)
                except Exception as parse_err:
                    logging.warning(f"Could not re-ingest nmap result: {parse_err}")

            return ScanResult(type="nmap", output=proc.stdout)
        except subprocess.TimeoutExpired:
            return ScanResult(type="nmap", output="", error="scan timed out after 120s")
        except FileNotFoundError:
            return ScanResult(type="nmap", output="", error="nmap not found in PATH")
        except Exception as e:
            return ScanResult(type="nmap", output="", error=str(e))

    def _run_ssh_hostkey(self, ip: str, peer: Peer) -> ScanResult:
        """Fetch SSH host key fingerprints and compare against stored baseline."""
        ssh_ports = [
            p for p, svc in peer.metadata.services.items()
            if isinstance(svc, str) and svc.lower().startswith("ssh")
        ] or ([22] if 22 in peer.metadata.open_ports else [22])
        port_arg = ",".join(str(p) for p in ssh_ports)

        try:
            proc = subprocess.run(
                ["nmap", "-p", port_arg, "--script", "ssh-hostkey", "-oX", "-", ip],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if proc.returncode != 0:
                return ScanResult(
                    type="ssh_hostkey", output=proc.stdout, error=proc.stderr
                )

            changed_ports: list[int] = []
            try:
                nmaprun = xmltodict.parse(proc.stdout).get("nmaprun", {})
                hosts = nmaprun.get("host", [])
                if isinstance(hosts, dict):
                    hosts = [hosts]
                for host in hosts:
                    ports_data = (host.get("ports") or {}).get("port", [])
                    if isinstance(ports_data, dict):
                        ports_data = [ports_data]
                    for port_data in ports_data:
                        portid = int(port_data.get("@portid", 0))
                        if not portid:
                            continue
                        scripts = port_data.get("script", [])
                        if isinstance(scripts, dict):
                            scripts = [scripts]
                        for script in scripts:
                            if script.get("@id") != "ssh-hostkey":
                                continue
                            output = script.get("@output", "")
                            fps = _parse_ssh_fingerprints(output)
                            if fps:
                                prev = peer.ssh_host_keys.get(portid)
                                self.peer_store.ingest_ssh_hostkeys(ip, portid, fps)
                                if prev and prev != sorted(fps):
                                    changed_ports.append(portid)
            except Exception as parse_err:
                logging.warning(f"ssh_hostkey parse error: {parse_err}")

            annotation = (
                f" [KEY CHANGED on ports {changed_ports}]" if changed_ports else ""
            )
            return ScanResult(type="ssh_hostkey", output=proc.stdout + annotation)
        except subprocess.TimeoutExpired:
            return ScanResult(
                type="ssh_hostkey", output="", error="timed out after 60s"
            )
        except FileNotFoundError:
            return ScanResult(
                type="ssh_hostkey", output="", error="nmap not found in PATH"
            )
        except Exception as e:
            return ScanResult(type="ssh_hostkey", output="", error=str(e))

    def _run_ssl_cert(self, ip: str, peer: Peer) -> ScanResult:
        """Fetch SSL/TLS certificate fingerprints and compare against stored baseline."""
        ssl_ports = [
            p for p, svc in peer.metadata.services.items()
            if isinstance(svc, str)
            and any(k in svc.lower() for k in ("https", "ssl", "tls"))
        ] or ([443] if 443 in peer.metadata.open_ports else [443])
        port_arg = ",".join(str(p) for p in ssl_ports)

        try:
            proc = subprocess.run(
                ["nmap", "-p", port_arg, "--script", "ssl-cert", "-oX", "-", ip],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if proc.returncode != 0:
                return ScanResult(
                    type="ssl_cert", output=proc.stdout, error=proc.stderr
                )

            changed_ports: list[int] = []
            try:
                nmaprun = xmltodict.parse(proc.stdout).get("nmaprun", {})
                hosts = nmaprun.get("host", [])
                if isinstance(hosts, dict):
                    hosts = [hosts]
                for host in hosts:
                    ports_data = (host.get("ports") or {}).get("port", [])
                    if isinstance(ports_data, dict):
                        ports_data = [ports_data]
                    for port_data in ports_data:
                        portid = int(port_data.get("@portid", 0))
                        if not portid:
                            continue
                        scripts = port_data.get("script", [])
                        if isinstance(scripts, dict):
                            scripts = [scripts]
                        for script in scripts:
                            if script.get("@id") != "ssl-cert":
                                continue
                            output = script.get("@output", "")
                            fp = _parse_ssl_cert_fingerprint(output)
                            if fp:
                                prev = peer.ssl_cert_fingerprints.get(portid)
                                self.peer_store.ingest_ssl_cert(ip, portid, fp)
                                if prev and prev != fp:
                                    changed_ports.append(portid)
            except Exception as parse_err:
                logging.warning(f"ssl_cert parse error: {parse_err}")

            annotation = (
                f" [CERT CHANGED on ports {changed_ports}]" if changed_ports else ""
            )
            return ScanResult(type="ssl_cert", output=proc.stdout + annotation)
        except subprocess.TimeoutExpired:
            return ScanResult(type="ssl_cert", output="", error="timed out after 60s")
        except FileNotFoundError:
            return ScanResult(
                type="ssl_cert", output="", error="nmap not found in PATH"
            )
        except Exception as e:
            return ScanResult(type="ssl_cert", output="", error=str(e))

    def _run_traceroute(self, ip: str) -> ScanResult:
        try:
            proc = subprocess.run(
                ["traceroute", "-n", ip],
                capture_output=True,
                text=True,
                timeout=60,
            )
            return ScanResult(
                type="traceroute",
                output=proc.stdout,
                error=proc.stderr or None,
            )
        except subprocess.TimeoutExpired:
            return ScanResult(type="traceroute", output="", error="timed out after 60s")
        except FileNotFoundError:
            return ScanResult(
                type="traceroute", output="", error="traceroute not found in PATH"
            )
        except Exception as e:
            return ScanResult(type="traceroute", output="", error=str(e))

    def _run_tcpdump(self, ip: str) -> ScanResult:
        """Capture 50 packets from the target. Requires root/CAP_NET_RAW."""
        try:
            proc = subprocess.run(
                ["tcpdump", "-i", "any", "-c", "50", "-nn", "host", ip],
                capture_output=True,
                text=True,
                timeout=30,
            )
            # tcpdump writes summary to stderr
            output = (proc.stdout + proc.stderr).strip()
            return ScanResult(type="tcpdump", output=output)
        except subprocess.TimeoutExpired:
            return ScanResult(type="tcpdump", output="", error="timed out after 30s")
        except FileNotFoundError:
            return ScanResult(
                type="tcpdump", output="", error="tcpdump not found in PATH"
            )
        except Exception as e:
            return ScanResult(type="tcpdump", output="", error=str(e))

    # --------------------
    # Report output
    # --------------------

    def _write_report(self, report: InvestigationReport) -> Path:
        mac_slug = (report.mac_address or "unknown").replace(":", "")
        ts_slug = report.timestamp.strftime("%Y%m%d_%H%M%S")
        path = self.output_dir / f"investigation_{mac_slug}_{ts_slug}.json"
        with open(path, "w") as f:
            json.dump(report.model_dump(mode="json"), f, indent=2, default=str)
        logging.info(f"Report written: {path}")
        return path

    @staticmethod
    def _pick_target_ip(peer: Peer) -> str | None:
        """Prefer IPv4; fall back to IPv6."""
        ipv4 = [ip for ip in peer.ips if "." in ip]
        ipv6 = [ip for ip in peer.ips if ":" in ip]
        return (ipv4 or ipv6 or [None])[0]


def _parse_ssh_fingerprints(script_output: str) -> list[str]:
    """Extract SHA256 fingerprints from nmap ssh-hostkey script output text.

    nmap emits lines like: ``2048 SHA256:AbCdEf... (RSA)``
    """
    return sorted(re.findall(r"SHA256:[A-Za-z0-9+/=]+", script_output))


def _parse_ssl_cert_fingerprint(script_output: str) -> str | None:
    """Extract the SHA-256 certificate fingerprint from nmap ssl-cert script output.

    nmap emits a line like: ``SHA-256: aa:bb:cc:...`` (colon-separated hex bytes).
    Returns the fingerprint as a lowercase hex string without colons, or None.
    """
    m = re.search(r"SHA-256:\s*([0-9a-fA-F:]+)", script_output)
    if not m:
        return None
    return m.group(1).replace(":", "").lower()


def _strip_code_fence(text: str) -> str:
    """Remove markdown code fences that some models wrap JSON in."""
    if text.startswith("```"):
        lines = text.splitlines()
        # drop first line (``` or ```json) and last line (```)
        return "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    return text
