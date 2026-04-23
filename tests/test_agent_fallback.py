"""Tests for SuspiciousAgent rule-based fallback (no Ollama required)."""

from unittest.mock import MagicMock, patch

import pytest

from peerwatch.agent import AgentDecision, SuspiciousAgent
from peerwatch.peer_store import PeerStore

from tests.simulation.factories import scan, warm_up


def _make_agent(tmp_path) -> SuspiciousAgent:
    store = PeerStore()
    with (
        patch("peerwatch.agent.init_chat_model"),
        patch("builtins.open", side_effect=lambda *a, **k: MagicMock(
            __enter__=lambda s: MagicMock(read=lambda: ""),
            __exit__=MagicMock(return_value=False),
        )),
    ):
        agent = SuspiciousAgent.__new__(SuspiciousAgent)
        agent.peer_store = store
        agent.output_dir = tmp_path
        agent.threshold = 3.0
        agent.llm = MagicMock(side_effect=Exception("Ollama unavailable"))
    return agent


class TestRuleBasedFallback:
    def _peer_with_score(self, score: float, events: list[str] | None = None):
        store = PeerStore()
        baseline = scan()
        peer = warm_up(store, baseline)
        peer.suspicion_score = score
        if events:
            from datetime import datetime, timezone
            from peerwatch.peer_store import IdentityEvent
            for event in events:
                peer.identity_history.append(
                    IdentityEvent(
                        timestamp=datetime.now(timezone.utc),
                        event=event,
                        details={},
                    )
                )
        return peer

    def test_score_above_7_gives_high_severity(self, tmp_path):
        agent = _make_agent(tmp_path)
        peer = self._peer_with_score(7.0)
        decision = agent._rule_based_fallback(peer)
        assert decision.severity == "high"

    def test_score_above_4_gives_medium_severity(self, tmp_path):
        agent = _make_agent(tmp_path)
        peer = self._peer_with_score(5.0)
        decision = agent._rule_based_fallback(peer)
        assert decision.severity == "medium"

    def test_score_below_4_gives_low_severity(self, tmp_path):
        agent = _make_agent(tmp_path)
        peer = self._peer_with_score(3.5)
        decision = agent._rule_based_fallback(peer)
        assert decision.severity == "low"

    def test_score_exactly_4_gives_medium(self, tmp_path):
        agent = _make_agent(tmp_path)
        peer = self._peer_with_score(4.0)
        decision = agent._rule_based_fallback(peer)
        assert decision.severity == "medium"

    def test_score_exactly_7_gives_high(self, tmp_path):
        agent = _make_agent(tmp_path)
        peer = self._peer_with_score(7.0)
        decision = agent._rule_based_fallback(peer)
        assert decision.severity == "high"

    def test_route_event_adds_traceroute_recommendation(self, tmp_path):
        agent = _make_agent(tmp_path)
        peer = self._peer_with_score(5.0, events=["route_changed"])
        decision = agent._rule_based_fallback(peer)
        types = {r.type for r in decision.recommended_scans}
        assert "traceroute" in types

    def test_ttl_event_adds_traceroute_recommendation(self, tmp_path):
        agent = _make_agent(tmp_path)
        peer = self._peer_with_score(5.0, events=["ttl_deviation"])
        decision = agent._rule_based_fallback(peer)
        types = {r.type for r in decision.recommended_scans}
        assert "traceroute" in types

    def test_arp_event_adds_tcpdump_recommendation(self, tmp_path):
        agent = _make_agent(tmp_path)
        peer = self._peer_with_score(5.0, events=["arp_spoofing_detected"])
        decision = agent._rule_based_fallback(peer)
        types = {r.type for r in decision.recommended_scans}
        assert "tcpdump" in types

    def test_no_special_events_only_nmap_recommended(self, tmp_path):
        agent = _make_agent(tmp_path)
        peer = self._peer_with_score(5.0, events=["os_family_changed"])
        decision = agent._rule_based_fallback(peer)
        types = {r.type for r in decision.recommended_scans}
        assert "nmap" in types
        assert "traceroute" not in types
        assert "tcpdump" not in types

    def test_fallback_explanation_contains_score(self, tmp_path):
        agent = _make_agent(tmp_path)
        peer = self._peer_with_score(6.5)
        decision = agent._rule_based_fallback(peer)
        assert "6.5" in decision.explanation

    def test_fallback_explanation_contains_rule_based_label(self, tmp_path):
        agent = _make_agent(tmp_path)
        peer = self._peer_with_score(4.0)
        decision = agent._rule_based_fallback(peer)
        assert "Rule-based" in decision.explanation or "fallback" in decision.explanation.lower()

    def test_always_includes_nmap_recommendation(self, tmp_path):
        agent = _make_agent(tmp_path)
        peer = self._peer_with_score(3.5)
        decision = agent._rule_based_fallback(peer)
        types = {r.type for r in decision.recommended_scans}
        assert "nmap" in types
