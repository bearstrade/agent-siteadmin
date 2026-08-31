"""Оркестрация profile, security scan, telemetry и событий."""

from . import __version__
from .events import detect
from .security_scan import scan
from .system_profile import collect as collect_profile
from .telemetry import collect as collect_telemetry


class Collector:
    def __init__(self, state):
        self.state = state

    def profile(self):
        previous = self.state.read().get("security_state")
        findings, security_state = scan(previous)
        profile = collect_profile()
        self.state.update(security_state=security_state, profile_sent=True)
        return {"profile": {"agent_version": __version__, **profile}, "findings": findings}

    def telemetry(self):
        previous = self.state.read().get("telemetry", {})
        value = collect_telemetry(previous)
        events = detect(value, previous)
        self.state.update(telemetry=value)
        return value, events

    def scan(self):
        findings, security_state = scan(self.state.read().get("security_state"))
        self.state.update(security_state=security_state)
        return {"profile": {"agent_version": __version__, **collect_profile()}, "findings": findings}
