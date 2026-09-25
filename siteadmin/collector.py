"""Оркестрация profile, security scan, telemetry и событий."""

import os
import time
from datetime import datetime, timezone

from . import __version__
from . import maintenance
from .events import detect
from .security_scan import scan
from .system_profile import collect as collect_profile
from .telemetry import collect as collect_telemetry


class Collector:
    def __init__(self, state, *, autoclean=None, cleanup_settings=None):
        self.state = state
        self.autoclean = (autoclean if autoclean is not None else
                          os.environ.get("SITEADMIN_AUTOCLEAN", "1").strip().lower() not in {"0", "false", "no"})
        self.cleanup_settings = cleanup_settings or maintenance.CleanupSettings.from_env()

    def _with_maintenance(self, profile):
        last_cleanup = self.state.read().get("last_cleanup")
        if last_cleanup:
            profile["maintenance"] = {"last_cleanup": last_cleanup}
        return profile

    def profile(self):
        previous = self.state.read().get("security_state")
        findings, security_state = scan(previous)
        profile = self._with_maintenance(collect_profile())
        self.state.update(security_state=security_state, profile_sent=True)
        return {"profile": {"agent_version": __version__, **profile}, "findings": findings}

    def telemetry(self):
        previous = self.state.read().get("telemetry", {})
        events = []
        last_auto_cleanup = float(self.state.read().get("last_auto_cleanup", 0) or 0)
        if self.autoclean and time.time() - last_auto_cleanup >= 86400:
            report = maintenance.run_cleanup(settings=self.cleanup_settings)
            report["completed_at"] = datetime.now(timezone.utc).isoformat()
            self.state.update(last_auto_cleanup=time.time(), last_cleanup=report)
            events.append({
                "type": "auto_cleanup",
                "severity": "info" if all(item.get("ok") for item in report["actions"]) else "warning",
                "payload": {"freed_total": report["freed_total"], "skipped": report["skipped"]},
            })
        value = collect_telemetry(previous)
        last_cleanup = self.state.read().get("last_cleanup")
        if last_cleanup:
            value["maintenance"] = {"last_cleanup": last_cleanup}
        events.extend(detect(value, previous))
        self.state.update(telemetry=value)
        return value, events

    def scan(self):
        findings, security_state = scan(self.state.read().get("security_state"))
        self.state.update(security_state=security_state)
        return {"profile": {"agent_version": __version__, **self._with_maintenance(collect_profile())}, "findings": findings}
