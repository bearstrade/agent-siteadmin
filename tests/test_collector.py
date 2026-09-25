from siteadmin import collector
from siteadmin.collector import Collector
from siteadmin.state import State


def test_autocleanup_runs_once_per_day_and_is_exposed(monkeypatch, tmp_path):
    now = [100000.0]
    report = {
        "actions": [{"ok": True}], "freed_total": 42, "df_before": {}, "df_after": {},
        "duration_ms": 2, "skipped": [],
    }
    monkeypatch.setattr(collector.time, "time", lambda: now[0])
    monkeypatch.setattr(collector, "collect_telemetry", lambda previous: {"ts": "now", "disks": []})
    monkeypatch.setattr(collector, "detect", lambda current, previous: [])
    monkeypatch.setattr(collector.maintenance, "run_cleanup", lambda **kwargs: report)
    state = State(tmp_path / "state")
    engine = Collector(state, autoclean=True)

    value, events = engine.telemetry()
    assert len(events) == 1
    assert events[0]["type"] == "auto_cleanup"
    assert value["maintenance"]["last_cleanup"] == report

    now[0] += 3600
    engine.telemetry()
    assert state.read()["last_auto_cleanup"] == 100000.0

    now[0] += 86400
    engine.telemetry()
    assert state.read()["last_auto_cleanup"] == 190000.0