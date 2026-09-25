from types import SimpleNamespace

from siteadmin import maintenance
from siteadmin.maintenance import CleanupSettings


def test_dry_run_does_not_execute_commands(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(maintenance.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(maintenance, "_run", lambda command: calls.append(command))
    monkeypatch.setattr(maintenance, "_disk_usage", lambda: {
        "mount": "/", "total_bytes": 1000, "used_bytes": 500, "available_bytes": 500, "used_percent": 50,
    })

    report = maintenance.run_cleanup(dry_run=True, settings=CleanupSettings())

    assert calls == []
    assert report["freed_total"] == 0
    assert report["df_before"] == report["df_after"]
    assert report["actions"]


def test_missing_tools_are_reported_as_skipped(monkeypatch):
    monkeypatch.setattr(maintenance.shutil, "which", lambda name: None)
    monkeypatch.setattr(maintenance, "_disk_usage", lambda: {
        "mount": "/", "total_bytes": 1000, "used_bytes": 500, "available_bytes": 500, "used_percent": 50,
    })

    report = maintenance.run_cleanup(dry_run=True)

    skipped = {item["id"] for item in report["skipped"]}
    assert {"journal", "package_cache", "docker"}.issubset(skipped)


def test_command_freed_bytes_are_reported(monkeypatch):
    monkeypatch.setattr(maintenance.shutil, "which", lambda name: "/usr/bin/" + name if name == "journalctl" else None)
    usages = iter([
        {"mount": "/", "total_bytes": 1000, "used_bytes": 900, "available_bytes": 100, "used_percent": 90},
        {"mount": "/", "total_bytes": 1000, "used_bytes": 900, "available_bytes": 100, "used_percent": 90},
        {"mount": "/", "total_bytes": 1000, "used_bytes": 700, "available_bytes": 300, "used_percent": 70},
        {"mount": "/", "total_bytes": 1000, "used_bytes": 700, "available_bytes": 300, "used_percent": 70},
    ])
    monkeypatch.setattr(maintenance, "_disk_usage", lambda: next(usages))
    monkeypatch.setattr(maintenance, "_run", lambda command: SimpleNamespace(returncode=0, stdout="vacuumed", stderr=""))

    report = maintenance.run_cleanup(settings=CleanupSettings())

    assert report["actions"][0]["ok"] is True
    assert report["actions"][0]["freed_bytes"] == 200
    assert report["freed_total"] == 200