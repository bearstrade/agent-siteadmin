"""Безопасное удаление только модуля serverctl."""

import os
import shutil
import subprocess
from pathlib import Path


def uninstall(config, state, *, dry_run=False, runner=None):
    """Останавливает unit и удаляет только пути текущего модуля.

    Пути берутся из Config/State, поэтому тест может передать временный каталог.
    """
    if config.module != "serverctl":
        raise ValueError("uninstall доступен только для serverctl")
    unit = "serverctl.service"
    paths = [state.directory, config.install_dir, Path("/etc/serverctl"),
             Path("/usr/local/bin/serverctl"), Path("/etc/systemd/system/serverctl.service")]
    steps = [
        {"action": "stop", "unit": unit},
        {"action": "disable", "unit": unit},
        {"action": "remove", "path": str(config.install_dir)},
        {"action": "remove", "path": str(state.directory)},
        {"action": "remove", "path": "/etc/serverctl"},
        {"action": "remove", "path": "/usr/local/bin/serverctl"},
        {"action": "remove", "path": "/etc/systemd/system/serverctl.service"},
    ]
    if dry_run:
        return {"ok": True, "dry_run": True, "steps": steps}
    run = runner or subprocess.run
    if os.geteuid() != 0:
        raise PermissionError("serverctl uninstall требует root-привилегии")
    for action in ("stop", "disable"):
        run(("systemctl", action, unit), check=False, capture_output=True, text=True)
    for path in paths:
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
    return {"ok": True, "status": "uninstalled", "steps": steps}