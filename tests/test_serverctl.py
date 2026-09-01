from types import SimpleNamespace

from siteadmin import gateway
from siteadmin.config import Config
from siteadmin.gateway import OperationGateway
from siteadmin.state import State
from siteadmin.uninstall import uninstall


def test_monitor_cannot_execute_serverctl_catalog(tmp_path):
    state = State(tmp_path / "state")
    state.update(module="monitor")
    result = OperationGateway(state).execute("package_install", {"package": "nginx"})
    assert result["error"]["code"] == "unknown_operation"


def test_serverctl_shell_requires_owner_toggle_and_masks_output(tmp_path, monkeypatch):
    state = State(tmp_path / "state")
    state.update(module="serverctl", access_enabled=True, shell_enabled=False)
    monkeypatch.setattr(gateway.os, "geteuid", lambda: 0)
    engine = OperationGateway(state)

    assert engine.execute("shell", {"command": "printf 'token=secret'"}, dry_run=True)["error"]["code"] == "shell_disabled"
    state.update(shell_enabled=True)
    monkeypatch.setattr(gateway, "_run", lambda *args, **kwargs: SimpleNamespace(
        returncode=0, stdout="token=secret", stderr=""))
    preview = engine.execute("shell", {"command": "printf 'token=secret'"}, dry_run=True)
    assert preview["data"]["plan"]["command"] == "printf 'token=[redacted]"
    result = engine.execute("shell", {"command": "printf 'token=secret'"}, confirm_token=preview["confirm_token"])
    assert result["data"]["output"] == "token=[redacted]"


def test_dangerous_shell_uses_one_time_confirmation(tmp_path, monkeypatch):
    state = State(tmp_path / "state")
    state.update(module="serverctl", access_enabled=True, shell_enabled=True)
    monkeypatch.setattr(gateway.os, "geteuid", lambda: 0)
    monkeypatch.setattr(gateway, "_run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="ok", stderr=""))
    engine = OperationGateway(state)
    preview = engine.execute("shell", {"command": "rm -rf /tmp/example"}, dry_run=True)
    assert preview["data"]["plan"]["dangerous"] is True
    assert engine.execute("shell", {"command": "rm -rf /tmp/example"})["error"]["code"] == "confirm_required"
    assert engine.execute("shell", {"command": "rm -rf /tmp/example"}, confirm_token=preview["confirm_token"])["ok"] is True


def test_uninstall_removes_only_serverctl_paths(tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    install_dir = tmp_path / "serverctl"
    state_dir.mkdir()
    install_dir.mkdir()
    config = Config(endpoint="https://hub.example", state_dir=state_dir,
                    local_token_file=state_dir / "local.token", module="serverctl",
                    install_dir=install_dir)
    monkeypatch.setattr("siteadmin.uninstall.os.geteuid", lambda: 0)
    calls = []
    result = uninstall(config, State(state_dir), runner=lambda *args, **kwargs: calls.append(args[0]))
    assert result["status"] == "uninstalled"
    assert not state_dir.exists()
    assert not install_dir.exists()
    assert calls == [("systemctl", "stop", "serverctl.service"), ("systemctl", "disable", "serverctl.service")]