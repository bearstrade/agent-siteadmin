from types import SimpleNamespace

from siteadmin import gateway
from siteadmin.gateway import OperationGateway
from siteadmin.state import State


def test_l2_requires_one_time_confirmation(tmp_path, monkeypatch):
    state = State(tmp_path / "state")
    service_result = SimpleNamespace(returncode=0, stdout="restarted", stderr="")
    monkeypatch.setattr(gateway, "_run", lambda *args, **kwargs: service_result)
    engine = OperationGateway(state)

    preview = engine.execute("service_restart", {"service": "nginx"}, dry_run=True)
    token = preview["confirm_token"]
    assert preview["data"]["plan"]["service"] == "nginx"
    assert engine.execute("service_restart", {"service": "nginx"})["error"]["code"] == "confirm_required"
    assert engine.execute("service_restart", {"service": "nginx"}, confirm_token=token)["ok"] is True
    assert engine.execute("service_restart", {"service": "nginx"}, confirm_token=token)["error"]["code"] == "invalid_confirm_token"


def test_gateway_rejects_unknown_and_invalid_operations(tmp_path):
    engine = OperationGateway(State(tmp_path / "state"))

    assert engine.execute("shell", {})["error"]["code"] == "unknown_operation"
    assert engine.execute("logs_tail", {"service": "arbitrary"})["error"]["code"] == "invalid_service"
    assert engine.execute("config_apply", {"path": "/etc/passwd", "content": "x"})["error"]["code"] == "invalid_config_path"


def test_logs_are_masked_and_limited(tmp_path, monkeypatch):
    result = SimpleNamespace(returncode=0, stdout="token=secret password=hunter2 safe", stderr="")
    monkeypatch.setattr(gateway, "_run", lambda *args, **kwargs: result)
    engine = OperationGateway(State(tmp_path / "state"))

    value = engine.execute("logs_tail", {"service": "nginx", "lines": 100})

    assert value["ok"] is True
    assert "secret" not in value["data"]["lines"]
    assert "hunter2" not in value["data"]["lines"]
    assert value["data"]["lines"].count("[redacted]") == 2


def test_config_apply_rolls_back_when_post_verify_fails(tmp_path, monkeypatch):
    config_root = tmp_path / "nginx"
    config_root.mkdir()
    config_path = config_root / "site.conf"
    config_path.write_text("working", encoding="utf-8")
    monkeypatch.setattr(gateway, "CONFIG_ROOTS", (config_root,))
    monkeypatch.setattr(
        gateway, "_run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr="syntax error"),
    )
    engine = OperationGateway(State(tmp_path / "state"))

    preview = engine.execute("config_apply", {
        "path": str(config_path), "content": "broken",
    }, dry_run=True)
    result = engine.execute("config_apply", {
        "path": str(config_path), "content": "broken",
    }, confirm_token=preview["confirm_token"])

    assert result["ok"] is False
    assert result["rollback"]["used"] is True
    assert config_path.read_text(encoding="utf-8") == "working"
