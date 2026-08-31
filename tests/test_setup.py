import time

from siteadmin.gateway import OperationGateway
from siteadmin.setup import SetupError, setup_plan
from siteadmin.state import State


def active_state(tmp_path, privilege="root", session_id=7):
    state = State(tmp_path)
    state.update(setup_mode={"active": True, "session_id": session_id, "privilege": privilege,
                             "expires_at": time.time() + 600})
    return state


def test_setup_requires_live_session_and_matching_id(tmp_path):
    gateway = OperationGateway(State(tmp_path))
    result = gateway.execute("setup_ufw_rule", {"action": "allow", "port": "443"}, setup_session_id=7)
    assert result["error"]["code"] == "setup_required"
    state = active_state(tmp_path)
    result = OperationGateway(state).execute("setup_ufw_rule", {"action": "allow", "port": "443"}, setup_session_id=8)
    assert result["error"]["code"] == "setup_required"


def test_setup_blocklist_and_root_only_command(tmp_path):
    state = active_state(tmp_path, privilege="user_hosting")
    gateway = OperationGateway(state)
    result = gateway.execute("setup_run_cmd", {"command": "true"}, setup_session_id=7)
    assert result["error"]["code"] == "root_required"
    state.update(setup_mode={"active": True, "session_id": 7, "privilege": "root", "expires_at": time.time() + 600})
    result = gateway.execute("setup_run_cmd", {"command": "rm -rf /etc/passwd"}, setup_session_id=7)
    assert result["error"]["code"] == "blocked_command"


def test_setup_plan_allowlists_inputs(tmp_path):
    state = active_state(tmp_path)
    assert setup_plan("setup_install_pkg", {"packages": ["nginx", "certbot"]}, state)["packages"] == ["nginx", "certbot"]
    try:
        setup_plan("setup_install_pkg", {"packages": ["curl"]}, state)
    except SetupError as exc:
        assert exc.code == "invalid_package"
    else:
        raise AssertionError("unexpected package accepted")


def test_setup_start_and_expiry_are_atomic(tmp_path):
    state = State(tmp_path)
    from siteadmin.setup import setup_expire, setup_start, setup_status
    from datetime import datetime, timezone
    payload = {"session_id": 11, "privilege": "root",
               "expires_at": datetime.fromtimestamp(time.time() + 480 * 60 - 1, timezone.utc).isoformat()}
    assert setup_start(state, payload)["data"]["active"] is True
    assert setup_status(state)["active"] is True
    state.update(setup_mode={**state.read()["setup_mode"], "expires_at": time.time() - 1})
    assert setup_expire(state) is True
    assert setup_status(state)["active"] is False
