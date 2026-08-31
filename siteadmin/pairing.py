"""Первичное подключение агента по одноразовому pairing-коду."""

import json
import socket
from urllib import request

from . import __version__
from .config import Config
from .state import State


def pair(config: Config, state: State, code: str) -> dict:
    if not config.endpoint:
        raise ValueError("SITEADMIN_ENDPOINT не задан")
    payload = json.dumps({
        "pairing_code": code.strip(),
        "hostname": socket.gethostname(),
        "version": __version__,
        "agent_key": state.read().get("agent_id", ""),
    }).encode("utf-8")
    req = request.Request(config.endpoint + "/api/agent/pair", data=payload,
                          headers={"Content-Type": "application/json", "User-Agent": "uHive-SiteAdmin/0.1"}, method="POST")
    with request.urlopen(req, timeout=20) as response:
        result = json.load(response)
    state.update(agent_id=result["agent_id"], agent_token=result["agent_token"], paired=True)
    return result
