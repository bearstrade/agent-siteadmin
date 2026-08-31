"""Исходящий HTTPS-канал, long-poll и файловый outbox."""

import json
import time
from urllib import error, parse, request

from .config import Config
from .state import State


class Channel:
    def __init__(self, config: Config, state: State):
        self.config = config
        self.state = state
        self._check_endpoint()

    def _check_endpoint(self):
        if not self.config.endpoint:
            raise ValueError("SITEADMIN_ENDPOINT не задан")
        parsed = parse.urlparse(self.config.endpoint)
        insecure = parsed.hostname in {"127.0.0.1", "localhost", "::1"} and parsed.scheme == "http"
        if parsed.scheme != "https" and not insecure:
            raise ValueError("SITEADMIN_ENDPOINT должен использовать https")

    def _request(self, path: str, method="GET", body=None, timeout=30):
        token = self.state.read().get("agent_token", "")
        headers = {"User-Agent": "uHive-SiteAdmin/0.1"}
        if token:
            headers["X-Agent-Token"] = token
        data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = request.Request(self.config.endpoint + path, data=data, headers=headers, method=method)
        with request.urlopen(req, timeout=timeout) as response:
            return json.load(response)

    @staticmethod
    def _paths():
        return {"profile": "/api/agent/profile", "telemetry": "/api/agent/telemetry",
                "events": "/api/agent/events", "result": "/api/agent/result"}

    def send(self, kind: str, payload: dict) -> bool:
        try:
            self._request(self._paths()[kind], method="POST", body=payload, timeout=30)
            return True
        except (error.HTTPError, error.URLError, OSError, TimeoutError, ValueError):
            self.state.enqueue(kind, payload)
            return False

    def flush(self, limit=20) -> int:
        sent = 0
        for path in self.state.pending()[:limit]:
            try:
                item = json.loads(path.read_text(encoding="utf-8"))
                self._request(self._paths()[item["kind"]], method="POST", body=item["payload"], timeout=30)
                path.unlink()
                sent += 1
            except (error.HTTPError, error.URLError, OSError, TimeoutError, ValueError, KeyError):
                break
        return sent

    def poll(self):
        try:
            return self._request("/api/agent/poll?timeout=%d" % self.config.poll_timeout,
                                 timeout=self.config.poll_timeout + 10)
        except (error.HTTPError, error.URLError, OSError, TimeoutError, ValueError):
            time.sleep(2)
            return {"cmd": "offline"}

    def result(self, command_id: int, result: dict):
        payload = {"command_id": command_id, "result": result}
        try:
            return self._request(self._paths()["result"], method="POST", body=payload, timeout=30)
        except (error.HTTPError, error.URLError, OSError, TimeoutError, ValueError):
            self.state.enqueue("result", payload)
            return {"ok": False, "queued": True}
