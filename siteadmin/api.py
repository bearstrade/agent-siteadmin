"""Локальный API агента только на 127.0.0.1."""

import json
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer

from .gateway import OperationGateway


class LocalAPI:
    def __init__(self, state, collector, gateway=None):
        self.state = state
        self.collector = collector
        self.gateway = gateway or OperationGateway(state)
        self.token = self._load_token()

    def _load_token(self):
        path = self.state.directory / "local.token"
        if not path.exists():
            path.write_text(secrets.token_urlsafe(24), encoding="ascii")
            path.chmod(0o600)
        return path.read_text(encoding="ascii").strip()

    def serve(self, port=8765):
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                return

            def do_GET(self):
                if self.headers.get("X-Local-Token") != owner.token:
                    self.send_error(401)
                    return
                if self.path == "/status":
                    body = {key: value for key, value in owner.state.read().items() if key != "agent_token"}
                    self._json(body)
                else:
                    self.send_error(404)

            def do_POST(self):
                if self.headers.get("X-Local-Token") != owner.token or self.path not in {"/scan", "/op"}:
                    self.send_error(401)
                    return
                if self.path == "/scan":
                    self._json(owner.collector.scan())
                    return
                try:
                    length = min(int(self.headers.get("Content-Length", "0")), 65536)
                    body = json.loads(self.rfile.read(length) or b"{}")
                    value = owner.gateway.execute(body.get("op", ""), body.get("params", {}),
                                                  dry_run=bool(body.get("dry_run")),
                                                  confirm_token=body.get("confirm_token"))
                    self._json(value)
                except (ValueError, TypeError, json.JSONDecodeError):
                    self.send_error(400)

            def _json(self, value):
                data = json.dumps(value, ensure_ascii=False, default=str).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        HTTPServer(("127.0.0.1", port), Handler).serve_forever()
