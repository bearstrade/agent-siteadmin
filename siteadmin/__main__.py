"""CLI и сервисный цикл siteadmin."""

import argparse
import json
import threading
import time

from .api import LocalAPI
from .channel import Channel
from .collector import Collector
from .config import Config
from .gateway import OperationGateway
from .pairing import pair
from .state import State
from .update import UpdateError, UpdateManager


def run():
    config = Config.from_env()
    state = State(config.state_dir)
    collector = Collector(state)
    gateway = OperationGateway(state)
    channel = Channel(config, state)
    if not state.read().get("paired"):
        raise SystemExit("Агент не привязан: задайте pairing-код через siteadmin pair CODE")
    threading.Thread(target=LocalAPI(state, collector, gateway).serve, daemon=True, name="siteadmin-local-api").start()
    if not state.read().get("profile_sent"):
        channel.send("profile", collector.profile())
    last_telemetry = 0
    while True:
        channel.flush()
        if gateway.expire_setup():
            channel.send("events", {"events": [{"type": "setup_expired", "severity": "warning",
                                                   "payload": {"message": "Режим настройки выключен по таймеру"}}]})
        if time.time() - last_telemetry >= config.telemetry_interval:
            telemetry, events = collector.telemetry()
            channel.send("telemetry", {"ts": telemetry["ts"], "payload": telemetry})
            if events:
                channel.send("events", {"events": events})
            last_telemetry = time.time()
        command = channel.poll()
        if command.get("cmd") == "scan":
            result = collector.scan()
            channel.send("profile", result)
            if command.get("command_id"):
                try:
                    channel.result(command["command_id"], {"ok": True, "findings": len(result["findings"])})
                except OSError:
                    pass
        elif command.get("cmd") == "op" and command.get("command_id"):
            payload = command.get("payload") if isinstance(command.get("payload"), dict) else command
            result = gateway.execute(payload.get("op", ""), payload.get("params", {}),
                                     dry_run=payload.get("mode") == "dry",
                                     confirm_token=payload.get("confirm_token"),
                                     setup_session_id=payload.get("setup_session_id"))
            channel.result(command["command_id"], {"op": payload.get("op"), **result})
        elif command.get("cmd") == "setup_start" and command.get("command_id"):
            payload = command.get("payload") if isinstance(command.get("payload"), dict) else command
            try:
                result = gateway.start_setup(payload)
            except Exception as exc:  # ответ сервера не должен теряться при плохом payload
                result = {"ok": False, "error": {"code": getattr(exc, "code", "setup_start_failed"), "message": str(exc)}}
            channel.result(command["command_id"], result)
        elif command.get("cmd") == "setup_stop" and command.get("command_id"):
            payload = command.get("payload") if isinstance(command.get("payload"), dict) else command
            channel.result(command["command_id"], gateway.stop_setup(payload.get("reason", "service")))


def main():
    parser = argparse.ArgumentParser(prog="siteadmin")
    sub = parser.add_subparsers(dest="command")
    pair_parser = sub.add_parser("pair")
    pair_parser.add_argument("code")
    sub.add_parser("status")
    sub.add_parser("scan")
    sub.add_parser("run")
    sub.add_parser("logs")
    update_parser = sub.add_parser("update")
    update_parser.add_argument("manifest_url", nargs="?")
    update_parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    config = Config.from_env()
    state = State(config.state_dir)
    if args.command == "pair":
        print(json.dumps(pair(config, state, args.code), ensure_ascii=False, indent=2))
    elif args.command == "status":
        print(json.dumps({key: value for key, value in state.read().items() if key != "agent_token"}, ensure_ascii=False, indent=2))
    elif args.command == "scan":
        print(json.dumps(Collector(state).scan(), ensure_ascii=False, indent=2))
    elif args.command == "logs":
        print("Логи агента доступны через journalctl -u siteadmin.service")
    elif args.command == "update":
        try:
            manager = UpdateManager(config, state)
            value = manager.check(args.manifest_url) if args.check else manager.apply(args.manifest_url)
            print(json.dumps(value, ensure_ascii=False, indent=2, default=str))
        except UpdateError as exc:
            raise SystemExit("Ошибка обновления [%s]: %s" % (exc.code, exc)) from exc
    else:
        run()


if __name__ == "__main__":
    main()
