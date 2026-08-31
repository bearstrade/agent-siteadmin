"""Конфигурация агента из переменных окружения."""

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Config:
    endpoint: str
    state_dir: Path
    local_token_file: Path
    update_url: str = ""
    install_dir: Path = Path("/opt/siteadmin")
    poll_timeout: int = 55
    telemetry_interval: int = 300

    @classmethod
    def from_env(cls):
        state_dir = Path(os.environ.get("SITEADMIN_STATE_DIR", "/var/lib/siteadmin"))
        return cls(
            endpoint=os.environ.get("SITEADMIN_ENDPOINT", "").rstrip("/"),
            state_dir=state_dir,
            local_token_file=Path(os.environ.get("SITEADMIN_LOCAL_TOKEN", state_dir / "local.token")),
            update_url=os.environ.get("SITEADMIN_UPDATE_URL", "").strip(),
            install_dir=Path(os.environ.get("SITEADMIN_INSTALL_DIR", "/opt/siteadmin")),
            poll_timeout=max(5, min(60, int(os.environ.get("SITEADMIN_POLL_TIMEOUT", "55")))),
            telemetry_interval=max(60, int(os.environ.get("SITEADMIN_TELEMETRY_INTERVAL", "300"))),
        )
