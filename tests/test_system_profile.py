"""Тесты расширенного системного профиля: load, swap, топ-процессы, топ-папки."""

from siteadmin import system_profile as sp


def test_top_processes_parses_ps_sorted(monkeypatch):
    fake = (
        "154475 hermes-gateway 27.1 267123\n"
        "16822 systemd-journald 10.6 105123\n"
        "37393 orlimit 4.2 42123\n"
    )
    monkeypatch.setattr(sp, "_command", lambda *a, **k: fake)
    rows = sp._top_processes()
    assert [r["name"] for r in rows] == ["hermes-gateway", "systemd-journald", "orlimit"]
    assert rows[0]["pid"] == 154475
    assert rows[0]["mem_percent"] == 27.1
    assert rows[0]["rss_bytes"] == 267123 * 1024
    # лимит сверху
    assert len(sp._top_processes(limit=2)) == 2


def test_top_processes_empty_on_command_failure(monkeypatch):
    monkeypatch.setattr(sp, "_command", lambda *a, **k: "")
    assert sp._top_processes() == []


def test_disk_top_consumers_sorts_and_skips_root(monkeypatch):
    fake = (
        "900\t/usr\n"
        "5600\t/root\n"
        "90\t/var\n"
        "7\t/\n"  # сам корень пропускается
    )
    monkeypatch.setattr(sp, "_command", lambda *a, **k: fake)
    rows = sp._disk_top_consumers()
    assert [r["path"] for r in rows] == ["/root", "/usr", "/var"]
    assert rows[0]["bytes"] == 5600 * 1024
    assert len(rows) <= 4


def test_loadavg_parses(monkeypatch):
    class FakePath:
        _files = {"/proc/loadavg": "0.07 0.06 0.01 1/233 12345\n"}

        def __init__(self, path):
            self.path = path

        def read_text(self, *a, **k):
            return self._files[self.path]

    monkeypatch.setattr(sp, "Path", FakePath)
    assert sp._loadavg() == [0.07, 0.06, 0.01]


def test_swap_parses_and_absent_when_zero(monkeypatch):
    class FakePath:
        _files = {
            "/proc/loadavg": "1.0 1.0 1.0 1/1 1\n",
            "/proc/meminfo": (
                "MemTotal: 983040 kB\nMemFree: 69000 kB\n"
                "SwapTotal: 1048576 kB\nSwapFree: 917504 kB\n"
            ),
        }

        def __init__(self, path):
            self.path = path

        def read_text(self, *a, **k):
            return self._files[self.path]

    monkeypatch.setattr(sp, "Path", FakePath)
    swap = sp._swap()
    assert swap is not None
    assert swap["total_bytes"] == 1048576 * 1024
    assert swap["used_bytes"] == (1048576 - 917504) * 1024
    assert swap["used_percent"] == 12.5

    # нет swap → None (UI просто не покажет блок)
    FakePath._files["/proc/meminfo"] = "MemTotal: 983040 kB\nSwapTotal: 0 kB\n"
    assert sp._swap() is None


def test_hermes_state_detects_container_process(monkeypatch):
    """Бот в чужом контейнере (имя/образ без 'hermes', напр. xfw-bot), но
    процесс внутри — с 'hermes': значит установлен и работает."""
    def fake_command(*args, **kwargs):
        if args[:2] == ("ps", "-eo"):
            return ("/usr/local/lib/hermes-agent/venv/bin/python "
                    "-m hermes_cli.main gateway run")
        return ""

    monkeypatch.setattr(sp, "_command", fake_command)
    monkeypatch.setattr(sp.shutil, "which", lambda name: None)
    monkeypatch.setattr(sp, "_hermes_paths", lambda: False)
    assert sp._hermes_state() == {"installed": True, "running": True}


def test_hermes_state_stopped_container_is_installed_only(monkeypatch):
    def fake_command(*args, **kwargs):
        if args[:3] == ("docker", "ps", "-a"):
            return ("my-hermes\tghcr.io/nousresearch/hermes-agent:latest\t"
                    "/hermes run")
        return ""

    monkeypatch.setattr(sp, "_command", fake_command)
    monkeypatch.setattr(
        sp.shutil, "which",
        lambda name: "/usr/bin/docker" if name == "docker" else None)
    monkeypatch.setattr(sp, "_hermes_paths", lambda: False)
    assert sp._hermes_state() == {"installed": True, "running": False}


def test_hermes_state_absent(monkeypatch):
    monkeypatch.setattr(sp, "_command", lambda *a, **k: "")
    monkeypatch.setattr(sp.shutil, "which", lambda name: None)
    monkeypatch.setattr(sp, "_hermes_paths", lambda: False)
    assert sp._hermes_state() == {"installed": False, "running": False}


def test_hermes_paths_matches_srv_bot_home(monkeypatch, tmp_path):
    """`/srv/<bot>/hermes` (home контейнерного бота на хосте) = установлен."""
    bot_home = tmp_path / "xfw-bot" / "hermes"
    bot_home.mkdir(parents=True)

    class FakePath:
        def __init__(self, value):
            self.value = str(value)

        def exists(self):
            return False  # типовые каталоги отсутствуют

        def glob(self, pattern):
            return iter([bot_home])

    monkeypatch.setattr(sp, "Path", FakePath)
    assert sp._hermes_paths() is True


def test_software_state_shape(monkeypatch):
    monkeypatch.setattr(
        sp.shutil, "which",
        lambda name: "/usr/bin/" + name
        if name in ("nginx", "docker", "systemctl") else None)

    def fake_command(*args, **kwargs):
        if args[:2] == ("systemctl", "is-active") and args[2] == "nginx":
            return "active"
        return "inactive"

    monkeypatch.setattr(sp, "_command", fake_command)
    monkeypatch.setattr(sp, "_hermes_state",
                        lambda: {"installed": True, "running": False})
    software = sp.software_state()
    assert software["nginx"] == {"installed": True, "running": True}
    assert software["docker"] == {"installed": True, "running": False}
    assert software["podman"] == {"installed": False, "running": None}
    assert software["hermes"] == {"installed": True, "running": False}

