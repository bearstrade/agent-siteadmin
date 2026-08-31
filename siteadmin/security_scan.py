"""Небольшой Linux security-аудит по известным локальным источникам."""

import os
import shutil
import socket
import subprocess
from pathlib import Path


def _finding(severity, title, detail, evidence, fix):
    return {"severity": severity, "title": title, "detail": detail,
            "evidence": evidence[:1000], "fix_suggestion": fix, "status": "open"}


def _listeners():
    ports = set()
    try:
        for filename in ("/proc/net/tcp", "/proc/net/tcp6"):
            for line in Path(filename).read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) > 3 and fields[3] == "0A":
                    ports.add(int(fields[1].rsplit(":", 1)[1], 16))
    except (OSError, ValueError, IndexError):
        pass
    return sorted(ports)


def _ssh_values():
    result = {}
    try:
        for line in Path("/etc/ssh/sshd_config").read_text(errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                key, _, value = line.partition(" ")
                result[key.lower()] = value.strip().lower()
    except OSError:
        pass
    return result


def _run(*args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=8, check=False)
    except (OSError, subprocess.SubprocessError):
        return None


def _firewall():
    if shutil.which("ufw"):
        result = _run("ufw", "status")
        return bool(result and "status: active" in result.stdout.lower())
    if shutil.which("firewall-cmd"):
        result = _run("firewall-cmd", "--state")
        return bool(result and result.stdout.strip().lower() == "running")
    return None


def _pending_updates():
    if shutil.which("apt-get"):
        result = _run("apt-get", "--just-print", "upgrade")
        if not result:
            return 0
        return sum(1 for line in result.stdout.splitlines() if line.startswith("Inst "))
    manager = "dnf" if shutil.which("dnf") else "yum" if shutil.which("yum") else ""
    if manager:
        result = _run(manager, "-q", "check-update")
        return len([line for line in (result.stdout if result else "").splitlines() if line and not line.startswith("Last metadata")])
    return None


def _package_version(name):
    if shutil.which("dpkg-query"):
        result = _run("dpkg-query", "-W", "-f=${Version}", name)
        return result.stdout.strip() if result and result.returncode == 0 else ""
    if shutil.which("rpm"):
        result = _run("rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", name)
        return result.stdout.strip() if result and result.returncode == 0 else ""
    return ""


def _old_package_findings():
    findings = []
    known = {
        "nginx": ("1.10.", "high"),
        "apache2": ("2.2.", "high"),
        "httpd": ("2.2.", "high"),
        "openssl": ("1.0.", "high"),
        "php": ("5.", "high"),
        "nodejs": ("10.", "medium"),
    }
    for package, (prefix, severity) in known.items():
        version = _package_version(package)
        if version.startswith(prefix):
            findings.append(_finding(severity, f"Установлена устаревшая версия {package}",
                                     f"Локальный пакет {package} имеет версию из известной уязвимой ветки.",
                                     f"{package} version family: {prefix}",
                                     f"Обновите {package} штатным пакетным менеджером и проверьте changelog дистрибутива."))
    return findings


def scan(previous=None):
    findings = []
    ports = _listeners()
    if 22 in ports:
        ssh = _ssh_values()
        if ssh.get("permitrootlogin") in {"yes", "without-password", "prohibit-password"}:
            findings.append(_finding("high", "Разрешён вход root по SSH", "SSH принимает вход под root.", "sshd_config: PermitRootLogin configured", "Установите PermitRootLogin no и перезапустите sshd."))
        if ssh.get("passwordauthentication") == "yes":
            findings.append(_finding("medium", "Разрешена парольная аутентификация SSH", "Пароли расширяют поверхность атаки SSH.", "sshd_config: PasswordAuthentication yes", "Используйте ключи и установите PasswordAuthentication no."))
    if ports:
        findings.append(_finding("low", "Обнаружены слушающие порты", "Проверьте, что каждый сервис нужен.", "ports: " + ", ".join(map(str, ports)), "Закройте ненужные порты firewall-правилами."))
    if not shutil.which("fail2ban-client"):
        findings.append(_finding("medium", "Fail2ban не установлен", "Автоматическая блокировка перебора SSH недоступна.", "fail2ban-client is absent", "Установите fail2ban и включите jail для SSH."))
    else:
        result = _run("fail2ban-client", "ping")
        if not result or result.returncode != 0 or "pong" not in result.stdout.lower():
            findings.append(_finding("medium", "Fail2ban не отвечает", "Клиент Fail2ban установлен, но служба не ответила.", "fail2ban-client ping failed", "Запустите fail2ban и проверьте журнал службы."))
    firewall = _firewall()
    if firewall is False:
        findings.append(_finding("high", "Firewall не активен", "UFW или firewalld установлен, но не сообщает об активном состоянии.", "firewall status is inactive", "Включите firewall и задайте минимальные правила для нужных сервисов."))
    elif firewall is None and not shutil.which("ufw") and not shutil.which("firewall-cmd"):
        findings.append(_finding("high", "Не найден активный firewall", "Не обнаружен ufw или firewalld.", "ufw/firewalld executable is absent", "Установите и включите ufw или firewalld."))
    updates = _pending_updates()
    if updates:
        findings.append(_finding("medium", "Доступны обновления системы", f"Пакетный менеджер сообщает о пакетах для обновления: {updates}.", "local package-manager check", "Установите обновления и отдельно проверьте security-обновления."))
    if not shutil.which("unattended-upgrade") and not shutil.which("dnf-automatic"):
        findings.append(_finding("low", "Автообновления не настроены", "Не найден unattended-upgrades или dnf-automatic.", "automatic update executable is absent", "Настройте автоматическую установку security-обновлений по политике сервера."))
    for path in ("/etc/shadow", "/etc/ssh/sshd_config"):
        try:
            mode = os.stat(path).st_mode & 0o777
            if mode & 0o077:
                findings.append(_finding("high", "Слишком открытые права конфигурации", f"Файл {path} доступен группе или другим пользователям.", f"mode={mode:04o}", f"Ограничьте права {path}, обычно до 0600/0644 по назначению."))
        except OSError:
            pass
    findings.extend(_old_package_findings())
    if previous and set(ports) - set(previous.get("ports", [])):
        added = sorted(set(ports) - set(previous.get("ports", [])))
        findings.append(_finding("medium", "Появился новый слушатель", "Список открытых локальных портов изменился.", "new ports: " + ", ".join(map(str, added)), "Проверьте процесс и закройте порт, если он не нужен."))
    return findings, {"ports": ports}
