"""Проверка и применение подписанных релизов агента."""

import base64
import binascii
import compileall
import hashlib
import io
import json
import os
import shutil
import tarfile
import tempfile
import time
from pathlib import Path
from urllib import parse, request

from . import __version__


# Публичный Ed25519-ключ релизов. Приватный ключ хранится только у издателя.
RELEASE_PUBLIC_KEY_B64 = "/BY/PPxHsf4nKmZEf+MONPNcMruJ6UIshAk1RnDiiC4="
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024


class UpdateError(Exception):
    """Ошибка, при которой текущая установленная версия не меняется."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _canonical_manifest(manifest: dict) -> bytes:
    signed = {key: manifest.get(key) for key in ("version", "archive_url", "sha256")}
    return json.dumps(signed, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _public_key():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(RELEASE_PUBLIC_KEY_B64, validate=True))
    except (ImportError, ValueError, binascii.Error) as exc:
        raise UpdateError("crypto_unavailable", "Недоступна проверка подписи релиза") from exc


def verify_manifest(manifest: dict) -> None:
    if not isinstance(manifest, dict) or not all(isinstance(manifest.get(key), str) for key in ("version", "archive_url", "sha256", "signature")):
        raise UpdateError("invalid_manifest", "Манифест релиза неполный")
    if not manifest["version"] or len(manifest["version"]) > 64:
        raise UpdateError("invalid_manifest", "Версия релиза некорректна")
    digest = manifest["sha256"].lower()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise UpdateError("invalid_manifest", "SHA-256 релиза некорректен")
    try:
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:
        raise UpdateError("crypto_unavailable", "Недоступна проверка подписи релиза") from exc
    try:
        signature = base64.b64decode(manifest["signature"], validate=True)
        _public_key().verify(signature, _canonical_manifest(manifest))
    except (ValueError, binascii.Error, InvalidSignature) as exc:
        raise UpdateError("invalid_signature", "Подпись релиза недействительна") from exc


def _url(value: str, *, allow_local_http=False) -> str:
    parsed = parse.urlparse(value)
    local = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if parsed.scheme != "https" and not (allow_local_http and parsed.scheme == "http" and local):
        raise UpdateError("insecure_update_url", "Релиз можно получать только по HTTPS")
    if not parsed.netloc:
        raise UpdateError("invalid_update_url", "URL релиза некорректен")
    return value


def _read_response(response, limit=MAX_ARCHIVE_BYTES) -> bytes:
    chunks = []
    total = 0
    while True:
        chunk = response.read(min(1024 * 1024, limit - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise UpdateError("archive_too_large", "Архив релиза превышает лимит")
        chunks.append(chunk)
    return b"".join(chunks)


def _fetch(url: str, timeout=30) -> bytes:
    try:
        with request.urlopen(request.Request(url, headers={"User-Agent": "uHive-SiteAdmin/%s" % __version__}), timeout=timeout) as response:
            return _read_response(response)
    except UpdateError:
        raise
    except Exception as exc:
        raise UpdateError("download_failed", "Не удалось получить релиз") from exc


def _validate_archive(blob: bytes, target: Path) -> Path:
    try:
        archive = tarfile.open(fileobj=io.BytesIO(blob), mode="r:*")
    except (tarfile.TarError, OSError) as exc:
        raise UpdateError("invalid_archive", "Архив релиза не читается") from exc
    with archive:
        members = archive.getmembers()
        if not members:
            raise UpdateError("invalid_archive", "Архив релиза пуст")
        root = target.resolve()
        for member in members:
            relative = Path(member.name)
            destination = (target / relative).resolve()
            if relative.is_absolute() or root not in (destination, *destination.parents):
                raise UpdateError("invalid_archive", "Архив содержит выход за пределы каталога")
            if member.issym() or member.islnk() or member.isdev():
                raise UpdateError("invalid_archive", "Архив содержит ссылку или device-файл")
        archive.extractall(target)
    package = target / "siteadmin"
    if not (package / "__init__.py").is_file() or not (package / "__main__.py").is_file():
        raise UpdateError("invalid_archive", "В архиве отсутствует пакет siteadmin")
    if not compileall.compile_dir(str(package), quiet=1):
        raise UpdateError("invalid_archive", "Новый пакет не проходит компиляцию")
    return package


class UpdateManager:
    def __init__(self, config, state):
        self.config = config
        self.state = state
        self.install_dir = Path(config.install_dir)
        self.package_dir = self.install_dir / "siteadmin"
        self.update_dir = state.directory / "updates"
        self.update_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.update_dir, 0o700)

    def check(self, manifest_url: str | None = None) -> dict:
        url = _url(manifest_url or self.config.update_url)
        try:
            with request.urlopen(request.Request(url, headers={"User-Agent": "uHive-SiteAdmin/%s" % __version__}), timeout=30) as response:
                manifest = json.load(response)
        except UpdateError:
            raise
        except Exception as exc:
            raise UpdateError("manifest_download_failed", "Не удалось получить манифест") from exc
        verify_manifest(manifest)
        manifest["archive_url"] = parse.urljoin(url, manifest["archive_url"])
        _url(manifest["archive_url"])
        manifest["current_version"] = __version__
        manifest["update_available"] = manifest["version"] != __version__
        return manifest

    def apply(self, manifest_url: str | None = None) -> dict:
        manifest = self.check(manifest_url)
        blob = _fetch(manifest["archive_url"])
        if hashlib.sha256(blob).hexdigest() != manifest["sha256"].lower():
            raise UpdateError("checksum_mismatch", "SHA-256 архива не совпадает с манифестом")
        stage = Path(tempfile.mkdtemp(prefix="siteadmin-update-", dir=self.update_dir))
        backup = self.update_dir / (manifest["version"] + "-" + str(time.time_ns()))
        old_moved = False
        try:
            package = _validate_archive(blob, stage)
            if self.package_dir.exists():
                self.package_dir.rename(backup)
                old_moved = True
            self.install_dir.mkdir(parents=True, exist_ok=True)
            package.rename(self.package_dir)
            self.state.update(last_update={"version": manifest["version"], "backup": str(backup) if old_moved else None,
                                           "updated_at": time.time(), "pairing_preserved": True})
            return {"ok": True, "version": manifest["version"], "backup": str(backup) if old_moved else None,
                    "restart_required": True, "pairing_preserved": True}
        except (OSError, UpdateError) as exc:
            if self.package_dir.exists() and old_moved:
                shutil.rmtree(self.package_dir)
            if old_moved and backup.exists():
                backup.rename(self.package_dir)
            raise exc if isinstance(exc, UpdateError) else UpdateError("update_failed", "Не удалось применить релиз") from exc
        finally:
            shutil.rmtree(stage, ignore_errors=True)
