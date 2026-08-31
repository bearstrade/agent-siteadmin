import base64
import hashlib
import io
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import siteadmin.update as update
from siteadmin.state import State
from siteadmin.update import UpdateError, UpdateManager, _canonical_manifest, _validate_archive, verify_manifest


def signed_manifest(private_key, version="0.2.0", archive_url="https://releases.example/siteadmin.tar.gz"):
    manifest = {"version": version, "archive_url": archive_url, "sha256": "0" * 64}
    manifest["signature"] = base64.b64encode(
        private_key.sign(_canonical_manifest(manifest))
    ).decode("ascii")
    return manifest


def archive_bytes(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            encoded = content.encode("utf-8")
            info.size = len(encoded)
            archive.addfile(info, io.BytesIO(encoded))
    return stream.getvalue()


def test_valid_ed25519_manifest(monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    monkeypatch.setattr(update, "RELEASE_PUBLIC_KEY_B64", base64.b64encode(public_key).decode("ascii"))
    verify_manifest(signed_manifest(private_key))


def test_invalid_signature_is_normalized(monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    manifest = signed_manifest(private_key)
    manifest["signature"] = base64.b64encode(b"bad").decode("ascii")
    with pytest.raises(UpdateError, match="Подпись") as error:
        verify_manifest(manifest)
    assert error.value.code == "invalid_signature"


def test_checksum_mismatch_does_not_create_update(tmp_path, monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    blob = archive_bytes({"siteadmin/__init__.py": "", "siteadmin/__main__.py": ""})
    manifest = signed_manifest(private_key)
    manifest["sha256"] = "f" * 64
    monkeypatch.setattr(UpdateManager, "check", lambda self, manifest_url=None: manifest)
    monkeypatch.setattr(update, "_fetch", lambda url: blob)
    manager = UpdateManager(type("Config", (), {"install_dir": tmp_path / "install"})(), State(tmp_path / "state"))
    with pytest.raises(UpdateError) as error:
        manager.apply()
    assert error.value.code == "checksum_mismatch"
    assert not manager.package_dir.exists()


def test_archive_rejects_path_traversal(tmp_path):
    blob = archive_bytes({"../escape": "bad"})
    with pytest.raises(UpdateError) as error:
        _validate_archive(blob, tmp_path / "stage")
    assert error.value.code == "invalid_archive"


def test_failed_replacement_restores_previous_package(tmp_path, monkeypatch):
    install_dir = tmp_path / "install"
    package_dir = install_dir / "siteadmin"
    package_dir.mkdir(parents=True)
    (package_dir / "__init__.py").write_text("OLD = True\n", encoding="utf-8")
    (package_dir / "__main__.py").write_text("OLD = True\n", encoding="utf-8")
    blob = archive_bytes({"siteadmin/__init__.py": "NEW = True\n", "siteadmin/__main__.py": "NEW = True\n"})
    digest = hashlib.sha256(blob).hexdigest()
    manager = UpdateManager(type("Config", (), {"install_dir": install_dir})(), State(tmp_path / "state"))
    manifest = {"version": "0.2.0", "archive_url": "https://releases.example/siteadmin.tar.gz", "sha256": digest,
                "signature": "unused"}
    monkeypatch.setattr(UpdateManager, "check", lambda self, manifest_url=None: manifest)
    monkeypatch.setattr(update, "_fetch", lambda url: blob)
    original_rename = Path.rename

    def fail_new_package(self, target):
        if Path(target) == manager.package_dir and self.name == "siteadmin":
            raise OSError("simulated replacement failure")
        return original_rename(self, target)

    monkeypatch.setattr(Path, "rename", fail_new_package)
    with pytest.raises(UpdateError) as error:
        manager.apply()
    assert error.value.code == "update_failed"
    assert (package_dir / "__init__.py").read_text(encoding="utf-8") == "OLD = True\n"
    assert not list(manager.update_dir.glob("siteadmin-update-*"))
