import hashlib
import io
import json
import urllib.error
import zipfile
from pathlib import Path

import pytest

from core.api import VaultApi
from core.updater import (
    _extract_windows_exe_from_zip,
    build_windows_updater_ps_script,
    check_for_updates,
    is_newer_version,
    parse_version,
    verify_sha256_from_sums,
)


def test_semantic_version_parsing_and_comparison():
    assert parse_version("v0.2.0") == (0, 2, 0, 1)
    assert parse_version("0.10.0") > parse_version("0.2.9")
    assert parse_version("v1.0.0") > parse_version("v1.0.0-beta.1")
    assert is_newer_version("v0.2.1", "0.2.0") is True
    assert is_newer_version("v0.2.0", "0.2.0") is False
    assert is_newer_version("v0.1.9", "0.2.0") is False


def test_check_for_updates_api_and_rate_limit_fallback(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("sys.platform", "win32")

    fake_release_json = json.dumps(
        {
            "tag_name": "v0.3.0",
            "html_url": "https://github.com/ataiben/md-vault/releases/tag/v0.3.0",
            "body": "- 新增本地一键自动更新",
            "published_at": "2026-11-11T10:00:00Z",
            "assets": [
                {
                    "name": "MD-Vault-Windows-x64.zip",
                    "browser_download_url": "https://example.com/MD-Vault-Windows-x64.zip",
                },
                {
                    "name": "SHA256SUMS.txt",
                    "browser_download_url": "https://example.com/SHA256SUMS.txt",
                },
            ],
        }
    ).encode("utf-8")

    class DummyResp:
        def __init__(self, data: bytes, url: str = ""):
            self._data = data
            self._url = url

        def read(self) -> bytes:
            return self._data

        def geturl(self) -> str:
            return self._url

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=8.0: DummyResp(fake_release_json))
    res = check_for_updates(tmp_path, current_version="0.2.0")
    assert res["ok"] is True
    assert res["has_update"] is True
    assert res["latest_version"] == "0.3.0"
    assert res["asset_name"] == "MD-Vault-Windows-x64.zip"
    assert res["sha256_url"] == "https://example.com/SHA256SUMS.txt"

    # Simulate GitHub API 403 rate limit -> fallback to /releases/latest redirect
    def rate_limited_urlopen(req, timeout=8.0):
        url = req.full_url
        if "api.github.com" in url:
            raise urllib.error.HTTPError(url, 403, "rate limit exceeded", hdrs=None, fp=None)
        return DummyResp(b"", url="https://github.com/ataiben/md-vault/releases/tag/v0.4.0")

    monkeypatch.setattr("urllib.request.urlopen", rate_limited_urlopen)
    fallback_res = check_for_updates(tmp_path, current_version="0.2.0")
    assert fallback_res["ok"] is True
    assert fallback_res["has_update"] is True
    assert fallback_res["latest_version"] == "0.4.0"
    assert fallback_res["download_url"].endswith("/v0.4.0/MD-Vault-Windows-x64.zip")


def test_sha256_verification_and_windows_zip_extraction(tmp_path: Path):
    zip_path = tmp_path / "MD-Vault-Windows-x64.zip"
    dummy_exe_bytes = b"MZ" + (b"\x90" * (600 * 1024))
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("MD-Vault.exe", dummy_exe_bytes)
        zf.writestr("README.md", "hello")

    actual_sha = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    sums_ok = f"{actual_sha}  MD-Vault-Windows-x64.zip\n"
    assert verify_sha256_from_sums(zip_path, "MD-Vault-Windows-x64.zip", sums_ok) is True

    sums_tampered = f"{'0' * 64}  MD-Vault-Windows-x64.zip\n"
    with pytest.raises(ValueError, match="SHA-256"):
        verify_sha256_from_sums(zip_path, "MD-Vault-Windows-x64.zip", sums_tampered)

    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir()
    extracted_exe = _extract_windows_exe_from_zip(zip_path, extract_dir)
    assert extracted_exe.name == "MD-Vault.exe"
    assert extracted_exe.stat().st_size == len(dummy_exe_bytes)

    # Verify PowerShell script safely quotes Chinese paths and single quotes
    cn_dir = tmp_path / "中文目录'测试"
    ps = build_windows_updater_ps_script(
        pid=12345,
        staged_exe=cn_dir / "MD-Vault.exe.new",
        target_exe=cn_dir / "MD-Vault.exe",
        temp_dir=extract_dir,
    )
    assert "Wait-Process -Id 12345" in ps
    assert "中文目录''测试" in ps


def test_auto_update_preference_persistence(tmp_path: Path):
    api = VaultApi(tmp_path)
    assert api.get_status()["auto_check_updates"] is True

    res = api.set_auto_check_updates(False)
    assert res["ok"] is True
    assert res["auto_check_updates"] is False

    # Switch vault path and ensure both vault_path and auto_check_updates coexist in .vault_prefs.json
    custom_md = tmp_path / "custom" / "my_vault.md"
    api._storage.set_vault_path(custom_md)

    api2 = VaultApi(tmp_path)
    st = api2.get_status()
    assert st["auto_check_updates"] is False
    assert Path(st["vault_path"]) == custom_md.resolve()
    api._storage.stop_watching()
    api2._storage.stop_watching()
