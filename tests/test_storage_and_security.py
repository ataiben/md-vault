from __future__ import annotations

import sys
import types
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from core.api import VaultApi
from core.storage import ExternalConflictError, VaultStorage


def test_tiered_backup_retention_preserves_hourly_daily_weekly(tmp_path: Path):
    backup_dir = tmp_path / ".vault_backups"
    backup_dir.mkdir(parents=True)
    stem = "accounts_vault"

    base_now = datetime(2026, 11, 13, 16, 30, 0)

    def make_snap(dt: datetime, content: str = "snap") -> Path:
        stamp = dt.strftime("%Y%m%d_%H%M%S_%f")
        p = backup_dir / f"{stem}_{stamp}.md"
        p.write_text(content, encoding="utf-8")
        return p

    # 1. Create historical weekly snapshots (3 weeks ago & 2 weeks ago)
    weekly_3 = make_snap(base_now - timedelta(weeks=3))
    weekly_2 = make_snap(base_now - timedelta(weeks=2))

    # 2. Create historical daily snapshots (5 days ago & 2 days ago)
    daily_5 = make_snap(base_now - timedelta(days=5))
    daily_2 = make_snap(base_now - timedelta(days=2))

    # 3. Create historical hourly snapshots today (4 hours ago & 2 hours ago, 2 per hour)
    hourly_4_old = make_snap(base_now - timedelta(hours=4, minutes=20))
    hourly_4_new = make_snap(base_now - timedelta(hours=4, minutes=5))
    hourly_2_new = make_snap(base_now - timedelta(hours=2, minutes=10))

    # 4. Simulate a burst of 15 saves within the current minute!
    burst_files = [
        make_snap(base_now - timedelta(seconds=30 - i)) for i in range(15)
    ]

    retained = VaultStorage.prune_backups(
        backup_dir,
        stem,
        keep_recent=10,
        keep_hourly=24,
        keep_daily=30,
        keep_weekly=12,
    )
    retained_set = set(retained)

    # Newest 10 burst snapshots must be kept; older 5 in the same minute/hour pruned
    for p in burst_files[-10:]:
        assert p in retained_set
    for p in burst_files[:5]:
        assert p not in retained_set
        assert not p.exists()

    # Earlier hours, days, and weeks MUST survive the 15-save burst!
    assert hourly_4_new in retained_set
    assert hourly_4_old not in retained_set  # Superseded by hourly_4_new in same hour bucket
    assert hourly_2_new in retained_set
    assert daily_2 in retained_set
    assert daily_5 in retained_set
    assert weekly_2 in retained_set
    assert weekly_3 in retained_set


def test_backup_list_restore_and_password_rotation_snapshot(tmp_path: Path):
    api = VaultApi(tmp_path)
    api.create_vault("OldPass#111", vault_name="快照测试库", use_starter_template=False)

    # Save 1st entry
    r1 = api.save_entry(
        {
            "category": "开发与云服务",
            "title": "GitLab 账号",
            "username": "dev1@example.com",
            "password": "gitlab_secret_1",
        }
    )
    assert r1["ok"] is True

    # Save 2nd entry (creates snapshot containing 1 entry)
    r2 = api.save_entry(
        {
            "category": "开发与云服务",
            "title": "DockerHub 账号",
            "username": "dev2@example.com",
            "password": "docker_secret_2",
        }
    )
    assert r2["ok"] is True
    assert len(r2["entries"]) == 2

    backups_res = api.list_backups()
    assert backups_res["ok"] is True
    snaps = backups_res["backups"]
    assert len(snaps) >= 2
    one_entry_snap = next(b for b in snaps if b["entry_count"] == 1)

    # Path traversal must be rejected
    bad_restore = api.restore_backup("../accounts_vault.md")
    assert bad_restore["ok"] is False

    # Restore snapshot under same master password -> stays unlocked & restores 1 entry
    restored = api.restore_backup(one_entry_snap["filename"])
    assert restored["ok"] is True
    assert restored.get("requires_unlock") is not True
    assert len(restored["entries"]) == 1
    assert restored["entries"][0]["title"] == "GitLab 账号"

    # Rotate master password, then restore the snapshot encrypted with OldPass#111
    rot = api.change_master_password("OldPass#111", "NewPass#222")
    assert rot["ok"] is True

    restored_old_key = api.restore_backup(one_entry_snap["filename"])
    assert restored_old_key["ok"] is True
    assert restored_old_key["requires_unlock"] is True
    assert restored_old_key["is_unlocked"] is False

    # Unlocking with OldPass#111 now succeeds cleanly
    assert api.unlock_vault("NewPass#222")["ok"] is False
    reunlocked = api.unlock_vault("OldPass#111")
    assert reunlocked["ok"] is True
    restored_id = reunlocked["entries"][0]["id"]
    assert reunlocked["entries"][0]["password"] == ""
    assert reunlocked["entries"][0]["has_password"] is True
    assert api.reveal_entry_secret(restored_id, "password")["value"] == "gitlab_secret_1"

    api._storage.stop_watching()


def test_external_conflict_detection_and_three_way_merge(tmp_path: Path):
    api = VaultApi(tmp_path)
    init = api.create_vault("Master#999", vault_name="冲突合并库", use_starter_template=False)
    assert init["ok"] is True

    s1 = api.save_entry(
        {
            "category": "开发与云服务",
            "title": "AWS 控制台",
            "username": "aws@example.com",
            "password": "aws_v1_password",
        }
    )
    aws_id = s1["saved_id"]

    # Simulate external edit in Obsidian: append a brand-new plaintext account entry!
    vault_path = Path(init["vault_path"])
    disk_md = vault_path.read_text(encoding="utf-8")
    obsidian_addition = (
        "\n## 社交与娱乐\n\n"
        "### Netflix · 家庭车队\n"
        "<!-- id: acc_obsidian1 -->\n"
        "- **登录账号**: `nf@example.com`\n"
        "- **登录密码**: `PlainObsidianPwd#2026`\n"
    )
    vault_path.write_text(disk_md + obsidian_addition, encoding="utf-8")

    # 1. Default save_entry ('abort') MUST detect conflict and NOT overwrite Obsidian's edit
    conflict_res = api.save_entry(
        {
            "id": aws_id,
            "category": "开发与云服务",
            "title": "AWS 控制台",
            "username": "aws@example.com",
            "password": "aws_v2_updated_in_ui",
        }
    )
    assert conflict_res["ok"] is False
    assert conflict_res.get("conflict") is True
    assert "Netflix · 家庭车队" in vault_path.read_text(encoding="utf-8")
    # In-memory state must remain uncorrupted (still v1)
    cur_data = api.get_vault_data()
    assert cur_data["entries"][0]["password"] == ""
    assert api.reveal_entry_secret(aws_id, "password")["value"] == "aws_v1_password"

    # 2. change_master_password with default 'abort' must also abort without locking current session
    mpw_conflict = api.change_master_password("Master#999", "Rotated#000")
    assert mpw_conflict["ok"] is False
    assert mpw_conflict.get("conflict") is True
    assert api.get_vault_data()["ok"] is True

    # 3. Retry save_entry with conflict_mode='merge': keeps BOTH UI update AND Obsidian entry (and auto-seals plaintext!)
    merged_res = api.save_entry(
        {
            "id": aws_id,
            "category": "开发与云服务",
            "title": "AWS 控制台",
            "username": "aws@example.com",
            "password": "aws_v2_updated_in_ui",
        },
        conflict_mode="merge",
    )
    assert merged_res["ok"] is True
    assert merged_res["auto_sealed"] is True
    by_id = {e["id"]: e for e in merged_res["entries"]}
    assert by_id[aws_id]["has_password"] is True
    assert by_id["acc_obsidian1"]["has_password"] is True
    assert api.reveal_entry_secret(aws_id, "password")["value"] == "aws_v2_updated_in_ui"
    assert api.reveal_entry_secret("acc_obsidian1", "password")["value"] == "PlainObsidianPwd#2026"

    # Verify plaintext password written by Obsidian is now encrypted on disk with v2 AAD
    persisted_md = vault_path.read_text(encoding="utf-8")
    assert "PlainObsidianPwd#2026" not in persisted_md
    assert "ENC[v2:" in persisted_md

    # 4. External edit + conflict_mode='overwrite' backs up external file before overwriting
    vault_path.write_text(persisted_md + "\n<!-- external_marker_xyz -->\n", encoding="utf-8")
    with pytest.raises(ExternalConflictError):
        api._storage.write_markdown(persisted_md, force=False)

    overwritten = api.toggle_favorite(aws_id, conflict_mode="overwrite")
    assert overwritten["ok"] is True
    backup_contents = [
        p.read_text(encoding="utf-8") for p in api._storage.backup_dir.glob("*.md")
    ]
    assert any("external_marker_xyz" in txt for txt in backup_contents)

    api._storage.stop_watching()


def test_auto_lock_prefs_and_minimize_window_hook(tmp_path: Path):
    api = VaultApi(tmp_path)
    init_status = api.get_status()
    assert init_status["auto_lock_minutes"] == 15
    assert init_status["lock_on_minimize"] is False

    upd = api.set_auto_lock_prefs(5, True)
    assert upd == {"ok": True, "auto_lock_minutes": 5, "lock_on_minimize": True}

    # Verify persistence across a fresh VaultApi instance
    api._storage.stop_watching()
    api2 = VaultApi(tmp_path)
    api2.create_vault("LockTest#123", use_starter_template=False)
    assert api2.get_status()["auto_lock_minutes"] == 5
    assert api2.get_status()["lock_on_minimize"] is True

    # Simulate native pywebview window minimize event
    js_calls = []

    class DummyEventHook:
        def __init__(self):
            self.handlers = []

        def __iadd__(self, fn):
            self.handlers.append(fn)
            return self

        def fire(self):
            for fn in list(self.handlers):
                fn()

    class DummyWindow:
        def __init__(self):
            self.events = types.SimpleNamespace(minimized=DummyEventHook())

        def evaluate_js(self, code: str):
            js_calls.append(code)

    win = DummyWindow()
    api2._bind_window(win)
    assert api2.get_status()["is_unlocked"] is True

    win.events.minimized.fire()
    assert api2.get_status()["is_unlocked"] is False
    assert any("onBackendAutoLocked" in c for c in js_calls)

    api2._storage.stop_watching()


def test_clipboard_privacy_formats_win32_and_macos(tmp_path: Path, monkeypatch):
    api = VaultApi(tmp_path)

    # 1. Test macOS NSPasteboard concealed & transient markers when sensitive=True
    monkeypatch.setattr(sys, "platform", "darwin")
    pb_records = []

    class FakePasteboard:
        def clearContents(self):
            pb_records.append(("clear", None, None))

        def setString_forType_(self, val, ptype):
            pb_records.append(("set", val, ptype))

    fake_appkit = types.ModuleType("AppKit")
    fake_appkit.NSPasteboard = types.SimpleNamespace(generalPasteboard=lambda: FakePasteboard())
    fake_appkit.NSPasteboardTypeString = "public.utf8-plain-text"
    monkeypatch.setitem(sys.modules, "AppKit", fake_appkit)

    res_secret = api.copy_to_clipboard("MyTopSecret#1", auto_clear_seconds=0, sensitive=True)
    assert res_secret["ok"] is True
    types_written = [r[2] for r in pb_records if r[0] == "set"]
    assert "public.utf8-plain-text" in types_written
    assert "org.nspasteboard.ConcealedType" in types_written
    assert "org.nspasteboard.TransientType" in types_written

    # 2. Test Windows clipboard privacy format registration on Win32
    monkeypatch.undo()
    if sys.platform == "win32":
        import ctypes

        user32 = ctypes.windll.user32
        user32.RegisterClipboardFormatW.argtypes = [ctypes.c_wchar_p]
        user32.RegisterClipboardFormatW.restype = ctypes.c_uint
        user32.IsClipboardFormatAvailable.argtypes = [ctypes.c_uint]
        user32.IsClipboardFormatAvailable.restype = ctypes.c_int

        fmt_exclude = user32.RegisterClipboardFormatW(
            "ExcludeClipboardContentFromMonitorProcessing"
        )
        fmt_history = user32.RegisterClipboardFormatW("CanIncludeInClipboardHistory")
        fmt_cloud = user32.RegisterClipboardFormatW("CanUploadToCloudClipboard")

        try:
            # Sensitive copy -> all 3 privacy formats must be present on live OS clipboard
            VaultApi._win32_set_clipboard("WinSecret#99", sensitive=True)
            assert api._get_clipboard_text() == "WinSecret#99"
            assert bool(user32.IsClipboardFormatAvailable(fmt_exclude)) is True
            assert bool(user32.IsClipboardFormatAvailable(fmt_history)) is True
            assert bool(user32.IsClipboardFormatAvailable(fmt_cloud)) is True

            # Non-sensitive copy -> privacy formats should NOT be attached
            VaultApi._win32_set_clipboard("PublicUsername", sensitive=False)
            assert api._get_clipboard_text() == "PublicUsername"
            assert bool(user32.IsClipboardFormatAvailable(fmt_exclude)) is False
            assert bool(user32.IsClipboardFormatAvailable(fmt_history)) is False
            assert bool(user32.IsClipboardFormatAvailable(fmt_cloud)) is False

            # Clean up clipboard after test
            VaultApi._win32_set_clipboard("", sensitive=True)
        except RuntimeError:
            # Headless CI session without interactive desktop clipboard access
            pass

    api._storage.stop_watching()
