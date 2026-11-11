from pathlib import Path

from core.api import VaultApi


def test_full_api_lifecycle_and_master_password_rotation(tmp_path: Path):
    api = VaultApi(tmp_path)
    status = api.get_status()
    assert status["exists"] is False

    # 1. Create vault with starter templates
    res = api.create_vault("InitPass#123", vault_name="集成测试库", use_starter_template=True)
    assert res["ok"] is True
    assert len(res["entries"]) == 4
    vault_file = Path(res["vault_path"])
    assert vault_file.exists()

    # 2. Add a new China region Apple ID
    save_res = api.save_entry(
        {
            "category": "苹果商店与生态",
            "title": "Apple Store · 港区备用号",
            "platform": "Apple ID",
            "tags": "港区, 备用",
            "username": "hk_apple@icloud.com",
            "password": "HK_Secret_Password!",
            "security_questions": [{"question": "出生地？", "answer": "HongKong"}],
        }
    )
    assert save_res["ok"] is True
    assert len(save_res["entries"]) == 5

    # 3. Rotate master password and verify old password fails while new password unlocks all entries
    rot_res = api.change_master_password("InitPass#123", "NewMaster#456")
    assert rot_res["ok"] is True

    api.lock_vault()
    bad_unlock = api.unlock_vault("InitPass#123")
    assert bad_unlock["ok"] is False

    good_unlock = api.unlock_vault("NewMaster#456")
    assert good_unlock["ok"] is True
    hk_item = next(e for e in good_unlock["entries"] if e["username"] == "hk_apple@icloud.com")
    assert hk_item["password"] == "HK_Secret_Password!"
    assert hk_item["security_questions"][0]["answer"] == "HongKong"

    # Verify rolling backup was created
    backup_dir = vault_file.parent / ".vault_backups"
    assert backup_dir.exists()
    assert len(list(backup_dir.glob("*.md"))) >= 1

    api._storage.stop_watching()


def test_category_scoped_saved_tags_and_url_launcher(tmp_path: Path, monkeypatch):
    api = VaultApi(tmp_path)
    res = api.create_vault("Pass#1234", vault_name="标签测试库", use_starter_template=False)
    assert res["ok"] is True
    assert res["saved_tags"] == {}

    # Save entry in category A -> auto-saves tags under category A only
    res_a = api.save_entry(
        {
            "category": "苹果商店与生态",
            "title": "Apple 日区号",
            "tags": "日区, 游戏专用",
            "username": "jp@icloud.com",
            "password": "jp_pass",
        }
    )
    assert res_a["saved_tags"]["苹果商店与生态"] == ["日区", "游戏专用"]
    assert "邮箱账号" not in res_a["saved_tags"]

    # Delete a quick tag via small 'x' button and verify persistence across lock/unlock
    del_res = api.delete_saved_tag("苹果商店与生态", "游戏专用")
    assert del_res["saved_tags"]["苹果商店与生态"] == ["日区"]

    api.lock_vault()
    reunlocked = api.unlock_vault("Pass#1234")
    assert reunlocked["saved_tags"]["苹果商店与生态"] == ["日区"]

    # Test safe URL opening & scheme validation
    opened_urls = []
    monkeypatch.setattr("webbrowser.open", lambda u: opened_urls.append(u) or True)

    ok_url = api.open_external_url("account.apple.com")
    assert ok_url["ok"] is True
    assert opened_urls == ["https://account.apple.com"]

    bad_url = api.open_external_url("javascript:alert(1)")
    assert bad_url["ok"] is False
    assert len(opened_urls) == 1

    api._storage.stop_watching()


def test_master_password_whitespace_consistency(tmp_path: Path):
    api = VaultApi(tmp_path)

    # Pure whitespace must be rejected
    blank_res = api.create_vault("     ", vault_name="空白密码测试", use_starter_template=False)
    assert blank_res["ok"] is False

    # Passwords with intentional leading/trailing spaces must unlock with exact match
    spaced_pwd = "  MySpacedPass#1  "
    create_res = api.create_vault(spaced_pwd, vault_name="空格一致性库", use_starter_template=False)
    assert create_res["ok"] is True

    api.lock_vault()
    assert api.unlock_vault("MySpacedPass#1")["ok"] is False
    assert api.unlock_vault(spaced_pwd)["ok"] is True

    # Rotating to another spaced password must also stay consistent
    next_spaced = " NextPass#2 "
    rot_res = api.change_master_password(spaced_pwd, next_spaced)
    assert rot_res["ok"] is True

    api.lock_vault()
    assert api.unlock_vault("NextPass#2")["ok"] is False
    assert api.unlock_vault(next_spaced)["ok"] is True

    api._storage.stop_watching()


def test_macos_finder_and_clipboard_integration(tmp_path: Path, monkeypatch):
    api = VaultApi(tmp_path)
    api.create_vault("MacPass#123", vault_name="Mac测试库", use_starter_template=False)

    monkeypatch.setattr("sys.platform", "darwin")

    spawned_cmds = []
    monkeypatch.setattr("subprocess.Popen", lambda cmd, *a, **kw: spawned_cmds.append(cmd))
    reveal_res = api.reveal_vault_in_explorer()
    assert reveal_res["ok"] is True
    assert spawned_cmds[0][:2] == ["open", "-R"]

    clipboard_buf = {"data": b""}

    class DummyCompleted:
        def __init__(self, stdout=b""):
            self.stdout = stdout

    def fake_run(cmd, input=None, capture_output=False, env=None, check=False):
        assert env is not None and env.get("LC_CTYPE") == "UTF-8"
        if cmd == ["pbcopy"]:
            clipboard_buf["data"] = input or b""
            return DummyCompleted()
        if cmd == ["pbpaste"]:
            return DummyCompleted(stdout=clipboard_buf["data"])
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr("subprocess.run", fake_run)
    copy_res = api.copy_to_clipboard("测试中文密码#2026", auto_clear_seconds=0)
    assert copy_res["ok"] is True
    assert api._get_clipboard_text() == "测试中文密码#2026"

    api._storage.stop_watching()

