from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.api import VaultApi
from core.crypto import (
    CryptoEngine,
    CryptoIntegrityError,
    VERIFIER_AAD,
    VERIFIER_PLAINTEXT,
    is_v2_encrypted_token,
)
from core.importer import decode_csv_bytes
from core.markdown_codec import (
    decrypt_entry_for_view,
    dumps_vault,
    encrypt_entry_for_storage,
    loads_vault,
    seal_document_entries,
)
from core.models import AccountEntry, VaultDocument
from core.totp import generate_totp_token


def _make_legacy_v1_token(engine: CryptoEngine, plaintext: str) -> str:
    """Construct a genuine legacy ENC[v1:<nonce>:<ct>] token (no AAD) to test backward compatibility."""
    token = engine.encrypt_value(plaintext, aad=None)
    assert token.startswith("ENC[v1:")
    return token


def test_v2_aad_prevents_ciphertext_swapping_and_preserves_v1_compat():
    engine, salt_b64, verifier = CryptoEngine.create_new("StrongMaster#2026")
    assert is_v2_encrypted_token(verifier)

    # Unlocking with v2 verifier works cleanly
    unlocked = CryptoEngine.unlock_existing("StrongMaster#2026", salt_b64, verifier)
    assert unlocked.decrypt_token(verifier, aad=VERIFIER_AAD) == VERIFIER_PLAINTEXT

    e1 = encrypt_entry_for_storage(
        AccountEntry(
            id="acc_alpha001",
            category="开发",
            title="Alpha",
            password="AlphaSecretPassword!",
            two_fa_recovery="ALPHA-2FA-CODE",
        ),
        engine,
    )
    e2 = encrypt_entry_for_storage(
        AccountEntry(
            id="acc_beta0002",
            category="开发",
            title="Beta",
            password="BetaSecretPassword!",
        ),
        engine,
    )
    assert is_v2_encrypted_token(e1.password)
    assert is_v2_encrypted_token(e2.password)

    # 1. Cross-entry swap attack: copy Alpha's password token into Beta's password field
    swapped_cross_entry = e2.model_copy(deep=True)
    swapped_cross_entry.password = e1.password
    with pytest.raises(CryptoIntegrityError):
        decrypt_entry_for_view(swapped_cross_entry, engine)

    # 2. Same-entry cross-field swap attack: copy Alpha's 2FA token into Alpha's password field
    swapped_cross_field = e1.model_copy(deep=True)
    swapped_cross_field.password = e1.two_fa_recovery
    with pytest.raises(CryptoIntegrityError):
        decrypt_entry_for_view(swapped_cross_field, engine)

    # 3. Legacy ENC[v1:...] backward compatibility & seamless upgrade to ENC[v2:...]
    legacy_verifier = _make_legacy_v1_token(engine, VERIFIER_PLAINTEXT)
    legacy_unlocked = CryptoEngine.unlock_existing("StrongMaster#2026", salt_b64, legacy_verifier)
    legacy_entry = AccountEntry(
        id="acc_legacy01",
        category="历史分类",
        title="旧版 V1 记录",
        password=_make_legacy_v1_token(engine, "OldV1Password#88"),
    )
    decrypted_legacy = decrypt_entry_for_view(legacy_entry, legacy_unlocked)
    assert decrypted_legacy.password == "OldV1Password#88"

    legacy_doc = VaultDocument(entries=[legacy_entry])
    was_upgraded = seal_document_entries(legacy_doc, legacy_unlocked, upgrade_v1=True)
    assert was_upgraded is True
    assert is_v2_encrypted_token(legacy_doc.entries[0].password)
    assert decrypt_entry_for_view(legacy_doc.entries[0], legacy_unlocked).password == "OldV1Password#88"


def test_auto_heal_nested_double_encrypted_v1_wrapping_v2_and_header_guard(tmp_path: Path):
    """
    Reproduce & verify automatic self-healing when an older v1-only MD-Vault binary
    opened a vault with v1 header verifier + v2 entry tokens and double-encrypted
    ENC[v2:...] inside ENC[v1:...].
    """
    api = VaultApi(tmp_path)
    init = api.create_vault("RealMaster#2026", use_starter_template=False)
    vault_path = Path(init["vault_path"])

    saved = api.save_entry(
        {
            "id": "acc_3127b84e",
            "category": "邮箱账号",
            "title": "Gmail · 个人核心主邮箱",
            "username": "boachietite496@gmail.com",
            "password": "RealPass10",
            "two_fa_recovery": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        }
    )
    assert saved["ok"] is True

    # Simulate legacy state: v1 verifier + old binary wrapping ENC[v2:...] inside ENC[v1:...]
    assert api._crypto is not None
    raw_doc = loads_vault(vault_path.read_text(encoding="utf-8"))
    raw_doc.header.vault_version = 1
    raw_doc.header.verifier = api._crypto.encrypt_value(VERIFIER_PLAINTEXT, aad=None)  # v1 verifier
    ent = raw_doc.entries[0]
    assert ent.password.startswith("ENC[v2:")
    assert ent.two_fa_recovery.startswith("ENC[v2:")
    # Old v1-only seal_if_plaintext treated ENC[v2:...] as plaintext and wrapped it in ENC[v1:...]
    ent.password = api._crypto.encrypt_value(ent.password, aad=None)
    ent.two_fa_recovery = api._crypto.encrypt_value(ent.two_fa_recovery, aad=None)
    assert ent.password.startswith("ENC[v1:")
    vault_path.write_text(dumps_vault(raw_doc), encoding="utf-8")

    api.lock_vault()

    # Unlocking must automatically unwrap nested layers, heal disk file, and upgrade header verifier to v2
    unlocked = api.unlock_vault("RealMaster#2026")
    assert unlocked["ok"] is True
    assert unlocked["auto_sealed"] is True

    rev_pwd = api.reveal_entry_secret("acc_3127b84e", "password")
    assert rev_pwd["ok"] is True
    assert rev_pwd["value"] == "RealPass10"

    rev_2fa = api.reveal_entry_secret("acc_3127b84e", "2fa")
    assert rev_2fa["ok"] is True
    assert rev_2fa["value"] == "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

    totp_res = api.get_entry_totp("acc_3127b84e")
    assert totp_res["ok"] is True
    assert totp_res["source"] == "two_fa_recovery"
    assert len(totp_res["code"]) == 6

    # Verify disk file is now clean single-layer ENC[v2:...] AND header verifier is ENC[v2:...]
    healed_doc = loads_vault(vault_path.read_text(encoding="utf-8"))
    assert is_v2_encrypted_token(healed_doc.header.verifier)
    assert healed_doc.header.vault_version == 2
    assert is_v2_encrypted_token(healed_doc.entries[0].password)

    api._storage.stop_watching()


def test_lazy_decryption_and_direct_backend_clipboard_copy(tmp_path: Path, monkeypatch):
    api = VaultApi(tmp_path)
    init = api.create_vault("VaultMaster#888", vault_name="按需解密测试", use_starter_template=False)
    assert init["ok"] is True

    saved = api.save_entry(
        {
            "category": "开发与云服务",
            "title": "GitHub 主号",
            "username": "octocat",
            "password": "SuperSecretLogin#1",
            "totp_secret": "JBSWY3DPEHPK3PXP",
            "two_fa_recovery": "REC-1111-2222",
            "security_questions": [{"question": "宠物名？", "answer": "Mochi"}],
        }
    )
    assert saved["ok"] is True
    eid = saved["saved_id"]

    # Bulk list state MUST NOT contain any plaintext secrets
    serialized_json = json.dumps(saved, ensure_ascii=False)
    assert "SuperSecretLogin#1" not in serialized_json
    assert "JBSWY3DPEHPK3PXP" not in serialized_json
    assert "REC-1111-2222" not in serialized_json
    assert "Mochi" not in serialized_json

    item = saved["entries"][0]
    assert item["has_password"] is True
    assert item["has_totp"] is True
    assert item["has_two_fa"] is True
    assert item["security_questions"][0]["has_answer"] is True

    # Reveal individual fields on demand
    assert api.reveal_entry_secret(eid, "password")["value"] == "SuperSecretLogin#1"
    assert api.reveal_entry_secret(eid, "totp_secret")["value"] == "JBSWY3DPEHPK3PXP"
    assert api.reveal_entry_secret(eid, "2fa")["value"] == "REC-1111-2222"
    assert api.reveal_entry_secret(eid, "qa_0")["value"] == "Mochi"

    # Direct backend clipboard copy never returns the secret in its response dict
    copied_box = {}
    monkeypatch.setattr(
        api,
        "copy_to_clipboard",
        lambda text, auto_clear_seconds=0, sensitive=None: copied_box.update(
            {"text": text, "clear": auto_clear_seconds, "sensitive": sensitive}
        )
        or {"ok": True},
    )
    copy_res = api.copy_entry_secret(eid, "password", auto_clear_seconds=30)
    assert copy_res == {"ok": True}
    assert copied_box == {"text": "SuperSecretLogin#1", "clear": 30, "sensitive": True}

    # Locking vault blocks all on-demand secret endpoints
    api.lock_vault()
    assert api.reveal_entry_secret(eid, "password")["ok"] is False
    assert api.get_entry_for_edit(eid)["ok"] is False
    api._storage.stop_watching()


def test_master_password_policy_strength_and_notes_leak_guard(tmp_path: Path):
    api = VaultApi(tmp_path)

    # Master password minimum length (>= 8) and anti-repeat enforcement
    assert api.create_vault("Short1!", use_starter_template=False)["ok"] is False
    assert api.create_vault("aaaaaaaaaa", use_starter_template=False)["ok"] is False

    weak_eval = api.check_password_strength("12345678", username="admin")
    strong_eval = api.check_password_strength("Tr0ub4dor&3_Xy9#Zp2!", username="admin")
    assert weak_eval["is_weak"] is True
    assert strong_eval["is_weak"] is False
    assert strong_eval["score"] >= 3

    assert api.create_vault("ValidMaster#2026", use_starter_template=False)["ok"] is True

    # Notes containing private key or API token or password line should trigger warning first
    risky_payload = {
        "category": "开发与云服务",
        "title": "OpenAI API",
        "username": "dev@openai.com",
        "password": "LoginPwd#12345",
        "notes": "线上环境变量：\nAPIKey = sk-proj1234567890abcdefghijklmnop\n-----BEGIN OPENSSH PRIVATE KEY-----",
    }
    warn_res = api.save_entry(risky_payload)
    assert warn_res["ok"] is False
    assert warn_res.get("notes_warning") is True
    assert len(warn_res.get("risks", [])) >= 2

    # User explicitly confirms saving risky plaintext notes -> succeeds
    ok_res = api.save_entry(risky_payload, allow_risky_notes=True)
    assert ok_res["ok"] is True

    api._storage.stop_watching()


def test_builtin_totp_rfc6238_and_markdown_roundtrip(tmp_path: Path):
    # Deterministic TOTP check (JBSWY3DPEHPK3PXP at t=0 -> 282760)
    tok0 = generate_totp_token("JBSWY3DPEHPK3PXP", timestamp=0)
    assert tok0["code"] == "282760"
    assert tok0["digits"] == 6
    assert tok0["remaining"] == 30

    # otpauth:// URI with custom digits=8 and SHA256
    uri = "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=30"
    tok_uri = generate_totp_token(uri, timestamp=1700000000)
    assert len(tok_uri["code"]) == 8
    assert tok_uri["algorithm"] == "SHA256"

    api = VaultApi(tmp_path)
    init = api.create_vault("TotpMaster#2026", use_starter_template=False)
    vault_path = Path(init["vault_path"])

    # Invalid Base32 TOTP secret is rejected cleanly on save
    bad_totp = api.save_entry(
        {"category": "开发", "title": "Bad TOTP", "totp_secret": "NOT_BASE32_1890!!!"}
    )
    assert bad_totp["ok"] is False

    good_totp = api.save_entry(
        {"category": "开发", "title": "GitHub TOTP", "totp_secret": "JBSWY3DPEHPK3PXP"}
    )
    assert good_totp["ok"] is True
    eid = good_totp["saved_id"]

    # Verify encrypted persistence in Markdown & Obsidian plaintext auto-sealing
    md_text = vault_path.read_text(encoding="utf-8")
    assert "**TOTP 密钥**: `ENC[v2:" in md_text
    assert "JBSWY3DPEHPK3PXP" not in md_text

    live = api.get_entry_totp(eid)
    assert live["ok"] is True
    assert len(live["code"]) == 6 and live["code"].isdigit()

    # Simulate user adding plaintext TOTP key in Obsidian
    obsidian_md = (
        md_text
        + "\n### Cloudflare 账号\n"
        + "<!-- id: acc_cf_totp1 -->\n"
        + "- **登录账号**: `cf@example.com`\n"
        + "- **TOTP 密钥**: `JBSWY3DPEHPK3PXP`\n"
    )
    vault_path.write_text(obsidian_md, encoding="utf-8")
    reloaded = api.reload_from_disk()
    assert reloaded["ok"] is True
    assert reloaded["auto_sealed"] is True
    assert "JBSWY3DPEHPK3PXP" not in vault_path.read_text(encoding="utf-8")
    assert api.get_entry_totp("acc_cf_totp1")["ok"] is True

    api._storage.stop_watching()


def test_totp_auto_fallback_from_legacy_two_fa_recovery_and_preview(tmp_path: Path, monkeypatch):
    api = VaultApi(tmp_path)
    api.create_vault("LegacyTotp#2026", use_starter_template=False)

    # 1. Legacy account storing spaced Google Authenticator seed inside two_fa_recovery
    legacy_res = api.save_entry(
        {
            "category": "邮箱账号",
            "title": "Gmail 历史账号",
            "username": "user@gmail.com",
            "password": "StrongPwd#2026",
            "totp_secret": "",
            "two_fa_recovery": "jbsw y3dp ehpk 3pxp",
        }
    )
    assert legacy_res["ok"] is True
    legacy_id = legacy_res["saved_id"]

    totp_live = api.get_entry_totp(legacy_id)
    assert totp_live["ok"] is True
    assert totp_live["source"] == "two_fa_recovery"
    assert len(totp_live["code"]) == 6 and totp_live["code"].isdigit()

    # Reveal & copy TOTP work seamlessly via fallback
    rev = api.reveal_entry_secret(legacy_id, "totp_secret")
    assert rev["ok"] is True and rev["value"] == "jbsw y3dp ehpk 3pxp"

    copied_box = {}
    monkeypatch.setattr(
        api,
        "copy_to_clipboard",
        lambda text, auto_clear_seconds=0, sensitive=False: (
            copied_box.update({"text": text, "sensitive": sensitive}) or {"ok": True}
        ),
    )
    assert api.copy_entry_totp(legacy_id, 30)["ok"] is True
    assert len(copied_box["text"]) == 6 and copied_box["sensitive"] is True

    # Single-line TOTP seed sets has_totp=True and has_two_fa=False (no duplicate bottom card)
    redacted_single = next(e for e in legacy_res["entries"] if e["id"] == legacy_id)
    assert redacted_single["has_totp"] is True
    assert redacted_single["has_two_fa"] is False

    # Unified edit payload keeps the seed directly inside two_fa_recovery
    edit_payload = api.get_entry_for_edit(legacy_id)
    assert edit_payload["ok"] is True
    assert edit_payload["entry"]["two_fa_recovery"] == "jbsw y3dp ehpk 3pxp"
    assert edit_payload["entry"]["totp_secret"] == ""

    # 2. Multiline two_fa_recovery with TOTP + backup codes sets BOTH has_totp=True and has_two_fa=True
    mixed_res = api.save_entry(
        {
            "category": "开发与云服务",
            "title": "AWS Mixed 2FA",
            "two_fa_recovery": "pstniyo7witba6s6oicv2o3d3kbpnwhe\n备用码: 19283746 / 56473829",
        }
    )
    mixed_id = mixed_res["saved_id"]
    mixed_totp = api.get_entry_totp(mixed_id)
    assert mixed_totp["ok"] is True
    assert mixed_totp["source"] == "two_fa_recovery"
    redacted_mixed = next(e for e in mixed_res["entries"] if e["id"] == mixed_id)
    assert redacted_mixed["has_totp"] is True
    assert redacted_mixed["has_two_fa"] is True

    # 3. Normal backup recovery codes (with digits 0/1/8/9 or slash list) must NOT false-trigger TOTP
    backup_only_res = api.save_entry(
        {
            "category": "邮箱账号",
            "title": "Backup Codes Only",
            "two_fa_recovery": "1928 3746 / 5647 3829 / RK9X-72LM-99PA-44QW",
        }
    )
    backup_id = backup_only_res["saved_id"]
    no_totp = api.get_entry_totp(backup_id)
    assert no_totp["ok"] is False
    assert no_totp.get("no_totp") is True
    redacted_backup = next(e for e in backup_only_res["entries"] if e["id"] == backup_id)
    assert redacted_backup["has_totp"] is False
    assert redacted_backup["has_two_fa"] is True

    # 4. Editor live preview helper on unified 2FA text
    prev_ok = api.preview_totp_secret("pstniyo7witba6s6oicv2o3d3kbpnwhe")
    assert prev_ok["ok"] is True and len(prev_ok["code"]) == 6
    prev_backup = api.preview_totp_secret("1234-5678-9012")
    assert prev_backup["ok"] is False and prev_backup.get("backup_only") is True

    api._storage.stop_watching()


def test_csv_import_export_across_browsers_and_password_managers(tmp_path: Path):
    # Verify GBK fallback decoding for Windows localized CSV files
    gbk_bytes = "名称,网址,用户名,密码\n网易邮箱,https://mail.163.com,user_cn,Pass#163\n".encode("gbk")
    assert "网易邮箱" in decode_csv_bytes(gbk_bytes)

    api = VaultApi(tmp_path)
    api.create_vault("ImportPass#2026", use_starter_template=False)

    # 1. Import Chrome CSV
    chrome_csv = (
        "name,url,username,password,note\n"
        "github.com,https://github.com/login,octocat,GhPass#2026!,Personal GitHub\n"
        "google.com,https://accounts.google.com,octo@gmail.com,GoogPass#99!,\n"
    )
    imp1 = api.import_csv_content(chrome_csv, default_category="浏览器迁入")
    assert imp1["ok"] is True
    assert imp1["imported_count"] == 2
    assert "Chrome" in imp1["detected_source"]

    # Re-importing the exact same CSV skips duplicates automatically!
    imp_dup = api.import_csv_content(chrome_csv, default_category="浏览器迁入")
    assert imp_dup["ok"] is True
    assert imp_dup["imported_count"] == 0
    assert imp_dup["skipped_duplicates"] == 2

    # 2. Import Bitwarden CSV (with folder, favorite, and login_totp)
    bw_csv = (
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
        "云服务器,1,login,AWS Root,生产环境账号,,0,https://console.aws.amazon.com,root@aws.com,AwsRoot#2026!,JBSWY3DPEHPK3PXP\n"
    )
    imp2 = api.import_csv_content(bw_csv)
    assert imp2["ok"] is True
    assert imp2["imported_count"] == 1
    assert "Bitwarden" in imp2["detected_source"]
    aws_item = next(e for e in imp2["entries"] if e["title"] == "AWS Root")
    assert aws_item["category"] == "云服务器"
    assert aws_item["favorite"] is True
    assert aws_item["has_totp"] is True

    # 3. Export CSV requires valid master password re-verification
    assert api.export_csv_content("")["ok"] is False
    assert api.export_csv_content("WrongPassword#1")["ok"] is False

    exp = api.export_csv_content("ImportPass#2026")
    assert exp["ok"] is True
    assert exp["entry_count"] == 3
    assert "AwsRoot#2026!" in exp["csv_text"]

    # Round-trip exported CSV into a second vault
    api2 = VaultApi(tmp_path / "vault2")
    api2.create_vault("SecondVault#2026", use_starter_template=False)
    imp_rt = api2.import_csv_content(exp["csv_text"])
    assert imp_rt["ok"] is True
    assert imp_rt["imported_count"] == 3

    api._storage.stop_watching()
    api2._storage.stop_watching()


def test_offline_password_health_audit_report(tmp_path: Path):
    api = VaultApi(tmp_path)
    init = api.create_vault("HealthPass#2026", use_starter_template=False)
    vault_path = Path(init["vault_path"])

    # Add 2 entries reusing the same strong password, and 1 entry with a weak password
    api.save_entry(
        {
            "category": "社交",
            "title": "微博账号",
            "username": "weibo_user",
            "password": "SharedPassword#2026!",
        }
    )
    api.save_entry(
        {
            "category": "社交",
            "title": "知乎账号",
            "username": "zhihu_user",
            "password": "SharedPassword#2026!",
        }
    )
    s_weak = api.save_entry(
        {
            "category": "邮箱",
            "title": "旧备用邮箱",
            "username": "old_mail",
            "password": "password123",
            "totp_secret": "JBSWY3DPEHPK3PXP",
        }
    )

    # Backdate one entry's updated_at on disk to > 200 days ago
    doc = loads_vault(vault_path.read_text(encoding="utf-8"))
    for ent in doc.entries:
        if ent.id == s_weak["saved_id"]:
            ent.updated_at = "2024-01-15 09:00:00"
    vault_path.write_text(dumps_vault(doc), encoding="utf-8")
    api.reload_from_disk()

    health_res = api.get_password_health_report(stale_days=180)
    assert health_res["ok"] is True
    report = health_res["report"]
    summary = report["summary"]

    assert summary["total_entries"] == 3
    assert summary["reused_group_count"] == 1
    assert summary["reused_entry_count"] == 2
    assert summary["weak_count"] == 1
    assert summary["unprotected_2fa_count"] == 2  # 微博 & 知乎 lack TOTP/2FA
    assert summary["stale_count"] == 1

    # Ensure zero plaintext passwords leak in the health report payload
    report_dump = json.dumps(report, ensure_ascii=False)
    assert "SharedPassword#2026!" not in report_dump
    assert "password123" not in report_dump

    api._storage.stop_watching()
