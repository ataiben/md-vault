from core.crypto import CryptoEngine, is_encrypted_token
from core.markdown_codec import (
    decrypt_entry_for_view,
    dumps_vault,
    encrypt_entry_for_storage,
    loads_vault,
    seal_document_entries,
)
from core.models import AccountEntry, SecurityQA, VaultDocument, VaultHeader


def test_roundtrip_multi_region_accounts_and_security_qa():
    engine, salt, verifier = CryptoEngine.create_new("VaultMaster!88", iterations=10_000)

    us_apple = encrypt_entry_for_storage(
        AccountEntry(
            id="acc_us001",
            category="苹果商店与生态",
            title="Apple Store · 美区主力号",
            platform="Apple ID",
            tags=["美区", "主力", "免税州"],
            favorite=True,
            username="us_store@gmail.com",
            password="US_Secret_Password_1!",
            phone="+1 302-555-0188",
            recovery_email="backup@outlook.com",
            url="https://account.apple.com",
            security_questions=[
                SecurityQA(question="你少年时代最好的朋友叫什么名字？", answer="Tom"),
                SecurityQA(question="你的第一份工作是在哪个城市？", answer="Boston"),
                SecurityQA(question="你理想的工作是什么？", answer="Engineer"),
            ],
            two_fa_recovery="LINE1-CODE\nLINE2-CODE",
            notes="免税州地址：Delaware\n长期自用美区账号。",
        ),
        engine,
    )

    tr_apple = encrypt_entry_for_storage(
        AccountEntry(
            id="acc_tr002",
            category="苹果商店与生态",
            title="Apple Store · 土耳其区订阅号",
            platform="Apple ID",
            tags=["土耳其区", "订阅"],
            username="tr_store@icloud.com",
            password="TR_Secret_Password_2!",
        ),
        engine,
    )

    doc = VaultDocument(
        header=VaultHeader(vault_name="测试汇总密码库", salt=salt, verifier=verifier),
        categories=["苹果商店与生态", "邮箱账号", "空分类测试"],
        entries=[us_apple, tr_apple],
    )

    md_text = dumps_vault(doc)

    # Plaintext secrets must NEVER appear in the persisted Markdown text
    assert "US_Secret_Password_1!" not in md_text
    assert "TR_Secret_Password_2!" not in md_text
    assert "Boston" not in md_text
    assert "LINE1-CODE" not in md_text
    # Readable metadata MUST appear in Markdown text
    assert "## 苹果商店与生态" in md_text
    assert "### Apple Store · 美区主力号" in md_text
    assert "`us_store@gmail.com`" in md_text
    assert "## 空分类测试" in md_text

    # Parse back from Markdown
    parsed = loads_vault(md_text)
    assert parsed.header.vault_name == "测试汇总密码库"
    assert parsed.categories == ["苹果商店与生态", "邮箱账号", "空分类测试"]
    assert len(parsed.entries) == 2

    dec_us = decrypt_entry_for_view(parsed.entries[0], engine)
    assert dec_us.id == "acc_us001"
    assert dec_us.favorite is True
    assert dec_us.tags == ["美区", "主力", "免税州"]
    assert dec_us.password == "US_Secret_Password_1!"
    assert len(dec_us.security_questions) == 3
    assert dec_us.security_questions[1].answer == "Boston"
    assert dec_us.two_fa_recovery == "LINE1-CODE\nLINE2-CODE"
    assert "Delaware" in dec_us.notes


def test_external_handwritten_markdown_auto_seal_and_custom_fields():
    engine, salt, verifier = CryptoEngine.create_new("MasterPass99", iterations=10_000)

    handwritten_md = f"""---
vault_version: 1
vault_name: 手改测试库
kdf: pbkdf2-sha256
kdf_iterations: 10000
salt: {salt}
verifier: {verifier}
---

# 手改测试库

## 邮箱账号

### Outlook · 手写新增工作邮箱
- **服务/平台**: Microsoft Outlook
- **分区/标签**: 工作, 海外
- **登录账号**: manual_edit@outlook.com
- **登录密码**: MyPlainHandwrittenPass123
- **礼品卡余额**: $25.00

#### 密保与恢复信息
- **密保问题 1**: 母亲的生日？ :: 1970-01-01
- **2FA / 恢复码**: PLAIN-RECOVERY-9988

#### 备注说明
这是我直接用记事本打开 .md 手写添加的账号。
"""

    parsed = loads_vault(handwritten_md)
    assert len(parsed.entries) == 1
    ent = parsed.entries[0]
    assert ent.id.startswith("acc_")  # Auto-assigned missing ID
    assert ent.tags == ["工作", "海外"]
    assert ent.custom_fields == {"礼品卡余额": "$25.00"}
    assert ent.password == "MyPlainHandwrittenPass123"

    # Seal external plaintext fields
    was_sealed = seal_document_entries(parsed, engine)
    assert was_sealed is True
    assert is_encrypted_token(ent.password)
    assert is_encrypted_token(ent.security_questions[0].answer)
    assert is_encrypted_token(ent.two_fa_recovery)

    # Re-dump and verify custom_fields survived round-trip
    dumped = dumps_vault(parsed)
    assert "MyPlainHandwrittenPass123" not in dumped
    assert "PLAIN-RECOVERY-9988" not in dumped
    assert "- **礼品卡余额**: $25.00" in dumped
