from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

import yaml

from core.crypto import (
    VERIFIER_AAD,
    VERIFIER_PLAINTEXT,
    CryptoEngine,
    CryptoError,
    build_field_aad,
    is_encrypted_token,
    is_v2_encrypted_token,
)
from core.models import (
    AccountEntry,
    SecurityQA,
    VaultDocument,
    VaultHeader,
    generate_entry_id,
    now_timestamp,
)
from core.totp import extract_totp_from_text, has_extra_recovery_beyond_totp

ID_COMMENT_RE = re.compile(r"^<!--\s*id:\s*([A-Za-z0-9_\-]+)\s*-->$")
BULLET_KV_RE = re.compile(r"^-\s+\*\*(.+?)\*\*:\s*(.*)$")
EMPTY_CAT_MARKER = "_暂无账号记录_"
TOC_HEADING = "目录索引"


def _strip_single_backticks(val: str) -> str:
    val = val.strip()
    if len(val) >= 2 and val.startswith("`") and val.endswith("`") and "`" not in val[1:-1]:
        return val[1:-1]
    return val


def _wrap_inline_code(val: str) -> str:
    if not val:
        return ""
    if "`" in val:
        return f"`` {val} ``"
    return f"`{val}`"


def _parse_tags(raw: str) -> List[str]:
    if not raw.strip():
        return []
    # Extract backticked items first if present, otherwise split by comma/Chinese comma
    backticked = re.findall(r"`([^`]+)`", raw)
    if backticked:
        return [t.strip() for t in backticked if t.strip()]
    parts = re.split(r"[,，、;；]+", raw)
    return [p.strip() for p in parts if p.strip()]


def _anchor_slug(category: str) -> str:
    # GitHub/Obsidian compatible anchor slug
    slug = re.sub(r"[^\w\u4e00-\u9fff\s\-]", "", category.strip().lower())
    return re.sub(r"\s+", "-", slug)


def seal_document_entries(
    doc: VaultDocument, crypto: CryptoEngine, upgrade_v1: bool = False
) -> bool:
    """
    Ensure all sensitive fields in doc.entries are encrypted with AAD-bound ENC[v2:...].
    Existing valid ENC[v1:...] fields remain readable unless upgrade_v1=True.
    Returns True if any sensitive field was newly sealed or upgraded.
    """
    modified = False
    for entry in doc.entries:
        if not entry.id:
            entry.id = generate_entry_id()
            modified = True

        if entry.password:
            sealed, changed = crypto.seal_if_plaintext(
                entry.password,
                aad=build_field_aad(entry.id, "password"),
                upgrade_v1=upgrade_v1,
            )
            entry.password = sealed
            modified = modified or changed

        if entry.totp_secret:
            sealed, changed = crypto.seal_if_plaintext(
                entry.totp_secret,
                aad=build_field_aad(entry.id, "totp_secret"),
                upgrade_v1=upgrade_v1,
            )
            entry.totp_secret = sealed
            modified = modified or changed

        if entry.two_fa_recovery:
            sealed, changed = crypto.seal_if_plaintext(
                entry.two_fa_recovery,
                aad=build_field_aad(entry.id, "two_fa_recovery"),
                upgrade_v1=upgrade_v1,
            )
            entry.two_fa_recovery = sealed
            modified = modified or changed

        qa_aad = build_field_aad(entry.id, "security_qa")
        for qa in entry.security_questions:
            if qa.answer:
                sealed, changed = crypto.seal_if_plaintext(
                    qa.answer,
                    aad=qa_aad,
                    upgrade_v1=upgrade_v1,
                )
                qa.answer = sealed
                modified = modified or changed

    # If any entry uses v2 encryption, ensure header verifier is also v2-protected
    # so older v1-only binaries refuse to unlock instead of double-encrypting v2 tokens.
    has_any_v2_field = any(
        is_v2_encrypted_token(e.password)
        or is_v2_encrypted_token(e.totp_secret)
        or is_v2_encrypted_token(e.two_fa_recovery)
        or any(is_v2_encrypted_token(qa.answer) for qa in e.security_questions)
        for e in doc.entries
    )
    if (
        has_any_v2_field
        and doc.header.salt
        and doc.header.verifier
        and not is_v2_encrypted_token(doc.header.verifier)
    ):
        doc.header.verifier = crypto.encrypt_value(VERIFIER_PLAINTEXT, aad=VERIFIER_AAD)
        doc.header.vault_version = max(doc.header.vault_version, 2)
        modified = True

    return modified


def decrypt_entry_for_view(entry: AccountEntry, crypto: CryptoEngine) -> AccountEntry:
    """Return a copy of AccountEntry with sensitive fields decrypted (verifying AAD on v2)."""
    copy_entry = entry.model_copy(deep=True)
    eid = copy_entry.id or "unknown"
    copy_entry.password = crypto.decrypt_if_needed(
        copy_entry.password, aad=build_field_aad(eid, "password")
    )
    copy_entry.totp_secret = crypto.decrypt_if_needed(
        copy_entry.totp_secret, aad=build_field_aad(eid, "totp_secret")
    )
    copy_entry.two_fa_recovery = crypto.decrypt_if_needed(
        copy_entry.two_fa_recovery, aad=build_field_aad(eid, "two_fa_recovery")
    )
    qa_aad = build_field_aad(eid, "security_qa")
    for qa in copy_entry.security_questions:
        qa.answer = crypto.decrypt_if_needed(qa.answer, aad=qa_aad)
    return copy_entry


def redact_entry_for_list(
    entry: AccountEntry, crypto: Optional[CryptoEngine] = None
) -> Dict[str, Any]:
    """
    Serialize non-secret metadata for UI list/detail rendering without exposing secrets.
    Computes accurate boolean flags (`has_totp`, `has_two_fa`) for the unified 2FA/TOTP field.
    """
    raw_has_totp_field = bool(entry.totp_secret and entry.totp_secret.strip())
    raw_has_two_fa_field = bool(entry.two_fa_recovery and entry.two_fa_recovery.strip())
    has_totp = raw_has_totp_field
    has_two_fa = raw_has_two_fa_field

    if crypto is not None and crypto.is_unlocked and raw_has_two_fa_field:
        try:
            two_fa_plain = crypto.decrypt_if_needed(
                entry.two_fa_recovery, aad=build_field_aad(entry.id, "two_fa_recovery")
            )
            extracted = extract_totp_from_text(two_fa_plain)
            if extracted:
                has_totp = True
                # Only show separate bottom 2FA recovery card if there are extra recovery lines
                # or a separate dedicated totp_secret was also present
                has_two_fa = raw_has_totp_field or has_extra_recovery_beyond_totp(two_fa_plain)
        except Exception:
            pass

    return {
        "id": entry.id,
        "category": entry.category,
        "title": entry.title,
        "platform": entry.platform,
        "tags": list(entry.tags),
        "favorite": bool(entry.favorite),
        "username": entry.username,
        "password": "",
        "has_password": bool(entry.password and entry.password.strip()),
        "phone": entry.phone,
        "recovery_email": entry.recovery_email,
        "url": entry.url,
        "security_questions": [
            {
                "question": qa.question,
                "answer": "",
                "has_answer": bool(qa.answer and qa.answer.strip()),
            }
            for qa in entry.security_questions
        ],
        "totp_secret": "",
        "has_totp": has_totp,
        "two_fa_recovery": "",
        "has_two_fa": has_two_fa,
        "notes": entry.notes,
        "custom_fields": dict(entry.custom_fields),
        "updated_at": entry.updated_at,
    }


def _unwrap_if_already_encrypted(value: str, crypto: CryptoEngine, aad: bytes) -> str:
    if not value:
        return ""
    if is_encrypted_token(value):
        try:
            return crypto.decrypt_if_needed(value, aad=aad)
        except CryptoError:
            return value
    return value


def encrypt_entry_for_storage(entry: AccountEntry, crypto: CryptoEngine) -> AccountEntry:
    """Encrypt plaintext sensitive fields from UI form into AAD-bound ENC[v2:...] storage form."""
    stored = entry.model_copy(deep=True)
    if not stored.id:
        stored.id = generate_entry_id()
    eid = stored.id
    pwd_aad = build_field_aad(eid, "password")
    totp_aad = build_field_aad(eid, "totp_secret")
    twofa_aad = build_field_aad(eid, "two_fa_recovery")
    qa_aad = build_field_aad(eid, "security_qa")

    pwd_plain = _unwrap_if_already_encrypted(stored.password, crypto, pwd_aad)
    totp_plain = _unwrap_if_already_encrypted(stored.totp_secret, crypto, totp_aad)
    twofa_plain = _unwrap_if_already_encrypted(stored.two_fa_recovery, crypto, twofa_aad)

    stored.password = crypto.encrypt_value(pwd_plain, aad=pwd_aad) if pwd_plain else ""
    stored.totp_secret = crypto.encrypt_value(totp_plain, aad=totp_aad) if totp_plain else ""
    stored.two_fa_recovery = (
        crypto.encrypt_value(twofa_plain, aad=twofa_aad) if twofa_plain else ""
    )

    new_qas: List[SecurityQA] = []
    for qa in stored.security_questions:
        q = qa.question.strip()
        a_plain = _unwrap_if_already_encrypted(qa.answer, crypto, qa_aad)
        if q or a_plain:
            new_qas.append(
                SecurityQA(
                    question=q,
                    answer=crypto.encrypt_value(a_plain, aad=qa_aad) if a_plain else "",
                )
            )
    stored.security_questions = new_qas
    return stored


def dumps_vault(doc: VaultDocument) -> str:
    """Serialize VaultDocument into a single, human-readable Markdown string."""
    header_dict: Dict[str, object] = {
        "vault_version": doc.header.vault_version,
        "vault_name": doc.header.vault_name,
        "kdf": doc.header.kdf,
        "kdf_iterations": doc.header.kdf_iterations,
        "salt": doc.header.salt,
        "verifier": doc.header.verifier,
    }
    if doc.header.saved_tags is not None:
        header_dict["saved_tags"] = doc.header.saved_tags
    header_dict["updated_at"] = doc.header.updated_at or now_timestamp()
    fm_yaml = yaml.safe_dump(
        header_dict,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    ).strip()

    # Build ordered category list preserving empty categories + any categories on entries
    ordered_categories: List[str] = []
    for cat in doc.categories:
        c = cat.strip()
        if c and c not in ordered_categories:
            ordered_categories.append(c)

    grouped: Dict[str, List[AccountEntry]] = {cat: [] for cat in ordered_categories}
    for entry in doc.entries:
        cat = (entry.category or "未分类").strip()
        if cat not in grouped:
            grouped[cat] = []
            ordered_categories.append(cat)
        grouped[cat].append(entry)

    lines: List[str] = [
        "---",
        fm_yaml,
        "---",
        "",
        f"# {doc.header.vault_name}",
        "",
        "> 本文件由 **MD-Vault** 本地维护，支持使用任意 Markdown 编辑器直接查阅与修改。",
        "> `ENC[v2:...]` 为主密码（AES-256-GCM + AAD 绑定）加密字段；请保留条目下方的 `<!-- id: ... -->` 注释。若在外部直接填入明文密码，下次解锁将自动加密落盘。",
        "",
    ]

    if ordered_categories:
        lines.append(f"## {TOC_HEADING}")
        lines.append("")
        for cat in ordered_categories:
            count = len(grouped.get(cat, []))
            lines.append(f"- [{cat} ({count})](#{_anchor_slug(cat)})")
        lines.append("")
        lines.append("---")
        lines.append("")

    for cat_idx, cat in enumerate(ordered_categories):
        lines.append(f"## {cat}")
        lines.append("")
        cat_entries = grouped.get(cat, [])
        if not cat_entries:
            lines.append(EMPTY_CAT_MARKER)
            lines.append("")
        else:
            for ent_idx, entry in enumerate(cat_entries):
                lines.append(f"### {entry.title.strip()}")
                lines.append(f"<!-- id: {entry.id} -->")
                if entry.favorite:
                    lines.append("- **收藏星标**: 是")
                if entry.platform.strip():
                    lines.append(f"- **服务/平台**: {entry.platform.strip()}")
                if entry.tags:
                    tags_fmt = ", ".join(_wrap_inline_code(t) for t in entry.tags if t.strip())
                    if tags_fmt:
                        lines.append(f"- **分区/标签**: {tags_fmt}")
                if entry.username.strip():
                    lines.append(f"- **登录账号**: {_wrap_inline_code(entry.username.strip())}")
                if entry.password.strip():
                    lines.append(f"- **登录密码**: {_wrap_inline_code(entry.password.strip())}")
                if entry.phone.strip():
                    lines.append(f"- **绑定手机**: {_wrap_inline_code(entry.phone.strip())}")
                if entry.recovery_email.strip():
                    lines.append(
                        f"- **辅助邮箱**: {_wrap_inline_code(entry.recovery_email.strip())}"
                    )
                if entry.url.strip():
                    lines.append(f"- **网址/入口**: {entry.url.strip()}")
                for c_key, c_val in entry.custom_fields.items():
                    if c_key.strip() and str(c_val).strip():
                        lines.append(f"- **{c_key.strip()}**: {str(c_val).strip()}")
                lines.append(f"- **更新日期**: {entry.updated_at or now_timestamp()}")
                lines.append("")

                has_security = (
                    bool(entry.security_questions)
                    or bool(entry.totp_secret.strip())
                    or bool(entry.two_fa_recovery.strip())
                )
                if has_security:
                    lines.append("#### 密保与恢复信息")
                    for q_idx, qa in enumerate(entry.security_questions, start=1):
                        q_text = qa.question.strip() or f"问题 {q_idx}"
                        a_text = _wrap_inline_code(qa.answer.strip()) if qa.answer.strip() else ""
                        lines.append(f"- **密保问题 {q_idx}**: {q_text} :: {a_text}".rstrip())
                    if entry.totp_secret.strip():
                        lines.append(
                            f"- **TOTP 密钥**: {_wrap_inline_code(entry.totp_secret.strip())}"
                        )
                    if entry.two_fa_recovery.strip():
                        lines.append(
                            f"- **2FA / 恢复码**: {_wrap_inline_code(entry.two_fa_recovery.strip())}"
                        )
                    lines.append("")

                if entry.notes.strip():
                    lines.append("#### 备注说明")
                    lines.extend(entry.notes.rstrip().splitlines())
                    lines.append("")

                if ent_idx < len(cat_entries) - 1:
                    lines.append("---")
                    lines.append("")

        if cat_idx < len(ordered_categories) - 1:
            lines.append("---")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def loads_vault(markdown_text: str) -> VaultDocument:
    """Parse a single Markdown vault file back into a structured VaultDocument."""
    text = markdown_text.replace("\r\n", "\n")
    header = VaultHeader()
    body = text

    # 1. Extract YAML frontmatter if present
    if text.startswith("---\n"):
        end_fm = text.find("\n---\n", 4)
        if end_fm != -1:
            raw_yaml = text[4:end_fm]
            loaded = yaml.safe_load(raw_yaml) or {}
            if isinstance(loaded, dict):
                raw_saved = loaded.get("saved_tags", None)
                parsed_saved_tags: Optional[Dict[str, List[str]]] = None
                if isinstance(raw_saved, dict):
                    parsed_saved_tags = {}
                    for k, v in raw_saved.items():
                        cat_key = str(k).strip()
                        if cat_key and isinstance(v, list):
                            parsed_saved_tags[cat_key] = [
                                str(item).strip() for item in v if str(item).strip()
                            ]
                header = VaultHeader(
                    vault_version=int(loaded.get("vault_version", 1)),
                    vault_name=str(loaded.get("vault_name", "我的账号密码库")),
                    kdf=str(loaded.get("kdf", "pbkdf2-sha256")),
                    kdf_iterations=int(loaded.get("kdf_iterations", 600000)),
                    salt=str(loaded.get("salt", "")),
                    verifier=str(loaded.get("verifier", "")),
                    saved_tags=parsed_saved_tags,
                    updated_at=str(loaded.get("updated_at", now_timestamp())),
                )
            body = text[end_fm + 5 :]

    categories: List[str] = []
    entries: List[AccountEntry] = []

    current_category: Optional[str] = None
    in_toc = False
    current_entry: Optional[AccountEntry] = None
    current_sub: str = "main"  # "main" | "security" | "notes"
    note_lines: List[str] = []
    seen_ids: set[str] = set()

    def finalize_entry() -> None:
        nonlocal current_entry, note_lines, current_sub
        if current_entry is None:
            return
        if note_lines:
            # Trim leading/trailing blank lines and trailing horizontal rule divider
            while note_lines and not note_lines[0].strip():
                note_lines.pop(0)
            while note_lines and (
                not note_lines[-1].strip() or note_lines[-1].strip() == "---"
            ):
                note_lines.pop()
            current_entry.notes = "\n".join(note_lines)
        if not current_entry.id or current_entry.id in seen_ids:
            current_entry.id = generate_entry_id()
        seen_ids.add(current_entry.id)
        entries.append(current_entry)
        current_entry = None
        note_lines = []
        current_sub = "main"

    for line in body.split("\n"):
        stripped = line.strip()

        # Top-level H1 vault title
        if line.startswith("# ") and not line.startswith("## "):
            h1_title = line[2:].strip()
            if h1_title and header.vault_name == "我的账号密码库":
                header.vault_name = h1_title
            continue

        # Category H2
        if line.startswith("## ") and not line.startswith("### "):
            finalize_entry()
            h2_title = line[3:].strip()
            if h2_title == TOC_HEADING:
                in_toc = True
                current_category = None
            else:
                in_toc = False
                current_category = h2_title
                if current_category and current_category not in categories:
                    categories.append(current_category)
            continue

        if in_toc:
            continue

        # Entry H3
        if line.startswith("### ") and not line.startswith("#### "):
            finalize_entry()
            ent_title = line[4:].strip()
            cat_name = current_category or "未分类"
            if cat_name not in categories:
                categories.append(cat_name)
            current_entry = AccountEntry(
                id="",
                category=cat_name,
                title=ent_title or "未命名账号",
                updated_at=now_timestamp(),
            )
            current_sub = "main"
            continue

        if current_entry is None:
            continue

        # Entry Subsections H4
        if line.startswith("#### "):
            sub_title = line[5:].strip()
            if (
                "密保" in sub_title
                or "恢复" in sub_title
                or "2FA" in sub_title.upper()
                or "TOTP" in sub_title.upper()
            ):
                current_sub = "security"
            elif "备注" in sub_title or "说明" in sub_title:
                current_sub = "notes"
            else:
                current_sub = "notes"
                note_lines.append(line)
            continue

        # Inside Notes subsection
        if current_sub == "notes":
            note_lines.append(line)
            continue

        # ID HTML comment
        id_match = ID_COMMENT_RE.match(stripped)
        if id_match:
            current_entry.id = id_match.group(1)
            continue

        if not stripped or stripped == "---" or stripped == EMPTY_CAT_MARKER:
            continue

        # Bullet key-value pairs
        kv_match = BULLET_KV_RE.match(stripped)
        if kv_match:
            key = kv_match.group(1).strip()
            raw_val = kv_match.group(2).strip()

            if current_sub == "security":
                if key.startswith("密保问题") or key.lower().startswith("question"):
                    q_part = raw_val
                    a_part = ""
                    if " :: " in raw_val:
                        q_part, a_part = raw_val.rsplit(" :: ", 1)
                    elif "::" in raw_val:
                        q_part, a_part = raw_val.rsplit("::", 1)
                    elif " -> " in raw_val:
                        q_part, a_part = raw_val.rsplit(" -> ", 1)
                    current_entry.security_questions.append(
                        SecurityQA(
                            question=q_part.strip(),
                            answer=_strip_single_backticks(a_part),
                        )
                    )
                elif "TOTP" in key.upper() or "动态码" in key or "动态口令" in key:
                    current_entry.totp_secret = _strip_single_backticks(raw_val)
                elif "2FA" in key.upper() or "恢复码" in key:
                    current_entry.two_fa_recovery = _strip_single_backticks(raw_val)
                else:
                    current_entry.custom_fields[key] = raw_val
            else:
                if key in ("服务/平台", "平台", "服务"):
                    current_entry.platform = _strip_single_backticks(raw_val)
                elif key in ("分区/标签", "标签", "地区", "分区"):
                    current_entry.tags = _parse_tags(raw_val)
                elif key in ("收藏星标", "收藏", "星标"):
                    current_entry.favorite = raw_val.lower() in ("是", "true", "yes", "1", "⭐")
                elif key in ("登录账号", "账号", "用户名"):
                    current_entry.username = _strip_single_backticks(raw_val)
                elif key in ("登录密码", "密码"):
                    current_entry.password = _strip_single_backticks(raw_val)
                elif "TOTP" in key.upper() or key in ("动态码密钥", "动态口令"):
                    current_entry.totp_secret = _strip_single_backticks(raw_val)
                elif key in ("绑定手机", "手机号", "手机"):
                    current_entry.phone = _strip_single_backticks(raw_val)
                elif key in ("辅助邮箱", "绑定邮箱", "恢复邮箱"):
                    current_entry.recovery_email = _strip_single_backticks(raw_val)
                elif key in ("网址/入口", "网址", "链接", "URL"):
                    current_entry.url = _strip_single_backticks(raw_val)
                elif key in ("更新日期", "更新时间"):
                    current_entry.updated_at = _strip_single_backticks(raw_val)
                else:
                    current_entry.custom_fields[key] = raw_val

    finalize_entry()
    return VaultDocument(header=header, categories=categories, entries=entries)
