from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

import yaml

from core.crypto import CryptoEngine
from core.models import (
    AccountEntry,
    SecurityQA,
    VaultDocument,
    VaultHeader,
    generate_entry_id,
    now_timestamp,
)

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


def seal_document_entries(doc: VaultDocument, crypto: CryptoEngine) -> bool:
    """
    Ensure all sensitive fields in doc.entries are encrypted with ENC[v1:...].
    Returns True if any plaintext sensitive field was newly sealed.
    """
    modified = False
    for entry in doc.entries:
        if entry.password:
            sealed, changed = crypto.seal_if_plaintext(entry.password)
            entry.password = sealed
            modified = modified or changed

        if entry.two_fa_recovery:
            sealed, changed = crypto.seal_if_plaintext(entry.two_fa_recovery)
            entry.two_fa_recovery = sealed
            modified = modified or changed

        for qa in entry.security_questions:
            if qa.answer:
                sealed, changed = crypto.seal_if_plaintext(qa.answer)
                qa.answer = sealed
                modified = modified or changed
    return modified


def decrypt_entry_for_view(entry: AccountEntry, crypto: CryptoEngine) -> AccountEntry:
    """Return a copy of AccountEntry with sensitive fields decrypted for UI display."""
    copy_entry = entry.model_copy(deep=True)
    copy_entry.password = crypto.decrypt_if_needed(copy_entry.password)
    copy_entry.two_fa_recovery = crypto.decrypt_if_needed(copy_entry.two_fa_recovery)
    for qa in copy_entry.security_questions:
        qa.answer = crypto.decrypt_if_needed(qa.answer)
    return copy_entry


def encrypt_entry_for_storage(entry: AccountEntry, crypto: CryptoEngine) -> AccountEntry:
    """Encrypt plaintext sensitive fields from UI form into ENC[v1:...] storage form."""
    stored = entry.model_copy(deep=True)
    stored.password = crypto.encrypt_value(stored.password) if stored.password else ""
    stored.two_fa_recovery = (
        crypto.encrypt_value(stored.two_fa_recovery) if stored.two_fa_recovery else ""
    )
    new_qas: List[SecurityQA] = []
    for qa in stored.security_questions:
        q = qa.question.strip()
        a = qa.answer
        if q or a:
            new_qas.append(
                SecurityQA(
                    question=q,
                    answer=crypto.encrypt_value(a) if a else "",
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
        "> `ENC[v1:...]` 为主密码（AES-256-GCM）加密字段；若你在外部编辑器直接填入明文密码，下次在客户端解锁后将自动加密落盘。",
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

                has_security = bool(entry.security_questions) or bool(entry.two_fa_recovery.strip())
                if has_security:
                    lines.append("#### 密保与恢复信息")
                    for q_idx, qa in enumerate(entry.security_questions, start=1):
                        q_text = qa.question.strip() or f"问题 {q_idx}"
                        a_text = _wrap_inline_code(qa.answer.strip()) if qa.answer.strip() else ""
                        lines.append(f"- **密保问题 {q_idx}**: {q_text} :: {a_text}".rstrip())
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
            if "密保" in sub_title or "恢复" in sub_title or "2FA" in sub_title:
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
