from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.crypto import (
    CryptoEngine,
    CryptoError,
    CryptoIntegrityError,
    InvalidMasterPasswordError,
)
from core.markdown_codec import (
    decrypt_entry_for_view,
    dumps_vault,
    encrypt_entry_for_storage,
    loads_vault,
    seal_document_entries,
)
from core.models import (
    AccountEntry,
    SecurityQA,
    VaultDocument,
    VaultHeader,
    generate_entry_id,
    now_timestamp,
)
from core.password_gen import generate_password
from core.storage import VaultStorage


def _build_starter_entries(crypto: CryptoEngine) -> tuple[List[str], List[AccountEntry]]:
    """Build helpful categorized starter templates for Apple ID regions & emails."""
    categories = [
        "苹果商店与生态",
        "邮箱账号",
        "开发与云服务",
        "社交与娱乐",
    ]
    raw_entries = [
        AccountEntry(
            category="苹果商店与生态",
            title="Apple Store · 美区主力号（示例）",
            platform="Apple ID",
            tags=["美区", "主力", "免税州"],
            favorite=True,
            username="us_apple_demo@gmail.com",
            password="Demo#US_Apple_2026!",
            phone="+1 (302) 555-0199",
            recovery_email="my_main_mail@gmail.com",
            url="https://account.apple.com",
            security_questions=[
                SecurityQA(question="你少年时代最好的朋友叫什么名字？", answer="Alex"),
                SecurityQA(question="你的第一份工作是在哪个城市？", answer="Seattle"),
                SecurityQA(question="你理想的工作是什么？", answer="Architect"),
            ],
            two_fa_recovery="RK9X-72LM-99PA-44QW",
            notes="免税州地址：Delaware (DE)，邮编 19702。\n可直接编辑此示例为您真实的美区账号，或删除此示例。",
        ),
        AccountEntry(
            category="苹果商店与生态",
            title="Apple Store · 国区日常号（示例）",
            platform="Apple ID",
            tags=["国区", "日常", "iCloud"],
            favorite=False,
            username="cn_apple_demo@icloud.com",
            password="Demo#CN_Apple_2026!",
            phone="+86 138-0000-0000",
            recovery_email="backup_cn@qq.com",
            url="https://account.apple.com",
            notes="绑定国内常用支付方式，用于日常国区 App 下载与家庭共享。",
        ),
        AccountEntry(
            category="苹果商店与生态",
            title="Apple Store · 土耳其区订阅号（示例）",
            platform="Apple ID",
            tags=["土耳其区", "低价订阅"],
            favorite=False,
            username="tr_apple_demo@outlook.com",
            password="Demo#TR_Apple_2026!",
            recovery_email="us_apple_demo@gmail.com",
            url="https://account.apple.com",
            notes="专用于高性价比订阅服务，平时通过土区礼品卡充值。",
        ),
        AccountEntry(
            category="邮箱账号",
            title="Gmail · 个人核心主邮箱（示例）",
            platform="Google / Gmail",
            tags=["主力", "海外服务绑定"],
            favorite=True,
            username="my_main_mail@gmail.com",
            password="Demo#Gmail_Master_88!",
            phone="+86 138-0000-0000",
            recovery_email="backup_mail@outlook.com",
            url="https://mail.google.com",
            two_fa_recovery="1928 3746 / 5647 3829 / 9182 7364",
            notes="核心绑定邮箱，已开启 Google Authenticator 两步验证。",
        ),
    ]
    encrypted_entries = [encrypt_entry_for_storage(e, crypto) for e in raw_entries]
    return categories, encrypted_entries


class VaultApi:
    """In-process Python backend API exposed to the pywebview desktop window."""

    def __init__(self, project_root: Path):
        self._project_root = project_root
        self._storage = VaultStorage(project_root)
        self._crypto: Optional[CryptoEngine] = None
        self._doc: Optional[VaultDocument] = None
        self._window: Any = None
        self._clipboard_timer: Optional[threading.Timer] = None
        self._lock = threading.RLock()

        self._storage.start_watching(self._notify_frontend_external_change)

    def _bind_window(self, window: Any) -> None:
        self._window = window

    def _notify_frontend_external_change(self) -> None:
        if self._window is not None:
            try:
                self._window.evaluate_js(
                    "window.onExternalVaultChanged && window.onExternalVaultChanged();"
                )
            except Exception:
                pass

    @staticmethod
    def _ensure_saved_tags(doc: VaultDocument) -> bool:
        """Initialize per-category saved_tags from existing entries if absent in frontmatter."""
        if doc.header.saved_tags is not None:
            return False
        seeded: Dict[str, List[str]] = {}
        for entry in doc.entries:
            cat = (entry.category or "未分类").strip()
            bucket = seeded.setdefault(cat, [])
            for t in entry.tags:
                clean_t = t.strip()
                if clean_t and clean_t not in bucket:
                    bucket.append(clean_t)
        doc.header.saved_tags = seeded
        return True

    @staticmethod
    def _merge_tags_into_saved(doc: VaultDocument, category: str, tags: List[str]) -> None:
        if doc.header.saved_tags is None:
            doc.header.saved_tags = {}
        bucket = doc.header.saved_tags.setdefault(category, [])
        for t in tags:
            clean_t = t.strip()
            if clean_t and clean_t not in bucket:
                bucket.append(clean_t)

    def _serialize_unlocked_state(self, auto_sealed: bool = False) -> Dict[str, Any]:
        if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
            raise CryptoError("密码库尚未解锁")

        decrypted_entries = [
            decrypt_entry_for_view(e, self._crypto).model_dump() for e in self._doc.entries
        ]
        # Collect tag frequency preserving appearance order
        tag_counts: Dict[str, int] = {}
        for e in self._doc.entries:
            for t in e.tags:
                tag_counts[t] = tag_counts.get(t, 0) + 1

        categories: List[str] = list(self._doc.categories)
        for e in self._doc.entries:
            if e.category not in categories:
                categories.append(e.category)

        return {
            "ok": True,
            "is_unlocked": True,
            "vault_path": str(self._storage.vault_path),
            "vault_name": self._doc.header.vault_name,
            "updated_at": self._doc.header.updated_at,
            "categories": categories,
            "entries": decrypted_entries,
            "tag_counts": tag_counts,
            "saved_tags": dict(self._doc.header.saved_tags or {}),
            "auto_sealed": auto_sealed,
            "external_changed": self._storage.external_changed,
        }

    def get_status(self) -> Dict[str, Any]:
        """Return initial boot status of the vault."""
        with self._lock:
            exists = self._storage.exists()
            vault_name = "我的账号密码库"
            if exists:
                try:
                    doc = loads_vault(self._storage.read_markdown())
                    vault_name = doc.header.vault_name
                except Exception:
                    pass
            return {
                "ok": True,
                "exists": exists,
                "is_unlocked": bool(self._crypto and self._crypto.is_unlocked),
                "vault_path": str(self._storage.vault_path),
                "vault_name": vault_name,
                "external_changed": self._storage.external_changed,
            }

    def create_vault(
        self,
        master_password: str,
        vault_name: str = "我的账号密码库",
        use_starter_template: bool = True,
    ) -> Dict[str, Any]:
        """Initialize a brand-new encrypted single-file Markdown vault."""
        with self._lock:
            pwd = master_password or ""
            if not pwd.strip() or len(pwd) < 4:
                return {"ok": False, "error": "主密码长度至少需要 4 个字符（且不能全为空格）"}

            engine, salt_b64, verifier = CryptoEngine.create_new(pwd)
            clean_name = (vault_name or "我的账号密码库").strip()

            if use_starter_template:
                categories, entries = _build_starter_entries(engine)
            else:
                categories = ["苹果商店与生态", "邮箱账号", "常用软件"]
                entries = []

            doc = VaultDocument(
                header=VaultHeader(
                    vault_version=1,
                    vault_name=clean_name,
                    salt=salt_b64,
                    verifier=verifier,
                    saved_tags=None,
                    updated_at=now_timestamp(),
                ),
                categories=categories,
                entries=entries,
            )
            self._ensure_saved_tags(doc)
            md_text = dumps_vault(doc)
            self._storage.write_markdown(md_text)
            self._storage.start_watching(self._notify_frontend_external_change)

            self._crypto = engine
            self._doc = doc
            return self._serialize_unlocked_state()

    def unlock_vault(self, master_password: str) -> Dict[str, Any]:
        """Unlock existing Markdown vault and auto-seal any plaintext credentials."""
        with self._lock:
            if not self._storage.exists():
                return {"ok": False, "error": "当前路径下尚未创建密码库文件"}

            try:
                raw_md = self._storage.read_markdown()
                doc = loads_vault(raw_md)
            except Exception as exc:
                return {"ok": False, "error": f"解析 Markdown 文件失败: {exc}"}

            # Support unlocking a hand-crafted Markdown file that hasn't initialized salt/verifier yet
            if not doc.header.salt or not doc.header.verifier:
                engine, salt_b64, verifier = CryptoEngine.create_new(master_password)
                doc.header.salt = salt_b64
                doc.header.verifier = verifier
                seal_document_entries(doc, engine)
                self._ensure_saved_tags(doc)
                doc.header.updated_at = now_timestamp()
                self._storage.write_markdown(dumps_vault(doc))
                self._crypto = engine
                self._doc = doc
                return self._serialize_unlocked_state(auto_sealed=True)

            try:
                engine = CryptoEngine.unlock_existing(
                    master_password=master_password,
                    salt_b64=doc.header.salt,
                    verifier_token=doc.header.verifier,
                    iterations=doc.header.kdf_iterations,
                )
            except InvalidMasterPasswordError as exc:
                return {"ok": False, "error": str(exc)}
            except CryptoError as exc:
                return {"ok": False, "error": f"加密校验异常: {exc}"}

            # Verify entries can decrypt cleanly & auto-seal any external plaintext edits
            try:
                was_sealed = seal_document_entries(doc, engine)
                for entry in doc.entries:
                    decrypt_entry_for_view(entry, engine)
            except CryptoIntegrityError as exc:
                engine.lock()
                return {"ok": False, "error": f"部分加密字段损坏或与当前主密码不匹配: {exc}"}

            tags_seeded = self._ensure_saved_tags(doc)
            if was_sealed or tags_seeded:
                doc.header.updated_at = now_timestamp()
                self._storage.write_markdown(dumps_vault(doc))

            self._crypto = engine
            self._doc = doc
            return self._serialize_unlocked_state(auto_sealed=was_sealed)

    def lock_vault(self) -> Dict[str, Any]:
        """Lock vault and purge key and entries from memory."""
        with self._lock:
            if self._crypto is not None:
                self._crypto.lock()
                self._crypto = None
            self._doc = None
            return self.get_status()

    def reload_from_disk(self) -> Dict[str, Any]:
        """Re-parse the .md file from disk while unlocked (handling external editor changes)."""
        with self._lock:
            if self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定，请先解锁"}
            try:
                raw_md = self._storage.read_markdown()
                doc = loads_vault(raw_md)
                was_sealed = seal_document_entries(doc, self._crypto)
                tags_seeded = self._ensure_saved_tags(doc)
                if was_sealed or tags_seeded:
                    doc.header.updated_at = now_timestamp()
                    self._storage.write_markdown(dumps_vault(doc))
                self._doc = doc
                return self._serialize_unlocked_state(auto_sealed=was_sealed)
            except Exception as exc:
                return {"ok": False, "error": f"重新读取本地文件失败: {exc}"}

    def get_vault_data(self) -> Dict[str, Any]:
        """Return full unlocked state."""
        with self._lock:
            try:
                return self._serialize_unlocked_state()
            except Exception as exc:
                return {"ok": False, "error": str(exc)}

    def _persist_current_doc(self) -> None:
        assert self._doc is not None
        self._doc.header.updated_at = now_timestamp()
        self._storage.write_markdown(dumps_vault(self._doc))

    def save_entry(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Create or update an account entry and persist to the single Markdown file."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}

            title = str(payload.get("title", "")).strip()
            if not title:
                return {"ok": False, "error": "请填写账号条目名称（例如：Apple Store · 美区主力号）"}

            category = str(payload.get("category", "")).strip() or "未分类"
            entry_id = str(payload.get("id", "")).strip()

            raw_tags = payload.get("tags", [])
            if isinstance(raw_tags, str):
                tags = [t.strip() for t in raw_tags.replace("，", ",").split(",") if t.strip()]
            else:
                tags = [str(t).strip() for t in raw_tags if str(t).strip()]

            raw_qas = payload.get("security_questions", []) or []
            qas: List[SecurityQA] = []
            for item in raw_qas:
                if isinstance(item, dict):
                    q = str(item.get("question", "")).strip()
                    a = str(item.get("answer", "")).strip()
                    if q or a:
                        qas.append(SecurityQA(question=q, answer=a))

            existing_custom: Dict[str, str] = {}
            existing_idx: Optional[int] = None
            if entry_id:
                for idx, ent in enumerate(self._doc.entries):
                    if ent.id == entry_id:
                        existing_idx = idx
                        existing_custom = dict(ent.custom_fields)
                        break

            plain_entry = AccountEntry(
                id=entry_id or generate_entry_id(),
                category=category,
                title=title,
                platform=str(payload.get("platform", "")).strip(),
                tags=tags,
                favorite=bool(payload.get("favorite", False)),
                username=str(payload.get("username", "")).strip(),
                password=str(payload.get("password", "")),
                phone=str(payload.get("phone", "")).strip(),
                recovery_email=str(payload.get("recovery_email", "")).strip(),
                url=str(payload.get("url", "")).strip(),
                security_questions=qas,
                two_fa_recovery=str(payload.get("two_fa_recovery", "")).strip(),
                notes=str(payload.get("notes", "")).rstrip(),
                custom_fields=payload.get("custom_fields") or existing_custom,
                updated_at=now_timestamp(),
            )

            encrypted_entry = encrypt_entry_for_storage(plain_entry, self._crypto)

            if category not in self._doc.categories:
                self._doc.categories.append(category)

            # Auto-save user-entered tags under this category's quick-tags list
            self._merge_tags_into_saved(self._doc, category, tags)

            if existing_idx is not None:
                self._doc.entries[existing_idx] = encrypted_entry
            else:
                self._doc.entries.insert(0, encrypted_entry)

            self._persist_current_doc()
            res = self._serialize_unlocked_state()
            res["saved_id"] = encrypted_entry.id
            return res

    def delete_entry(self, entry_id: str) -> Dict[str, Any]:
        """Delete an account entry by ID."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            before = len(self._doc.entries)
            self._doc.entries = [e for e in self._doc.entries if e.id != entry_id]
            if len(self._doc.entries) == before:
                return {"ok": False, "error": "未找到要删除的账号记录"}
            self._persist_current_doc()
            return self._serialize_unlocked_state()

    def toggle_favorite(self, entry_id: str) -> Dict[str, Any]:
        """Toggle favorite star on an account entry."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            for ent in self._doc.entries:
                if ent.id == entry_id:
                    ent.favorite = not ent.favorite
                    ent.updated_at = now_timestamp()
                    self._persist_current_doc()
                    return self._serialize_unlocked_state()
            return {"ok": False, "error": "未找到对应账号"}

    def add_category(self, name: str) -> Dict[str, Any]:
        """Add a new category heading to the Markdown vault."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            clean = (name or "").strip()
            if not clean:
                return {"ok": False, "error": "分类名称不能为空"}
            if clean in self._doc.categories:
                return {"ok": False, "error": f"分类「{clean}」已存在"}
            self._doc.categories.append(clean)
            self._persist_current_doc()
            return self._serialize_unlocked_state()

    def rename_category(self, old_name: str, new_name: str) -> Dict[str, Any]:
        """Rename an existing category and update all its entries."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            old_c = (old_name or "").strip()
            new_c = (new_name or "").strip()
            if not new_c:
                return {"ok": False, "error": "新分类名称不能为空"}
            if old_c == new_c:
                return self._serialize_unlocked_state()

            updated_cats: List[str] = []
            for c in self._doc.categories:
                mapped = new_c if c == old_c else c
                if mapped not in updated_cats:
                    updated_cats.append(mapped)
            if new_c not in updated_cats:
                updated_cats.append(new_c)
            self._doc.categories = updated_cats

            for ent in self._doc.entries:
                if ent.category == old_c:
                    ent.category = new_c

            if self._doc.header.saved_tags is not None and old_c in self._doc.header.saved_tags:
                old_tags = self._doc.header.saved_tags.pop(old_c)
                self._merge_tags_into_saved(self._doc, new_c, old_tags)

            self._persist_current_doc()
            return self._serialize_unlocked_state()

    def delete_category(self, name: str, move_to: str = "未分类") -> Dict[str, Any]:
        """Delete a category; if it has entries, move them to fallback category."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            target = (name or "").strip()
            has_entries = any(e.category == target for e in self._doc.entries)
            self._doc.categories = [c for c in self._doc.categories if c != target]
            fallback = (move_to or "未分类").strip()
            if fallback == target:
                fallback = "未分类"
            if has_entries:
                if fallback not in self._doc.categories:
                    self._doc.categories.append(fallback)
                for ent in self._doc.entries:
                    if ent.category == target:
                        ent.category = fallback
            if self._doc.header.saved_tags is not None and target in self._doc.header.saved_tags:
                moved_tags = self._doc.header.saved_tags.pop(target)
                if has_entries:
                    self._merge_tags_into_saved(self._doc, fallback, moved_tags)
            self._persist_current_doc()
            return self._serialize_unlocked_state()

    def add_saved_tag(self, category: str, tag: str) -> Dict[str, Any]:
        """Save a quick tag under a specific category."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            clean_cat = (category or "未分类").strip()
            clean_tag = (tag or "").strip()
            if not clean_tag:
                return {"ok": False, "error": "标签不能为空"}
            self._merge_tags_into_saved(self._doc, clean_cat, [clean_tag])
            self._persist_current_doc()
            return self._serialize_unlocked_state()

    def delete_saved_tag(self, category: str, tag: str) -> Dict[str, Any]:
        """Remove a saved quick tag from a category (or across all if category is empty)."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            clean_cat = (category or "").strip()
            clean_tag = (tag or "").strip()
            if self._doc.header.saved_tags is None:
                self._ensure_saved_tags(self._doc)
            assert self._doc.header.saved_tags is not None

            if clean_cat:
                if clean_cat in self._doc.header.saved_tags:
                    self._doc.header.saved_tags[clean_cat] = [
                        t for t in self._doc.header.saved_tags[clean_cat] if t != clean_tag
                    ]
            else:
                for cat_key in list(self._doc.header.saved_tags.keys()):
                    self._doc.header.saved_tags[cat_key] = [
                        t for t in self._doc.header.saved_tags[cat_key] if t != clean_tag
                    ]

            self._persist_current_doc()
            return self._serialize_unlocked_state()

    def generate_random_password(self, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate a strong random password with customizable rules."""
        opts = options or {}
        pwd = generate_password(
            length=int(opts.get("length", 18)),
            use_upper=bool(opts.get("use_upper", True)),
            use_lower=bool(opts.get("use_lower", True)),
            use_digits=bool(opts.get("use_digits", True)),
            use_symbols=bool(opts.get("use_symbols", True)),
            exclude_ambiguous=bool(opts.get("exclude_ambiguous", True)),
        )
        return {"ok": True, "password": pwd}

    def change_master_password(self, current_password: str, new_password: str) -> Dict[str, Any]:
        """Verify current master password and re-encrypt entire vault with a new key & salt."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            new_pwd = new_password or ""
            if not new_pwd.strip() or len(new_pwd) < 4:
                return {"ok": False, "error": "新主密码长度至少需要 4 个字符（且不能全为空格）"}

            # Verify current password against header
            try:
                CryptoEngine.unlock_existing(
                    master_password=current_password,
                    salt_b64=self._doc.header.salt,
                    verifier_token=self._doc.header.verifier,
                    iterations=self._doc.header.kdf_iterations,
                )
            except InvalidMasterPasswordError:
                return {"ok": False, "error": "当前主密码输入错误"}

            # Decrypt all entries in memory using old engine
            plain_entries = [decrypt_entry_for_view(e, self._crypto) for e in self._doc.entries]

            # Create brand-new engine, salt, and verifier
            new_engine, new_salt, new_verifier = CryptoEngine.create_new(
                new_pwd, iterations=self._doc.header.kdf_iterations
            )
            re_encrypted = [encrypt_entry_for_storage(e, new_engine) for e in plain_entries]

            old_engine = self._crypto
            self._doc.header.salt = new_salt
            self._doc.header.verifier = new_verifier
            self._doc.entries = re_encrypted
            self._crypto = new_engine
            self._persist_current_doc()
            old_engine.lock()

            return self._serialize_unlocked_state()

    def copy_to_clipboard(self, text: str, auto_clear_seconds: int = 0) -> Dict[str, Any]:
        """Copy text to OS clipboard and optionally auto-clear after N seconds if unchanged."""
        if text is None:
            return {"ok": False, "error": "复制内容为空"}
        try:
            self._set_clipboard_text(str(text))
        except Exception as exc:
            return {"ok": False, "error": f"写入剪贴板失败: {exc}"}

        if self._clipboard_timer is not None:
            self._clipboard_timer.cancel()
            self._clipboard_timer = None

        if auto_clear_seconds and auto_clear_seconds > 0:
            copied_snapshot = str(text)

            def _clear_if_same() -> None:
                try:
                    current = self._get_clipboard_text()
                    if current == copied_snapshot:
                        self._set_clipboard_text("")
                except Exception:
                    pass

            timer = threading.Timer(float(auto_clear_seconds), _clear_if_same)
            timer.daemon = True
            self._clipboard_timer = timer
            timer.start()

        return {"ok": True}

    @staticmethod
    def _set_clipboard_text(value: str) -> None:
        if sys.platform == "darwin":
            env = {**os.environ, "LANG": "en_US.UTF-8", "LC_CTYPE": "UTF-8"}
            subprocess.run(["pbcopy"], input=value.encode("utf-8"), env=env, check=True)
            return

        if sys.platform == "win32":
            try:
                VaultApi._win32_set_clipboard(value)
                return
            except Exception:
                pass

        import tkinter as tk

        root = tk.Tk()
        root.withdraw()
        root.clipboard_clear()
        root.clipboard_append(value)
        root.update()
        root.destroy()

    @staticmethod
    def _get_clipboard_text() -> str:
        if sys.platform == "darwin":
            env = {**os.environ, "LANG": "en_US.UTF-8", "LC_CTYPE": "UTF-8"}
            res = subprocess.run(["pbpaste"], capture_output=True, env=env, check=True)
            return res.stdout.decode("utf-8", errors="replace")

        if sys.platform == "win32":
            try:
                return VaultApi._win32_get_clipboard()
            except Exception:
                pass

        import tkinter as tk

        root = tk.Tk()
        root.withdraw()
        try:
            val = root.clipboard_get()
        except Exception:
            val = ""
        root.destroy()
        return val

    @staticmethod
    def _win32_set_clipboard(value: str) -> None:
        import ctypes

        CF_UNICODETEXT = 13
        GMEM_MOVEABLE = 0x0002

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        user32.OpenClipboard.argtypes = [ctypes.c_void_p]
        user32.OpenClipboard.restype = ctypes.c_int
        user32.EmptyClipboard.argtypes = []
        user32.EmptyClipboard.restype = ctypes.c_int
        user32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
        user32.SetClipboardData.restype = ctypes.c_void_p
        user32.CloseClipboard.argtypes = []
        user32.CloseClipboard.restype = ctypes.c_int

        kernel32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
        kernel32.GlobalAlloc.restype = ctypes.c_void_p
        kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalLock.restype = ctypes.c_void_p
        kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalUnlock.restype = ctypes.c_int
        kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
        kernel32.GlobalFree.restype = ctypes.c_void_p

        encoded = value.encode("utf-16-le") + b"\x00\x00"
        opened = False
        for _ in range(5):
            if user32.OpenClipboard(None):
                opened = True
                break
            time.sleep(0.01)
        if not opened:
            raise RuntimeError("无法打开系统剪贴板")

        try:
            user32.EmptyClipboard()
            h_mem = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(encoded))
            if not h_mem:
                raise MemoryError("剪贴板内存分配失败")
            ptr = kernel32.GlobalLock(h_mem)
            if not ptr:
                kernel32.GlobalFree(h_mem)
                raise MemoryError("剪贴板内存锁定失败")
            try:
                ctypes.memmove(ptr, encoded, len(encoded))
            finally:
                kernel32.GlobalUnlock(h_mem)
            if not user32.SetClipboardData(CF_UNICODETEXT, h_mem):
                kernel32.GlobalFree(h_mem)
                raise RuntimeError("写入剪贴板数据失败")
        finally:
            user32.CloseClipboard()

    @staticmethod
    def _win32_get_clipboard() -> str:
        import ctypes

        CF_UNICODETEXT = 13
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        user32.OpenClipboard.argtypes = [ctypes.c_void_p]
        user32.OpenClipboard.restype = ctypes.c_int
        user32.IsClipboardFormatAvailable.argtypes = [ctypes.c_uint]
        user32.IsClipboardFormatAvailable.restype = ctypes.c_int
        user32.GetClipboardData.argtypes = [ctypes.c_uint]
        user32.GetClipboardData.restype = ctypes.c_void_p
        user32.CloseClipboard.argtypes = []
        user32.CloseClipboard.restype = ctypes.c_int

        kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalLock.restype = ctypes.c_void_p
        kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalUnlock.restype = ctypes.c_int

        opened = False
        for _ in range(5):
            if user32.OpenClipboard(None):
                opened = True
                break
            time.sleep(0.01)
        if not opened:
            return ""

        try:
            if not user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
                return ""
            h_data = user32.GetClipboardData(CF_UNICODETEXT)
            if not h_data:
                return ""
            ptr = kernel32.GlobalLock(h_data)
            if not ptr:
                return ""
            try:
                return ctypes.wstring_at(ptr)
            finally:
                kernel32.GlobalUnlock(h_data)
        finally:
            user32.CloseClipboard()

    def choose_existing_vault_file(self) -> Dict[str, Any]:
        """Open native OS file picker to mount an existing .md vault file."""
        if self._window is None:
            return {"ok": False, "error": "窗口尚未就绪"}
        import webview

        open_mode = webview.FileDialog.OPEN if hasattr(webview, "FileDialog") else webview.OPEN_DIALOG
        dialog_dir = self._storage.vault_path.parent
        if not dialog_dir.exists():
            dialog_dir = Path.home()

        result = self._window.create_file_dialog(
            open_mode,
            directory=str(dialog_dir),
            allow_multiple=False,
            file_types=("Markdown 文件 (*.md)", "所有文件 (*.*)"),
        )
        if not result:
            return {"ok": False, "cancelled": True}

        chosen = Path(result[0] if isinstance(result, (list, tuple)) else result)
        with self._lock:
            if self._crypto is not None:
                self._crypto.lock()
                self._crypto = None
            self._doc = None
            self._storage.set_vault_path(chosen)
            return self.get_status()

    def choose_new_vault_location(self) -> Dict[str, Any]:
        """Open native OS save dialog to choose where a new .md vault will be saved."""
        if self._window is None:
            return {"ok": False, "error": "窗口尚未就绪"}
        import webview

        save_mode = webview.FileDialog.SAVE if hasattr(webview, "FileDialog") else webview.SAVE_DIALOG
        dialog_dir = self._storage.vault_path.parent
        try:
            dialog_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            dialog_dir = Path.home()

        result = self._window.create_file_dialog(
            save_mode,
            directory=str(dialog_dir),
            save_filename="accounts_vault.md",
            file_types=("Markdown 文件 (*.md)",),
        )
        if not result:
            return {"ok": False, "cancelled": True}

        chosen_str = result[0] if isinstance(result, (list, tuple)) else result
        chosen = Path(chosen_str)
        if chosen.suffix.lower() != ".md":
            chosen = chosen.with_suffix(".md")

        with self._lock:
            if self._crypto is not None:
                self._crypto.lock()
                self._crypto = None
            self._doc = None
            self._storage.set_vault_path(chosen)
            return self.get_status()

    def reveal_vault_in_explorer(self) -> Dict[str, Any]:
        """Open OS file manager (Windows Explorer / macOS Finder) and highlight the .md file."""
        target = self._storage.vault_path
        folder = target.parent if target.parent.exists() else self._project_root
        try:
            if sys.platform == "win32":
                if target.exists():
                    subprocess.Popen(["explorer.exe", f"/select,{target}"])
                else:
                    subprocess.Popen(["explorer.exe", str(folder)])
            elif sys.platform == "darwin":
                if target.exists():
                    subprocess.Popen(["open", "-R", str(target)])
                else:
                    subprocess.Popen(["open", str(folder)])
            else:
                subprocess.Popen(["xdg-open", str(folder)])
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def open_external_url(self, url: str) -> Dict[str, Any]:
        """Open an HTTP/HTTPS URL safely in the user's default system browser."""
        raw = (url or "").strip()
        if not raw:
            return {"ok": False, "error": "网址为空"}
        # Prepend https:// only when no URI scheme (excluding host:port) is present
        if "://" not in raw and not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*:(?!\d)", raw):
            raw = "https://" + raw
        parsed = urlparse(raw)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
            return {"ok": False, "error": "仅支持打开有效的 http / https 网页链接"}
        try:
            webbrowser.open(raw)
            return {"ok": True, "url": raw}
        except Exception as exc:
            return {"ok": False, "error": f"打开浏览器失败: {exc}"}
