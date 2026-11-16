from __future__ import annotations

import json
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
    VERIFIER_AAD,
    VERIFIER_PLAINTEXT,
    CryptoEngine,
    CryptoError,
    CryptoIntegrityError,
    InvalidMasterPasswordError,
    build_field_aad,
    is_v2_encrypted_token,
)
from core.health import (
    audit_vault_health,
    evaluate_password_strength,
    scan_plaintext_notes_risks,
    validate_master_password_policy,
)
from core.importer import (
    decode_csv_bytes,
    export_entries_to_csv,
    parse_imported_csv,
)
from core.markdown_codec import (
    decrypt_entry_for_view,
    dumps_vault,
    encrypt_entry_for_storage,
    loads_vault,
    redact_entry_for_list,
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
from core.storage import ExternalConflictError, VaultStorage
from core.totp import extract_totp_from_text, generate_totp_token, parse_totp_config
from core.updater import apply_update_and_prepare_restart, check_for_updates
from core.version import __version__


def _build_starter_entries(crypto: CryptoEngine) -> tuple[List[str], List[AccountEntry]]:
    """Build helpful categorized starter templates for common account types."""
    categories = [
        "开发与云服务",
        "工作与个人邮箱",
        "常用软件与网站",
        "社交与娱乐",
    ]
    raw_entries = [
        AccountEntry(
            category="开发与云服务",
            title="GitHub · 个人主力账号（示例）",
            platform="GitHub",
            tags=["主力", "个人", "开源"],
            favorite=True,
            username="dev_demo@example.com",
            password="Demo#GitHub_2026!",
            recovery_email="backup_mail@example.com",
            url="https://github.com",
            two_fa_recovery="TOTP: JBSWY3DPEHPK3PXP\n备用码: RK9X-72LM-99PA-44QW",
            notes="已开启两步验证（内置 TOTP 动态口令演示）与通行密钥（Passkey）。\n可直接编辑此示例为您真实的账号，或删除此示例。",
        ),
        AccountEntry(
            category="工作与个人邮箱",
            title="Gmail · 个人核心主邮箱（示例）",
            platform="Google / Gmail",
            tags=["主力", "重要绑定"],
            favorite=True,
            username="my_main_mail@gmail.com",
            password="Demo#Gmail_Master_88!",
            phone="+86 138-0000-0000",
            recovery_email="backup_mail@outlook.com",
            url="https://mail.google.com",
            two_fa_recovery="1928 3746 / 5647 3829 / 9182 7364",
            notes="核心绑定邮箱，已开启 Authenticator 动态口令验证。",
        ),
        AccountEntry(
            category="开发与云服务",
            title="云服务 · 控制台管理号（示例）",
            platform="Cloud Console",
            tags=["工作", "运维"],
            favorite=False,
            username="ops_admin@example.com",
            password="Demo#Cloud_Ops_2026!",
            phone="+86 139-0000-0000",
            url="https://console.example.com",
            security_questions=[
                SecurityQA(question="你少年时代最好的朋友叫什么名字？", answer="Alex"),
                SecurityQA(question="你的第一份工作是在哪个城市？", answer="Shenzhen"),
                SecurityQA(question="你理想的工作是什么？", answer="Architect"),
            ],
            notes="用于日常云服务器与域名解析维护。",
        ),
        AccountEntry(
            category="社交与娱乐",
            title="Steam · 游戏娱乐账号（示例）",
            platform="Steam",
            tags=["个人", "娱乐"],
            favorite=False,
            username="player_demo",
            password="Demo#Steam_Play_2026!",
            recovery_email="my_main_mail@gmail.com",
            url="https://store.steampowered.com",
            notes="已绑定手机令牌 Steam Guard。",
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
        self._base_doc: Optional[VaultDocument] = None
        self._window: Any = None
        self._clipboard_timer: Optional[threading.Timer] = None
        self._latest_update_info: Optional[Dict[str, Any]] = None
        self._lock = threading.RLock()

        self._storage.start_watching(self._notify_frontend_external_change)

    def _bind_window(self, window: Any) -> None:
        self._window = window

        def _on_minimized() -> None:
            with self._lock:
                should_lock = bool(
                    self._storage.lock_on_minimize
                    and self._crypto is not None
                    and self._crypto.is_unlocked
                )
                if not should_lock:
                    return
                self.lock_vault()
            if self._window is not None:
                try:
                    self._window.evaluate_js(
                        "window.onBackendAutoLocked && window.onBackendAutoLocked('窗口已最小化，密码库已自动锁定');"
                    )
                except Exception:
                    pass

        try:
            window.events.minimized += _on_minimized
        except Exception:
            pass

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

    @staticmethod
    def _entry_plain_fingerprint(entry: AccountEntry, crypto: CryptoEngine) -> Dict[str, Any]:
        """Return a deterministic decrypted dict (excluding updated_at) for 3-way comparison."""
        plain = decrypt_entry_for_view(entry, crypto)
        return plain.model_dump(exclude={"updated_at"})

    @classmethod
    def _three_way_merge_docs(
        cls,
        base: VaultDocument,
        local: VaultDocument,
        remote: VaultDocument,
        crypto: CryptoEngine,
    ) -> VaultDocument:
        """
        Merge local in-memory changes with external on-disk edits at entry & category granularity.
        When the exact same entry was modified on both sides, local user intent takes precedence.
        """
        base_map = {e.id: e for e in base.entries}
        local_map = {e.id: e for e in local.entries}
        remote_map = {e.id: e for e in remote.entries}

        fp_cache: Dict[Tuple[str, str], Dict[str, Any]] = {}

        def get_fp(side: str, ent: AccountEntry) -> Dict[str, Any]:
            key = (side, ent.id)
            if key not in fp_cache:
                fp_cache[key] = cls._entry_plain_fingerprint(ent, crypto)
            return fp_cache[key]

        merged_entries: List[AccountEntry] = []
        handled_ids: set[str] = set()

        # 1. Process entries present in local (preserving local ordering & newly added items)
        for ent in local.entries:
            eid = ent.id
            if eid not in base_map:
                merged_entries.append(ent.model_copy(deep=True))
                handled_ids.add(eid)
                continue

            local_changed = get_fp("local", ent) != get_fp("base", base_map[eid])
            if eid not in remote_map:
                # Deleted externally: keep only if local explicitly modified it
                if local_changed:
                    merged_entries.append(ent.model_copy(deep=True))
                handled_ids.add(eid)
                continue

            remote_ent = remote_map[eid]
            remote_changed = get_fp("remote", remote_ent) != get_fp("base", base_map[eid])
            if local_changed:
                merged_entries.append(ent.model_copy(deep=True))
            elif remote_changed:
                merged_entries.append(remote_ent.model_copy(deep=True))
            else:
                merged_entries.append(remote_ent.model_copy(deep=True))
            handled_ids.add(eid)

        # 2. Include entries added externally or modified externally despite local deletion
        remote_insertions: List[AccountEntry] = []
        for ent in remote.entries:
            eid = ent.id
            if eid in handled_ids:
                continue
            if eid not in base_map:
                # Newly added in external editor
                remote_insertions.append(ent.model_copy(deep=True))
                handled_ids.add(eid)
            else:
                # Deleted locally: preserve only if external editor modified this entry
                remote_changed = get_fp("remote", ent) != get_fp("base", base_map[eid])
                if remote_changed:
                    remote_insertions.append(ent.model_copy(deep=True))
                handled_ids.add(eid)

        if remote_insertions:
            merged_entries.extend(remote_insertions)

        # 3. Merge categories respecting deletions and additions on both sides
        base_cats = set(base.categories)
        deleted_remote_cats = base_cats - set(remote.categories)
        surviving_entry_cats = {e.category for e in merged_entries}

        merged_cats: List[str] = []
        for c in local.categories:
            if c in deleted_remote_cats and c not in surviving_entry_cats:
                continue
            if c not in merged_cats:
                merged_cats.append(c)
        for c in remote.categories:
            if c not in base_cats and c not in merged_cats:
                merged_cats.append(c)
        for e in merged_entries:
            if e.category not in merged_cats:
                merged_cats.append(e.category)

        # 4. Merge saved quick tags
        base_tags = base.header.saved_tags or {}
        local_tags = local.header.saved_tags or {}
        remote_tags = remote.header.saved_tags or {}
        merged_saved_tags: Dict[str, List[str]] = {}
        all_tag_cats = list(dict.fromkeys([*local_tags.keys(), *remote_tags.keys()]))
        for cat_k in all_tag_cats:
            b_set = set(base_tags.get(cat_k, []))
            l_list = list(local_tags.get(cat_k, []))
            r_list = list(remote_tags.get(cat_k, []))
            deleted_in_remote = b_set - set(r_list)
            bucket: List[str] = [t for t in l_list if t not in deleted_in_remote]
            for t in r_list:
                if t not in b_set and t not in bucket:
                    bucket.append(t)
            if bucket:
                merged_saved_tags[cat_k] = bucket

        merged_header = local.header.model_copy(deep=True)
        if (
            remote.header.vault_name != base.header.vault_name
            and local.header.vault_name == base.header.vault_name
        ):
            merged_header.vault_name = remote.header.vault_name
        merged_header.saved_tags = merged_saved_tags
        merged_header.updated_at = now_timestamp()

        return VaultDocument(
            header=merged_header,
            categories=merged_cats,
            entries=merged_entries,
        )

    @staticmethod
    def _conflict_error_response(exc: ExternalConflictError) -> Dict[str, Any]:
        return {
            "ok": False,
            "conflict": True,
            "external_changed": True,
            "error": str(exc),
        }

    def _commit_doc_mutation(
        self, candidate_doc: VaultDocument, conflict_mode: str = "abort"
    ) -> bool:
        """
        Persist candidate_doc according to conflict_mode ('abort' | 'merge' | 'overwrite').
        Updates self._doc and self._base_doc only after disk write succeeds.
        Returns True if external plaintext fields were auto-sealed during merge.
        """
        assert self._crypto is not None and self._crypto.is_unlocked
        mode = (conflict_mode or "abort").strip().lower()
        if (
            candidate_doc.header.salt
            and candidate_doc.header.verifier
            and not is_v2_encrypted_token(candidate_doc.header.verifier)
        ):
            candidate_doc.header.verifier = self._crypto.encrypt_value(
                VERIFIER_PLAINTEXT, aad=VERIFIER_AAD
            )
            candidate_doc.header.vault_version = max(candidate_doc.header.vault_version, 2)
        candidate_doc.header.updated_at = now_timestamp()

        if mode == "overwrite":
            self._storage.write_markdown(dumps_vault(candidate_doc), force=True)
            self._doc = candidate_doc
            self._base_doc = candidate_doc.model_copy(deep=True)
            return False

        if mode == "merge":
            raw_md = self._storage.read_markdown()
            remote_doc = loads_vault(raw_md)
            if remote_doc.header.salt and remote_doc.header.salt != candidate_doc.header.salt:
                raise CryptoIntegrityError("外部文件已更换主密码盐值，无法自动合并，请先重新加载文件")
            was_sealed = seal_document_entries(remote_doc, self._crypto)
            for entry in remote_doc.entries:
                decrypt_entry_for_view(entry, self._crypto)
            base_ref = self._base_doc if self._base_doc is not None else candidate_doc
            merged_doc = self._three_way_merge_docs(
                base_ref, candidate_doc, remote_doc, self._crypto
            )
            self._ensure_saved_tags(merged_doc)
            merged_doc.header.updated_at = now_timestamp()
            self._storage.write_markdown(dumps_vault(merged_doc), force=True)
            self._doc = merged_doc
            self._base_doc = merged_doc.model_copy(deep=True)
            return was_sealed

        # Default: 'abort' — raises ExternalConflictError if disk hash diverged
        self._storage.write_markdown(dumps_vault(candidate_doc), force=False)
        self._doc = candidate_doc
        self._base_doc = candidate_doc.model_copy(deep=True)
        return False

    def _serialize_unlocked_state(self, auto_sealed: bool = False) -> Dict[str, Any]:
        if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
            raise CryptoError("密码库尚未解锁")

        # On-demand (lazy) decryption: expose only metadata + presence flags to list/DOM state
        redacted_entries = [redact_entry_for_list(e, crypto=self._crypto) for e in self._doc.entries]
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
            "app_version": __version__,
            "auto_check_updates": self._storage.auto_check_updates,
            "auto_lock_minutes": self._storage.auto_lock_minutes,
            "lock_on_minimize": self._storage.lock_on_minimize,
            "vault_path": str(self._storage.vault_path),
            "vault_name": self._doc.header.vault_name,
            "updated_at": self._doc.header.updated_at,
            "categories": categories,
            "entries": redacted_entries,
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
            if self._doc is not None:
                vault_name = self._doc.header.vault_name
            elif exists:
                try:
                    doc = loads_vault(self._storage.read_markdown())
                    vault_name = doc.header.vault_name
                except Exception:
                    pass
            return {
                "ok": True,
                "exists": exists,
                "is_unlocked": bool(self._crypto and self._crypto.is_unlocked),
                "app_version": __version__,
                "auto_check_updates": self._storage.auto_check_updates,
                "auto_lock_minutes": self._storage.auto_lock_minutes,
                "lock_on_minimize": self._storage.lock_on_minimize,
                "vault_path": str(self._storage.vault_path),
                "vault_name": vault_name,
                "external_changed": self._storage.external_changed,
            }

    def set_auto_lock_prefs(
        self, auto_lock_minutes: int, lock_on_minimize: bool = False
    ) -> Dict[str, Any]:
        """Configure idle auto-lock timeout (minutes, 0 = disabled) and lock-on-minimize."""
        with self._lock:
            self._storage.set_auto_lock_minutes(int(auto_lock_minutes))
            self._storage.set_lock_on_minimize(bool(lock_on_minimize))
            return {
                "ok": True,
                "auto_lock_minutes": self._storage.auto_lock_minutes,
                "lock_on_minimize": self._storage.lock_on_minimize,
            }

    def check_password_strength(
        self, password: str, username: str = ""
    ) -> Dict[str, Any]:
        """Evaluate password entropy and strength label without persisting anything."""
        return {"ok": True, **evaluate_password_strength(password or "", username=username or "")}

    def create_vault(
        self,
        master_password: str,
        vault_name: str = "我的账号密码库",
        use_starter_template: bool = True,
    ) -> Dict[str, Any]:
        """Initialize a brand-new encrypted single-file Markdown vault."""
        with self._lock:
            pwd = master_password or ""
            policy_err = validate_master_password_policy(pwd)
            if policy_err:
                return {"ok": False, "error": policy_err}

            engine, salt_b64, verifier = CryptoEngine.create_new(pwd)
            clean_name = (vault_name or "我的账号密码库").strip()

            if use_starter_template:
                categories, entries = _build_starter_entries(engine)
            else:
                categories = ["开发与云服务", "工作与个人邮箱", "常用软件与网站"]
                entries = []

            doc = VaultDocument(
                header=VaultHeader(
                    vault_version=2,
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
            self._storage.write_markdown(md_text, force=True)
            self._storage.start_watching(self._notify_frontend_external_change)

            self._crypto = engine
            self._doc = doc
            self._base_doc = doc.model_copy(deep=True)
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
                self._storage.write_markdown(dumps_vault(doc), force=True)
                self._crypto = engine
                self._doc = doc
                self._base_doc = doc.model_copy(deep=True)
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
                self._storage.write_markdown(dumps_vault(doc), force=True)

            self._crypto = engine
            self._doc = doc
            self._base_doc = doc.model_copy(deep=True)
            return self._serialize_unlocked_state(auto_sealed=was_sealed)

    def lock_vault(self) -> Dict[str, Any]:
        """Lock vault and purge key and entries from memory."""
        with self._lock:
            if self._crypto is not None:
                self._crypto.lock()
                self._crypto = None
            self._doc = None
            self._base_doc = None
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
                for entry in doc.entries:
                    decrypt_entry_for_view(entry, self._crypto)
                tags_seeded = self._ensure_saved_tags(doc)
                if was_sealed or tags_seeded:
                    doc.header.updated_at = now_timestamp()
                    self._storage.write_markdown(dumps_vault(doc), force=True)
                self._doc = doc
                self._base_doc = doc.model_copy(deep=True)
                return self._serialize_unlocked_state(auto_sealed=was_sealed)
            except Exception as exc:
                return {"ok": False, "error": f"重新读取本地文件失败: {exc}"}

    def list_backups(self) -> Dict[str, Any]:
        """List tiered historical snapshots in .vault_backups for the current vault."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            raw_list = self._storage.list_backups()
            enriched: List[Dict[str, Any]] = []
            for item in raw_list:
                entry_count: Optional[int] = None
                try:
                    md_text = self._storage.read_backup_markdown(item["filename"])
                    parsed = loads_vault(md_text)
                    entry_count = len(parsed.entries)
                except Exception:
                    pass
                enriched.append({**item, "entry_count": entry_count})
            return {"ok": True, "backups": enriched}

    def restore_backup(self, filename: str) -> Dict[str, Any]:
        """
        Restore a snapshot from .vault_backups (automatically backing up the current .md first).
        """
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            try:
                backup_md = self._storage.read_backup_markdown(filename)
                restored_doc = loads_vault(backup_md)
            except Exception as exc:
                return {"ok": False, "error": f"读取备份快照失败: {exc}"}

            # Snapshot current vault before replacing with historical backup
            self._storage.write_markdown(backup_md, force=True)

            # Check whether the restored snapshot can be decrypted with the current session key
            try:
                if restored_doc.header.verifier:
                    verified = self._crypto.decrypt_token(
                        restored_doc.header.verifier, aad=VERIFIER_AAD
                    )
                    if verified != VERIFIER_PLAINTEXT:
                        raise CryptoIntegrityError("Verifier mismatch")
                was_sealed = seal_document_entries(restored_doc, self._crypto)
                for entry in restored_doc.entries:
                    decrypt_entry_for_view(entry, self._crypto)
                tags_seeded = self._ensure_saved_tags(restored_doc)
                if was_sealed or tags_seeded:
                    restored_doc.header.updated_at = now_timestamp()
                    self._storage.write_markdown(dumps_vault(restored_doc), force=True)
                self._doc = restored_doc
                self._base_doc = restored_doc.model_copy(deep=True)
                res = self._serialize_unlocked_state(auto_sealed=was_sealed)
                res["restored"] = True
                return res
            except CryptoError:
                # Snapshot used an older/different master password; lock cleanly for re-auth
                self._crypto.lock()
                self._crypto = None
                self._doc = None
                self._base_doc = None
                status = self.get_status()
                status["restored"] = True
                status["requires_unlock"] = True
                return status

    def get_vault_data(self) -> Dict[str, Any]:
        """Return unlocked metadata state (with sensitive secrets redacted for on-demand access)."""
        with self._lock:
            try:
                return self._serialize_unlocked_state()
            except Exception as exc:
                return {"ok": False, "error": str(exc)}

    def _find_entry(self, entry_id: str) -> Optional[AccountEntry]:
        if self._doc is None:
            return None
        target = (entry_id or "").strip()
        for ent in self._doc.entries:
            if ent.id == target:
                return ent
        return None

    def _resolve_entry_totp_secret(self, entry: AccountEntry) -> tuple[str, str]:
        """
        Resolve effective TOTP secret for a single entry.
        Prefers dedicated entry.totp_secret; falls back to extracting a valid Base32 / otpauth://
        seed from entry.two_fa_recovery so existing accounts work immediately without re-editing.
        Returns (secret_str, source_field) where source_field is 'totp_secret', 'two_fa_recovery', or ''.
        """
        assert self._crypto is not None and self._crypto.is_unlocked
        if entry.totp_secret and entry.totp_secret.strip():
            raw = self._crypto.decrypt_if_needed(
                entry.totp_secret, aad=build_field_aad(entry.id, "totp_secret")
            )
            if raw.strip():
                return raw.strip(), "totp_secret"

        if entry.two_fa_recovery and entry.two_fa_recovery.strip():
            two_fa_plain = self._crypto.decrypt_if_needed(
                entry.two_fa_recovery, aad=build_field_aad(entry.id, "two_fa_recovery")
            )
            extracted = extract_totp_from_text(two_fa_plain)
            if extracted:
                return extracted, "two_fa_recovery"

        return "", ""

    def _decrypt_single_field(self, entry: AccountEntry, field_key: str) -> str:
        assert self._crypto is not None and self._crypto.is_unlocked
        key = (field_key or "").strip()
        if key == "password":
            return self._crypto.decrypt_if_needed(
                entry.password, aad=build_field_aad(entry.id, "password")
            )
        if key in ("totp", "totp_secret"):
            secret_raw, _ = self._resolve_entry_totp_secret(entry)
            return secret_raw
        if key in ("2fa", "two_fa_recovery"):
            return self._crypto.decrypt_if_needed(
                entry.two_fa_recovery, aad=build_field_aad(entry.id, "two_fa_recovery")
            )
        if key.startswith("qa_"):
            try:
                idx = int(key.split("_", 1)[1])
            except ValueError as exc:
                raise ValueError("无效的密保问题索引") from exc
            if idx < 0 or idx >= len(entry.security_questions):
                raise ValueError("密保问题索引超出范围")
            return self._crypto.decrypt_if_needed(
                entry.security_questions[idx].answer,
                aad=build_field_aad(entry.id, "security_qa"),
            )
        raise ValueError(f"不支持的加密字段标识: {key}")

    def reveal_entry_secret(self, entry_id: str, field_key: str) -> Dict[str, Any]:
        """Decrypt a single sensitive field on demand when user clicks the eye button."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            entry = self._find_entry(entry_id)
            if entry is None:
                return {"ok": False, "error": "未找到对应账号记录"}
            try:
                plain_val = self._decrypt_single_field(entry, field_key)
                return {"ok": True, "entry_id": entry.id, "field_key": field_key, "value": plain_val}
            except Exception as exc:
                return {"ok": False, "error": f"解密字段失败: {exc}"}

    def copy_entry_secret(
        self, entry_id: str, field_key: str, auto_clear_seconds: int = 30
    ) -> Dict[str, Any]:
        """
        Decrypt a single sensitive field in Python and copy directly to OS clipboard
        with privacy shielding, without ever sending the plaintext secret to WebView JS.
        """
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            entry = self._find_entry(entry_id)
            if entry is None:
                return {"ok": False, "error": "未找到对应账号记录"}
            try:
                plain_val = self._decrypt_single_field(entry, field_key)
            except Exception as exc:
                return {"ok": False, "error": f"解密字段失败: {exc}"}
            if not plain_val:
                return {"ok": False, "error": "该字段内容为空"}
            return self.copy_to_clipboard(
                plain_val, auto_clear_seconds=max(0, int(auto_clear_seconds)), sensitive=True
            )

    def get_entry_for_edit(self, entry_id: str) -> Dict[str, Any]:
        """Decrypt and return a single entry payload when entering edit/duplicate mode."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            entry = self._find_entry(entry_id)
            if entry is None:
                return {"ok": False, "error": "未找到对应账号记录"}
            try:
                decrypted = decrypt_entry_for_view(entry, self._crypto).model_dump()
                totp_val = (decrypted.get("totp_secret") or "").strip()
                twofa_val = (decrypted.get("two_fa_recovery") or "").strip()
                if totp_val:
                    if not twofa_val or twofa_val == totp_val:
                        decrypted["two_fa_recovery"] = totp_val
                    elif totp_val not in twofa_val:
                        decrypted["two_fa_recovery"] = f"TOTP: {totp_val}\n{twofa_val}"
                    decrypted["totp_secret"] = ""
                return {"ok": True, "entry": decrypted}
            except Exception as exc:
                return {"ok": False, "error": f"读取编辑数据失败: {exc}"}

    def preview_totp_secret(self, raw_secret: str) -> Dict[str, Any]:
        """Validate unified 2FA/TOTP text in the editor form and preview live code if a TOTP seed is present."""
        cleaned = (raw_secret or "").strip()
        if not cleaned:
            return {"ok": False, "empty": True}
        if cleaned.lower().startswith("otpauth://"):
            try:
                token_info = generate_totp_token(cleaned)
                return {"ok": True, **token_info}
            except ValueError as exc:
                return {"ok": False, "invalid_uri": True, "error": str(exc)}
        extracted = extract_totp_from_text(cleaned)
        if extracted:
            try:
                token_info = generate_totp_token(extracted)
                return {"ok": True, **token_info}
            except ValueError as exc:
                return {"ok": False, "error": str(exc)}
        return {"ok": False, "backup_only": True}

    def get_entry_totp(self, entry_id: str) -> Dict[str, Any]:
        """Compute current RFC 6238 TOTP code & countdown for an entry without exposing its secret."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            entry = self._find_entry(entry_id)
            if entry is None:
                return {"ok": False, "error": "未找到对应账号记录"}
            try:
                secret_raw, source_field = self._resolve_entry_totp_secret(entry)
                if not secret_raw:
                    return {"ok": False, "no_totp": True, "error": "该账号尚未配置 TOTP 密钥"}
                token_info = generate_totp_token(secret_raw)
                return {
                    "ok": True,
                    "entry_id": entry.id,
                    "source": source_field,
                    **token_info,
                }
            except Exception as exc:
                return {"ok": False, "error": f"生成动态验证码失败: {exc}"}

    def copy_entry_totp(
        self, entry_id: str, auto_clear_seconds: int = 30
    ) -> Dict[str, Any]:
        """Generate current TOTP code in Python and copy directly to clipboard with privacy shield."""
        res = self.get_entry_totp(entry_id)
        if not res.get("ok"):
            return res
        code = str(res.get("code", ""))
        copy_res = self.copy_to_clipboard(
            code, auto_clear_seconds=max(0, int(auto_clear_seconds)), sensitive=True
        )
        if not copy_res.get("ok"):
            return copy_res
        return {"ok": True, "remaining": res.get("remaining"), "period": res.get("period")}

    def save_entry(
        self,
        payload: Dict[str, Any],
        conflict_mode: str = "abort",
        allow_risky_notes: bool = False,
    ) -> Dict[str, Any]:
        """Create or update an account entry and persist to the single Markdown file."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}

            title = str(payload.get("title", "")).strip()
            if not title:
                return {"ok": False, "error": "请填写账号条目名称（例如：GitHub · 个人主力账号）"}

            totp_secret = str(payload.get("totp_secret", "")).strip()
            if totp_secret:
                try:
                    parse_totp_config(totp_secret)
                except ValueError as exc:
                    return {"ok": False, "error": f"TOTP 动态码配置无效：{exc}"}

            notes_text = str(payload.get("notes", "")).rstrip()
            allow_notes = bool(allow_risky_notes or payload.get("allow_risky_notes", False))
            if notes_text and not allow_notes:
                risks = scan_plaintext_notes_risks(notes_text)
                if risks:
                    return {
                        "ok": False,
                        "notes_warning": True,
                        "risks": risks,
                        "error": "检测到「备注说明」中包含疑似高敏密钥或密码（备注在 .md 文件中为明文存储）",
                    }

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

            candidate_doc = self._doc.model_copy(deep=True)
            existing_custom: Dict[str, str] = {}
            existing_idx: Optional[int] = None
            if entry_id:
                for idx, ent in enumerate(candidate_doc.entries):
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
                totp_secret=totp_secret,
                security_questions=qas,
                two_fa_recovery=str(payload.get("two_fa_recovery", "")).strip(),
                notes=notes_text,
                custom_fields=payload.get("custom_fields") or existing_custom,
                updated_at=now_timestamp(),
            )

            encrypted_entry = encrypt_entry_for_storage(plain_entry, self._crypto)

            if category not in candidate_doc.categories:
                candidate_doc.categories.append(category)

            # Auto-save user-entered tags under this category's quick-tags list
            self._merge_tags_into_saved(candidate_doc, category, tags)

            if existing_idx is not None:
                candidate_doc.entries[existing_idx] = encrypted_entry
            else:
                candidate_doc.entries.insert(0, encrypted_entry)

            try:
                was_sealed = self._commit_doc_mutation(candidate_doc, conflict_mode=conflict_mode)
            except ExternalConflictError as exc:
                return self._conflict_error_response(exc)
            except Exception as exc:
                return {"ok": False, "error": f"保存失败: {exc}"}

            res = self._serialize_unlocked_state(auto_sealed=was_sealed)
            res["saved_id"] = encrypted_entry.id
            return res

    def delete_entry(self, entry_id: str, conflict_mode: str = "abort") -> Dict[str, Any]:
        """Delete an account entry by ID."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            candidate_doc = self._doc.model_copy(deep=True)
            before = len(candidate_doc.entries)
            candidate_doc.entries = [e for e in candidate_doc.entries if e.id != entry_id]
            if len(candidate_doc.entries) == before:
                return {"ok": False, "error": "未找到要删除的账号记录"}
            try:
                was_sealed = self._commit_doc_mutation(candidate_doc, conflict_mode=conflict_mode)
            except ExternalConflictError as exc:
                return self._conflict_error_response(exc)
            except Exception as exc:
                return {"ok": False, "error": f"删除失败: {exc}"}
            return self._serialize_unlocked_state(auto_sealed=was_sealed)

    def toggle_favorite(self, entry_id: str, conflict_mode: str = "abort") -> Dict[str, Any]:
        """Toggle favorite star on an account entry."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            candidate_doc = self._doc.model_copy(deep=True)
            found = False
            for ent in candidate_doc.entries:
                if ent.id == entry_id:
                    ent.favorite = not ent.favorite
                    ent.updated_at = now_timestamp()
                    found = True
                    break
            if not found:
                return {"ok": False, "error": "未找到对应账号"}
            try:
                was_sealed = self._commit_doc_mutation(candidate_doc, conflict_mode=conflict_mode)
            except ExternalConflictError as exc:
                return self._conflict_error_response(exc)
            except Exception as exc:
                return {"ok": False, "error": f"更新星标失败: {exc}"}
            return self._serialize_unlocked_state(auto_sealed=was_sealed)

    def add_category(self, name: str, conflict_mode: str = "abort") -> Dict[str, Any]:
        """Add a new category heading to the Markdown vault."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            clean = (name or "").strip()
            if not clean:
                return {"ok": False, "error": "分类名称不能为空"}
            if clean in self._doc.categories:
                return {"ok": False, "error": f"分类「{clean}」已存在"}
            candidate_doc = self._doc.model_copy(deep=True)
            candidate_doc.categories.append(clean)
            try:
                was_sealed = self._commit_doc_mutation(candidate_doc, conflict_mode=conflict_mode)
            except ExternalConflictError as exc:
                return self._conflict_error_response(exc)
            except Exception as exc:
                return {"ok": False, "error": f"添加分类失败: {exc}"}
            return self._serialize_unlocked_state(auto_sealed=was_sealed)

    def rename_category(
        self, old_name: str, new_name: str, conflict_mode: str = "abort"
    ) -> Dict[str, Any]:
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

            candidate_doc = self._doc.model_copy(deep=True)
            updated_cats: List[str] = []
            for c in candidate_doc.categories:
                mapped = new_c if c == old_c else c
                if mapped not in updated_cats:
                    updated_cats.append(mapped)
            if new_c not in updated_cats:
                updated_cats.append(new_c)
            candidate_doc.categories = updated_cats

            for ent in candidate_doc.entries:
                if ent.category == old_c:
                    ent.category = new_c

            if candidate_doc.header.saved_tags is not None and old_c in candidate_doc.header.saved_tags:
                old_tags = candidate_doc.header.saved_tags.pop(old_c)
                self._merge_tags_into_saved(candidate_doc, new_c, old_tags)

            try:
                was_sealed = self._commit_doc_mutation(candidate_doc, conflict_mode=conflict_mode)
            except ExternalConflictError as exc:
                return self._conflict_error_response(exc)
            except Exception as exc:
                return {"ok": False, "error": f"重命名分类失败: {exc}"}
            return self._serialize_unlocked_state(auto_sealed=was_sealed)

    def delete_category(
        self, name: str, move_to: str = "未分类", conflict_mode: str = "abort"
    ) -> Dict[str, Any]:
        """Delete a category; if it has entries, move them to fallback category."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            candidate_doc = self._doc.model_copy(deep=True)
            target = (name or "").strip()
            has_entries = any(e.category == target for e in candidate_doc.entries)
            candidate_doc.categories = [c for c in candidate_doc.categories if c != target]
            fallback = (move_to or "未分类").strip()
            if fallback == target:
                fallback = "未分类"
            if has_entries:
                if fallback not in candidate_doc.categories:
                    candidate_doc.categories.append(fallback)
                for ent in candidate_doc.entries:
                    if ent.category == target:
                        ent.category = fallback
            if (
                candidate_doc.header.saved_tags is not None
                and target in candidate_doc.header.saved_tags
            ):
                moved_tags = candidate_doc.header.saved_tags.pop(target)
                if has_entries:
                    self._merge_tags_into_saved(candidate_doc, fallback, moved_tags)

            try:
                was_sealed = self._commit_doc_mutation(candidate_doc, conflict_mode=conflict_mode)
            except ExternalConflictError as exc:
                return self._conflict_error_response(exc)
            except Exception as exc:
                return {"ok": False, "error": f"移除分类失败: {exc}"}
            return self._serialize_unlocked_state(auto_sealed=was_sealed)

    def add_saved_tag(
        self, category: str, tag: str, conflict_mode: str = "abort"
    ) -> Dict[str, Any]:
        """Save a quick tag under a specific category."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            clean_cat = (category or "未分类").strip()
            clean_tag = (tag or "").strip()
            if not clean_tag:
                return {"ok": False, "error": "标签不能为空"}
            candidate_doc = self._doc.model_copy(deep=True)
            self._merge_tags_into_saved(candidate_doc, clean_cat, [clean_tag])
            try:
                was_sealed = self._commit_doc_mutation(candidate_doc, conflict_mode=conflict_mode)
            except ExternalConflictError as exc:
                return self._conflict_error_response(exc)
            except Exception as exc:
                return {"ok": False, "error": f"保存标签失败: {exc}"}
            return self._serialize_unlocked_state(auto_sealed=was_sealed)

    def delete_saved_tag(
        self, category: str, tag: str, conflict_mode: str = "abort"
    ) -> Dict[str, Any]:
        """Remove a saved quick tag from a category (or across all if category is empty)."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            clean_cat = (category or "").strip()
            clean_tag = (tag or "").strip()
            candidate_doc = self._doc.model_copy(deep=True)
            if candidate_doc.header.saved_tags is None:
                self._ensure_saved_tags(candidate_doc)
            assert candidate_doc.header.saved_tags is not None

            if clean_cat:
                if clean_cat in candidate_doc.header.saved_tags:
                    candidate_doc.header.saved_tags[clean_cat] = [
                        t for t in candidate_doc.header.saved_tags[clean_cat] if t != clean_tag
                    ]
            else:
                for cat_key in list(candidate_doc.header.saved_tags.keys()):
                    candidate_doc.header.saved_tags[cat_key] = [
                        t for t in candidate_doc.header.saved_tags[cat_key] if t != clean_tag
                    ]

            try:
                was_sealed = self._commit_doc_mutation(candidate_doc, conflict_mode=conflict_mode)
            except ExternalConflictError as exc:
                return self._conflict_error_response(exc)
            except Exception as exc:
                return {"ok": False, "error": f"删除标签失败: {exc}"}
            return self._serialize_unlocked_state(auto_sealed=was_sealed)

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

    def change_master_password(
        self, current_password: str, new_password: str, conflict_mode: str = "abort"
    ) -> Dict[str, Any]:
        """Verify current master password and re-encrypt entire vault with a new key & salt."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            new_pwd = new_password or ""
            policy_err = validate_master_password_policy(new_pwd)
            if policy_err:
                return {"ok": False, "error": policy_err}

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

            mode = (conflict_mode or "abort").strip().lower()
            if mode == "abort" and self._storage.has_external_conflict():
                return self._conflict_error_response(
                    ExternalConflictError(
                        "检测到本地 .md 文件已被外部修改，为防止覆盖外部改动已中止主密码修改"
                    )
                )

            source_doc = self._doc
            was_sealed = False
            if mode == "merge":
                try:
                    raw_md = self._storage.read_markdown()
                    remote_doc = loads_vault(raw_md)
                    if (
                        remote_doc.header.salt
                        and remote_doc.header.salt != self._doc.header.salt
                    ):
                        return {"ok": False, "error": "外部文件已更换主密码，请先重新加载"}
                    was_sealed = seal_document_entries(remote_doc, self._crypto)
                    base_ref = self._base_doc if self._base_doc is not None else self._doc
                    source_doc = self._three_way_merge_docs(
                        base_ref, self._doc, remote_doc, self._crypto
                    )
                except Exception as exc:
                    return {"ok": False, "error": f"合并外部修改失败: {exc}"}

            # Decrypt all entries in memory using old engine
            plain_entries = [decrypt_entry_for_view(e, self._crypto) for e in source_doc.entries]

            # Create brand-new engine, salt, and verifier
            new_engine, new_salt, new_verifier = CryptoEngine.create_new(
                new_pwd, iterations=source_doc.header.kdf_iterations
            )
            re_encrypted = [encrypt_entry_for_storage(e, new_engine) for e in plain_entries]

            next_doc = source_doc.model_copy(deep=True)
            next_doc.header.salt = new_salt
            next_doc.header.verifier = new_verifier
            next_doc.header.updated_at = now_timestamp()
            next_doc.entries = re_encrypted

            try:
                self._storage.write_markdown(
                    dumps_vault(next_doc), force=(mode in ("overwrite", "merge"))
                )
            except ExternalConflictError as exc:
                new_engine.lock()
                return self._conflict_error_response(exc)
            except Exception as exc:
                new_engine.lock()
                return {"ok": False, "error": f"写入新加密库失败: {exc}"}

            old_engine = self._crypto
            self._doc = next_doc
            self._base_doc = next_doc.model_copy(deep=True)
            self._crypto = new_engine
            old_engine.lock()

            return self._serialize_unlocked_state(auto_sealed=was_sealed)

    def get_password_health_report(self, stale_days: int = 180) -> Dict[str, Any]:
        """Run offline password security health check entirely in Python without exposing passwords."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            try:
                plain_entries = [
                    decrypt_entry_for_view(e, self._crypto) for e in self._doc.entries
                ]
                report = audit_vault_health(plain_entries, stale_days=max(30, int(stale_days)))
                return {"ok": True, "report": report}
            except Exception as exc:
                return {"ok": False, "error": f"密码体检分析失败: {exc}"}

    def import_csv_content(
        self,
        csv_text: str,
        default_category: str = "外部导入",
        conflict_mode: str = "abort",
    ) -> Dict[str, Any]:
        """Parse mainstream password manager CSV text, deduplicate, encrypt, and persist."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}

            clean_cat = (default_category or "外部导入").strip() or "外部导入"
            candidate_doc = self._doc.model_copy(deep=True)
            try:
                existing_plain = [
                    decrypt_entry_for_view(e, self._crypto) for e in candidate_doc.entries
                ]
                parsed_res = parse_imported_csv(
                    csv_text,
                    default_category=clean_cat,
                    existing_entries=existing_plain,
                )
            except ValueError as exc:
                return {"ok": False, "error": str(exc)}
            except Exception as exc:
                return {"ok": False, "error": f"解析 CSV 数据失败: {exc}"}

            new_plain_entries: List[AccountEntry] = parsed_res["entries"]
            was_sealed = False
            if new_plain_entries:
                encrypted_batch = [
                    encrypt_entry_for_storage(ent, self._crypto) for ent in new_plain_entries
                ]
                for ent in encrypted_batch:
                    if ent.category not in candidate_doc.categories:
                        candidate_doc.categories.append(ent.category)
                    if ent.tags:
                        self._merge_tags_into_saved(candidate_doc, ent.category, ent.tags)
                candidate_doc.entries = encrypted_batch + candidate_doc.entries

                try:
                    was_sealed = self._commit_doc_mutation(
                        candidate_doc, conflict_mode=conflict_mode
                    )
                except ExternalConflictError as exc:
                    return self._conflict_error_response(exc)
                except Exception as exc:
                    return {"ok": False, "error": f"写入导入记录失败: {exc}"}

            res = self._serialize_unlocked_state(auto_sealed=was_sealed)
            res["imported_count"] = parsed_res["imported_count"]
            res["skipped_duplicates"] = parsed_res["skipped_duplicates"]
            res["skipped_empty"] = parsed_res["skipped_empty"]
            res["detected_source"] = parsed_res["detected_source"]
            return res

    def import_csv_file(
        self,
        default_category: str = "外部导入",
        conflict_mode: str = "abort",
    ) -> Dict[str, Any]:
        """Open native OS file picker for a .csv export and import into current vault."""
        if self._window is None:
            return {"ok": False, "error": "窗口尚未就绪"}
        import webview

        open_mode = (
            webview.FileDialog.OPEN if hasattr(webview, "FileDialog") else webview.OPEN_DIALOG
        )
        dialog_dir = Path.home() / "Downloads"
        if not dialog_dir.exists():
            dialog_dir = Path.home()

        result = self._window.create_file_dialog(
            open_mode,
            directory=str(dialog_dir),
            allow_multiple=False,
            file_types=("CSV 密码导出文件 (*.csv)", "所有文件 (*.*)"),
        )
        if not result:
            return {"ok": False, "cancelled": True}

        chosen = Path(result[0] if isinstance(result, (list, tuple)) else result)
        try:
            raw_bytes = chosen.read_bytes()
            csv_text = decode_csv_bytes(raw_bytes)
        except Exception as exc:
            return {"ok": False, "error": f"读取 CSV 文件失败: {exc}"}

        res = self.import_csv_content(
            csv_text, default_category=default_category, conflict_mode=conflict_mode
        )
        res["source_file"] = chosen.name
        return res

    def export_csv_content(self, master_password: str) -> Dict[str, Any]:
        """Re-verify master password and serialize all entries to standard CSV."""
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            if not master_password:
                return {"ok": False, "error": "导出明文 CSV 前必须输入当前主密码进行二次验证"}

            try:
                verify_engine = CryptoEngine.unlock_existing(
                    master_password=master_password,
                    salt_b64=self._doc.header.salt,
                    verifier_token=self._doc.header.verifier,
                    iterations=self._doc.header.kdf_iterations,
                )
                verify_engine.lock()
            except InvalidMasterPasswordError:
                return {"ok": False, "error": "主密码验证失败，已拒绝导出明文 CSV"}
            except CryptoError as exc:
                return {"ok": False, "error": f"加密校验失败: {exc}"}

            plain_entries = [decrypt_entry_for_view(e, self._crypto) for e in self._doc.entries]
            csv_text = export_entries_to_csv(plain_entries)
            return {
                "ok": True,
                "csv_text": csv_text,
                "entry_count": len(plain_entries),
            }

    def export_vault_file(
        self, export_format: str = "encrypted_md", master_password: str = ""
    ) -> Dict[str, Any]:
        """Export vault to an encrypted .md backup or a master-password-verified .csv file."""
        fmt = (export_format or "encrypted_md").strip().lower()
        with self._lock:
            if self._doc is None or self._crypto is None or not self._crypto.is_unlocked:
                return {"ok": False, "error": "密码库已锁定"}
            if fmt == "plaintext_csv":
                csv_res = self.export_csv_content(master_password)
                if not csv_res.get("ok"):
                    return csv_res
                export_payload = csv_res["csv_text"]
                entry_count = csv_res["entry_count"]
            elif fmt == "encrypted_md":
                export_payload = dumps_vault(self._doc)
                entry_count = len(self._doc.entries)
            else:
                return {"ok": False, "error": f"不支持的导出格式: {export_format}"}

        if self._window is None:
            return {"ok": False, "error": "窗口尚未就绪"}
        import webview

        save_mode = (
            webview.FileDialog.SAVE if hasattr(webview, "FileDialog") else webview.SAVE_DIALOG
        )
        dialog_dir = self._storage.vault_path.parent
        if not dialog_dir.exists():
            dialog_dir = Path.home()

        stamp = time.strftime("%Y%m%d_%H%M%S")
        if fmt == "plaintext_csv":
            default_name = f"md_vault_export_{stamp}.csv"
            file_types = ("CSV 表格文件 (*.csv)",)
            suffix = ".csv"
            encoding = "utf-8-sig"
        else:
            default_name = f"{self._storage.vault_path.stem}_backup_{stamp}.md"
            file_types = ("加密 Markdown 备份 (*.md)",)
            suffix = ".md"
            encoding = "utf-8"

        result = self._window.create_file_dialog(
            save_mode,
            directory=str(dialog_dir),
            save_filename=default_name,
            file_types=file_types,
        )
        if not result:
            return {"ok": False, "cancelled": True}

        chosen_str = result[0] if isinstance(result, (list, tuple)) else result
        chosen = Path(chosen_str)
        if chosen.suffix.lower() != suffix:
            chosen = chosen.with_suffix(suffix)

        try:
            chosen.write_text(export_payload, encoding=encoding)
            return {
                "ok": True,
                "export_path": str(chosen),
                "entry_count": entry_count,
                "format": fmt,
            }
        except Exception as exc:
            return {"ok": False, "error": f"导出文件写入失败: {exc}"}

    def copy_to_clipboard(
        self,
        text: str,
        auto_clear_seconds: int = 0,
        sensitive: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Copy text to OS clipboard, excluding sensitive items from OS clipboard history & cloud sync,
        and optionally auto-clearing after N seconds if unchanged.
        """
        if text is None:
            return {"ok": False, "error": "复制内容为空"}
        is_sensitive = (
            bool(auto_clear_seconds and auto_clear_seconds > 0)
            if sensitive is None
            else bool(sensitive)
        )
        try:
            self._set_clipboard_text(str(text), sensitive=is_sensitive)
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
                        self._set_clipboard_text("", sensitive=True)
                except Exception:
                    pass

            timer = threading.Timer(float(auto_clear_seconds), _clear_if_same)
            timer.daemon = True
            self._clipboard_timer = timer
            timer.start()

        return {"ok": True}

    @staticmethod
    def _set_clipboard_text(value: str, sensitive: bool = False) -> None:
        if sys.platform == "darwin":
            if sensitive:
                try:
                    from AppKit import NSPasteboard, NSPasteboardTypeString  # type: ignore

                    pb = NSPasteboard.generalPasteboard()
                    pb.clearContents()
                    pb.setString_forType_(value, NSPasteboardTypeString)
                    pb.setString_forType_("", "org.nspasteboard.ConcealedType")
                    pb.setString_forType_("", "org.nspasteboard.TransientType")
                    return
                except Exception:
                    pass
            env = {**os.environ, "LANG": "en_US.UTF-8", "LC_CTYPE": "UTF-8"}
            subprocess.run(["pbcopy"], input=value.encode("utf-8"), env=env, check=True)
            return

        if sys.platform == "win32":
            try:
                VaultApi._win32_set_clipboard(value, sensitive=sensitive)
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
    def _win32_set_clipboard(value: str, sensitive: bool = False) -> None:
        import ctypes

        CF_UNICODETEXT = 13
        GMEM_MOVEABLE = 0x0002
        GMEM_ZEROINIT = 0x0040

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        user32.OpenClipboard.argtypes = [ctypes.c_void_p]
        user32.OpenClipboard.restype = ctypes.c_int
        user32.EmptyClipboard.argtypes = []
        user32.EmptyClipboard.restype = ctypes.c_int
        user32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
        user32.SetClipboardData.restype = ctypes.c_void_p
        user32.RegisterClipboardFormatW.argtypes = [ctypes.c_wchar_p]
        user32.RegisterClipboardFormatW.restype = ctypes.c_uint
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

        def _set_zero_dword_format(fmt_name: str) -> None:
            fmt_id = user32.RegisterClipboardFormatW(fmt_name)
            if not fmt_id:
                return
            h_flag = kernel32.GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, 4)
            if not h_flag:
                return
            p_flag = kernel32.GlobalLock(h_flag)
            if not p_flag:
                kernel32.GlobalFree(h_flag)
                return
            try:
                ctypes.memset(p_flag, 0, 4)
            finally:
                kernel32.GlobalUnlock(h_flag)
            if not user32.SetClipboardData(fmt_id, h_flag):
                kernel32.GlobalFree(h_flag)

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

            if sensitive:
                # Prevent Win+V local clipboard history & Windows Cloud Clipboard synchronization
                _set_zero_dword_format("ExcludeClipboardContentFromMonitorProcessing")
                _set_zero_dword_format("CanIncludeInClipboardHistory")
                _set_zero_dword_format("CanUploadToCloudClipboard")
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
            self._base_doc = None
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
            self._base_doc = None
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

    def set_auto_check_updates(self, enabled: bool) -> Dict[str, Any]:
        """Enable or disable automatic GitHub Release update check on startup."""
        with self._lock:
            self._storage.set_auto_check_updates(bool(enabled))
            return {"ok": True, "auto_check_updates": self._storage.auto_check_updates}

    def check_app_update(self) -> Dict[str, Any]:
        """Check GitHub Releases for a newer version of MD-Vault."""
        res = check_for_updates(self._project_root, current_version=__version__)
        with self._lock:
            if res.get("ok"):
                self._latest_update_info = dict(res)
            res["auto_check_updates"] = self._storage.auto_check_updates
        return res

    def install_app_update(self) -> Dict[str, Any]:
        """Download, verify SHA-256, stage update, and restart into the new version."""
        with self._lock:
            info = self._latest_update_info

        if not info or not info.get("has_update"):
            info = check_for_updates(self._project_root, current_version=__version__)
            if not info.get("ok"):
                return info
            with self._lock:
                self._latest_update_info = dict(info)

        def _emit_progress(message: str, percent: int) -> None:
            if self._window is not None:
                payload_json = json.dumps(
                    {"message": message, "percent": int(percent)}, ensure_ascii=False
                )
                try:
                    self._window.evaluate_js(
                        f"window.onUpdateProgress && window.onUpdateProgress({payload_json});"
                    )
                except Exception:
                    pass

        res = apply_update_and_prepare_restart(
            self._project_root,
            info,
            progress_cb=_emit_progress,
        )
        if res.get("ok") and res.get("restart"):
            with self._lock:
                if self._crypto is not None:
                    self._crypto.lock()
                    self._crypto = None
                self._doc = None
                self._base_doc = None
                self._storage.stop_watching()

            def _force_exit() -> None:
                os._exit(0)

            def _close_for_restart() -> None:
                # Watchdog ensures prompt exit even if WebView2 / GUI teardown lingers
                force_timer = threading.Timer(0.8, _force_exit)
                force_timer.daemon = True
                force_timer.start()
                if self._window is not None:
                    try:
                        self._window.destroy()
                        return
                    except Exception:
                        pass
                os._exit(0)

            t = threading.Timer(0.35, _close_for_restart)
            t.daemon = True
            t.start()

        return res
