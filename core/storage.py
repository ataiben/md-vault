from __future__ import annotations

import hashlib
import json
import os
import shutil
import threading
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from watchfiles import watch


class VaultStorage:
    """Handles atomic Markdown persistence, rolling backups, and external edit detection."""

    def __init__(self, project_root: Path):
        self._project_root = project_root
        self._prefs_path = project_root / ".vault_prefs.json"
        self._default_vault_path = project_root / "data" / "accounts_vault.md"
        self._vault_path: Path = self._load_saved_vault_path()
        self._last_written_hash: str = ""
        self._external_changed: bool = False
        self._stop_event: Optional[threading.Event] = None
        self._watch_thread: Optional[threading.Thread] = None
        self._on_external_change: Optional[Callable[[], None]] = None

        if self._vault_path.exists():
            self._last_written_hash = self._compute_file_hash(self._vault_path)

    def _read_prefs(self) -> dict:
        if self._prefs_path.exists():
            try:
                data = json.loads(self._prefs_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
            except Exception:
                pass
        return {}

    def _write_prefs(self, updates: dict) -> None:
        try:
            merged = self._read_prefs()
            merged.update(updates)
            self._prefs_path.write_text(
                json.dumps(merged, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

    def _load_saved_vault_path(self) -> Path:
        saved = self._read_prefs().get("vault_path", "")
        if saved:
            return Path(saved)
        return self._default_vault_path

    def _save_vault_path_pref(self) -> None:
        self._write_prefs({"vault_path": str(self._vault_path)})

    @property
    def auto_check_updates(self) -> bool:
        return bool(self._read_prefs().get("auto_check_updates", True))

    def set_auto_check_updates(self, enabled: bool) -> None:
        self._write_prefs({"auto_check_updates": bool(enabled)})

    @property
    def vault_path(self) -> Path:
        return self._vault_path

    @property
    def external_changed(self) -> bool:
        return self._external_changed

    def clear_external_changed(self) -> None:
        self._external_changed = False

    def set_vault_path(self, new_path: Path) -> None:
        self.stop_watching()
        self._vault_path = new_path.resolve()
        self._external_changed = False
        self._last_written_hash = (
            self._compute_file_hash(self._vault_path) if self._vault_path.exists() else ""
        )
        self._save_vault_path_pref()
        self.start_watching(self._on_external_change)

    def exists(self) -> bool:
        return self._vault_path.exists() and self._vault_path.stat().st_size > 0

    @staticmethod
    def _compute_file_hash(path: Path) -> str:
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except Exception:
            return ""

    def read_markdown(self) -> str:
        if not self._vault_path.exists():
            raise FileNotFoundError(f"未找到密码库文件: {self._vault_path}")
        content = self._vault_path.read_text(encoding="utf-8")
        self._last_written_hash = self._compute_file_hash(self._vault_path)
        self._external_changed = False
        return content

    def write_markdown(self, content: str, max_backups: int = 5) -> None:
        target = self._vault_path
        target.parent.mkdir(parents=True, exist_ok=True)

        # Rolling backup before overwriting existing non-empty file
        if target.exists() and target.stat().st_size > 0:
            old_hash = self._compute_file_hash(target)
            new_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
            if old_hash != new_hash:
                backup_dir = target.parent / ".vault_backups"
                backup_dir.mkdir(parents=True, exist_ok=True)
                stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                backup_file = backup_dir / f"{target.stem}_{stamp}.md"
                try:
                    shutil.copy2(target, backup_file)
                    backups = sorted(
                        backup_dir.glob(f"{target.stem}_*.md"),
                        key=lambda p: p.stat().st_mtime,
                        reverse=True,
                    )
                    for stale in backups[max_backups:]:
                        stale.unlink(missing_ok=True)
                except Exception:
                    pass

        # Pre-record expected hash so file watcher ignores our own atomic save
        encoded = content.encode("utf-8")
        self._last_written_hash = hashlib.sha256(encoded).hexdigest()

        tmp_path = target.with_suffix(target.suffix + ".tmp")
        tmp_path.write_bytes(encoded)
        os.replace(tmp_path, target)
        self._external_changed = False

    def start_watching(self, on_external_change: Optional[Callable[[], None]] = None) -> None:
        self._on_external_change = on_external_change
        self.stop_watching()

        watch_dir = self._vault_path.parent
        if not watch_dir.exists():
            return

        stop_event = threading.Event()
        self._stop_event = stop_event
        target_resolved = self._vault_path.resolve()

        def _worker() -> None:
            try:
                for changes in watch(watch_dir, stop_event=stop_event, debounce=400):
                    for _, changed_path in changes:
                        try:
                            p = Path(changed_path).resolve()
                        except Exception:
                            continue
                        if p == target_resolved and p.exists():
                            current_hash = self._compute_file_hash(p)
                            if current_hash and current_hash != self._last_written_hash:
                                self._external_changed = True
                                if self._on_external_change:
                                    try:
                                        self._on_external_change()
                                    except Exception:
                                        pass
            except Exception:
                pass

        thread = threading.Thread(target=_worker, name="VaultFileWatcher", daemon=True)
        self._watch_thread = thread
        thread.start()

    def stop_watching(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()
            self._stop_event = None
        self._watch_thread = None
