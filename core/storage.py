from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from watchfiles import watch

DEFAULT_AUTO_LOCK_MINUTES = 15
BACKUP_STAMP_RE = re.compile(r"_(\d{8}_\d{6}(?:_\d{1,6})?)\.md$")


class ExternalConflictError(Exception):
    """Raised when the on-disk .md file changed externally before a write."""


class VaultStorage:
    """Handles atomic Markdown persistence, tiered backups, and external edit detection."""

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
    def auto_lock_minutes(self) -> int:
        raw = self._read_prefs().get("auto_lock_minutes", DEFAULT_AUTO_LOCK_MINUTES)
        try:
            val = int(raw)
        except (TypeError, ValueError):
            val = DEFAULT_AUTO_LOCK_MINUTES
        return max(0, min(1440, val))

    def set_auto_lock_minutes(self, minutes: int) -> None:
        val = max(0, min(1440, int(minutes)))
        self._write_prefs({"auto_lock_minutes": val})

    @property
    def lock_on_minimize(self) -> bool:
        return bool(self._read_prefs().get("lock_on_minimize", False))

    def set_lock_on_minimize(self, enabled: bool) -> None:
        self._write_prefs({"lock_on_minimize": bool(enabled)})

    @property
    def vault_path(self) -> Path:
        return self._vault_path

    @property
    def backup_dir(self) -> Path:
        return self._vault_path.parent / ".vault_backups"

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

    def has_external_conflict(self) -> bool:
        """Check synchronously if the on-disk .md file differs from our last read/write hash."""
        if not self._vault_path.exists() or self._vault_path.stat().st_size == 0:
            return False
        if not self._last_written_hash:
            return False
        disk_hash = self._compute_file_hash(self._vault_path)
        if disk_hash and disk_hash != self._last_written_hash:
            self._external_changed = True
            return True
        return False

    def read_markdown(self) -> str:
        if not self._vault_path.exists():
            raise FileNotFoundError(f"未找到密码库文件: {self._vault_path}")
        raw_bytes = self._vault_path.read_bytes()
        content = raw_bytes.decode("utf-8")
        self._last_written_hash = hashlib.sha256(raw_bytes).hexdigest()
        self._external_changed = False
        return content

    @staticmethod
    def _parse_backup_datetime(path: Path) -> datetime:
        """Extract timestamp from backup filename, falling back to file mtime."""
        m = BACKUP_STAMP_RE.search(path.name)
        if m:
            stamp = m.group(1)
            for fmt in ("%Y%m%d_%H%M%S_%f", "%Y%m%d_%H%M%S"):
                try:
                    return datetime.strptime(stamp, fmt)
                except ValueError:
                    continue
        try:
            return datetime.fromtimestamp(path.stat().st_mtime)
        except Exception:
            return datetime.min

    @classmethod
    def prune_backups(
        cls,
        backup_dir: Path,
        stem: str,
        *,
        keep_recent: int = 10,
        keep_hourly: int = 24,
        keep_daily: int = 30,
        keep_weekly: int = 12,
    ) -> List[Path]:
        """
        Prune snapshots using tiered retention (recent + hourly + daily + weekly buckets).
        Returns the sorted list (newest first) of retained backup files.
        """
        if not backup_dir.exists():
            return []

        prefix = f"{stem}_"
        candidates: List[Tuple[datetime, Path]] = []
        for p in backup_dir.glob(f"{stem}_*.md"):
            if p.is_file() and p.name.startswith(prefix):
                candidates.append((cls._parse_backup_datetime(p), p))

        candidates.sort(key=lambda item: (item[0], item[1].name), reverse=True)
        keep_set: Set[Path] = set()

        # Tier 1: unconditional recent burst protection
        for _, p in candidates[: max(0, keep_recent)]:
            keep_set.add(p)

        # Tier 2: newest snapshot per distinct hour bucket
        seen_hours: Set[Tuple[int, int, int, int]] = set()
        for dt, p in candidates:
            if len(seen_hours) >= max(0, keep_hourly):
                break
            bucket_h = (dt.year, dt.month, dt.day, dt.hour)
            if bucket_h not in seen_hours:
                seen_hours.add(bucket_h)
                keep_set.add(p)

        # Tier 3: newest snapshot per distinct calendar day bucket
        seen_days: Set[Tuple[int, int, int]] = set()
        for dt, p in candidates:
            if len(seen_days) >= max(0, keep_daily):
                break
            bucket_d = (dt.year, dt.month, dt.day)
            if bucket_d not in seen_days:
                seen_days.add(bucket_d)
                keep_set.add(p)

        # Tier 4: newest snapshot per distinct ISO week bucket
        seen_weeks: Set[Tuple[int, int]] = set()
        for dt, p in candidates:
            if len(seen_weeks) >= max(0, keep_weekly):
                break
            iso = dt.isocalendar()
            bucket_w = (int(iso[0]), int(iso[1]))
            if bucket_w not in seen_weeks:
                seen_weeks.add(bucket_w)
                keep_set.add(p)

        retained: List[Path] = []
        for _, p in candidates:
            if p in keep_set:
                retained.append(p)
            else:
                p.unlink(missing_ok=True)
        return retained

    def list_backups(self) -> List[Dict[str, Any]]:
        """List available backup snapshots for the current vault (newest first)."""
        bdir = self.backup_dir
        if not bdir.exists():
            return []
        stem = self._vault_path.stem
        prefix = f"{stem}_"
        items: List[Tuple[datetime, Path]] = []
        for p in bdir.glob(f"{stem}_*.md"):
            if p.is_file() and p.name.startswith(prefix):
                items.append((self._parse_backup_datetime(p), p))

        items.sort(key=lambda item: (item[0], item[1].name), reverse=True)
        result: List[Dict[str, Any]] = []
        for dt, p in items:
            try:
                size = p.stat().st_size
            except Exception:
                size = 0
            result.append(
                {
                    "filename": p.name,
                    "created_at": dt.strftime("%Y-%m-%d %H:%M:%S") if dt != datetime.min else "-",
                    "size_bytes": size,
                }
            )
        return result

    def read_backup_markdown(self, filename: str) -> str:
        """Safely read a backup snapshot file belonging to the current vault."""
        clean_name = (filename or "").strip()
        if not clean_name or Path(clean_name).name != clean_name or not clean_name.endswith(".md"):
            raise ValueError("无效的备份文件名")
        stem = self._vault_path.stem
        if not clean_name.startswith(f"{stem}_"):
            raise ValueError("备份文件与当前密码库不匹配")
        bdir = self.backup_dir.resolve()
        candidate = (bdir / clean_name).resolve()
        if candidate.parent != bdir or not candidate.is_file():
            raise FileNotFoundError("未找到指定的历史快照文件")
        return candidate.read_text(encoding="utf-8")

    def write_markdown(
        self,
        content: str,
        *,
        force: bool = False,
        keep_recent: int = 10,
        keep_hourly: int = 24,
        keep_daily: int = 30,
        keep_weekly: int = 12,
    ) -> None:
        target = self._vault_path
        target.parent.mkdir(parents=True, exist_ok=True)

        if not force and self.has_external_conflict():
            raise ExternalConflictError(
                "检测到本地 .md 文件已被外部修改，为防止覆盖外部改动已中止保存"
            )

        # Tiered snapshot backup before overwriting existing non-empty file
        if target.exists() and target.stat().st_size > 0:
            old_hash = self._compute_file_hash(target)
            new_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
            if old_hash != new_hash:
                bdir = self.backup_dir
                bdir.mkdir(parents=True, exist_ok=True)
                stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                backup_file = bdir / f"{target.stem}_{stamp}.md"
                try:
                    shutil.copy2(target, backup_file)
                    self.prune_backups(
                        bdir,
                        target.stem,
                        keep_recent=keep_recent,
                        keep_hourly=keep_hourly,
                        keep_daily=keep_daily,
                        keep_weekly=keep_weekly,
                    )
                except Exception:
                    pass

        # Pre-record expected hash so file watcher ignores our own atomic save
        encoded = content.encode("utf-8")
        self._last_written_hash = hashlib.sha256(encoded).hexdigest()

        tmp_path = target.parent / f".{target.name}.tmp"
        try:
            with open(tmp_path, "wb") as fp:
                fp.write(encoded)
                fp.flush()
                os.fsync(fp.fileno())

            last_err: Optional[Exception] = None
            for attempt in range(3):
                try:
                    os.replace(tmp_path, target)
                    last_err = None
                    break
                except PermissionError as exc:
                    last_err = exc
                    if attempt < 2:
                        time.sleep(0.03)
            if last_err is not None:
                raise last_err
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink(missing_ok=True)
                except Exception:
                    pass

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
