from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Tuple

import webview

from core.api import VaultApi


def _is_writable_dir(directory: Path) -> bool:
    """Check whether the directory can be created and written to."""
    try:
        directory.mkdir(parents=True, exist_ok=True)
        probe = directory / ".md_vault_write_probe.tmp"
        probe.write_bytes(b"ok")
        probe.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def resolve_runtime_paths() -> Tuple[Path, Path]:
    """
    Resolve (resource_root, data_root) across source mode and PyInstaller builds
    on Windows, macOS (.app bundle), and Linux.
    """
    if not getattr(sys, "frozen", False):
        source_root = Path(__file__).resolve().parent
        return source_root, source_root

    # Frozen bundle (PyInstaller)
    exe_dir = Path(sys.executable).resolve().parent
    meipass = getattr(sys, "_MEIPASS", None)
    resource_candidates = []
    if meipass:
        resource_candidates.append(Path(meipass))
    # macOS .app bundle Contents/Resources fallback
    resource_candidates.append(exe_dir.parent / "Resources")
    resource_candidates.append(exe_dir)

    resource_root = resource_candidates[0]
    for candidate in resource_candidates:
        if (candidate / "ui" / "index.html").exists():
            resource_root = candidate
            break

    if sys.platform == "darwin":
        data_root = Path.home() / "Library" / "Application Support" / "MD-Vault"
        data_root.mkdir(parents=True, exist_ok=True)
        return resource_root, data_root

    if sys.platform == "win32":
        # Prefer portable directory next to MD-Vault.exe unless placed in protected system folders
        prog_files = {
            os.environ.get("ProgramFiles", "").lower(),
            os.environ.get("ProgramFiles(x86)", "").lower(),
        }
        exe_str_lower = str(exe_dir).lower()
        in_protected = any(pf and exe_str_lower.startswith(pf) for pf in prog_files)
        if not in_protected and _is_writable_dir(exe_dir / "data"):
            return resource_root, exe_dir

        local_appdata = Path(
            os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")
        )
        data_root = local_appdata / "MD-Vault"
        data_root.mkdir(parents=True, exist_ok=True)
        return resource_root, data_root

    xdg_data = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share"))
    data_root = xdg_data / "md-vault"
    data_root.mkdir(parents=True, exist_ok=True)
    return resource_root, data_root


def _apply_windows_app_icon(window: Any, ico_path: Path) -> None:
    """Apply custom .ico to Windows taskbar & window titlebar even when running from source."""
    if sys.platform != "win32" or not ico_path.exists():
        return
    try:
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("io.github.ataiben.mdvault")
    except Exception:
        pass

    def _on_shown() -> None:
        try:
            import ctypes

            user32 = ctypes.windll.user32
            IMAGE_ICON = 1
            LR_LOADFROMFILE = 0x0010
            LR_DEFAULTSIZE = 0x0040
            WM_SETICON = 0x0080
            ICON_SMALL = 0
            ICON_BIG = 1

            user32.LoadImageW.argtypes = [
                ctypes.c_void_p,
                ctypes.c_wchar_p,
                ctypes.c_uint,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_uint,
            ]
            user32.LoadImageW.restype = ctypes.c_void_p
            user32.FindWindowW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
            user32.FindWindowW.restype = ctypes.c_void_p
            user32.SendMessageW.argtypes = [
                ctypes.c_void_p,
                ctypes.c_uint,
                ctypes.c_size_t,
                ctypes.c_void_p,
            ]
            user32.SendMessageW.restype = ctypes.c_void_p

            hwnd = None
            native = getattr(window, "native", None)
            if native is not None and hasattr(native, "Handle"):
                try:
                    hwnd = int(native.Handle.ToInt64())
                except Exception:
                    hwnd = None
            if not hwnd:
                hwnd = user32.FindWindowW(None, window.title)
            if not hwnd:
                return

            h_small = user32.LoadImageW(None, str(ico_path), IMAGE_ICON, 16, 16, LR_LOADFROMFILE)
            h_big = user32.LoadImageW(
                None, str(ico_path), IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE
            )
            if h_small:
                user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, h_small)
            if h_big:
                user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, h_big)
        except Exception:
            pass

    try:
        window.events.shown += _on_shown
    except Exception:
        pass


def main() -> None:
    resource_root, data_root = resolve_runtime_paths()
    ui_entry = resource_root / "ui" / "index.html"
    ico_path = resource_root / "ui" / "assets" / "icon.ico"
    png_icon_path = resource_root / "ui" / "assets" / "icon.png"

    vault_api = VaultApi(data_root)

    window = webview.create_window(
        title="MD-Vault · 本地账号密码管家",
        url=str(ui_entry),
        js_api=vault_api,
        width=1220,
        height=780,
        min_size=(940, 600),
        text_select=True,
    )
    vault_api._bind_window(window)
    _apply_windows_app_icon(window, ico_path)

    # Use Edge WebView2 on Windows; native WebKit (Cocoa) on macOS; auto-detect elsewhere
    if sys.platform == "win32":
        webview.start(gui="edgechromium", debug=False)
    elif sys.platform == "darwin":
        webview.start(debug=False)
    else:
        webview.start(icon=str(png_icon_path) if png_icon_path.exists() else None, debug=False)


if __name__ == "__main__":
    sys.exit(main())
