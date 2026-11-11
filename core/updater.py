from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from core.version import GITHUB_REPO, __version__

ProgressCallback = Callable[[str, int], None]


def parse_version(version_str: str) -> Tuple[int, ...]:
    """
    Parse semantic version string like 'v0.2.1' or '0.2.1-beta.1' into comparable ints.
    Pre-release suffixes sort lower than final releases of the same numeric tuple.
    """
    cleaned = (version_str or "").strip().lstrip("vV")
    if not cleaned:
        return (0, 0, 0, 0)
    main_part, sep, _ = cleaned.partition("-")
    nums = [int(p) for p in re.findall(r"\d+", main_part)[:3]]
    while len(nums) < 3:
        nums.append(0)
    # 1 = final release, 0 = pre-release
    is_final = 0 if sep else 1
    return (nums[0], nums[1], nums[2], is_final)


def is_newer_version(latest: str, current: str = __version__) -> bool:
    """Return True strictly when latest > current."""
    return parse_version(latest) > parse_version(current)


def detect_install_mode(project_root: Path) -> str:
    """
    Determine how MD-Vault is currently installed:
    - 'frozen_win': Standalone PyInstaller Windows .exe
    - 'frozen_mac': Standalone PyInstaller macOS .app bundle
    - 'git_source': Source checkout with .git directory and git CLI available
    - 'manual': Other source/Linux environment (open browser to update)
    """
    if getattr(sys, "frozen", False):
        if sys.platform == "win32":
            return "frozen_win"
        if sys.platform == "darwin" and _find_macos_app_bundle(Path(sys.executable)) is not None:
            return "frozen_mac"
        return "manual"

    if (project_root / ".git").exists() and shutil.which("git"):
        return "git_source"
    return "manual"


def _find_macos_app_bundle(executable_path: Path) -> Optional[Path]:
    """Walk parents of executable to locate enclosing .app bundle on macOS."""
    for parent in executable_path.resolve().parents:
        if parent.suffix.lower() == ".app":
            return parent
    return None


def _expected_asset_keyword() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return ""


def _default_asset_name_for_platform() -> str:
    if sys.platform == "win32":
        return "MD-Vault-Windows-x64.zip"
    if sys.platform == "darwin":
        return "MD-Vault-macOS-arm64.zip"
    return ""


def _fetch_via_redirect_fallback(repo: str, timeout: float) -> Dict[str, Any]:
    """
    Fallback update check using GitHub's /releases/latest HTTP redirect
    (immune to unauthenticated REST API 60 req/hr IP rate limits).
    """
    latest_url = f"https://github.com/{repo}/releases/latest"
    req = urllib.request.Request(
        latest_url,
        headers={"User-Agent": f"MD-Vault/{__version__}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        final_url = resp.geturl()

    # Expected final URL: https://github.com/<owner>/<repo>/releases/tag/vX.Y.Z
    match = re.search(r"/releases/tag/([^/?#]+)", final_url)
    if not match:
        raise RuntimeError("当前暂无已发布的 GitHub Release 版本")

    tag_name = match.group(1)
    asset_name = _default_asset_name_for_platform()
    download_url = (
        f"https://github.com/{repo}/releases/download/{tag_name}/{asset_name}"
        if asset_name
        else ""
    )
    sha256_url = f"https://github.com/{repo}/releases/download/{tag_name}/SHA256SUMS.txt"
    return {
        "tag_name": tag_name,
        "html_url": final_url,
        "body": "",
        "published_at": "",
        "asset_name": asset_name,
        "download_url": download_url,
        "sha256_url": sha256_url,
    }


def check_for_updates(
    project_root: Path,
    current_version: str = __version__,
    repo: str = GITHUB_REPO,
    timeout: float = 8.0,
) -> Dict[str, Any]:
    """Query GitHub Releases for the latest version without sending any user data."""
    install_mode = detect_install_mode(project_root)
    api_url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(
        api_url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"MD-Vault/{current_version}",
        },
    )

    release_info: Optional[Dict[str, Any]] = None
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        tag_name = str(data.get("tag_name", "")).strip()
        assets = data.get("assets") or []
        kw = _expected_asset_keyword()
        asset_name = ""
        download_url = ""
        sha256_url = ""

        for item in assets:
            name = str(item.get("name", ""))
            url = str(item.get("browser_download_url", ""))
            lower_name = name.lower()
            if lower_name == "sha256sums.txt":
                sha256_url = url
            elif kw and kw in lower_name and lower_name.endswith(".zip"):
                asset_name = name
                download_url = url

        release_info = {
            "tag_name": tag_name,
            "html_url": str(data.get("html_url") or f"https://github.com/{repo}/releases"),
            "body": str(data.get("body") or "").strip(),
            "published_at": str(data.get("published_at") or ""),
            "asset_name": asset_name,
            "download_url": download_url,
            "sha256_url": sha256_url,
        }
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 429):
            try:
                release_info = _fetch_via_redirect_fallback(repo, timeout)
            except Exception as fallback_exc:
                return {"ok": False, "error": f"检查更新受限或网络异常: {fallback_exc}"}
        elif exc.code == 404:
            return {"ok": False, "error": "远端仓库尚未发布任何 Release 版本"}
        else:
            return {"ok": False, "error": f"请求 GitHub Releases 失败 (HTTP {exc.code})"}
    except Exception as exc:
        try:
            release_info = _fetch_via_redirect_fallback(repo, timeout)
        except Exception:
            return {"ok": False, "error": f"无法连接 GitHub 检查更新: {exc}"}

    latest_tag = release_info["tag_name"]
    latest_clean = latest_tag.lstrip("vV")
    has_update = is_newer_version(latest_tag, current_version)

    can_self_update = install_mode in ("frozen_win", "frozen_mac") and bool(
        release_info["download_url"]
    )
    if install_mode == "git_source":
        can_self_update = True

    return {
        "ok": True,
        "current_version": current_version,
        "latest_version": latest_clean,
        "tag_name": latest_tag,
        "has_update": has_update,
        "install_mode": install_mode,
        "can_self_update": can_self_update,
        "release_url": release_info["html_url"],
        "release_notes": release_info["body"],
        "published_at": release_info["published_at"],
        "asset_name": release_info["asset_name"],
        "download_url": release_info["download_url"],
        "sha256_url": release_info["sha256_url"],
    }


def _download_file_with_progress(
    url: str,
    dest_path: Path,
    progress_cb: Optional[ProgressCallback] = None,
    timeout: float = 30.0,
) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": f"MD-Vault/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        total = int(resp.headers.get("Content-Length") or 0)
        downloaded = 0
        chunk_size = 64 * 1024
        with dest_path.open("wb") as fh:
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                fh.write(chunk)
                downloaded += len(chunk)
                if progress_cb:
                    if total > 0:
                        pct = min(85, max(5, int(downloaded * 80 / total) + 5))
                        mb_done = downloaded / (1024 * 1024)
                        mb_total = total / (1024 * 1024)
                        progress_cb(
                            f"正在下载更新包... {mb_done:.1f} / {mb_total:.1f} MB",
                            pct,
                        )
                    else:
                        mb_done = downloaded / (1024 * 1024)
                        progress_cb(f"正在下载更新包... {mb_done:.1f} MB", 45)


def verify_sha256_from_sums(zip_path: Path, asset_name: str, sums_text: str) -> bool:
    """
    Verify zip_path SHA-256 against SHA256SUMS.txt content.
    Raises ValueError on hash mismatch; returns True if matched, False if asset not listed.
    """
    expected_hash = ""
    for line in sums_text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            candidate_hash = parts[0].strip().lower()
            candidate_file = parts[-1].lstrip("*").strip()
            if Path(candidate_file).name == asset_name:
                expected_hash = candidate_hash
                break

    if not expected_hash:
        return False

    digest = hashlib.sha256(zip_path.read_bytes()).hexdigest().lower()
    if digest != expected_hash:
        raise ValueError(
            f"安装包 SHA-256 完整性校验失败（预期 {expected_hash[:12]}...，实际 {digest[:12]}...）"
        )
    return True


def _extract_windows_exe_from_zip(zip_path: Path, extract_dir: Path) -> Path:
    """Extract MD-Vault.exe from release zip archive and validate non-trivial binary size."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        exe_members = [
            m
            for m in zf.namelist()
            if not m.endswith("/") and Path(m).name.lower() == "md-vault.exe"
        ]
        if not exe_members:
            exe_members = [
                m for m in zf.namelist() if not m.endswith("/") and m.lower().endswith(".exe")
            ]
        if not exe_members:
            raise RuntimeError("更新压缩包中未找到可执行文件 MD-Vault.exe")

        member = exe_members[0]
        extracted = Path(zf.extract(member, path=extract_dir))
        if extracted.stat().st_size < 512 * 1024:
            raise RuntimeError("解压出的可执行文件体积异常，已中止替换")
        return extracted


def build_windows_updater_ps_script(
    pid: int,
    staged_exe: Path,
    target_exe: Path,
    temp_dir: Path,
) -> str:
    """Build PowerShell script that waits for old PID exit, swaps .exe, cleans temp, and relaunches."""
    # Escape single quotes for PowerShell single-quoted literal strings
    s_staged = str(staged_exe).replace("'", "''")
    s_target = str(target_exe).replace("'", "''")
    s_workdir = str(target_exe.parent).replace("'", "''")
    s_temp = str(temp_dir).replace("'", "''")

    return f"""
$ErrorActionPreference = 'SilentlyContinue'
Wait-Process -Id {int(pid)} -Timeout 20
for ($i = 0; $i -lt 20; $i++) {{
    Move-Item -LiteralPath '{s_staged}' -Destination '{s_target}' -Force
    if ($?) {{ break }}
    Start-Sleep -Milliseconds 400
}}
Remove-Item -LiteralPath '{s_temp}' -Recurse -Force
Start-Process -FilePath '{s_target}' -WorkingDirectory '{s_workdir}'
""".strip()


def apply_update_and_prepare_restart(
    project_root: Path,
    update_info: Dict[str, Any],
    progress_cb: Optional[ProgressCallback] = None,
) -> Dict[str, Any]:
    """
    Download, verify, stage the update, and spawn a detached updater/relauncher.
    Caller should immediately lock vault and close the window upon {'ok': True, 'restart': True}.
    """
    install_mode = detect_install_mode(project_root)

    if install_mode == "git_source":
        if progress_cb:
            progress_cb("正在通过 Git 拉取最新开源代码...", 35)
        proc = subprocess.run(
            ["git", "pull", "--ff-only", "origin", "main"],
            cwd=str(project_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        if proc.returncode != 0:
            err_msg = (proc.stderr or proc.stdout or "").strip()
            return {
                "ok": False,
                "error": f"Git 自动拉取失败（可能本地有未提交改动）：{err_msg}",
            }
        if progress_cb:
            progress_cb("代码更新完成，正在重启应用...", 95)

        creationflags = 0
        if sys.platform == "win32":
            creationflags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            )
        subprocess.Popen(
            [sys.executable, str(project_root / "app.py")],
            cwd=str(project_root),
            creationflags=creationflags,
            start_new_session=(sys.platform != "win32"),
        )
        return {"ok": True, "restart": True}

    download_url = str(update_info.get("download_url") or "").strip()
    asset_name = str(update_info.get("asset_name") or _default_asset_name_for_platform()).strip()
    sha256_url = str(update_info.get("sha256_url") or "").strip()

    if not download_url:
        return {"ok": False, "error": "未找到适配当前操作系统的安装包下载链接"}

    temp_dir = Path(tempfile.mkdtemp(prefix="md_vault_update_"))
    zip_path = temp_dir / (asset_name or "update.zip")

    try:
        if progress_cb:
            progress_cb("正在连接 GitHub 下载新版安装包...", 5)
        _download_file_with_progress(download_url, zip_path, progress_cb=progress_cb)

        if sha256_url:
            if progress_cb:
                progress_cb("正在校验 SHA-256 数字签名完整性...", 88)
            try:
                req = urllib.request.Request(
                    sha256_url, headers={"User-Agent": f"MD-Vault/{__version__}"}
                )
                with urllib.request.urlopen(req, timeout=12) as resp:
                    sums_text = resp.read().decode("utf-8", errors="replace")
                verify_sha256_from_sums(zip_path, asset_name, sums_text)
            except urllib.error.HTTPError as exc:
                # Older releases (< v0.2.0) did not publish SHA256SUMS.txt (404)
                if exc.code != 404:
                    raise

        if install_mode == "frozen_win":
            if progress_cb:
                progress_cb("正在解压并准备替换本地程序...", 93)
            target_exe = Path(sys.executable).resolve()
            extracted_exe = _extract_windows_exe_from_zip(zip_path, temp_dir)
            staged_exe = target_exe.with_name(target_exe.name + ".new")
            shutil.copy2(extracted_exe, staged_exe)

            ps_script = build_windows_updater_ps_script(
                pid=os.getpid(),
                staged_exe=staged_exe,
                target_exe=target_exe,
                temp_dir=temp_dir,
            )
            encoded_cmd = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) | getattr(
                subprocess, "DETACHED_PROCESS", 0x00000008
            )
            subprocess.Popen(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-WindowStyle",
                    "Hidden",
                    "-EncodedCommand",
                    encoded_cmd,
                ],
                creationflags=flags,
            )
            if progress_cb:
                progress_cb("准备就绪，正在重启进入新版本...", 100)
            return {"ok": True, "restart": True}

        if install_mode == "frozen_mac":
            target_app = _find_macos_app_bundle(Path(sys.executable))
            if target_app is None:
                raise RuntimeError("未能定位当前 macOS .app 应用包路径")

            if progress_cb:
                progress_cb("正在解压 macOS 应用包...", 92)
            extract_dir = temp_dir / "extracted"
            extract_dir.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["/usr/bin/ditto", "-x", "-k", str(zip_path), str(extract_dir)],
                check=True,
            )
            apps = list(extract_dir.glob("*.app"))
            if not apps:
                apps = list(extract_dir.rglob("*.app"))
            if not apps:
                raise RuntimeError("更新压缩包中未找到 MD-Vault.app")

            new_app = apps[0]
            subprocess.run(["/usr/bin/xattr", "-cr", str(new_app)], check=False)

            sh_script = temp_dir / "apply_mac_update.sh"
            pid = os.getpid()
            sh_script.write_text(
                f"""#!/bin/sh
for i in $(seq 1 40); do
    if ! kill -0 {pid} 2>/dev/null; then
        break
    fi
    sleep 0.3
done
rm -rf "{target_app}"
mv "{new_app}" "{target_app}"
open "{target_app}"
rm -rf "{temp_dir}"
""",
                encoding="utf-8",
            )
            sh_script.chmod(0o755)
            subprocess.Popen(["/bin/sh", str(sh_script)], start_new_session=True)
            if progress_cb:
                progress_cb("准备就绪，正在重启进入新版本...", 100)
            return {"ok": True, "restart": True}

        shutil.rmtree(temp_dir, ignore_errors=True)
        return {"ok": False, "error": "当前运行模式不支持自动覆盖，请前往 GitHub 下载页面手动更新"}
    except Exception as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return {"ok": False, "error": f"自动更新失败: {exc}"}
