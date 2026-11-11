"""
Cross-platform PyInstaller build script for MD-Vault.

Usage:
    pip install -r requirements-dev.txt
    python build_app.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


def main() -> int:
    project_root = Path(__file__).resolve().parent
    ui_dir = project_root / "ui"
    if not (ui_dir / "index.html").exists():
        print("Error: ui/index.html not found.", file=sys.stderr)
        return 1

    # Clean previous build artifacts
    for folder in ("build", "dist"):
        target = project_root / folder
        if target.exists():
            shutil.rmtree(target)

    data_sep = ";" if sys.platform == "win32" else ":"
    add_data_arg = f"{ui_dir}{data_sep}ui"

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--windowed",
        "--name",
        "MD-Vault",
        "--add-data",
        add_data_arg,
    ]

    if sys.platform == "win32":
        ico_file = ui_dir / "assets" / "icon.ico"
        if ico_file.exists():
            cmd.extend(["--icon", str(ico_file)])
        # Single portable executable on Windows
        cmd.append("--onefile")
    elif sys.platform == "darwin":
        icns_file = ui_dir / "assets" / "icon.icns"
        if icns_file.exists():
            cmd.extend(["--icon", str(icns_file)])
        # Native macOS .app bundle
        cmd.extend(["--osx-bundle-identifier", "io.github.ataiben.mdvault"])

    cmd.append(str(project_root / "app.py"))

    print("Running PyInstaller:", " ".join(cmd))
    res = subprocess.run(cmd, cwd=str(project_root))
    if res.returncode != 0:
        return res.returncode

    dist_dir = project_root / "dist"
    print(f"\nBuild succeeded! Artifacts are located in: {dist_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
