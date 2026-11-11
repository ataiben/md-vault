#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
    PYTHON_BIN="$SCRIPT_DIR/.venv/bin/python"
elif [ -x "$SCRIPT_DIR/venv/bin/python" ]; then
    PYTHON_BIN="$SCRIPT_DIR/venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
else
    echo "未检测到 Python 3 环境，请先安装 Python 3.9+（例如 brew install python）。"
    read -r -p "按回车键退出..."
    exit 1
fi

if ! "$PYTHON_BIN" -c "import webview, cryptography, pydantic, yaml, watchfiles" >/dev/null 2>&1; then
    echo "检测到当前 Python 环境缺少运行依赖，正在为您创建虚拟环境或提示安装："
    echo "建议在终端执行："
    echo "  cd \"$SCRIPT_DIR\""
    echo "  python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt"
    read -r -p "按回车键退出..."
    exit 1
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/app.py"
