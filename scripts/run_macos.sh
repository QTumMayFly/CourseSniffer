#!/bin/bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_PATH="$PROJECT_DIR/build/CourseSniffer.app/Contents/MacOS/CourseSniffer"
if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "此脚本用于 macOS。"
    exit 1
fi
if [[ "$EUID" -eq 0 ]]; then
    echo "请使用普通用户运行此脚本；实时捕获会通过系统 sudo 完成临时授权。"
    exit 1
fi
if [[ ! -x "$APP_PATH" ]]; then
    echo "请执行 bash scripts/build_macos.sh 构建应用。"
    exit 1
fi
cd "$PROJECT_DIR"
for argument in "$@"; do
    case "$argument" in
        --demo|--demo-pcap|--demo-pcap=*|--help|-h|--version|-v|--smoke-test|--screenshot|--screenshot=*|--stream-screenshot|--stream-screenshot=*)
            exec "$APP_PATH" "$@"
            ;;
    esac
done
if ! command -v python3 >/dev/null 2>&1; then
    echo "缺少 Python 3，请使用本机 Python 3.9 或更新版本运行权限脚本。"
    exit 1
fi
exec python3 "$PROJECT_DIR/scripts/capture_permissions_macos.py" -- "$APP_PATH" "$@"
