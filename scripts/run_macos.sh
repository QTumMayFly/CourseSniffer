#!/bin/bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_PATH="$PROJECT_DIR/build/CourseSniffer.app/Contents/MacOS/CourseSniffer"
if [[ ! -x "$APP_PATH" ]]; then
    echo "请执行 bash scripts/build_macos.sh 构建应用。"
    exit 1
fi
if [[ "${1:-}" == "--demo" ]]; then
    exec "$APP_PATH" "$@"
fi
exec sudo "$APP_PATH" "$@"
