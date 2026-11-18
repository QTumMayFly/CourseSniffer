#!/bin/bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULT_DIR="$PROJECT_DIR/local-validation"
TEST_PATH="$PROJECT_DIR/build/sniffer_gui_tests"
if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "此脚本用于 macOS 本机抓包验证。"
    exit 1
fi
if [[ ! -x "$TEST_PATH" ]]; then
    echo "请执行 bash scripts/build_macos.sh 构建程序及测试。"
    exit 1
fi
PYTHON_PATH="$(command -v python3)"
mkdir -p "$RESULT_DIR"
sudo env QT_QPA_PLATFORM=offscreen COURSESNIFFER_LIVE_TEST=1 \
    COURSESNIFFER_PYTHON="$PYTHON_PATH" \
    "$PYTHON_PATH" "$PROJECT_DIR/scripts/run_capture_tests.py" \
    "$TEST_PATH" 2>&1 | tee "$RESULT_DIR/live_capture.txt"
echo "本机抓包验证完成，结果位于 $RESULT_DIR/live_capture.txt"
