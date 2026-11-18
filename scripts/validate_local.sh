#!/bin/bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULT_DIR="$PROJECT_DIR/local-validation"
mkdir -p "$RESULT_DIR"
{
    date -u '+UTC %Y-%m-%d %H:%M:%S'
    uname -a
    if command -v sw_vers >/dev/null 2>&1; then sw_vers; fi
    clang++ --version
    cmake --version
    if command -v brew >/dev/null 2>&1; then brew list --versions qtbase cmake ninja; fi
} > "$RESULT_DIR/environment.txt" 2>&1
ctest --test-dir "$PROJECT_DIR/build" --output-on-failure 2>&1 | tee "$RESULT_DIR/ctest.txt"
echo "验证记录路径：$RESULT_DIR"
echo "本机实际抓包请按照 docs 中的验证说明执行，并保存截图。"
