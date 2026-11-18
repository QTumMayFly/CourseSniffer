#!/bin/bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "此脚本用于 macOS。"
    exit 1
fi
for command in brew cmake ninja clang++; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "缺少构建工具：$command。请安装 Command Line Tools，并执行 brew install qtbase cmake ninja。"
        exit 1
    fi
done
QT_PREFIX="$(brew --prefix qtbase 2>/dev/null || brew --prefix qt)"
cmake -S "$PROJECT_DIR" -B "$PROJECT_DIR/build" -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_PREFIX_PATH="$QT_PREFIX"
cmake --build "$PROJECT_DIR/build" --parallel 4
ctest --test-dir "$PROJECT_DIR/build" --output-on-failure
echo "应用路径：$PROJECT_DIR/build/CourseSniffer.app"
