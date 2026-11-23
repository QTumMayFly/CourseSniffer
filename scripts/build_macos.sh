#!/bin/bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULT_DIR="$PROJECT_DIR/local-validation"
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
if [[ ! -f "$QT_PREFIX/lib/cmake/Qt6/Qt6Config.cmake" ]]; then
    echo "Qt 6 配置文件不可用，请执行 brew install qtbase。"
    exit 1
fi
MACOS_SDK_PATH="$(xcrun --sdk macosx --show-sdk-path)"
MACOS_ARCH="$(uname -m)"
mkdir -p "$RESULT_DIR"
cmake -S "$PROJECT_DIR" -B "$PROJECT_DIR/build" -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_PREFIX_PATH="$QT_PREFIX" \
    -DCMAKE_OSX_SYSROOT="$MACOS_SDK_PATH" -DCMAKE_OSX_ARCHITECTURES="$MACOS_ARCH" \
    -DSNIFFER_BUILD_GUI=ON -DBUILD_TESTING=ON \
    2>&1 | tee "$RESULT_DIR/configure.txt"
cmake --build "$PROJECT_DIR/build" --parallel 4 2>&1 | tee "$RESULT_DIR/build.txt"
APP_PATH="$PROJECT_DIR/build/CourseSniffer.app/Contents/MacOS/CourseSniffer"
if [[ ! -x "$APP_PATH" || ! -x "$PROJECT_DIR/build/sniffer_gui_tests" ]]; then
    echo "构建结果缺少应用或 GUI 测试程序，请查看 local-validation/build.txt。"
    exit 1
fi
ctest --test-dir "$PROJECT_DIR/build" --no-tests=error --output-on-failure \
    --output-junit "$RESULT_DIR/ctest.xml" \
    2>&1 | tee "$RESULT_DIR/ctest.txt"
echo "应用路径：$PROJECT_DIR/build/CourseSniffer.app"
