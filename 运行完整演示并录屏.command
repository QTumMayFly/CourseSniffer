#!/bin/bash
set -u
cd "$(dirname "$0")" || exit 2
/bin/bash scripts/record_demo_macos.sh
result=$?
printf '\n操作结束，退出状态：%s。\n' "$result"
read -r -p '按回车键关闭终端窗口：' _
exit "$result"
