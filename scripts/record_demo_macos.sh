#!/bin/bash
# CourseSniffer 实验 1A：物理网卡与回环抓包、界面操作和字幕录制。
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "录制脚本需要在有图形桌面的 macOS 设备上运行。" >&2
    exit 2
fi
if [[ "$EUID" -eq 0 ]]; then
    echo "请在普通用户的 Terminal 中运行；系统会在抓包时单独申请管理员授权。" >&2
    exit 2
fi
if ! command -v brew >/dev/null 2>&1; then
    echo "缺少 Homebrew，请安装后重新运行。" >&2
    exit 2
fi
if ! xcrun --sdk macosx --show-sdk-path >/dev/null 2>&1; then
    echo "缺少 macOS Command Line Tools；请在系统终端执行 xcode-select --install。" >&2
    exit 2
fi
export HOMEBREW_NO_AUTO_UPDATE=1
for formula in qtbase cmake ninja ffmpeg; do
    if [[ -z "$(brew list --versions "$formula" 2>/dev/null)" ]]; then
        echo "安装依赖：$formula"
        brew install "$formula"
    fi
done
if ! ffmpeg -hide_banner -encoders 2>/dev/null | grep -E '[[:space:]]libx264[[:space:]]' >/dev/null; then
    echo "当前 ffmpeg 不支持 H.264 编码器 libx264。请安装 Homebrew 的 ffmpeg。" >&2
    exit 2
fi
if [[ ! -f "demo/protocol_examples.pcap" ]]; then
    echo "缺少离线协议样例 demo/protocol_examples.pcap。" >&2
    exit 2
fi
# 构建并运行测试。失败即终止录制，避免输出错误演示。
bash scripts/build_macos.sh
APP="$PROJECT_DIR/build/CourseSniffer.app/Contents/MacOS/CourseSniffer"
if [[ ! -x "$APP" ]]; then
    echo "应用构建文件不存在。" >&2
    exit 2
fi
OUT_DIR="$PROJECT_DIR/recordings"
mkdir -p "$OUT_DIR"
MOVIE="$OUT_DIR/仲泓宇_202618013229068_ex1A_play.mp4"
PYTHON="$(command -v python3)"
FFMPEG="$(command -v ffmpeg)"
ROUTE="$(/sbin/route -n get default)"
INTERFACE="$(awk '/interface:/{print $2; exit}' <<< "$ROUTE")"
GATEWAY="$(awk '/gateway:/{print $2; exit}' <<< "$ROUTE")"
if ! [[ "$INTERFACE" =~ ^en[0-9]+$ ]]; then
    echo "默认 IPv4 路由需要经过活动的 Wi-Fi 或以太网接口，当前接口：$INTERFACE。" >&2
    exit 2
fi
SOURCE="$(/usr/sbin/ipconfig getifaddr "$INTERFACE")"
"$PYTHON" - "$SOURCE" "$GATEWAY" <<'PY'
from ipaddress import IPv4Address
import sys
source, gateway = map(IPv4Address, sys.argv[1:])
if source == gateway or source.is_loopback or gateway.is_loopback:
    raise SystemExit("物理接口的本机地址和网关地址必须有效且不同。")
PY
printf '\n录制真实 CourseSniffer 操作，输出文件：\n%s\n' "$MOVIE"
echo "即将申请 BPF 抓包临时权限，演示接口为 $INTERFACE 和 lo0。"
"$PYTHON" "$PROJECT_DIR/scripts/capture_permissions_macos.py" --timeout 300 -- \
    /usr/bin/env "COURSESNIFFER_PYTHON=$PYTHON" "COURSESNIFFER_FFMPEG=$FFMPEG" \
    "COURSESNIFFER_RECORD_INTERFACE=$INTERFACE" "COURSESNIFFER_RECORD_SOURCE=$SOURCE" \
    "COURSESNIFFER_RECORD_GATEWAY=$GATEWAY" \
    "$APP" --record-demo "$MOVIE" \
    --demo-script "$PROJECT_DIR/demo/run_demo.py" \
    --sample-pcap "$PROJECT_DIR/demo/protocol_examples.pcap"
python3 - "$MOVIE" <<'PY'
from pathlib import Path
import json
import sys
movie = Path(sys.argv[1])
record = json.loads(movie.with_suffix('.proof.json').read_text(encoding='utf-8'))
if not movie.is_file() or movie.stat().st_size < 100_000 or not record['passed']:
    raise SystemExit('视频结果检查失败，请查看 recordings 目录中的日志。')
if not movie.with_suffix('.srt').is_file():
    raise SystemExit('未生成字幕文件。')
physical = record.get('physical_capture', {})
if not physical.get('promiscuous_requested') or not physical.get('capture_activated'):
    raise SystemExit('物理网卡混杂模式的演示记录不完整。')
if not physical.get('echo_requests'):
    raise SystemExit('物理网卡演示缺少本机发出的网关探测报文。')
print('\n真实操作视频录制完成。')
print('MP4:', movie)
print('字幕:', movie.with_suffix('.srt'))
print('验证:', movie.with_suffix('.proof.json'))
PY
