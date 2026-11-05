#!/usr/bin/env bash
# 上海三网 IPv4 网络质量检测：三个独立开关，回车默认 y。
# 运行源： https://github.com/byilrq/vps/tree/main/tcpquality
set -Eeuo pipefail

RAW_BASE="${TCPQUALITY_RAW_BASE:-https://raw.githubusercontent.com/byilrq/vps/main/tcpquality}"
case "$RAW_BASE" in
  https://*|http://*) ;;
  *) echo "[X] TCPQUALITY_RAW_BASE 必须是 http(s) 地址" >&2; exit 1 ;;
esac
RAW_BASE="${RAW_BASE%/}"
export TCPQUALITY_RAW_BASE="$RAW_BASE"

SHOW_HELP=0
NO_ROOTFS=0
DEBUG=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help) SHOW_HELP=1 ;;
    --no-rootfs) NO_ROOTFS=1 ;;
    --debug) DEBUG=1 ;;
    *) printf '[X] 不支持的参数: %s\n' "$1" >&2; exit 2 ;;
  esac
  shift
done
if [ "$SHOW_HELP" -eq 1 ]; then
  cat <<'EOF'
TcpQuality · 上海三网 IPv4 专用版
用法：bash runTcpQuality.sh [--no-rootfs] [--debug]

启动后逐项询问，回车默认 y：
  1. 上海电信/联通/移动 IPv4 回程（线路 + 丢包/延迟）
  2. 上海电信/联通/移动 IPv4 大包回程
  3. 上海电信/联通/移动 IPv4 单线程测速（上传/下载）

默认在临时 Debian rootfs 中运行，避免在宿主系统安装探测依赖。
--no-rootfs：直接在宿主系统运行，依赖需安装，特别是大包探测的 nexttrace-tiny。
结果显示在终端，并保存本地 CSV；默认不上传在线报告。
EOF
  exit 0
fi

question() {
  local label="$1" answer="" prompt
  prompt="${label} [Y/n]："
  while :; do
    printf '%s' "$prompt" >&2
    if [ -t 2 ] && [ -r /dev/tty ] && [ -w /dev/tty ]; then
      IFS= read -r answer </dev/tty || answer=""
    else
      IFS= read -r answer || answer=""
    fi
    answer="${answer,,}"
    case "$answer" in
      ''|y|yes) printf '1'; return 0 ;;
      n|no) printf '0'; return 0 ;;
      *) printf '  请输入 y 或 n；直接回车代表 y。\n' >&2 ;;
    esac
  done
}

printf '\n===== TcpQuality | 上海三网 IPv4 =====\n' >&2
NORMAL=$(question '1. 测试上海三网 IPv4 回程？')
LARGE=$(question '2. 测试上海三网 IPv4 大包回程？')
SPEED=$(question '3. 测试上海三网 IPv4 单线程测速？')
if [ "$NORMAL$LARGE$SPEED" = '000' ]; then
  echo '[i] 三项均选 n，没有执行任何测试。' >&2
  exit 0
fi

CORE_ARGS=(--shanghai-only)
[ "$NORMAL" -eq 1 ] && CORE_ARGS+=(--sh-normal)
[ "$LARGE" -eq 1 ] && CORE_ARGS+=(--sh-large)
if [ "$SPEED" -eq 1 ]; then
  if [ "$NORMAL" -eq 0 ] && [ "$LARGE" -eq 0 ]; then
    CORE_ARGS+=(--only-speedtest)
  else
    CORE_ARGS+=(--speedtest)
  fi
fi
[ "$DEBUG" -eq 1 ] && CORE_ARGS+=(--debug)

printf '\n[√] 运行选择：IPv4回程=%s  IPv4大包=%s  单线程测速=%s\n' \
  "$([ "$NORMAL" -eq 1 ] && echo y || echo n)" \
  "$([ "$LARGE" -eq 1 ] && echo y || echo n)" \
  "$([ "$SPEED" -eq 1 ] && echo y || echo n)" >&2
printf '[i] 仅限上海电信 / 联通 / 移动；仅限 IPv4。\n\n' >&2

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || printf '.')
CORE="$SCRIPT_DIR/runTcpQuality-core.sh"
ROOTFS_RUNNER="$SCRIPT_DIR/runTcpQuality-rootfs.sh"
TEMP_DIR=""
cleanup() {
  [ -z "$TEMP_DIR" ] || rm -rf -- "$TEMP_DIR"
}
trap cleanup EXIT

fetch_script() {
  local file="$1" target="$2"
  echo "[i] 正在下载必要程序: $file" >&2
  curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 \
    "$RAW_BASE/$file" -o "$target" || {
    printf '[X] 下载失败: %s/%s\n' "$RAW_BASE" "$file" >&2
    return 1
  }
  chmod 0755 "$target"
}
if [ ! -r "$CORE" ] || { [ "$NO_ROOTFS" -eq 0 ] && [ ! -r "$ROOTFS_RUNNER" ]; }; then
  TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/tcpquality-sh.XXXXXX")
  if [ ! -r "$CORE" ]; then
    CORE="$TEMP_DIR/runTcpQuality-core.sh"
    fetch_script runTcpQuality-core.sh "$CORE"
  fi
  if [ "$NO_ROOTFS" -eq 0 ] && [ ! -r "$ROOTFS_RUNNER" ]; then
    ROOTFS_RUNNER="$TEMP_DIR/runTcpQuality-rootfs.sh"
    fetch_script runTcpQuality-rootfs.sh "$ROOTFS_RUNNER"
  fi
fi

if [ "$NO_ROOTFS" -eq 1 ]; then
  bash "$CORE" "${CORE_ARGS[@]}"
  exit $?
fi
if [ "$(uname -s)" != 'Linux' ]; then
  echo '[X] rootfs 运行模式仅支持 Linux；请使用 Linux VPS。' >&2
  exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
  echo '[X] rootfs 运行需要 root 权限，请使用 sudo bash runTcpQuality.sh。' >&2
  exit 1
fi
export TCPQUALITY_CORE_SCRIPT="$CORE"
[ ! -r "$SCRIPT_DIR/tcpquality-tcpinfo.c" ] || export TCPQUALITY_TCP_INFO_SOURCE="$SCRIPT_DIR/tcpquality-tcpinfo.c"
[ ! -r "$SCRIPT_DIR/tcpquality-retrans-seq.bt" ] || export TCPQUALITY_RETRANS_TRACE_SCRIPT_SOURCE="$SCRIPT_DIR/tcpquality-retrans-seq.bt"
[ ! -r "$SCRIPT_DIR/tcpquality-retrans-skb.bt" ] || export TCPQUALITY_RETRANS_TRACE_FALLBACK_SCRIPT_SOURCE="$SCRIPT_DIR/tcpquality-retrans-skb.bt"
# 传入明确的参数，禁止 rootfs 原版再次弹出其全国/国际测试问答。
bash "$ROOTFS_RUNNER" --distro debian -- "${CORE_ARGS[@]}"
