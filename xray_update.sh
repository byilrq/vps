#!/bin/bash
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# -----------------------------
#  日志文件路径
# -----------------------------
LOG_FILE="/var/log/xray_update.log"

# -----------------------------
#  输出函数
# -----------------------------
msg_ok()  { echo -e "\e[1;42m $1 \e[0m"; }
msg_err() { echo -e "\e[1;41m $1 \e[0m"; }
msg_inf() { echo -e "\e[1;34m$1\e[0m"; }
msg_warn(){ echo -e "\e[1;33m$1\e[0m"; }

TMP_DIR=""
NEED_RESTART_XUI="n"
BACKUP_TIME=""
UPDATE_SUCCESS="no"
FINAL_MESSAGE=""

cleanup() {
    [[ -n "${TMP_DIR:-}" && -d "${TMP_DIR:-}" ]] && rm -rf "$TMP_DIR" || true
    # 在脚本退出前将最终结果写入日志文件
    if [[ -n "$FINAL_MESSAGE" ]]; then
        echo "$FINAL_MESSAGE" >> "$LOG_FILE" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# -----------------------------
#  记录更新结果到日志文件
# -----------------------------
record_result() {
    local status="$1"   # SUCCESS / FAILED / SKIPPED / INFO
    local message="$2"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    FINAL_MESSAGE="[${timestamp}] ${status}: ${message}"
}

# -----------------------------
#  CPU 架构识别：匹配 3x-ui 安装脚本命名
# -----------------------------
arch() {
    case "$(uname -m)" in
        x86_64|x64|amd64) echo "amd64" ;;
        i*86|x86) echo "386" ;;
        armv8*|armv8|arm64|aarch64) echo "arm64" ;;
        armv7*|armv7|arm) echo "armv7" ;;
        armv6*|armv6) echo "armv6" ;;
        armv5*|armv5) echo "armv5" ;;
        s390x) echo "s390x" ;;
        *) msg_err "不支持的 CPU 架构: $(uname -m)"; record_result "FAILED" "不支持的 CPU 架构: $(uname -m)"; exit 1 ;;
    esac
}

# -----------------------------
#  架构映射到 XTLS/Xray-core 发布包名称
# -----------------------------
xray_pkg_arch() {
    case "$(arch)" in
        amd64) echo "64" ;;
        386) echo "32" ;;
        arm64) echo "arm64-v8a" ;;
        armv7) echo "arm32-v7a" ;;
        armv6|armv5) echo "arm32-v6a" ;;
        s390x) echo "s390x" ;;
        *) msg_err "当前架构暂不支持自动更新"; record_result "FAILED" "当前架构暂不支持自动更新"; exit 1 ;;
    esac
}

# -----------------------------
#  安装必要工具
# -----------------------------
ensure_tools() {
    local need_pkgs=()

    command -v unzip >/dev/null 2>&1 || need_pkgs+=("unzip")
    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || need_pkgs+=("curl")
    command -v sort >/dev/null 2>&1 || need_pkgs+=("coreutils")

    if [[ ${#need_pkgs[@]} -eq 0 ]]; then
        return 0
    fi

    msg_inf "缺少依赖: ${need_pkgs[*]}，尝试安装..."

    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y -q >/dev/null 2>&1 || true
        apt-get install -y "${need_pkgs[@]}" >/dev/null 2>&1 || {
            msg_err "依赖安装失败: ${need_pkgs[*]}"
            record_result "FAILED" "依赖安装失败: ${need_pkgs[*]}"
            exit 1
        }
    elif command -v yum >/dev/null 2>&1; then
        yum install -y "${need_pkgs[@]}" >/dev/null 2>&1 || {
            msg_err "依赖安装失败: ${need_pkgs[*]}"
            record_result "FAILED" "依赖安装失败: ${need_pkgs[*]}"
            exit 1
        }
    else
        msg_err "未检测到受支持的包管理器，无法安装依赖"
        record_result "FAILED" "未检测到受支持的包管理器"
        exit 1
    fi
}

fetch_url() {
    local url="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 15 --max-time 300 --retry 2 "$url"
    else
        wget -qO- --timeout=20 --tries=2 "$url"
    fi
}

download_file() {
    local url="$1"
    local out="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -L --fail --connect-timeout 15 --max-time 300 --retry 2 -o "$out" "$url"
    else
        wget -qO "$out" --timeout=20 --tries=2 "$url"
    fi
}

# -----------------------------
#  选择 3x-ui 实际 Xray 目标文件
# -----------------------------
detect_xray_paths() {
    XRAY_DIR="/usr/local/x-ui/bin"
    XRAY_BIN_MAIN="${XRAY_DIR}/xray"
    XRAY_BIN_ARCH="${XRAY_DIR}/xray-linux-$(arch)"
    XRAY_BIN_ARM="${XRAY_DIR}/xray-linux-arm"

    [[ -d "$XRAY_DIR" ]] || {
        msg_err "未找到 x-ui 目录: $XRAY_DIR"
        record_result "FAILED" "未找到 x-ui 目录: $XRAY_DIR"
        exit 1
    }

    if [[ -x "$XRAY_BIN_ARCH" ]]; then
        XRAY_TARGET="$XRAY_BIN_ARCH"
    elif [[ -x "$XRAY_BIN_MAIN" ]]; then
        XRAY_TARGET="$XRAY_BIN_MAIN"
    elif [[ -x "$XRAY_BIN_ARM" ]]; then
        XRAY_TARGET="$XRAY_BIN_ARM"
    else
        msg_err "未找到 3x-ui 自带的 xray 可执行文件"
        record_result "FAILED" "未找到 3x-ui 自带的 xray 可执行文件"
        exit 1
    fi
}

get_xray_version_from_file() {
    local bin="$1"
    [[ -x "$bin" ]] || return 0
    "$bin" version 2>/dev/null | head -n1 | sed -E 's/^Xray[[:space:]]+v?([0-9]+(\.[0-9]+)+).*/\1/' || true
}

# -----------------------------
#  获取本地 xray 版本
# -----------------------------
get_local_xray_version() {
    get_xray_version_from_file "$XRAY_TARGET"
}

# -----------------------------
#  获取远端最高版本
#  重要：/releases/latest 只会返回 GitHub 标记的 Latest，
#  Xray-core 的 v26.4.x 可能不是 latest，但 3x-ui 面板会列出来。
#  所以这里扫描 releases 列表并选版本号最高的 tag。
# -----------------------------
get_latest_xray_version() {
    local api_all="https://api.github.com/repos/XTLS/Xray-core/releases?per_page=50"
    local api_latest="https://api.github.com/repos/XTLS/Xray-core/releases/latest"
    local tags=""
    local latest_tag=""

    tags="$(fetch_url "$api_all" 2>/dev/null \
        | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"v[0-9]+(\.[0-9]+)+"' \
        | sed -E 's/.*"(v[0-9]+(\.[0-9]+)+)".*/\1/' \
        | sort -Vu || true)"

    if [[ -n "$tags" ]]; then
        latest_tag="$(printf '%s\n' "$tags" | sed 's/^v//' | sort -Vu | tail -n1)"
        echo "$latest_tag"
        return 0
    fi

    latest_tag="$(fetch_url "$api_latest" 2>/dev/null \
        | grep '"tag_name":' \
        | head -n1 \
        | sed -E 's/.*"v?([0-9]+(\.[0-9]+)+)".*/\1/' || true)"

    echo "$latest_tag"
}

# -----------------------------
#  比较版本
#  返回 0 = 需要更新
#  返回 1 = 不需要更新
# -----------------------------
need_update() {
    local local_ver="$1"
    local remote_ver="$2"
    local newest=""

    [[ -z "$remote_ver" ]] && return 1
    [[ -z "$local_ver" ]] && return 0
    [[ "$local_ver" == "$remote_ver" ]] && return 1

    newest="$(printf '%s\n%s\n' "$local_ver" "$remote_ver" | sort -V | tail -n1)"
    [[ "$newest" == "$remote_ver" && "$remote_ver" != "$local_ver" ]]
}

# -----------------------------
#  停止相关服务/进程
# -----------------------------
stop_related_services() {
    if systemctl is-active --quiet x-ui 2>/dev/null; then
        NEED_RESTART_XUI="y"
        systemctl stop x-ui >/dev/null 2>&1 || true
    else
        NEED_RESTART_XUI="n"
    fi

    pkill -f '/usr/local/x-ui/bin/xray' 2>/dev/null || true
    pkill -f 'xray-linux' 2>/dev/null || true
    pkill -x xray 2>/dev/null || true
    sleep 2
}

# -----------------------------
#  恢复服务：重启面板，让面板重新读取/展示新 Xray 版本
# -----------------------------
start_related_services() {
    systemctl daemon-reload >/dev/null 2>&1 || true

    if [[ "$NEED_RESTART_XUI" == "y" ]]; then
        systemctl start x-ui >/dev/null 2>&1 || {
            msg_err "x-ui 启动失败，请检查备份并手动回滚"
            record_result "FAILED" "x-ui 启动失败"
            exit 1
        }
    else
        systemctl restart x-ui >/dev/null 2>&1 || true
    fi

    sleep 3

    if command -v nginx >/dev/null 2>&1; then
        nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || true
    fi
}

# -----------------------------
#  备份原有 xray
# -----------------------------
backup_existing_binaries() {
    BACKUP_TIME="$(date +%Y%m%d_%H%M%S)"

    [[ -f "$XRAY_BIN_MAIN" ]] && cp -af "$XRAY_BIN_MAIN" "${XRAY_BIN_MAIN}.bak.${BACKUP_TIME}" || true
    [[ -f "$XRAY_BIN_ARCH" ]] && cp -af "$XRAY_BIN_ARCH" "${XRAY_BIN_ARCH}.bak.${BACKUP_TIME}" || true
    [[ -f "$XRAY_BIN_ARM"  ]] && cp -af "$XRAY_BIN_ARM"  "${XRAY_BIN_ARM}.bak.${BACKUP_TIME}"  || true
}

# -----------------------------
#  写入新 xray：同时覆盖 3x-ui 可能使用的多个文件名
# -----------------------------
install_new_binary() {
    local new_bin="$1"

    install -m 755 "$new_bin" "$XRAY_BIN_MAIN"
    install -m 755 "$new_bin" "$XRAY_BIN_ARCH"

    if [[ "$(arch)" == "armv5" || "$(arch)" == "armv6" || "$(arch)" == "armv7" ]]; then
        install -m 755 "$new_bin" "$XRAY_BIN_ARM"
    fi
}

verify_installed_version() {
    local expected="$1"
    local got=""
    got="$(get_xray_version_from_file "$XRAY_BIN_ARCH")"
    [[ -z "$got" ]] && got="$(get_xray_version_from_file "$XRAY_BIN_MAIN")"

    echo "写入后版本: ${got:-未知}"

    if [[ -z "$got" ]]; then
        msg_err "无法读取写入后的 Xray 版本"
        return 1
    fi

    if [[ "$got" != "$expected" ]]; then
        msg_warn "写入后的版本与预期不一致：预期 ${expected}，实际 ${got}"
        return 1
    fi

    # 同步版本号到 x-ui 数据库，防止面板检测到版本不一致覆盖二进制文件
    local xuidb="/etc/x-ui/x-ui.db"
    if [[ -f "$xuidb" ]] && command -v sqlite3 >/dev/null 2>&1; then
        local db_ver
        db_ver=$(sqlite3 "$xuidb" "SELECT value FROM settings WHERE key='xrayVersion';" 2>/dev/null || true)
        if [[ -n "$db_ver" ]]; then
            sqlite3 "$xuidb" "UPDATE settings SET value='v${expected}' WHERE key='xrayVersion';" 2>/dev/null && \
                msg_inf "已同步 xrayVersion 到数据库: v${expected}"
        fi
    fi

    return 0
}

# -----------------------------
#  更新 Xray-core
# -----------------------------
xray_update() {
    local ZIP_FILE=""
    local DOWNLOAD_URL=""
    local REMOTE_VER=""
    local LOCAL_VER=""
    local PKG_ARCH=""
    local API_TAG=""
    local FORCE_UPDATE="n"

    if [[ "${1:-}" == "--force" || "${1:-}" == "-f" ]]; then
        FORCE_UPDATE="y"
    fi

    ensure_tools
    detect_xray_paths

    TMP_DIR="/tmp/xray_update_$$"
    mkdir -p "$TMP_DIR"

    PKG_ARCH="$(xray_pkg_arch)"
    LOCAL_VER="$(get_local_xray_version)"
    REMOTE_VER="$(get_latest_xray_version)"

    echo "----------------------------------------------------------------"
    echo "Xray-core 更新检查"
    echo "----------------------------------------------------------------"
    echo "当前文件: $XRAY_TARGET"
    echo "本地版本: ${LOCAL_VER:-未知}"
    echo "远端最高版本: ${REMOTE_VER:-获取失败}"

    if [[ -z "$REMOTE_VER" ]]; then
        msg_err "获取远端 Xray-core 版本失败。请检查 GitHub API 访问或网络/DNS。"
        record_result "FAILED" "获取远端版本失败"
        exit 1
    fi

    if [[ "$FORCE_UPDATE" != "y" ]] && ! need_update "$LOCAL_VER" "$REMOTE_VER"; then
        msg_ok "当前已是最高版本，无需更新"
        record_result "SKIPPED" "当前版本 ${LOCAL_VER:-未知} 已是最新，无需更新"
        start_related_services
        return 0
    fi

    API_TAG="v${REMOTE_VER}"
    DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/download/${API_TAG}/Xray-linux-${PKG_ARCH}.zip"
    ZIP_FILE="${TMP_DIR}/xray.zip"

    msg_inf "开始下载 Xray-core ${API_TAG} ..."
    msg_inf "$DOWNLOAD_URL"

    download_file "$DOWNLOAD_URL" "$ZIP_FILE" || {
        msg_err "下载失败：${DOWNLOAD_URL}"
        record_result "FAILED" "下载失败: ${DOWNLOAD_URL}"
        exit 1
    }

    unzip -oq "$ZIP_FILE" -d "$TMP_DIR" || {
        msg_err "解压失败"
        record_result "FAILED" "解压失败"
        exit 1
    }

    [[ -f "${TMP_DIR}/xray" ]] || {
        msg_err "解压后未找到 xray 文件"
        record_result "FAILED" "解压后未找到 xray 文件"
        exit 1
    }

    chmod +x "${TMP_DIR}/xray"

    stop_related_services
    backup_existing_binaries
    install_new_binary "${TMP_DIR}/xray"
    verify_installed_version "$REMOTE_VER" || true
    start_related_services

    msg_ok "Xray-core 更新完成并已重启 3x-ui/xray"
    echo "更新前版本: ${LOCAL_VER:-未知}"
    echo "目标版本: ${REMOTE_VER}"
    echo "备份时间戳: ${BACKUP_TIME:-未知}"
    echo
    echo "建议在面板刷新页面后，再打开版本弹窗确认当前选中版本。"

    record_result "SUCCESS" "从 ${LOCAL_VER:-未知} 更新到 ${REMOTE_VER}"
}

main() {
    xray_update "${1:-}"
}

main "$@"
