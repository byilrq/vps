#!/bin/bash
set -e

# -----------------------------
#  输出函数
# -----------------------------
msg_ok()  { echo -e "\e[1;42m $1 \e[0m"; }
msg_err() { echo -e "\e[1;41m $1 \e[0m"; }
msg_inf() { echo -e "\e[1;34m$1\e[0m"; }

# -----------------------------
#  CPU 架构识别
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
        *)
            msg_err "不支持的 CPU 架构: $(uname -m)"
            exit 1
            ;;
    esac
}

# -----------------------------
#  架构映射到 Xray 发布包名称
# -----------------------------
xray_pkg_arch() {
    case "$(arch)" in
        amd64) echo "64" ;;
        386) echo "32" ;;
        arm64) echo "arm64-v8a" ;;
        armv7) echo "arm32-v7a" ;;
        armv6|armv5) echo "arm32-v6a" ;;
        *)
            msg_err "当前架构暂不支持自动更新"
            exit 1
            ;;
    esac
}

# -----------------------------
#  安装必要工具
# -----------------------------
ensure_tools() {
    local need_pkgs=()

    command -v unzip >/dev/null 2>&1 || need_pkgs+=("unzip")
    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || need_pkgs+=("curl")

    if [[ ${#need_pkgs[@]} -eq 0 ]]; then
        return 0
    fi

    msg_inf "缺少依赖: ${need_pkgs[*]}，尝试安装..."

    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y -q >/dev/null 2>&1 || true
        apt-get install -y "${need_pkgs[@]}" >/dev/null 2>&1 || {
            msg_err "依赖安装失败: ${need_pkgs[*]}"
            exit 1
        }
    elif command -v yum >/dev/null 2>&1; then
        yum install -y "${need_pkgs[@]}" >/dev/null 2>&1 || {
            msg_err "依赖安装失败: ${need_pkgs[*]}"
            exit 1
        }
    else
        msg_err "未检测到受支持的包管理器，无法安装依赖"
        exit 1
    fi
}

# -----------------------------
#  选择 xray 目标文件
# -----------------------------
detect_xray_paths() {
    XRAY_DIR="/usr/local/x-ui/bin"
    XRAY_BIN_MAIN="${XRAY_DIR}/xray"
    XRAY_BIN_ARCH="${XRAY_DIR}/xray-linux-$(arch)"
    XRAY_BIN_ARM="${XRAY_DIR}/xray-linux-arm"

    [[ -d "$XRAY_DIR" ]] || {
        msg_err "未找到 x-ui 目录: $XRAY_DIR"
        exit 1
    }

    if [[ -x "$XRAY_BIN_ARCH" ]]; then
        XRAY_TARGET="$XRAY_BIN_ARCH"
    elif [[ -x "$XRAY_BIN_MAIN" ]]; then
        XRAY_TARGET="$XRAY_BIN_MAIN"
    elif [[ -x "$XRAY_BIN_ARM" ]]; then
        XRAY_TARGET="$XRAY_BIN_ARM"
    else
        msg_err "未找到 x-ui 自带的 xray 可执行文件"
        exit 1
    fi
}

# -----------------------------
#  获取本地 xray 版本
# -----------------------------
get_local_xray_version() {
    local ver
    ver="$("$XRAY_TARGET" version 2>/dev/null | head -n1 | sed -E 's/^Xray[[:space:]]+([0-9.]+).*/\1/' || true)"
    echo "$ver"
}

# -----------------------------
#  获取远端最新版本
# -----------------------------
get_latest_xray_version() {
    local api="https://api.github.com/repos/XTLS/Xray-core/releases/latest"
    local tag=""

    if command -v curl >/dev/null 2>&1; then
        tag="$(curl -fsSL "$api" | grep '"tag_name":' | head -n1 | sed -E 's/.*"([^"]+)".*/\1/' || true)"
    else
        tag="$(wget -qO- "$api" | grep '"tag_name":' | head -n1 | sed -E 's/.*"([^"]+)".*/\1/' || true)"
    fi

    echo "${tag#v}"
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
    if systemctl is-active --quiet x-ui; then
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
#  恢复服务
# -----------------------------
start_related_services() {
    if [[ "$NEED_RESTART_XUI" == "y" ]]; then
        systemctl start x-ui >/dev/null 2>&1 || {
            msg_err "x-ui 启动失败，请检查备份并手动回滚"
            exit 1
        }
    else
        systemctl restart x-ui >/dev/null 2>&1 || true
    fi

    nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || true
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
#  写入新 xray
# -----------------------------
install_new_binary() {
    local new_bin="$1"

    cp -f "$new_bin" "$XRAY_BIN_MAIN" 2>/dev/null || true
    chmod +x "$XRAY_BIN_MAIN" 2>/dev/null || true

    cp -f "$new_bin" "$XRAY_BIN_ARCH" 2>/dev/null || true
    chmod +x "$XRAY_BIN_ARCH" 2>/dev/null || true

    if [[ "$(arch)" == "armv5" || "$(arch)" == "armv6" || "$(arch)" == "armv7" ]]; then
        cp -f "$new_bin" "$XRAY_BIN_ARM" 2>/dev/null || true
        chmod +x "$XRAY_BIN_ARM" 2>/dev/null || true
    fi
}

# -----------------------------
#  更新 Xray-core
# -----------------------------
xray_updata() {
    local TMP_DIR=""
    local ZIP_FILE=""
    local DOWNLOAD_URL=""
    local REMOTE_VER=""
    local LOCAL_VER=""
    local PKG_ARCH=""
    local API_TAG=""

    ensure_tools
    detect_xray_paths

    TMP_DIR="/tmp/xray_update_$$"
    mkdir -p "$TMP_DIR"

    PKG_ARCH="$(xray_pkg_arch)"
    LOCAL_VER="$(get_local_xray_version)"
    REMOTE_VER="$(get_latest_xray_version)"
    API_TAG="v${REMOTE_VER}"

    echo "----------------------------------------------------------------"
    echo "Xray-core 更新检查"
    echo "----------------------------------------------------------------"
    echo "当前文件: $XRAY_TARGET"
    echo "本地版本: ${LOCAL_VER:-未知}"
    echo "远端版本: ${REMOTE_VER:-未知}"

    if ! need_update "$LOCAL_VER" "$REMOTE_VER"; then
        msg_ok "当前已是最新版本，无需更新"
        rm -rf "$TMP_DIR"
        return 0
    fi

    DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/download/${API_TAG}/Xray-linux-${PKG_ARCH}.zip"
    ZIP_FILE="${TMP_DIR}/xray.zip"

    msg_inf "检测到新版本，开始下载..."
    msg_inf "$DOWNLOAD_URL"

    if command -v curl >/dev/null 2>&1; then
        curl -L --fail --connect-timeout 15 --max-time 300 -o "$ZIP_FILE" "$DOWNLOAD_URL" || {
            msg_err "下载失败"
            rm -rf "$TMP_DIR"
            exit 1
        }
    else
        wget -qO "$ZIP_FILE" "$DOWNLOAD_URL" || {
            msg_err "下载失败"
            rm -rf "$TMP_DIR"
            exit 1
        }
    fi

    unzip -oq "$ZIP_FILE" -d "$TMP_DIR" || {
        msg_err "解压失败"
        rm -rf "$TMP_DIR"
        exit 1
    }

    [[ -f "${TMP_DIR}/xray" ]] || {
        msg_err "解压后未找到 xray 文件"
        rm -rf "$TMP_DIR"
        exit 1
    }

    chmod +x "${TMP_DIR}/xray"

    stop_related_services
    backup_existing_binaries
    install_new_binary "${TMP_DIR}/xray"
    start_related_services

    msg_ok "Xray-core 更新完成"
    echo "更新前版本: ${LOCAL_VER:-未知}"
    echo "更新后版本: $(get_local_xray_version)"
    echo "备份时间戳: ${BACKUP_TIME:-未知}"

    rm -rf "$TMP_DIR"
}

main() {
    xray_updata
}

main "$@"
