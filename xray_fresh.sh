# -----------------------------
#  更新 Xray-core
# -----------------------------
xray_updata() {
    echo "----------------------------------------------------------------"
    echo "更新 Xray-core"
    echo "----------------------------------------------------------------"

    local XRAY_DIR="/usr/local/x-ui/bin"
    local XRAY_BIN_MAIN="${XRAY_DIR}/xray"
    local XRAY_BIN_ARCH="${XRAY_DIR}/xray-linux-$(arch)"
    local XRAY_TARGET=""
    local XRAY_OLD_VER="未知"
    local XRAY_NEW_VER="未知"
    local TMP_DIR="/tmp/xray_update_$$"
    local PKG_ARCH=""
    local API_URL="https://api.github.com/repos/XTLS/Xray-core/releases/latest"
    local TAG_VERSION=""
    local DOWNLOAD_URL=""
    local ZIP_FILE=""
    local NEED_RESTART_XUI="n"

    if [[ ! -d "$XRAY_DIR" ]]; then
        msg_err "未找到 x-ui 的 bin 目录：$XRAY_DIR"
        return 1
    fi

    if [[ -x "$XRAY_BIN_ARCH" ]]; then
        XRAY_TARGET="$XRAY_BIN_ARCH"
    elif [[ -x "$XRAY_BIN_MAIN" ]]; then
        XRAY_TARGET="$XRAY_BIN_MAIN"
    else
        msg_err "未找到现有 xray 可执行文件。"
        echo "已检查："
        echo "  $XRAY_BIN_ARCH"
        echo "  $XRAY_BIN_MAIN"
        return 1
    fi

    case "$(arch)" in
        amd64) PKG_ARCH="64" ;;
        386) PKG_ARCH="32" ;;
        arm64) PKG_ARCH="arm64-v8a" ;;
        armv7) PKG_ARCH="arm32-v7a" ;;
        armv6) PKG_ARCH="arm32-v6a" ;;
        *)
            msg_err "当前架构 $(arch) 暂未在此更新函数中适配。"
            return 1
            ;;
    esac

    if [[ -x "$XRAY_TARGET" ]]; then
        XRAY_OLD_VER="$("$XRAY_TARGET" version 2>/dev/null | head -n1)"
    fi

    echo "当前 xray 文件: $XRAY_TARGET"
    echo "当前版本: $XRAY_OLD_VER"
    echo

    read -rp "确认更新到 Xray-core 最新版？(Y/n): " confirm_xray_update
    if [[ "$confirm_xray_update" =~ ^[Nn]$ ]]; then
        msg_err "已取消更新。"
        return 0
    fi

    mkdir -p "$TMP_DIR" || {
        msg_err "无法创建临时目录：$TMP_DIR"
        return 1
    }

    if ! command -v unzip >/dev/null 2>&1; then
        msg_inf "未检测到 unzip，尝试安装..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -y -q >/dev/null 2>&1 || true
            apt-get install -y unzip >/dev/null 2>&1 || {
                msg_err "unzip 安装失败"
                rm -rf "$TMP_DIR"
                return 1
            }
        elif command -v yum >/dev/null 2>&1; then
            yum install -y unzip >/dev/null 2>&1 || {
                msg_err "unzip 安装失败"
                rm -rf "$TMP_DIR"
                return 1
            }
        else
            msg_err "未检测到支持的包管理器，无法安装 unzip"
            rm -rf "$TMP_DIR"
            return 1
        fi
    fi

    msg_inf "获取 Xray-core 最新版本..."
    TAG_VERSION="$(curl -fsSL "$API_URL" | grep '"tag_name":' | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')"
    if [[ -z "$TAG_VERSION" ]]; then
        msg_err "获取 Xray-core 最新版本失败"
        rm -rf "$TMP_DIR"
        return 1
    fi

    ZIP_FILE="${TMP_DIR}/Xray-linux-${PKG_ARCH}.zip"
    DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/download/${TAG_VERSION}/Xray-linux-${PKG_ARCH}.zip"

    msg_inf "最新版本: ${TAG_VERSION}"
    msg_inf "下载地址: ${DOWNLOAD_URL}"

    if ! curl -L --fail --connect-timeout 15 --max-time 300 -o "$ZIP_FILE" "$DOWNLOAD_URL"; then
        msg_err "下载 Xray-core 失败"
        rm -rf "$TMP_DIR"
        return 1
    fi

    if ! unzip -oq "$ZIP_FILE" -d "$TMP_DIR"; then
        msg_err "解压 Xray-core 失败"
        rm -rf "$TMP_DIR"
        return 1
    fi

    if [[ ! -f "${TMP_DIR}/xray" ]]; then
        msg_err "解压后未找到 xray 主程序"
        rm -rf "$TMP_DIR"
        return 1
    fi

    chmod +x "${TMP_DIR}/xray"

    msg_inf "停止 x-ui 服务..."
    if systemctl is-active --quiet x-ui; then
        NEED_RESTART_XUI="y"
        systemctl stop x-ui 2>/dev/null || true
    fi

    pkill -f '/usr/local/x-ui/bin/xray' 2>/dev/null || true
    pkill -f 'xray-linux' 2>/dev/null || true
    pkill -x xray 2>/dev/null || true
    sleep 2

    local backup_time
    backup_time="$(date +%Y%m%d_%H%M%S)"

    if [[ -f "$XRAY_BIN_MAIN" ]]; then
        cp -af "$XRAY_BIN_MAIN" "${XRAY_BIN_MAIN}.bak.${backup_time}" || true
    fi
    if [[ -f "$XRAY_BIN_ARCH" ]]; then
        cp -af "$XRAY_BIN_ARCH" "${XRAY_BIN_ARCH}.bak.${backup_time}" || true
    fi

    cp -f "${TMP_DIR}/xray" "$XRAY_BIN_MAIN" || {
        msg_err "替换 $XRAY_BIN_MAIN 失败"
        rm -rf "$TMP_DIR"
        return 1
    }
    chmod +x "$XRAY_BIN_MAIN"

    cp -f "${TMP_DIR}/xray" "$XRAY_BIN_ARCH" || true
    chmod +x "$XRAY_BIN_ARCH" 2>/dev/null || true

    if [[ "$(arch)" == "armv5" || "$(arch)" == "armv6" || "$(arch)" == "armv7" ]]; then
        cp -f "${TMP_DIR}/xray" "${XRAY_DIR}/xray-linux-arm" || true
        chmod +x "${XRAY_DIR}/xray-linux-arm" 2>/dev/null || true
    fi

    if [[ "$NEED_RESTART_XUI" == "y" ]]; then
        msg_inf "启动 x-ui 服务..."
        systemctl start x-ui || {
            msg_err "x-ui 启动失败，建议检查备份文件并手动回滚"
            rm -rf "$TMP_DIR"
            return 1
        }
        sleep 2
    fi

    XRAY_NEW_VER="$("$XRAY_BIN_MAIN" version 2>/dev/null | head -n1)"
    rm -rf "$TMP_DIR"

    msg_ok "Xray-core 更新完成"
    echo "更新前版本: $XRAY_OLD_VER"
    echo "更新后版本: $XRAY_NEW_VER"
    echo "备份文件示例："
    echo "  ${XRAY_BIN_MAIN}.bak.${backup_time}"
    echo "  ${XRAY_BIN_ARCH}.bak.${backup_time}"
}
