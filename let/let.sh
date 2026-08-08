#!/usr/bin/env bash
# ============================================================
# LET 管理脚本 v13 HTTP
# 默认 HTTP：0.0.0.0:5556
# ============================================================

set -o pipefail

APP_NAME="let"
SERVICE_NAME="let"
REPO_URL="https://github.com/byilrq/vps"
REPO_LET_DIR="let"
SRC_DIR="${INSTALL_PARENT}/.let-src"
INSTALL_DIR="/root/let"
INSTALL_PARENT="/root"
VENV_DIR="${INSTALL_DIR}/.venv"
DATA_DIR="${INSTALL_DIR}/data"
ENV_FILE="${DATA_DIR}/.env"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
HTTP_PORT="8069"
ENTRY_FILE=""

C_RESET="\033[0m"
C_RED="\033[91m"
C_GREEN="\033[92m"
C_YELLOW="\033[93m"
C_BLUE="\033[94m"
C_MAGENTA="\033[95m"
C_CYAN="\033[96m"
C_WHITE="\033[97m"
C_BOLD="\033[1m"

info(){ echo -e "${C_CYAN}ℹ️  [信息]${C_RESET} $*"; }
step(){ echo -e "${C_BLUE}🚀 [步骤]${C_RESET} $*"; }
ok(){ echo -e "${C_GREEN}✅ [成功]${C_RESET} $*"; }
warn(){ echo -e "${C_YELLOW}⚠️  [提示]${C_RESET} $*"; }
err(){ echo -e "${C_RED}❌ [错误]${C_RESET} $*"; }
pause(){ echo; read -erp "按回车键返回菜单..."; }

require_root(){
  if [ "$(id -u)" -ne 0 ]; then
    err "请使用 root 用户运行本脚本。"
    exit 1
  fi
}

read_token(){
  local token
  while true; do
    read -erp "请输入 ACCESS_TOKEN / 网页登录密码： " token
    token="$(printf '%s' "$token" | tr -d '\000-\010\013\014\016-\037\177')"
    if [ -n "$token" ]; then
      ACCESS_TOKEN="$token"
      break
    fi
    warn "密码不能为空，请重新输入。"
  done
}

read_domain(){
  local domain
  while true; do
    read -erp "请输入域名（如 example.com）： " domain
    domain="$(printf '%s' "$domain" | tr -d '\000-\010\013\014\016-\037\177')"
    if [ -n "$domain" ]; then
      if [ -f "/etc/letsencrypt/live/${domain}/fullchain.pem" ] && [ -f "/etc/letsencrypt/live/${domain}/privkey.pem" ]; then
        DOMAIN_NAME="$domain"
        break
      else
        err "证书文件不存在：/etc/letsencrypt/live/${domain}/ 下缺少 fullchain.pem 或 privkey.pem"
        info "请先使用 certbot 为 ${domain} 申请证书"
      fi
    fi
  done
  info "证书路径：/etc/letsencrypt/live/${DOMAIN_NAME}/fullchain.pem"
  info "证书路径：/etc/letsencrypt/live/${DOMAIN_NAME}/privkey.pem"
}

service_exists(){
  systemctl list-unit-files | grep -q "^${SERVICE_NAME}.service"
}

install_deps(){
  require_root
  echo "────────────────────────────────────────────────────────"
  step "安装原生运行依赖，不安装 Docker"

  local pkgs="ca-certificates curl git nano ufw sqlite3 unzip \
    python3 python3-venv python3-pip python3-dev \
    build-essential pkg-config libffi-dev libssl-dev"

  if ! command -v nginx >/dev/null 2>&1; then
    info "检测到 nginx 未安装，将一并安装。"
    pkgs="$pkgs nginx"
  else
    info "nginx 已存在，跳过安装。"
  fi

  apt update
  apt install -y $pkgs

  ok "基础依赖安装完成"
}

safe_clone_or_update(){
  step "准备项目源码仓库：${REPO_URL}"

  cd "$INSTALL_PARENT" || {
    err "无法进入父目录：$INSTALL_PARENT"
    return 1
  }

  if [ -d "$SRC_DIR/.git" ]; then
    step "检测到源码仓库已存在，正在更新：$SRC_DIR"
    cd "$SRC_DIR" || { err "进入源码目录失败：$SRC_DIR"; return 1; }
    git remote set-url origin "$REPO_URL" || true
    git fetch --all || { err "git fetch 失败，请检查网络或仓库权限。"; return 1; }
    git reset --hard origin/HEAD || { err "git reset 失败，请检查仓库状态。"; return 1; }
  else
    if [ -e "$SRC_DIR" ]; then
      warn "检测到 $SRC_DIR 已存在但不是 Git 仓库，将备份后重新克隆。"
      local backup="${SRC_DIR}.bak.$(date +%Y%m%d%H%M%S)"
      mv "$SRC_DIR" "$backup" || { err "备份旧目录失败：$SRC_DIR"; return 1; }
      warn "旧目录已备份到：$backup"
    fi

    step "正在克隆项目仓库"
    git clone "$REPO_URL" "$SRC_DIR" || { err "克隆失败，请检查仓库地址、网络、权限。"; return 1; }
  fi

  if [ ! -d "$SRC_DIR/$REPO_LET_DIR" ]; then
    err "仓库中未找到 let 子目录：$SRC_DIR/$REPO_LET_DIR"
    return 1
  fi

  step "同步 let 源码到：${INSTALL_DIR}"
  mkdir -p "$INSTALL_DIR"
  find "$SRC_DIR/$REPO_LET_DIR" -mindepth 1 -maxdepth 1 ! -name data -exec cp -a {} "$INSTALL_DIR/" \;

  cd "$INSTALL_DIR" || { err "进入项目目录失败：$INSTALL_DIR"; return 1; }
}

clean_native_files(){
  cd "$INSTALL_DIR" || return 1

  step "清理原生版不需要的 Docker / Mongo / 构建文件"

  rm -f docker-compose.yml docker-compose.yaml compose.yml compose.yaml
  rm -f Dockerfile Dockerfile.* .dockerignore
  rm -rf .github mongo mongodb mongo-data mongodb-data db/mongo db/mongodb patch_notes 2>/dev/null || true
  rm -f README_PATCH.txt 2>/dev/null || true
  find "$INSTALL_DIR" -maxdepth 2 -type f \( -name '*.zip' -o -name '*.tar.gz' -o -name '*.tgz' \) -delete 2>/dev/null || true

  mkdir -p "$DATA_DIR"
  ok "清理完成，仅保留原生运行所需文件"
}

prepare_config(){
  mkdir -p "$DATA_DIR"

  if [ ! -f "$DATA_DIR/config.json" ]; then
    if [ -f "$SRC_DIR/$REPO_LET_DIR/data/config.json" ]; then
      cp "$SRC_DIR/$REPO_LET_DIR/data/config.json" "$DATA_DIR/config.json"
      ok "已从源码 data/config.json 初始化配置：${DATA_DIR}/config.json"
    elif [ -f "$INSTALL_DIR/example.json" ]; then
      cp "$INSTALL_DIR/example.json" "$DATA_DIR/config.json"
      ok "已从 example.json 初始化配置：${DATA_DIR}/config.json"
    elif [ -f "$INSTALL_DIR/config.json" ]; then
      cp "$INSTALL_DIR/config.json" "$DATA_DIR/config.json"
      ok "已复制项目配置到：${DATA_DIR}/config.json"
    else
      echo '{}' > "$DATA_DIR/config.json"
      ok "已创建空配置：${DATA_DIR}/config.json"
    fi
  else
    info "检测到已有配置，保留不覆盖：${DATA_DIR}/config.json"
  fi
}

install_python_deps(){
  step "创建 Python 虚拟环境并安装依赖"

  cd "$INSTALL_DIR" || return 1

  python3 -m venv "$VENV_DIR" || { err "创建 Python 虚拟环境失败。"; return 1; }

  . "$VENV_DIR/bin/activate"

  python -m pip install --upgrade pip wheel setuptools || { err "升级 pip/wheel/setuptools 失败。"; return 1; }

  if [ -f requirements.txt ]; then
    pip install -r requirements.txt || { err "安装 requirements.txt 失败。"; return 1; }
  else
    warn "未找到 requirements.txt，安装基础依赖。"
    pip install flask requests beautifulsoup4 lxml curl_cffi cfscrape python-dotenv markdownify rich || {
      err "安装基础 Python 依赖失败。"
      return 1
    }
  fi

  ok "Python 依赖安装完成"
}

write_env_file(){
  step "写入环境变量"

  mkdir -p "$DATA_DIR"
  local clean_token
  clean_token="$(printf '%s' "$ACCESS_TOKEN" | tr -d '\000-\010\013\014\016-\037\177')"

  cat > "$ENV_FILE" <<EOF
ACCESS_TOKEN=${clean_token}
HOST=0.0.0.0
PORT=${HTTP_PORT}
DOMAIN=${DOMAIN_NAME}
SSL_CERT=/etc/letsencrypt/live/${DOMAIN_NAME}/fullchain.pem
SSL_KEY=/etc/letsencrypt/live/${DOMAIN_NAME}/privkey.pem
LET_SQLITE=${DATA_DIR}/let.sqlite3
PYTHONUNBUFFERED=1
EOF

  chmod 600 "$ENV_FILE"
  ok "环境变量已写入：$ENV_FILE"
}

detect_entry(){
  if [ -f "$INSTALL_DIR/web.py" ]; then
    ENTRY_FILE="web.py"
  elif [ -f "$INSTALL_DIR/app.py" ]; then
    ENTRY_FILE="app.py"
  elif [ -f "$INSTALL_DIR/main.py" ]; then
    ENTRY_FILE="main.py"
  elif [ -f "$INSTALL_DIR/server.py" ]; then
    ENTRY_FILE="server.py"
  else
    err "未找到启动入口 web.py/app.py/main.py/server.py。"
    return 1
  fi

  ok "启动入口：${ENTRY_FILE}"
}

patch_web_host(){
  cd "$INSTALL_DIR" || return 1

  if [ -z "${ENTRY_FILE:-}" ]; then
    detect_entry || return 1
  fi

  step "适配监听地址，确保 HTTP 可通过 ${HTTP_PORT} 外网访问"

  sed -i "s/host=['\"]127\.0\.0\.1['\"]/host=os.environ.get('HOST', '0.0.0.0')/g" "$ENTRY_FILE" 2>/dev/null || true
  sed -i "s/host=['\"]0\.0\.0\.0['\"]/host=os.environ.get('HOST', '0.0.0.0')/g" "$ENTRY_FILE" 2>/dev/null || true
  sed -i "s/port=5556/port=int(os.environ.get('PORT', '8069'))/g" "$ENTRY_FILE" 2>/dev/null || true

  if grep -q "os.environ" "$ENTRY_FILE" && ! grep -qE "^import os$|^import os," "$ENTRY_FILE"; then
    sed -i '1i import os' "$ENTRY_FILE"
  fi

  ok "监听地址适配完成"
}

write_systemd_service(){
  step "写入 systemd 服务"

  detect_entry || return 1
  patch_web_host || return 1

  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=let service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV_DIR}/bin/python ${INSTALL_DIR}/${ENTRY_FILE}
Restart=always
RestartSec=5
Nice=10
CPUQuota=70%
MemoryMax=512M

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
  ok "systemd 服务已写入：$SERVICE_FILE"
}

open_firewall(){
  step "放行防火墙端口"

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
    local ssh_port
    ssh_port="$(ss -lntp 2>/dev/null | awk '/sshd/ {print $4}' | awk -F: '{print $NF}' | head -n1)"
    [ -z "$ssh_port" ] && ssh_port="22"

    ufw allow "${ssh_port}/tcp" >/dev/null 2>&1 || true
    ufw allow "${HTTP_PORT}/tcp" >/dev/null 2>&1 || true
    ufw reload >/dev/null 2>&1 || true

    ok "UFW 已放行 SSH ${ssh_port}/tcp 与 HTTP ${HTTP_PORT}/tcp"
  else
    info "UFW 未启用，跳过防火墙配置。请自行放行端口 ${HTTP_PORT}。"
  fi

  warn "如果 VPS 服务商有安全组，请在面板里额外放行 TCP ${HTTP_PORT}"
}

stop_direct_process(){
  local pids
  pids="$(pgrep -f "${INSTALL_DIR}/web.py" 2>/dev/null || true)"
  if [ -n "$pids" ]; then
    warn "检测到非 systemd 方式运行的进程，将先停止。"
    echo "$pids" | xargs -r kill 2>/dev/null || true
    sleep 1
    pids="$(pgrep -f "${INSTALL_DIR}/web.py" 2>/dev/null || true)"
    if [ -n "$pids" ]; then
      echo "$pids" | xargs -r kill -9 2>/dev/null || true
    fi
  fi
}

install_app(){
  require_root
  echo "────────────────────────────────────────────────────────"
  step "开始原生安装 / 部署 let 到 ${INSTALL_DIR}"
  read_domain
  read_token

  safe_clone_or_update || return 1
  clean_native_files || return 1
  prepare_config
  install_python_deps || return 1
  write_env_file
  write_systemd_service || return 1

  open_firewall

  step "启动 let"
  stop_direct_process
  systemctl restart "$SERVICE_NAME"
  sleep 2

  if systemctl is-active --quiet "$SERVICE_NAME"; then
    ok "let 已启动"
    echo
    echo -e "${C_GREEN}HTTP 访问：${C_RESET}http://你的域名或IP:${HTTP_PORT}"
  else
    err "let 启动失败，请查看日志：journalctl -u let -n 100 --no-pager"
    return 1
  fi
}

ensure_service_ready(){
  if service_exists; then
    return 0
  fi

  warn "未找到 systemd 服务：${SERVICE_NAME}.service"
  warn "将根据当前目录自动写入服务。"

  if [ ! -d "$INSTALL_DIR" ]; then
    err "未找到项目目录：$INSTALL_DIR，请先使用菜单 2 安装 / 部署。"
    return 1
  fi

  if [ ! -d "$VENV_DIR" ]; then
    install_python_deps || return 1
  fi

  prepare_config

  if [ ! -f "$ENV_FILE" ]; then
    warn "未找到环境变量文件，需要设置网页登录密码。"
    read_token
    write_env_file
  fi

  write_systemd_service || return 1
}

restart_app(){
  require_root
  echo "────────────────────────────────────────────────────────"
  step "重启 let"

  ensure_service_ready || return 1
  stop_direct_process

  systemctl daemon-reload
  systemctl restart "$SERVICE_NAME"
  sleep 1
  systemctl status "$SERVICE_NAME" --no-pager
}

stop_app(){
  require_root
  echo "────────────────────────────────────────────────────────"
  step "停止 let 服务"

  stop_direct_process

  if service_exists; then
    systemctl stop "$SERVICE_NAME"
    sleep 1
    if systemctl is-active --quiet "$SERVICE_NAME"; then
      err "停止失败：服务仍在运行。"
      systemctl status "$SERVICE_NAME" --no-pager || true
      return 1
    fi
    ok "let 已停止。"
    info "这不会删除项目、数据库或配置。需要继续运行时，请使用菜单 7 重启服务。"
  else
    warn "未找到 systemd 服务：${SERVICE_NAME}.service"
    warn "如果这是全新环境，请先使用菜单 2 安装 / 部署。"
  fi
}

uninstall_app(){
  require_root
  echo -e "${C_RED}${C_BOLD}────────────────────────────────────────────────────────${C_RESET}"
  echo -e "${C_RED}${C_BOLD}卸载服务${C_RESET}"
  warn "即将卸载 let：服务与项目目录 ${INSTALL_DIR}"
  read -erp "确认卸载？请输入 YES： " yesno

  if [ "$yesno" != "YES" ]; then
    warn "已取消卸载。"
    return 0
  fi

  stop_direct_process
  systemctl stop "$SERVICE_NAME" 2>/dev/null || true
  systemctl disable "$SERVICE_NAME" 2>/dev/null || true
  rm -f "$SERVICE_FILE"
  systemctl daemon-reload

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
    ufw delete allow "${HTTP_PORT}/tcp" >/dev/null 2>&1 || true
    ufw reload >/dev/null 2>&1 || true
  fi

  cd "$INSTALL_PARENT" || cd /
  rm -rf "$INSTALL_DIR"

  ok "卸载完成"
}

reset_database(){
  require_root
  echo -e "${C_RED}${C_BOLD}────────────────────────────────────────────────────────${C_RESET}"
  echo -e "${C_RED}${C_BOLD}删除数据库 / 重新建立状态${C_RESET}"
  warn "此操作会删除运行数据库与运行日志，用于重新建立状态。"
  warn "保留配置文件：${DATA_DIR}/config.json"
  warn "删除后再次启动，程序会重新建立 RSS/帖子/楼层状态。"
  read -erp "确认删除数据库？请输入 YES： " yesno

  if [ "$yesno" != "YES" ]; then
    warn "已取消删除数据库。"
    return 0
  fi

  step "停止 let 服务"
  stop_direct_process
  systemctl stop "$SERVICE_NAME" 2>/dev/null || true

  step "备份并删除数据库"
  mkdir -p "$DATA_DIR"

  local ts backup_dir
  ts="$(date +%Y%m%d%H%M%S)"
  backup_dir="${DATA_DIR}/backup-${ts}"
  mkdir -p "$backup_dir"

  for f in \
    "${DATA_DIR}/let.sqlite3" \
    "${DATA_DIR}/let.sqlite3-shm" \
    "${DATA_DIR}/let.sqlite3-wal" \
    "${DATA_DIR}/runtime_logs.json" \
    "${DATA_DIR}/runtime_hits.json" \
    "${DATA_DIR}/runtime_log.json"
  do
    if [ -e "$f" ]; then
      cp -a "$f" "$backup_dir/" 2>/dev/null || true
      rm -f "$f"
    fi
  done

  ok "数据库/日志已删除，备份目录：$backup_dir"

  read -erp "是否立即重启 let 并重新建立状态？[Y/n] " yn
  yn="${yn:-Y}"
  if [[ "$yn" =~ ^[Yy]$ ]]; then
    ensure_service_ready || return 1
    systemctl start "$SERVICE_NAME"
    sleep 2
    systemctl status "$SERVICE_NAME" --no-pager
  else
    warn "服务保持停止。稍后可用菜单 7 重启服务。"
  fi
}

show_status(){
  echo "────────────────────────────────────────────────────────"
  step "当前运行状态总览"

  if service_exists; then
    systemctl status "$SERVICE_NAME" --no-pager || true
  else
    warn "未找到 systemd 服务：${SERVICE_NAME}.service，请先使用菜单 2 安装 / 部署。"
  fi

  echo "────────────────────────────────────────────────────────"
  echo "端口监听："
  ss -lntp | grep -E ":${HTTP_PORT}\b" || true

  echo "────────────────────────────────────────────────────────"
  echo "数据库文件："
  ls -lh "${DATA_DIR}" 2>/dev/null | grep -E 'let\.sqlite3|runtime|config|backup' || true

  echo "────────────────────────────────────────────────────────"
  echo "最近日志："
  journalctl -u "$SERVICE_NAME" -n 80 --no-pager || true

  echo "────────────────────────────────────────────────────────"
  echo "资源占用 TOP 10："
  ps aux --sort=-%cpu | head -10

  echo "────────────────────────────────────────────────────────"
  free -h
  df -h /
}

menu(){
  clear
  echo -e "${C_CYAN}${C_BOLD}╔════════════════════════════════════════════════════════════╗${C_RESET}"
  echo -e "${C_CYAN}${C_BOLD}║                  LET 管理脚本 v13 HTTP                    ║${C_RESET}"
  echo -e "${C_CYAN}${C_BOLD}║          原生安装 · 端口 8069 · /root/let                  ║${C_RESET}"
  echo -e "${C_CYAN}${C_BOLD}╚════════════════════════════════════════════════════════════╝${C_RESET}"
  echo
  echo -e "  ${C_GREEN}${C_BOLD}1.${C_RESET} ${C_GREEN}${C_BOLD}安装环境依赖${C_RESET}"
  echo -e "  ${C_BLUE}${C_BOLD}2.${C_RESET} ${C_BLUE}${C_BOLD}安装 / 部署（外网端口 8069）${C_RESET}"
  echo -e "  ${C_YELLOW}${C_BOLD}3.${C_RESET} ${C_YELLOW}${C_BOLD}停止服务${C_RESET}"
  echo -e "  ${C_CYAN}${C_BOLD}4.${C_RESET} ${C_CYAN}${C_BOLD}查看运行状态${C_RESET}"
  echo -e "  ${C_RED}${C_BOLD}5.${C_RESET} ${C_RED}${C_BOLD}卸载服务${C_RESET}"
  echo -e "  ${C_RED}${C_BOLD}6.${C_RESET} ${C_RED}${C_BOLD}删除数据库 / 重新建立状态${C_RESET}"
  echo -e "  ${C_MAGENTA}${C_BOLD}7.${C_RESET} ${C_MAGENTA}${C_BOLD}重启服务${C_RESET}"
  echo -e "  ${C_WHITE}${C_BOLD}0.${C_RESET} ${C_WHITE}${C_BOLD}退出脚本${C_RESET}"
  echo
  echo -e "${C_CYAN}────────────────────────────────────────────────────────${C_RESET}"
}

main(){
  require_root

  while true; do
    menu
    read -erp "请输入菜单编号 [0-7]： " choice
    case "$choice" in
      1) install_deps; pause ;;
      2) install_app; pause ;;
      3) stop_app; pause ;;
      4) show_status; pause ;;
      5) uninstall_app; pause ;;
      6) reset_database; pause ;;
      7) restart_app; pause ;;
      0) echo "再见。"; exit 0 ;;
      *) warn "无效输入，请重新选择。"; pause ;;
    esac
  done
}

main "$@"
