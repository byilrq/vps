#!/usr/bin/env bash
# h.sh - Hysteria 2 installer + management script (streamlined)

export LANG=C.UTF-8
export LC_ALL=C.UTF-8
export DEBIAN_FRONTEND=noninteractive

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"
hui='\e[37m'
zi='\033[35m'
tianlan='\033[96m'

# -----------------------------
# 函数：红色输出
# -----------------------------
red() { echo -e "${RED}\033[01m$1${PLAIN}"; }
# -----------------------------
# 函数：绿色输出
# -----------------------------
green() { echo -e "${GREEN}\033[01m$1${PLAIN}"; }
# -----------------------------
# 函数：黄色输出
# -----------------------------
yellow() { echo -e "${YELLOW}\033[01m$1${PLAIN}"; }
# -----------------------------
# 函数：天蓝色输出
# -----------------------------
skyblue() { echo -e "\033[1;36m$1\033[0m"; }


# -----------------------------
# 函数：可编辑明文输入
# -----------------------------
read_confirmed() {
  local __var="$1"
  local prompt="$2"
  local default_value="${3:-}"
  local allow_empty="${4:-false}"
  local value

  read -erp "$prompt" value
  [[ -z "$value" && -n "$default_value" ]] && value="$default_value"

  if [[ -z "$value" && "$allow_empty" != "true" ]]; then
    red "输入不能为空。"
    return 1
  fi

  printf -v "$__var" '%s' "$value"
  return 0
}

# -----------------------------
# 函数：可编辑明文密码输入
# -----------------------------
read_confirmed_password() {
  local __var="$1"
  local prompt="$2"
  local value

  read -erp "$prompt" value
  [[ -z "$value" ]] && value=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)

  if [[ ! "$value" =~ ^[A-Za-z0-9._~@%+-]+$ ]]; then
    red "密码仅支持字母、数字和 . _ ~ @ % + -，避免破坏 YAML 或分享链接"
    return 1
  fi

  printf -v "$__var" '%s' "$value"
  return 0
}

# -----------------------------
# 函数：检查 root 权限
# -----------------------------
need_root() {
  [[ $EUID -ne 0 ]] && red "注意：请在 root 用户下运行脚本" && exit 1
}

# -----------------------------
# 函数：等待 apt/dpkg 锁释放
# -----------------------------
wait_for_apt_lock() {
  local max_attempts=120
  local attempt=0

  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
    if [ "$attempt" -ge "$max_attempts" ]; then
      red "apt 锁等待超时，请手动检查相关进程并释放锁后重试。"
      exit 1
    fi
    yellow "apt 锁被占用（可能有其他更新进程），等待中... ($attempt/$max_attempts)"
    sleep 1
    attempt=$((attempt + 1))
  done
}

# -----------------------------
# 检测系统类型并准备安装命令
# -----------------------------
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "amazon linux" "fedora")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS" "Fedora")
PACKAGE_UPDATE=("apt-get update -y" "apt-get update -y" "yum -y update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt-get install -y" "apt-get install -y" "yum -y install" "yum -y install" "yum -y install")

CMD=(
  "$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)"
  "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)"
  "$(lsb_release -sd 2>/dev/null)"
  "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)"
  "$(grep . /etc/redhat-release 2>/dev/null)"
  "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')"
)

# -----------------------------
# 函数：检测系统发行版
# -----------------------------
detect_os() {
  local i
  for i in "${CMD[@]}"; do
    SYS="$i"
    [[ -n $SYS ]] && break
  done

  for ((int = 0; int < ${#REGEX[@]}; int++)); do
    if [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]]; then
      SYSTEM="${RELEASE[int]}"
      [[ -n $SYSTEM ]] && break
    fi
  done

  [[ -z $SYSTEM ]] && red "暂不支持当前 VPS 的操作系统。" && exit 1
}

# -----------------------------
# 函数：确保 curl 可用
# -----------------------------
ensure_curl() {
  if [[ -z $(type -P curl) ]]; then
    if [[ "$SYSTEM" != "CentOS" ]]; then
      wait_for_apt_lock || true
    fi
    ${PACKAGE_UPDATE[int]} || true
    ${PACKAGE_INSTALL[int]} curl || { red "curl 安装失败"; exit 1; }
  fi
}
# -----------------------------
# 函数：修复中断的 dpkg 状态
# -----------------------------
fix_dpkg_interrupt() {
  if command -v dpkg >/dev/null 2>&1; then
    env DEBIAN_FRONTEND=noninteractive \
      DEBCONF_NONINTERACTIVE_SEEN=true \
      DEBIAN_PRIORITY=critical \
      NEEDRESTART_MODE=a \
      APT_LISTCHANGES_FRONTEND=none \
      dpkg --configure -a >/dev/null 2>&1 || true

    env DEBIAN_FRONTEND=noninteractive \
      DEBCONF_NONINTERACTIVE_SEEN=true \
      DEBIAN_PRIORITY=critical \
      NEEDRESTART_MODE=a \
      APT_LISTCHANGES_FRONTEND=none \
      apt-get -f install -y -o Dpkg::Use-Pty=0 >/dev/null 2>&1 || true
  fi
}
# -----------------------------
# 函数：刷新软件源缓存
# -----------------------------
pkg_update() {
  if command -v apt-get >/dev/null 2>&1; then
    wait_for_apt_lock || true
    fix_dpkg_interrupt
    timeout 300 env DEBIAN_FRONTEND=noninteractive \
      NEEDRESTART_MODE=a \
      APT_LISTCHANGES_FRONTEND=none \
      apt-get update -y -o Dpkg::Use-Pty=0
  elif command -v dnf >/dev/null 2>&1; then
    timeout 300 dnf -y makecache
  elif command -v yum >/dev/null 2>&1; then
    timeout 300 yum -y makecache
  else
    return 1
  fi
}

# -----------------------------
# 函数：安装系统软件包
# -----------------------------
pkg_install() {
  if command -v apt-get >/dev/null 2>&1; then
    wait_for_apt_lock || true
    fix_dpkg_interrupt

    env DEBIAN_FRONTEND=noninteractive \
      NEEDRESTART_MODE=a \
      APT_LISTCHANGES_FRONTEND=none \
      UCF_FORCE_CONFNEW=1 \
      timeout 900 apt-get install -y --no-install-recommends \
      -o Dpkg::Use-Pty=0 \
      -o Dpkg::Options::="--force-confdef" \
      -o Dpkg::Options::="--force-confnew" \
      "$@"
  elif command -v dnf >/dev/null 2>&1; then
    timeout 900 dnf -y install "$@"
  elif command -v yum >/dev/null 2>&1; then
    timeout 900 yum -y install "$@"
  else
    return 1
  fi
}

# -----------------------------
# 函数：带重试下载文件
# -----------------------------
download_with_retry() {
  local url="$1"
  local out="$2"
  local i

  for i in 1 2 3; do
    yellow "下载中（第 $i 次）：$url"
    if curl -fsSL --connect-timeout 10 --max-time 120 "$url" -o "$out"; then
      [[ -s "$out" ]] && return 0
    fi
    sleep 2
  done

  return 1
}

# -----------------------------
# 函数：获取本机公网 IP
# -----------------------------
realip() {
  ip=$(curl -4fsS --max-time 8 ip.sb 2>/dev/null)
  [[ -z "$ip" ]] && ip=$(curl -6fsS --max-time 8 ip.sb 2>/dev/null)

  if [[ -z "$ip" ]]; then
    red "获取本机公网 IP 失败"
    return 1
  fi

  return 0
}

# -----------------------------
# 函数：校验域名格式
# -----------------------------
is_valid_domain() {
  local d="$1"
  [[ -n "$d" ]] || return 1
  [[ "$d" =~ ^([A-Za-z0-9][-A-Za-z0-9]{0,62}\.)+[A-Za-z]{2,63}$ ]]
}

# -----------------------------
# 函数：规范化域名/主机输入
# -----------------------------
normalize_host_input() {
  local v="$1"
  v="${v#http://}"
  v="${v#https://}"
  v="${v%%/*}"
  printf '%s' "$v"
}


ACME_DOMAIN_LOG="/etc/hysteria/ca.log"
HY2_STATE_FILE="/etc/hysteria/state.env"
HY2_CERT_RENEW_BIN="/usr/local/bin/hysteria-cert-renew"
HY2_CERT_WEEKLY_CRON="/etc/cron.weekly/hysteria-cert-renew"
HY2_CORE_UPDATE_BIN="/usr/local/bin/hysteria-core-update"
HY2_CORE_WEEKLY_CRON="/etc/cron.d/hysteria-core-update"
HY2_CORE_UPDATE_LOG="/var/log/hysteria-core-update.log"
HY2_FIREWALL_RESTORE_BIN="/usr/local/bin/hysteria-firewall-restore"
HY2_BOOT_FIX_SERVICE="/etc/systemd/system/hysteria-boot-fix.service"

# -----------------------------
# 函数：获取 Hysteria 服务名
# -----------------------------
get_hysteria_service_name() {
  if systemctl list-unit-files 2>/dev/null | grep -q '^hysteria-server\.service'; then
    echo "hysteria-server"
  elif systemctl list-unit-files 2>/dev/null | grep -q '^hysteria\.service'; then
    echo "hysteria"
  else
    echo "hysteria-server"
  fi
}

# -----------------------------
# 函数：读取证书主域名
# -----------------------------
get_cert_primary_domain() {
  local cert_file="$1"
  [[ -s "$cert_file" ]] || return 1

  openssl x509 -in "$cert_file" -noout -ext subjectAltName 2>/dev/null | \
    tr ',' '\n' | sed -n 's/.*DNS:\([^[:space:]]*\).*/\1/p' | head -n1
}

# -----------------------------
# 函数：校验证书域名匹配
# -----------------------------
cert_matches_domain() {
  local cert_file="$1"
  local domain="$2"

  [[ -s "$cert_file" && -n "$domain" ]] || return 1

  openssl x509 -in "$cert_file" -noout -ext subjectAltName 2>/dev/null | \
    tr ',' '\n' | sed -n 's/.*DNS:\([^[:space:]]*\).*/\1/p' | grep -Fxq "$domain" && return 0

  openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | sed -n 's/.*CN[[:space:]]*=[[:space:]]*\([^,/]*\).*/\1/p' | grep -Fxq "$domain"
}

# -----------------------------
# 函数：检查证书有效期
# -----------------------------
cert_not_expiring_soon() {
  local cert_file="$1"
  local days="${2:-14}"
  local seconds

  [[ -s "$cert_file" ]] || return 1
  seconds=$((days * 24 * 3600))
  openssl x509 -checkend "$seconds" -noout -in "$cert_file" >/dev/null 2>&1
}

# -----------------------------
# 函数：复用本地正式证书
# -----------------------------
existing_official_cert_usable() {
  local expect_domain="$1"
  local cert_file="/etc/hysteria/cert.crt"
  local key_file="/etc/hysteria/private.key"
  local stored_domain=""

  [[ -s "$cert_file" && -s "$key_file" ]] || return 1

  if [[ -f "$ACME_DOMAIN_LOG" ]]; then
    stored_domain=$(tr -d '\r\n' < "$ACME_DOMAIN_LOG" 2>/dev/null)
  fi
  [[ -z "$stored_domain" ]] && stored_domain=$(get_cert_primary_domain "$cert_file" 2>/dev/null || true)

  [[ -n "$stored_domain" ]] || return 1

  if [[ -n "$expect_domain" && "$stored_domain" != "$expect_domain" ]]; then
    cert_matches_domain "$cert_file" "$expect_domain" || return 1
    stored_domain="$expect_domain"
  fi

  cert_matches_domain "$cert_file" "$stored_domain" || return 1
  cert_not_expiring_soon "$cert_file" 14 || return 1

  echo "$stored_domain"
  return 0
}

# -----------------------------
# 函数：确保 HY2_INPUT 防火墙链存在
# -----------------------------
ensure_hy2_input_chain() {
  iptables -N HY2_INPUT >/dev/null 2>&1 || true
  iptables -F HY2_INPUT >/dev/null 2>&1 || true
  iptables -C INPUT -j HY2_INPUT >/dev/null 2>&1 || iptables -I INPUT 1 -j HY2_INPUT >/dev/null 2>&1 || true

  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -N HY2_INPUT >/dev/null 2>&1 || true
    ip6tables -F HY2_INPUT >/dev/null 2>&1 || true
    ip6tables -C INPUT -j HY2_INPUT >/dev/null 2>&1 || ip6tables -I INPUT 1 -j HY2_INPUT >/dev/null 2>&1 || true
  fi
}

# -----------------------------
# 函数：清空 HY2_INPUT 防火墙规则
# -----------------------------
clear_hy2_input_rules() {
  iptables -F HY2_INPUT >/dev/null 2>&1 || true
  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -F HY2_INPUT >/dev/null 2>&1 || true
  fi
}

# -----------------------------
# 函数：删除 HY2_INPUT 防火墙链
# -----------------------------
remove_hy2_input_chain() {
  iptables -D INPUT -j HY2_INPUT >/dev/null 2>&1 || true
  iptables -F HY2_INPUT >/dev/null 2>&1 || true
  iptables -X HY2_INPUT >/dev/null 2>&1 || true

  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -D INPUT -j HY2_INPUT >/dev/null 2>&1 || true
    ip6tables -F HY2_INPUT >/dev/null 2>&1 || true
    ip6tables -X HY2_INPUT >/dev/null 2>&1 || true
  fi
}

# -----------------------------
# 函数：应用 Hy2 防火墙规则
# -----------------------------
apply_hy2_firewall_rules() {
  local listen_port="$1"
  local range_start="$2"
  local range_end="$3"

  [[ -n "$listen_port" ]] || return 1

  ensure_hy2_input_chain
  clear_hy2_input_rules
  clear_hy2_jump_rules

  iptables -A HY2_INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1 || true
  iptables -A HY2_INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1 || true
  iptables -A HY2_INPUT -p udp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1 || true

  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -A HY2_INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1 || true
    ip6tables -A HY2_INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1 || true
    ip6tables -A HY2_INPUT -p udp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1 || true
  fi

  if [[ -n "$range_start" && -n "$range_end" ]]; then
    ensure_hy2_jump_chain
    iptables -A HY2_INPUT -p udp --dport "$range_start:$range_end" -j ACCEPT >/dev/null 2>&1 || true
    iptables -t nat -A HY2_JUMP -p udp --dport "$range_start:$range_end" -j DNAT --to-destination ":$listen_port" >/dev/null 2>&1 || true

    if command -v ip6tables >/dev/null 2>&1; then
      ip6tables -A HY2_INPUT -p udp --dport "$range_start:$range_end" -j ACCEPT >/dev/null 2>&1 || true
      ip6tables -t nat -A HY2_JUMP -p udp --dport "$range_start:$range_end" -j DNAT --to-destination ":$listen_port" >/dev/null 2>&1 || true
    fi
  fi
}

# -----------------------------
# 函数：加载 Hy2 状态文件
# -----------------------------
load_hy2_state() {
  [[ -f "$HY2_STATE_FILE" ]] || return 1
  # shellcheck disable=SC1090
  source "$HY2_STATE_FILE"
  return 0
}

# -----------------------------
# 函数：保存 Hy2 状态文件
# -----------------------------
save_hy2_state() {
  local state_port="$1"
  local state_range_start="$2"
  local state_range_end="$3"
  local state_domain="${4:-}"
  local state_cert_mode="${5:-}"
  local state_service
  local state_masquerade

  [[ -n "$state_port" ]] || state_port=$(get_hy2_listen_port /etc/hysteria/config.yaml)
  [[ -n "$state_domain" ]] || state_domain=$(grep -E '^\s*sni:' /root/hy/hy-client.yaml 2>/dev/null | awk '{print $2}' | tr -d '\r')
  [[ -n "$state_cert_mode" ]] || state_cert_mode="unknown"
  state_service=$(get_hysteria_service_name)
  state_masquerade=$(grep -E '^\s*url:\s*https?://' /etc/hysteria/config.yaml 2>/dev/null | awk '{print $2}' | tr -d '\r')

  mkdir -p /etc/hysteria >/dev/null 2>&1 || true

  cat > "$HY2_STATE_FILE" <<EOF
HY2_PORT=${state_port:-}
HY2_FIRST_PORT=${state_range_start:-}
HY2_END_PORT=${state_range_end:-}
HY2_DOMAIN=${state_domain:-}
HY2_CERT_MODE=${state_cert_mode:-}
HY2_SERVICE=${state_service:-}
HY2_MASQUERADE=${state_masquerade:-}
EOF

  chmod 600 "$HY2_STATE_FILE" >/dev/null 2>&1 || true
}



# -----------------------------
# 函数：读取 Hy2 监听端口
# -----------------------------
get_hy2_listen_port() {
  local config_file="${1:-/etc/hysteria/config.yaml}"
  sed -nE 's/^[[:space:]]*listen:[[:space:]]*:([0-9]+)[[:space:]]*$/\1/p' "$config_file" 2>/dev/null | head -n1 | tr -d '\r'
}

# -----------------------------
# 函数：读取客户端 server 字段
# -----------------------------
get_hy2_client_server() {
  local client_file="${1:-/root/hy/hy-client.yaml}"
  awk '/^server:[[:space:]]*/{print $2; exit}' "$client_file" 2>/dev/null | tr -d '\r'
}

# -----------------------------
# 函数：读取客户端连接主机
# -----------------------------
get_hy2_client_host() {
  local server host
  server="$(get_hy2_client_server "${1:-/root/hy/hy-client.yaml}")"
  if [[ "$server" =~ ^\[(.*)\]:([0-9]+)$ ]]; then
    host="${BASH_REMATCH[1]}"
  elif [[ "$server" == *:* ]]; then
    host="${server%:*}"
  else
    host="$server"
  fi
  printf '%s' "$host"
}

# -----------------------------
# 函数：修改服务端监听端口
# -----------------------------
set_hy2_listen_port() {
  local port="$1"
  local config_file="${2:-/etc/hysteria/config.yaml}"
  [[ "$port" =~ ^[0-9]+$ ]] || return 1
  if grep -qE '^[[:space:]]*listen:[[:space:]]*:' "$config_file" 2>/dev/null; then
    sed -i -E "s#^[[:space:]]*listen:[[:space:]]*:[0-9]+[[:space:]]*\$#listen: :${port}#" "$config_file"
  else
    sed -i -E "1s#.*#listen: :$port#" "$config_file"
  fi
}

# -----------------------------
# 函数：修改客户端 server 端口
# -----------------------------
set_hy2_client_server_port() {
  local port="$1"
  local client_file="${2:-/root/hy/hy-client.yaml}"
  local server host
  [[ "$port" =~ ^[0-9]+$ ]] || return 1
  server="$(get_hy2_client_server "$client_file")"
  if [[ "$server" =~ ^\[(.*)\]:([0-9]+)$ ]]; then
    host="[${BASH_REMATCH[1]}]"
  elif [[ "$server" == *:* ]]; then
    host="${server%:*}"
  else
    host="$server"
  fi
  [[ -n "$host" ]] || host="127.0.0.1"
  sed -i -E "s#^server:[[:space:]]*.*#server: $host:$port#" "$client_file"
}

# -----------------------------
# 函数：校验端口范围
# -----------------------------
validate_port_range() {
  local first="$1" end="$2"
  [[ "$first" =~ ^[0-9]+$ && "$end" =~ ^[0-9]+$ ]] || return 1
  ((first >= 1 && first <= 65535 && end >= 1 && end <= 65535 && first < end)) || return 1
}


# -----------------------------
# 函数：URL 编码参数
# -----------------------------
url_encode() {
  local string="$1"
  local length="${#string}"
  local i char

  for ((i = 0; i < length; i++)); do
    char="${string:i:1}"
    case "$char" in
      [a-zA-Z0-9.~_-]) printf '%s' "$char" ;;
      *) printf '%%%02X' "'$char" ;;
    esac
  done
}

# -----------------------------
# 函数：转义 sed 替换字符串
# -----------------------------
sed_escape_bang() {
  printf '%s' "$1" | sed 's/[\&!]/\&/g'
}

# -----------------------------
# 动态生成 Hysteria 2 分享链接
# 不再依赖 /root/hy/ur1.txt，每次从现有配置生成。
# -----------------------------
# -----------------------------
# 函数：动态生成 Hy2 分享链接
# -----------------------------
generate_hy2_link() {
  local client_file="/root/hy/hy-client.yaml"
  local config_file="/etc/hysteria/config.yaml"
  local server auth sni insecure host port first end mport link_host query auth_enc sni_enc

  [[ -f "$client_file" ]] || { red "客户端配置不存在：$client_file"; return 1; }

  server=$(awk '/^server:[[:space:]]*/{print $2; exit}' "$client_file" 2>/dev/null | tr -d '\r\n')
  auth=$(awk '/^auth:[[:space:]]*/{print $2; exit}' "$client_file" 2>/dev/null | tr -d '\r\n')
  sni=$(awk '/^[[:space:]]*sni:[[:space:]]*/{print $2; exit}' "$client_file" 2>/dev/null | tr -d '\r\n')
  insecure=$(awk '/^[[:space:]]*insecure:[[:space:]]*/{print $2; exit}' "$client_file" 2>/dev/null | tr -d '\r\n')

  [[ -n "$server" && -n "$auth" ]] || { red "无法从 $client_file 读取 server/auth"; return 1; }

  if [[ "$server" =~ ^\[(.*)\]:([0-9]+)$ ]]; then
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
  elif [[ "$server" =~ ^(.+):([0-9]+)$ ]]; then
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
  else
    host="$server"
    port=""
  fi

  if [[ -z "$port" || ! "$port" =~ ^[0-9]+$ ]]; then
    port=$(get_hy2_listen_port "$config_file")
  fi
  [[ -n "$host" && -n "$port" ]] || { red "无法解析客户端 server 地址或端口"; return 1; }

  load_hy2_state >/dev/null 2>&1 || true
  first="${HY2_FIRST_PORT:-}"
  end="${HY2_END_PORT:-}"

  if [[ -n "$first" && -n "$end" ]]; then
    mport="$first-$end"
  else
    mport="$port"
  fi

  # 分享链接的主机必须是实际连接地址，也就是 client 配置里的 server host。
  # sni 只作为 TLS 校验参数，不能拿来替代连接地址；否则自签 www.bing.com 会被错误打印为连接主机。
  link_host="$host"
  if [[ "$link_host" == *:* && "$link_host" != \[*\] ]]; then
    link_host="[$link_host]"
  fi

  auth_enc=$(url_encode "$auth")
  query="mport=$mport"
  if [[ -n "$sni" ]]; then
    sni_enc=$(url_encode "$sni")
    query="sni=$sni_enc&$query"
  fi
  if [[ "$insecure" == "true" ]]; then
    query="${query}&insecure=1"
  fi

  echo "hysteria2://$auth_enc@$link_host:$port/?$query#H"
}
# -----------------------------
# 函数：安装证书自动续签任务
# -----------------------------
install_hy2_cert_renew_job() {
  local cert_file="/etc/hysteria/cert.crt"
  local key_file="/etc/hysteria/private.key"

  cat > "$HY2_CERT_RENEW_BIN" <<EOF
#!/usr/bin/env bash
set -euo pipefail

CERT_FILE="$cert_file"
KEY_FILE="$key_file"
DOMAIN_LOG="$ACME_DOMAIN_LOG"
ACME_BIN="/root/.acme.sh/acme.sh"

[[ -x "\$ACME_BIN" ]] || exit 0
[[ -s "\$CERT_FILE" && -s "\$KEY_FILE" && -f "\$DOMAIN_LOG" ]] || exit 0

domain=\$(tr -d '\r\n' < "\$DOMAIN_LOG" 2>/dev/null || true)
[[ -n "\$domain" ]] || exit 0

if openssl x509 -checkend \$((7 * 24 * 3600)) -noout -in "\$CERT_FILE" >/dev/null 2>&1; then
  exit 0
fi

service_name="hysteria-server"
if systemctl list-unit-files 2>/dev/null | grep -q '^hysteria-server\.service'; then
  service_name="hysteria-server"
elif systemctl list-unit-files 2>/dev/null | grep -q '^hysteria\.service'; then
  service_name="hysteria"
fi

"\$ACME_BIN" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
"\$ACME_BIN" --renew -d "\$domain" --ecc --force >/dev/null 2>&1
"\$ACME_BIN" --install-cert -d "\$domain" \
  --key-file "\$KEY_FILE" \
  --fullchain-file "\$CERT_FILE" \
  --ecc \
  --reloadcmd "systemctl restart \$service_name" >/dev/null 2>&1
EOF

  chmod 700 "$HY2_CERT_RENEW_BIN" >/dev/null 2>&1 || true

  cat > "$HY2_CERT_WEEKLY_CRON" <<EOF
#!/usr/bin/env bash
"$HY2_CERT_RENEW_BIN"
EOF
  chmod 755 "$HY2_CERT_WEEKLY_CRON" >/dev/null 2>&1 || true

  if [[ -f /etc/crontab ]]; then
    sed -i '/acme\.sh --cron/d' /etc/crontab >/dev/null 2>&1 || true
    sed -i '/hysteria-cert-renew/d' /etc/crontab >/dev/null 2>&1 || true
  fi

  crontab -l 2>/dev/null | grep -v 'acme\.sh' | grep -v 'hysteria-cert-renew' | crontab - >/dev/null 2>&1 || true
  systemctl disable --now acme.timer >/dev/null 2>&1 || true
  systemctl disable --now acme-sh.timer >/dev/null 2>&1 || true
}

# -----------------------------
# 函数：安装开机防火墙恢复服务
# -----------------------------
install_hy2_boot_fix_service() {
  cat > "$HY2_FIREWALL_RESTORE_BIN" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

STATE_FILE="/etc/hysteria/state.env"
CONFIG_FILE="/etc/hysteria/config.yaml"

[[ -f "$STATE_FILE" ]] || exit 0
# shellcheck disable=SC1090
source "$STATE_FILE"

listen_port="${HY2_PORT:-}"
range_start="${HY2_FIRST_PORT:-}"
range_end="${HY2_END_PORT:-}"
service_name="${HY2_SERVICE:-hysteria-server}"

if [[ -z "$listen_port" && -f "$CONFIG_FILE" ]]; then
  listen_port=$(sed -nE 's/^[[:space:]]*listen:[[:space:]]*:([0-9]+)[[:space:]]*$/\1/p' "$CONFIG_FILE" 2>/dev/null | head -n1 | tr -d '\r')
fi
[[ -n "$listen_port" ]] || exit 0

iptables -N HY2_INPUT >/dev/null 2>&1 || true
iptables -F HY2_INPUT >/dev/null 2>&1 || true
iptables -C INPUT -j HY2_INPUT >/dev/null 2>&1 || iptables -I INPUT 1 -j HY2_INPUT >/dev/null 2>&1 || true
iptables -A HY2_INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1 || true
iptables -A HY2_INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1 || true
iptables -A HY2_INPUT -p udp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1 || true

if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -N HY2_INPUT >/dev/null 2>&1 || true
  ip6tables -F HY2_INPUT >/dev/null 2>&1 || true
  ip6tables -C INPUT -j HY2_INPUT >/dev/null 2>&1 || ip6tables -I INPUT 1 -j HY2_INPUT >/dev/null 2>&1 || true
  ip6tables -A HY2_INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1 || true
  ip6tables -A HY2_INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1 || true
  ip6tables -A HY2_INPUT -p udp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1 || true
fi

iptables -t nat -N HY2_JUMP >/dev/null 2>&1 || true
iptables -t nat -F HY2_JUMP >/dev/null 2>&1 || true
iptables -t nat -C PREROUTING -j HY2_JUMP >/dev/null 2>&1 || iptables -t nat -A PREROUTING -j HY2_JUMP >/dev/null 2>&1 || true

if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -t nat -N HY2_JUMP >/dev/null 2>&1 || true
  ip6tables -t nat -F HY2_JUMP >/dev/null 2>&1 || true
  ip6tables -t nat -C PREROUTING -j HY2_JUMP >/dev/null 2>&1 || ip6tables -t nat -A PREROUTING -j HY2_JUMP >/dev/null 2>&1 || true
fi

if [[ -n "$range_start" && -n "$range_end" ]]; then
  iptables -A HY2_INPUT -p udp --dport "$range_start:$range_end" -j ACCEPT >/dev/null 2>&1 || true
  iptables -t nat -A HY2_JUMP -p udp --dport "$range_start:$range_end" -j DNAT --to-destination ":$listen_port" >/dev/null 2>&1 || true

  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -A HY2_INPUT -p udp --dport "$range_start:$range_end" -j ACCEPT >/dev/null 2>&1 || true
    ip6tables -t nat -A HY2_JUMP -p udp --dport "$range_start:$range_end" -j DNAT --to-destination ":$listen_port" >/dev/null 2>&1 || true
  fi
fi

if command -v netfilter-persistent >/dev/null 2>&1; then
  systemctl enable netfilter-persistent >/dev/null 2>&1 || true
  netfilter-persistent save >/dev/null 2>&1 || true
elif command -v service >/dev/null 2>&1; then
  service iptables save >/dev/null 2>&1 || true
fi

systemctl restart "$service_name" >/dev/null 2>&1 || true
EOF

  chmod 700 "$HY2_FIREWALL_RESTORE_BIN" >/dev/null 2>&1 || true

  cat > "$HY2_BOOT_FIX_SERVICE" <<EOF
[Unit]
Description=Restore Hysteria firewall rules and restart service after network is online
After=network-online.target netfilter-persistent.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$HY2_FIREWALL_RESTORE_BIN
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable hysteria-boot-fix.service >/dev/null 2>&1 || true
}

# -----------------------------
# 函数：确保端口跳跃 NAT 链存在
# -----------------------------
ensure_hy2_jump_chain() {
  iptables -t nat -N HY2_JUMP >/dev/null 2>&1 || true
  iptables -t nat -F HY2_JUMP >/dev/null 2>&1 || true
  iptables -t nat -C PREROUTING -j HY2_JUMP >/dev/null 2>&1 || iptables -t nat -A PREROUTING -j HY2_JUMP >/dev/null 2>&1 || true

  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -t nat -N HY2_JUMP >/dev/null 2>&1 || true
    ip6tables -t nat -F HY2_JUMP >/dev/null 2>&1 || true
    ip6tables -t nat -C PREROUTING -j HY2_JUMP >/dev/null 2>&1 || ip6tables -t nat -A PREROUTING -j HY2_JUMP >/dev/null 2>&1 || true
  fi
}

# -----------------------------
# 函数：清空端口跳跃 NAT 规则
# -----------------------------
clear_hy2_jump_rules() {
  iptables -t nat -F HY2_JUMP >/dev/null 2>&1 || true
  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -t nat -F HY2_JUMP >/dev/null 2>&1 || true
  fi
}

# -----------------------------
# 函数：删除端口跳跃 NAT 链
# -----------------------------
remove_hy2_jump_chain() {
  iptables -t nat -D PREROUTING -j HY2_JUMP >/dev/null 2>&1 || true
  iptables -t nat -F HY2_JUMP >/dev/null 2>&1 || true
  iptables -t nat -X HY2_JUMP >/dev/null 2>&1 || true

  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -t nat -D PREROUTING -j HY2_JUMP >/dev/null 2>&1 || true
    ip6tables -t nat -F HY2_JUMP >/dev/null 2>&1 || true
    ip6tables -t nat -X HY2_JUMP >/dev/null 2>&1 || true
  fi
}

# -----------------------------
# 函数：检查 80 端口占用
# -----------------------------
check_port_80_free() {
  ! ss -lntp 2>/dev/null | grep -q ':80 '
}

# -----------------------------
# 函数：检查域名解析是否指向本机
# -----------------------------
check_domain_ready() {
  local domain="$1"
  local resolved_ip4 resolved_ip6

  realip || return 1

  resolved_ip4=$(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1; exit}')
  resolved_ip6=$(getent ahostsv6 "$domain" 2>/dev/null | awk '{print $1; exit}')

  if [[ "$ip" == *:* ]]; then
    [[ -n "$resolved_ip6" && "$resolved_ip6" == "$ip" ]]
  else
    [[ -n "$resolved_ip4" && "$resolved_ip4" == "$ip" ]]
  fi
}


# -----------------------------
# 函数：保存防火墙规则
# -----------------------------
save_firewall_rules() {
  if command -v netfilter-persistent >/dev/null 2>&1; then
    systemctl enable netfilter-persistent >/dev/null 2>&1 || true
    netfilter-persistent save >/dev/null 2>&1 || true
  elif command -v service >/dev/null 2>&1; then
    service iptables save >/dev/null 2>&1 || true
  fi

  if systemctl list-unit-files 2>/dev/null | grep -q '^netfilter-persistent\.service'; then
    systemctl enable netfilter-persistent >/dev/null 2>&1 || true
  fi
}


# -----------------------------
# 函数：修复 Hy2 文件权限
# -----------------------------
fix_hysteria_file_perms() {
  local dir="/etc/hysteria"
  local cfg="$dir/config.yaml"
  local crt="$dir/cert.crt"
  local key="$dir/private.key"
  local ca_log="$dir/ca.log"
  local hy_dir="/root/hy"

  local svc="/etc/systemd/system/hysteria-server.service"
  local u="hysteria" g="hysteria"

  if [[ -f "$svc" ]]; then
    u=$(grep -E '^\s*User=' "$svc" | tail -n1 | cut -d= -f2 | xargs)
    g=$(grep -E '^\s*Group=' "$svc" | tail -n1 | cut -d= -f2 | xargs)
    [[ -z "$u" ]] && u="hysteria"
    [[ -z "$g" ]] && g="$u"
  fi

  mkdir -p "$dir" >/dev/null 2>&1 || true

  chown root:"$g" "$dir" 2>/dev/null || chown root:root "$dir"
  chmod 750 "$dir" 2>/dev/null || true

  if [[ -f "$cfg" ]]; then
    chown root:"$g" "$cfg" 2>/dev/null || chown root:root "$cfg"
    chmod 640 "$cfg" 2>/dev/null || true
  fi

  if [[ -f "$key" ]]; then
    chown root:"$g" "$key" 2>/dev/null || chown root:root "$key"
    chmod 640 "$key" 2>/dev/null || true
  fi

  if [[ -f "$crt" ]]; then
    chown root:root "$crt" 2>/dev/null || true
    chmod 644 "$crt" 2>/dev/null || true
  fi

  if [[ -f "$ca_log" ]]; then
    chown root:root "$ca_log" 2>/dev/null || true
    chmod 600 "$ca_log" 2>/dev/null || true
  fi

  if [[ -d "$hy_dir" ]]; then
    chown -R root:root "$hy_dir" 2>/dev/null || true
    chmod 700 "$hy_dir" 2>/dev/null || true
    find "$hy_dir" -type f -exec chmod 600 {} \; 2>/dev/null || true
  fi
}

# -----------------------------
# 证书安装与配置
# -----------------------------

# -----------------------------
# 函数：安装或配置 TLS 证书
# -----------------------------
inst_cert() {
  green "Hysteria 2 协议证书申请方式如下："
  echo ""
  echo -e " ${GREEN}1.${PLAIN} Acme 脚本自动申请${YELLOW}（默认，强制校验证书）${PLAIN}"
  echo -e " ${GREEN}2.${PLAIN} 必应自签证书${YELLOW}（客户端将跳过证书校验）${PLAIN}"
  echo -e " ${GREEN}3.${PLAIN} 自定义证书路径${YELLOW}（默认强制校验）${PLAIN}"
  echo ""

  while true; do
    read_confirmed certInput "请输入选项 [1-3]（回车默认 1）: " "1" || return 1
    [[ "$certInput" =~ ^[1-3]$ ]] && break
    red "选项无效，请输入 1、2 或 3。"
  done

  mkdir -p /etc/hysteria >/dev/null 2>&1 || true

  tls_insecure="false"
  cert_mode="official"

  if [[ $certInput == 1 ]]; then
    cert_path="/etc/hysteria/cert.crt"
    key_path="/etc/hysteria/private.key"

    realip || return 1
    while true; do
      read_confirmed domain "请输入需要申请或复用证书的域名: " "" || return 1
      domain="$(normalize_host_input "$domain")"
      if is_valid_domain "$domain"; then
        break
      fi
      red "域名格式无效：$domain"
    done

    local reusable_domain=""
    reusable_domain=$(existing_official_cert_usable "$domain" 2>/dev/null || true)
    if [[ -n "$reusable_domain" ]]; then
      green "检测到域名 $reusable_domain 的本地正式证书已存在且有效，跳过重复申请"
      echo "$reusable_domain" > "$ACME_DOMAIN_LOG"
      hy_domain="$reusable_domain"
      tls_insecure="false"
      cert_mode="official"
      install_hy2_cert_renew_job
      return 0
    fi

    green "已输入的域名：$domain"
    green "检查域名解析..."
    check_domain_ready "$domain" || {
      red "当前域名解析的 IP 与当前 VPS 真实 IP 不匹配"
      yellow "建议：关闭 Cloudflare 小云朵（仅 DNS）、检查解析 IP 是否为真实 IP。"
      return 1
    }

    green "检查 80 端口..."
    check_port_80_free || {
      red "80 端口被占用，acme standalone 模式会失败或长时间卡住"
      yellow "请先停止占用 80 端口的服务（如 nginx/apache/caddy）后重试"
      return 1
    }

    green "安装申请证书所需依赖..."
    pkg_install curl wget sudo socat openssl >/dev/null 2>&1 || true

    green "安装 acme.sh ..."
    curl -fsSL https://get.acme.sh | sh -s email="$(date +%s%N | md5sum | cut -c 1-16)@gmail.com" || {
      red "安装 acme.sh 失败"
      return 1
    }

    source ~/.bashrc >/dev/null 2>&1 || true
    bash ~/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1 || true
    bash ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true

    green "开始签发证书，这一步可能需要几十秒..."
    if [[ -n $(echo "$ip" | grep ":") ]]; then
      timeout 300 bash ~/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --listen-v6 || {
        red "签发失败"
        return 1
      }
    else
      timeout 300 bash ~/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 || {
        red "签发失败"
        return 1
      }
    fi

    bash ~/.acme.sh/acme.sh --install-cert -d "${domain}"       --key-file "$key_path"       --fullchain-file "$cert_path"       --ecc       --reloadcmd "systemctl restart $(get_hysteria_service_name)" || {
      red "安装证书失败"
      return 1
    }

    if [[ -s "$cert_path" && -s "$key_path" ]]; then
      echo "$domain" > "$ACME_DOMAIN_LOG"
      install_hy2_cert_renew_job
      green "证书申请成功，已保存到 /etc/hysteria/"
      yellow "证书路径：$cert_path"
      yellow "私钥路径：$key_path"
      yellow "已创建每周检测任务：证书若已过期或 7 天内到期，将自动续签并重启 Hysteria"
      hy_domain="$domain"
      tls_insecure="false"
      cert_mode="official"
    else
      red "证书文件生成异常，请检查 acme.sh 输出"
      return 1
    fi

  elif [[ $certInput == 3 ]]; then
    while true; do
      read_confirmed cert_path "请输入公钥文件 crt 的路径: " "" || return 1
      [[ -s "$cert_path" ]] && break
      red "公钥文件不存在或为空：$cert_path"
    done
    while true; do
      read_confirmed key_path "请输入密钥文件 key 的路径: " "" || return 1
      [[ -s "$key_path" ]] && break
      red "密钥文件不存在或为空：$key_path"
    done
    while true; do
      read_confirmed domain "请输入证书的域名: " "" || return 1
      domain="$(normalize_host_input "$domain")"
      if is_valid_domain "$domain"; then
        break
      fi
      red "域名格式无效：$domain"
    done

    hy_domain="$domain"
    tls_insecure="false"
    cert_mode="custom"

  else
    green "将使用必应自签证书作为 Hysteria 2 的节点证书"
    cert_path="/etc/hysteria/cert.crt"
    key_path="/etc/hysteria/private.key"

    openssl ecparam -genkey -name prime256v1 -out "$key_path" || {
      red "生成私钥失败"
      return 1
    }

    openssl req -new -x509 -days 36500 -key "$key_path" -out "$cert_path" -subj "/CN=www.bing.com" || {
      red "生成证书失败"
      return 1
    }

    hy_domain="www.bing.com"
    domain="www.bing.com"
    tls_insecure="true"
    cert_mode="selfsigned"

    rm -f "$HY2_CERT_WEEKLY_CRON" "$HY2_CERT_RENEW_BIN" >/dev/null 2>&1 || true
    yellow "当前为自签证书模式，客户端将跳过证书校验"
  fi
}

# -----------------------------
# 端口与跳跃端口设置
# -----------------------------

# -----------------------------
# 函数：配置端口跳跃
# -----------------------------
inst_jump() {
  green "Hysteria 2 端口使用模式如下："
  echo ""
  echo -e " ${GREEN}1.${PLAIN} 单端口"
  echo -e " ${GREEN}2.${PLAIN} 端口跳跃${YELLOW}（默认）${PLAIN}"
  echo ""

  while true; do
    read_confirmed jumpInput "请输入选项 [1-2]（回车默认 2）: " "2" || return 1
    [[ "$jumpInput" =~ ^[1-2]$ ]] && break
    red "选项无效，请输入 1 或 2。"
  done

  if [[ $jumpInput == 2 ]]; then
    while true; do
      read_confirmed firstport "设置范围端口的起始端口（建议 10000-65535 之间）: " "" || return 1
      read_confirmed endport "设置范围端口的末尾端口（必须大于起始端口）: " "" || return 1
      validate_port_range "$firstport" "$endport" && break
      red "范围无效：端口必须为 1-65535，且起始端口必须小于末尾端口"
    done

    apply_hy2_firewall_rules "$port" "$firstport" "$endport"
    save_firewall_rules
    green "已启用端口跳跃：$firstport-$endport -> $port"
  else
    yellow "将继续使用单端口模式"
    firstport=""
    endport=""
    apply_hy2_firewall_rules "$port" "" ""
    save_firewall_rules
  fi
}

# -----------------------------
# 监听端口设置
# -----------------------------

# -----------------------------
# 函数：配置监听端口
# -----------------------------
inst_port() {
  clear_hy2_jump_rules
  clear_hy2_input_rules

  while true; do
    read_confirmed port "设置 Hysteria 2 监听端口 [1-65535]（回车默认 443）: " "443" || return 1

    [[ "$port" =~ ^[0-9]+$ ]] || { red "端口必须是数字"; continue; }
    ((port >= 1 && port <= 65535)) || { red "端口必须在 1-65535 之间"; continue; }

    if ss -lun | awk '{print $5}' | sed 's/.*://g' | grep -qw "$port"; then
      red "UDP 端口 $port 已被占用，请更换"
      continue
    fi

    break
  done

  yellow "Hysteria 2 使用端口：$port"
  inst_jump
}

# -----------------------------
# 函数：配置连接密码
# -----------------------------
inst_pwd() {
  read_confirmed_password auth_pwd "设置 Hysteria 2 密码（回车随机）: " || return 1
  yellow "密码：$auth_pwd"
}

# -----------------------------
# 函数：配置伪装站点
# -----------------------------
inst_site() {
  echo ""
  green "Hysteria 2 伪装站点模式如下："
  echo -e " ${GREEN}1.${PLAIN} 外部伪装站${YELLOW}（默认，例如 video.unext.jp）${PLAIN}"
  echo -e " ${GREEN}2.${PLAIN} 本机 WoW 注册站${YELLOW}（http://127.0.0.1:8080，需要先安装 wow.py local_proxy 模式）${PLAIN}"
  echo ""

  while true; do
    read_confirmed siteInput "请选择伪装站模式 [1-2]（回车默认 1）: " "1" || return 1
    [[ "$siteInput" =~ ^[1-2]$ ]] && break
    red "选项无效，请输入 1 或 2。"
  done

  if [[ "$siteInput" == "2" ]]; then
    read_confirmed local_wow_port "请输入本机 WoW 注册站端口（回车默认 8080）: " "8080" || return 1
    if [[ ! "$local_wow_port" =~ ^[0-9]+$ ]]; then
      red "端口必须是数字"
      return 1
    fi
    proxysite="127.0.0.1:$local_wow_port"
    masquerade_url="http://127.0.0.1:$local_wow_port"
    masquerade_rewrite_host="false"
    yellow "伪装站点：本机 WoW 注册站 $masquerade_url"
    yellow "提示：请确认本机测试 curl -I http://127.0.0.1:$local_wow_port 可以返回 200/301/302。"
    return 0
  fi

  while true; do
    read_confirmed proxysite "请输入外部伪装网站地址（去除 https://） [回车默认：video.unext.jp]: " "video.unext.jp" || return 1
    proxysite="$(normalize_host_input "$proxysite")"
    if is_valid_domain "$proxysite"; then
      masquerade_url="https://$proxysite"
      masquerade_rewrite_host="true"
      yellow "伪装站点：$masquerade_url"
      return 0
    fi
    red "伪装网站域名格式无效：$proxysite"
  done
}

# -----------------------------
# 安装防火墙持久化组件
# -----------------------------

# -----------------------------
# 函数：安装防火墙持久化组件
# -----------------------------
install_firewall_persistent() {
  green "安装防火墙持久化组件"

  fix_dpkg_interrupt

  if command -v apt-get >/dev/null 2>&1; then
    mkdir -p /etc/iptables >/dev/null 2>&1 || true
    touch /etc/iptables/rules.v4 /etc/iptables/rules.v6 >/dev/null 2>&1 || true

    command -v debconf-set-selections >/dev/null 2>&1 && {
      echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
      echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
      echo "iptables-persistent iptables-persistent/autosave_done note" | debconf-set-selections
    }

    if ! env DEBIAN_FRONTEND=noninteractive \
      DEBCONF_NONINTERACTIVE_SEEN=true \
      DEBIAN_PRIORITY=critical \
      NEEDRESTART_MODE=a \
      APT_LISTCHANGES_FRONTEND=none \
      timeout 300 apt-get install -y --no-install-recommends \
      -o Dpkg::Use-Pty=0 \
      -o Dpkg::Options::="--force-confdef" \
      -o Dpkg::Options::="--force-confnew" \
      -o DPkg::Pre-Install-Pkgs::= \
      iptables-persistent netfilter-persistent </dev/null; then

      yellow "首次安装防火墙持久化组件失败，尝试自动修复后重试..."
      fix_dpkg_interrupt
      pkg_update || true

      command -v debconf-set-selections >/dev/null 2>&1 && {
        echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
        echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
        echo "iptables-persistent iptables-persistent/autosave_done note" | debconf-set-selections
      }

      env DEBIAN_FRONTEND=noninteractive \
        DEBCONF_NONINTERACTIVE_SEEN=true \
        DEBIAN_PRIORITY=critical \
        NEEDRESTART_MODE=a \
        APT_LISTCHANGES_FRONTEND=none \
        timeout 300 apt-get install -y --no-install-recommends \
        -o Dpkg::Use-Pty=0 \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confnew" \
        -o DPkg::Pre-Install-Pkgs::= \
        iptables-persistent netfilter-persistent </dev/null || {
          red "iptables-persistent / netfilter-persistent 安装失败"
          return 1
        }
    fi

    systemctl enable netfilter-persistent >/dev/null 2>&1 || true
    systemctl restart netfilter-persistent >/dev/null 2>&1 || true
  else
    pkg_install iptables-services >/dev/null 2>&1 || true
    systemctl enable iptables >/dev/null 2>&1 || true
    systemctl restart iptables >/dev/null 2>&1 || true
    systemctl enable ip6tables >/dev/null 2>&1 || true
    systemctl restart ip6tables >/dev/null 2>&1 || true
  fi

  green "防火墙持久化组件安装完成"
  return 0
}

# -----------------------------
# 函数：安装 Hy2 环境依赖
# -----------------------------
install_hy_environment() {
  green "开始安装环境依赖"
  
  # ==========================================
  # 🌟 优化：提前更新软件源缓存，避免后续寻找不到包的报错
  # ==========================================
  green "正在刷新软件源缓存..."
  fix_dpkg_interrupt
  # 尝试静默更新软件源，如果不成功也不强求报错，留给后面的容错机制处理
  if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y -q >/dev/null 2>&1 || true
  fi
  # ==========================================

  green "安装基础依赖"
  fix_dpkg_interrupt

  if ! env DEBIAN_FRONTEND=noninteractive \
    DEBCONF_NONINTERACTIVE_SEEN=true \
    DEBIAN_PRIORITY=critical \
    NEEDRESTART_MODE=a \
    APT_LISTCHANGES_FRONTEND=none \
    timeout 300 apt-get install -y --no-install-recommends \
    -o Dpkg::Use-Pty=0 \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confnew" \
    -o DPkg::Pre-Install-Pkgs::= \
    curl wget sudo procps iptables ca-certificates </dev/null; then

    yellow "基础依赖安装失败，尝试刷新软件源并自动修复后重试..."
    fix_dpkg_interrupt
    pkg_update || {
      red "软件源更新失败"
      return 1
    }

    env DEBIAN_FRONTEND=noninteractive \
      DEBCONF_NONINTERACTIVE_SEEN=true \
      DEBIAN_PRIORITY=critical \
      NEEDRESTART_MODE=a \
      APT_LISTCHANGES_FRONTEND=none \
      timeout 300 apt-get install -y --no-install-recommends \
      -o Dpkg::Use-Pty=0 \
      -o Dpkg::Options::="--force-confdef" \
      -o Dpkg::Options::="--force-confnew" \
      -o DPkg::Pre-Install-Pkgs::= \
      curl wget sudo procps iptables ca-certificates </dev/null || {
        red "基础依赖安装失败"
        return 1
      }
  fi

  green "安装二维码与辅助工具"
  fix_dpkg_interrupt

  if ! env DEBIAN_FRONTEND=noninteractive \
    DEBCONF_NONINTERACTIVE_SEEN=true \
    DEBIAN_PRIORITY=critical \
    NEEDRESTART_MODE=a \
    APT_LISTCHANGES_FRONTEND=none \
    timeout 300 apt-get install -y --no-install-recommends \
    -o Dpkg::Use-Pty=0 \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confnew" \
    -o DPkg::Pre-Install-Pkgs::= \
    qrencode socat </dev/null; then

    yellow "qrencode / socat 安装失败，尝试刷新软件源并自动修复后重试..."
    fix_dpkg_interrupt
    pkg_update || {
      red "软件源更新失败"
      return 1
    }

    env DEBIAN_FRONTEND=noninteractive \
      DEBCONF_NONINTERACTIVE_SEEN=true \
      DEBIAN_PRIORITY=critical \
      NEEDRESTART_MODE=a \
      APT_LISTCHANGES_FRONTEND=none \
      timeout 300 apt-get install -y --no-install-recommends \
      -o Dpkg::Use-Pty=0 \
      -o Dpkg::Options::="--force-confdef" \
      -o Dpkg::Options::="--force-confnew" \
      -o DPkg::Pre-Install-Pkgs::= \
      qrencode socat </dev/null || {
        red "qrencode / socat 安装失败"
        return 1
      }
  fi

  green "安装 OpenSSL 相关组件"
  fix_dpkg_interrupt

  local ssl_pkg="libssl3"
  if command -v apt-get >/dev/null 2>&1; then
    if apt-get -s install libssl3 >/dev/null 2>&1; then
      ssl_pkg="libssl3"
    elif apt-get -s install libssl1.1 >/dev/null 2>&1; then
      ssl_pkg="libssl1.1"
    fi
  fi

  if ! env DEBIAN_FRONTEND=noninteractive \
    DEBCONF_NONINTERACTIVE_SEEN=true \
    DEBIAN_PRIORITY=critical \
    NEEDRESTART_MODE=a \
    APT_LISTCHANGES_FRONTEND=none \
    timeout 300 apt-get install -y --no-install-recommends \
    -o Dpkg::Use-Pty=0 \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confnew" \
    -o DPkg::Pre-Install-Pkgs::= \
    openssl "$ssl_pkg" </dev/null; then

    yellow "openssl / $ssl_pkg 安装失败，尝试刷新软件源并自动修复后重试..."
    fix_dpkg_interrupt
    pkg_update || {
      red "软件源更新失败"
      return 1
    }

    if command -v apt-get >/dev/null 2>&1; then
      if apt-get -s install libssl3 >/dev/null 2>&1; then
        ssl_pkg="libssl3"
      elif apt-get -s install libssl1.1 >/dev/null 2>&1; then
        ssl_pkg="libssl1.1"
      fi
    fi

    env DEBIAN_FRONTEND=noninteractive \
      DEBCONF_NONINTERACTIVE_SEEN=true \
      DEBIAN_PRIORITY=critical \
      NEEDRESTART_MODE=a \
      APT_LISTCHANGES_FRONTEND=none \
      timeout 300 apt-get install -y --no-install-recommends \
      -o Dpkg::Use-Pty=0 \
      -o Dpkg::Options::="--force-confdef" \
      -o Dpkg::Options::="--force-confnew" \
      -o DPkg::Pre-Install-Pkgs::= \
      openssl "$ssl_pkg" </dev/null || {
        red "openssl / $ssl_pkg 安装失败"
        return 1
      }
  fi

  green "安装防火墙持久化组件"
  install_firewall_persistent || return 1

  green "环境依赖安装完成"
  return 0
}
# -----------------------------
# 函数：安装 Hysteria 内核
# -----------------------------
install_hy_core() {
  green "开始安装 Hysteria 2 内核"

  timeout 300 bash -c 'bash <(curl -fsSL https://get.hy2.sh/)' || {
    red "Hysteria 2 官方安装失败或下载超时"
    return 1
  }

  [[ -x "/usr/local/bin/hysteria" ]] || {
    red "未检测到 /usr/local/bin/hysteria，安装可能失败"
    return 1
  }

  green "Hysteria 2 内核安装成功"
  return 0
}

# -----------------------------
# 安装 Hysteria 2
# -----------------------------

# -----------------------------
# 函数：安装并初始化 Hysteria 2
# -----------------------------
insthysteria() {
  green "开始安装 Hysteria 2"

  realip || return 1

  green "步骤 1/4：安装环境依赖"
  install_hy_environment || return 1
  install_firewall_persistent || return 1

  green "步骤 2/4：安装 Hysteria 内核"
  cd /tmp || return 1

  wget -N https://raw.githubusercontent.com/byilrq/vps/main/install_h.sh || {
    red "下载 install_h.sh 失败"
    return 1
  }

  [[ -s /tmp/install_h.sh ]] || {
    red "install_h.sh 文件为空"
    rm -f /tmp/install_h.sh >/dev/null 2>&1 || true
    return 1
  }

  bash /tmp/install_h.sh || {
    red "执行 install_h.sh 失败"
    rm -f /tmp/install_h.sh >/dev/null 2>&1 || true
    return 1
  }

  rm -f /tmp/install_h.sh

  if [[ -x "/usr/local/bin/hysteria" || -x "/usr/bin/hysteria" ]]; then
    green "Hysteria 2 安装成功！"
  else
    red "Hysteria 2 安装失败！"
    return 1
  fi

  green "步骤 3/4：配置证书、端口、密码、伪装站点"
  inst_cert || return 1
  inst_port || return 1
  inst_pwd || return 1
  inst_site || return 1

  mkdir -p /etc/hysteria /root/hy /var/lib/hysteria >/dev/null 2>&1 || true

  if [[ -n $(echo "$ip" | grep ":") ]]; then
    last_ip="[$ip]"
  else
    last_ip="$ip"
  fi

  if [[ -n "$hy_domain" ]]; then
    share_host="$hy_domain"
  else
    share_host="$last_ip"
  fi

  if [[ -n "$firstport" && -n "$endport" ]]; then
    port_range="$firstport-$endport"
  else
    port_range="$port"
  fi

  green "步骤 4/4：写入配置并启动服务"

  cat > /etc/hysteria/config.yaml <<EOF
listen: :$port

tls:
  cert: $cert_path
  key: $key_path

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 90s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false

auth:
  type: password
  password: $auth_pwd

speedTest: true

masquerade:
  type: proxy
  proxy:
    url: ${masquerade_url:-https://$proxysite}
    rewriteHost: ${masquerade_rewrite_host:-true}
  listenHTTPS: :443
EOF

  cat > /root/hy/hy-client.yaml <<EOF
server: $last_ip:$port

auth: $auth_pwd

tls:
  sni: $hy_domain
  insecure: $tls_insecure

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 90s
  keepAlivePeriod: 10s
  disablePathMTUDiscovery: false

fastOpen: true

socks5:
  listen: 127.0.0.1:5080

transport:
  type: udp
  udp:
    hopInterval: 30s
EOF


  apply_hy2_firewall_rules "$port" "$firstport" "$endport"
  save_hy2_state "$port" "$firstport" "$endport" "$hy_domain" "$cert_mode"
  install_hy2_boot_fix_service
  install_hy2_core_update_job
  fix_hysteria_file_perms

  systemctl daemon-reload
  hy_service=$(get_hysteria_service_name)

  systemctl enable "$hy_service" >/dev/null 2>&1 || true
  systemctl restart "$hy_service"

  if systemctl is-active --quiet "$hy_service" && [[ -f '/etc/hysteria/config.yaml' ]]; then
    green "Hysteria 2 服务启动成功"
  else
    red "Hysteria 2 服务启动失败，请检查以下信息："
    systemctl status "$hy_service" --no-pager -l || true
    journalctl -u "$hy_service" --no-pager -n 30 || true
    return 1
  fi

  save_firewall_rules
  systemctl restart hysteria-boot-fix.service >/dev/null 2>&1 || true

  red "======================================================================================"
  green "Hysteria 2 代理服务安装完成"
  yellow "服务端配置 /etc/hysteria/config.yaml："
  green "$(cat /etc/hysteria/config.yaml)"
  yellow "客户端配置 /root/hy/hy-client.yaml："
  green "$(cat /root/hy/hy-client.yaml)"
  local hy2_link
  hy2_link=$(generate_hy2_link) || hy2_link=""
  yellow "分享链接（动态生成）："
  green "$hy2_link"
  yellow "二维码："
  [[ -n "$hy2_link" ]] && qrencode -o - -t ANSIUTF8 "$hy2_link" || true

  if [[ "$tls_insecure" == "true" ]]; then
    yellow "当前证书模式：自签证书，客户端已启用跳过证书校验（insecure: true）"
  else
    yellow "当前证书模式：正式/自定义证书，客户端强制校验证书（insecure: false）"
  fi

  yellow "伪装站验证："
  green "1) 普通浏览器访问: https://$hy_domain"
  green "2) 查看日志: journalctl -u $hy_service -f"

  read -erp "回车返回菜单..." _
}


# -----------------------------
# 卸载 / 启动 / 停止
# -----------------------------

# -----------------------------
# 函数：卸载 Hysteria 2
# -----------------------------
unsthysteria() {
  local keep_cert="false"

  if [[ -f /etc/hysteria/ca.log && -f /etc/hysteria/cert.crt && -f /etc/hysteria/private.key ]]; then
    keep_cert="true"
  fi

  systemctl stop hysteria-boot-fix.service >/dev/null 2>&1 || true
  systemctl disable hysteria-boot-fix.service >/dev/null 2>&1 || true
  systemctl stop hysteria-server.service >/dev/null 2>&1 || true
  systemctl stop hysteria.service >/dev/null 2>&1 || true
  systemctl disable hysteria-server.service >/dev/null 2>&1 || true
  systemctl disable hysteria.service >/dev/null 2>&1 || true

  rm -f /lib/systemd/system/hysteria-server.service /lib/systemd/system/hysteria-server@.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/hysteria-server.service /etc/systemd/system/hysteria-server@.service >/dev/null 2>&1 || true
  rm -f /lib/systemd/system/hysteria.service /etc/systemd/system/hysteria.service >/dev/null 2>&1 || true
  rm -f "$HY2_BOOT_FIX_SERVICE" "$HY2_FIREWALL_RESTORE_BIN" "$HY2_STATE_FILE" "$HY2_CERT_WEEKLY_CRON" "$HY2_CORE_WEEKLY_CRON" >/dev/null 2>&1 || true
  rm -f /usr/local/bin/hysteria /usr/bin/hysteria "$HY2_CERT_RENEW_BIN" "$HY2_CORE_UPDATE_BIN" >/dev/null 2>&1 || true
  rm -rf /root/hy /root/hysteria.sh /var/lib/hysteria >/dev/null 2>&1 || true

  remove_hy2_input_chain >/dev/null 2>&1 || true
  remove_hy2_jump_chain >/dev/null 2>&1 || true
  save_firewall_rules
  systemctl daemon-reload >/dev/null 2>&1 || true

  if [[ "$keep_cert" == "true" ]]; then
    mkdir -p /etc/hysteria >/dev/null 2>&1 || true
    rm -f /etc/hysteria/config.yaml >/dev/null 2>&1 || true
    green "Hysteria 2 已卸载完成，已保留正式证书与域名记录，重装时可自动复用。"
  else
    rm -rf /etc/hysteria >/dev/null 2>&1 || true
    green "Hysteria 2 已彻底卸载完成。"
  fi

  read -erp "回车返回菜单..." _
}



# -----------------------------
# 函数：启动 Hysteria 2
# -----------------------------
starthysteria() {
  local hy_service current_port current_first current_end
  hy_service=$(get_hysteria_service_name)

  load_hy2_state >/dev/null 2>&1 || true
  current_port="${HY2_PORT:-$(get_hy2_listen_port /etc/hysteria/config.yaml)}"
  current_first="${HY2_FIRST_PORT:-}"
  current_end="${HY2_END_PORT:-}"

  apply_hy2_firewall_rules "$current_port" "$current_first" "$current_end" >/dev/null 2>&1 || true
  save_firewall_rules
  systemctl enable --now "$hy_service" >/dev/null 2>&1 || systemctl start "$hy_service"
  systemctl restart hysteria-boot-fix.service >/dev/null 2>&1 || true
}



# -----------------------------
# 函数：停止 Hysteria 2
# -----------------------------
stophysteria() {
  local hy_service
  hy_service=$(get_hysteria_service_name)
  systemctl disable --now "$hy_service" >/dev/null 2>&1 || systemctl stop "$hy_service"
}


# -----------------------------
# 函数：重启 Hysteria 2
# -----------------------------
restarthy2() {
  local hy_service current_port current_first current_end
  hy_service=$(get_hysteria_service_name)

  load_hy2_state >/dev/null 2>&1 || true
  current_port="${HY2_PORT:-$(get_hy2_listen_port /etc/hysteria/config.yaml)}"
  current_first="${HY2_FIRST_PORT:-}"
  current_end="${HY2_END_PORT:-}"

  if [[ -z "$current_port" ]]; then
    red "无法读取 Hysteria 2 监听端口，请检查 /etc/hysteria/config.yaml"
    read -erp "回车返回菜单..." _
    return 1
  fi

  apply_hy2_firewall_rules "$current_port" "$current_first" "$current_end" >/dev/null 2>&1 || true
  save_firewall_rules
  systemctl restart "$hy_service"
  systemctl restart hysteria-boot-fix.service >/dev/null 2>&1 || true

  if systemctl is-active --quiet "$hy_service"; then
    green "Hysteria 2 已重启成功"
  else
    red "Hysteria 2 重启失败，请查看日志：journalctl -u $hy_service -n 50 --no-pager"
  fi

  read -erp "回车返回菜单..." _
}
# -----------------------------
# 函数：查看协议运行状态
# -----------------------------
showstatus() {
  local hy_service
  hy_service=$(get_hysteria_service_name)
  systemctl status "$hy_service" --no-pager -l
  read -erp "回车返回菜单..." _
}

# -----------------------------
# 函数：打印协议链接与二维码
# -----------------------------
showconf() {
  local hy2_link
  hy2_link=$(generate_hy2_link) || hy2_link=""
  yellow "分享链接（动态生成）："
  green "$hy2_link"
  yellow "二维码："
  [[ -n "$hy2_link" ]] && qrencode -o - -t ANSIUTF8 "$hy2_link" || true

  read -erp "回车返回菜单..." _
}

# -----------------------------
# 修改 Hysteria 配置
# -----------------------------

# -----------------------------
# 函数：修改监听端口
# -----------------------------
changeport() {
  local oldport newport current_domain current_cert_mode current_first current_end hy_service
  oldport=$(get_hy2_listen_port /etc/hysteria/config.yaml)
  load_hy2_state >/dev/null 2>&1 || true
  [[ -z "$oldport" ]] && oldport="${HY2_PORT:-443}"

  while true; do
    read_confirmed newport "设置 Hysteria 2 监听端口 [1-65535]（回车保持当前：$oldport）: " "$oldport" || return 1

    [[ "$newport" =~ ^[0-9]+$ ]] || { red "端口必须是数字"; continue; }
    ((newport >= 1 && newport <= 65535)) || { red "端口必须在 1-65535 之间"; continue; }

    if [[ "$newport" != "$oldport" ]] && ss -lun | awk '{print $5}' | sed 's/.*://g' | grep -qw "$newport"; then
      red "UDP 端口 $newport 已被占用，请更换"
      continue
    fi

    break
  done

  set_hy2_listen_port "$newport" /etc/hysteria/config.yaml || { red "写入服务端监听端口失败"; return 1; }
  set_hy2_client_server_port "$newport" /root/hy/hy-client.yaml || { red "写入客户端 server 端口失败"; return 1; }

  current_domain=$(grep -E '^\s*sni:' /root/hy/hy-client.yaml 2>/dev/null | awk '{print $2}' | tr -d '
')
  current_cert_mode=$(grep -E '^HY2_CERT_MODE=' "$HY2_STATE_FILE" 2>/dev/null | cut -d= -f2-)
  load_hy2_state >/dev/null 2>&1 || true
  current_first="${HY2_FIRST_PORT:-}"
  current_end="${HY2_END_PORT:-}"

  apply_hy2_firewall_rules "$newport" "$current_first" "$current_end"
  save_hy2_state "$newport" "$current_first" "$current_end" "$current_domain" "$current_cert_mode"

  fix_hysteria_file_perms
  save_firewall_rules
  hy_service=$(get_hysteria_service_name)
  systemctl restart "$hy_service" >/dev/null 2>&1 || true
  systemctl restart hysteria-boot-fix.service >/dev/null 2>&1 || true

  green "Hysteria 2 监听端口已成功修改为：$newport"
  showconf
}

# -----------------------------
# 函数：修改跳跃端口
# -----------------------------
changejump() {
  local current_port current_first current_end first end current_domain current_cert_mode hy_service close_jump
  load_hy2_state >/dev/null 2>&1 || true
  current_port=$(get_hy2_listen_port /etc/hysteria/config.yaml)
  [[ -z "$current_port" ]] && current_port="${HY2_PORT:-443}"
  current_first="${HY2_FIRST_PORT:-}"
  current_end="${HY2_END_PORT:-}"

  if [[ -n "$current_first" && -n "$current_end" ]]; then
    yellow "当前跳变端口范围：$current_first-$current_end -> $current_port"
  else
    yellow "当前为单端口模式，未启用跳变端口"
  fi

  while true; do
    read_confirmed close_jump "是否关闭跳变端口？[y/N]（回车默认 N）: " "N" || return 1
    case "$close_jump" in
      y|Y)
        first=""
        end=""
        yellow "已选择关闭跳变端口，仅保留监听端口：$current_port"
        break
        ;;
      n|N)
        while true; do
          read_confirmed first "设置跳变端口起始端口: " "${current_first:-}" || return 1
          read_confirmed end "设置跳变端口结束端口: " "${current_end:-}" || return 1
          validate_port_range "$first" "$end" && break
          red "范围无效：端口必须为 1-65535，且起始端口必须小于结束端口"
        done
        break
        ;;
      *) red "请输入 y 或 n。" ;;
    esac
  done

  current_domain=$(grep -E '^\s*sni:' /root/hy/hy-client.yaml 2>/dev/null | awk '{print $2}' | tr -d '
')
  current_cert_mode=$(grep -E '^HY2_CERT_MODE=' "$HY2_STATE_FILE" 2>/dev/null | cut -d= -f2-)

  apply_hy2_firewall_rules "$current_port" "$first" "$end"
  save_hy2_state "$current_port" "$first" "$end" "$current_domain" "$current_cert_mode"

  fix_hysteria_file_perms
  save_firewall_rules
  hy_service=$(get_hysteria_service_name)
  systemctl restart "$hy_service" >/dev/null 2>&1 || true
  systemctl restart hysteria-boot-fix.service >/dev/null 2>&1 || true

  if [[ -n "$first" && -n "$end" ]]; then
    green "跳变端口已修改为：$first-$end -> $current_port"
  else
    green "跳变端口已关闭，当前监听端口：$current_port"
  fi
  showconf
}

# -----------------------------
# 函数：修改连接密码
# -----------------------------
changepasswd() {
  local config_file="/etc/hysteria/config.yaml"
  local client_file="/root/hy/hy-client.yaml"

  [[ -f $config_file ]] || { red "配置文件不存在：$config_file"; return 1; }
  [[ -f $client_file ]] || { red "客户端配置不存在：$client_file"; return 1; }

  cp "$config_file" "${config_file}.bak" >/dev/null 2>&1 || true

  local oldpasswd
  oldpasswd=$(awk '/auth:/,/password:/ {if ($1 ~ /password:/) print $2}' "$config_file" | xargs)
  [[ -n "$oldpasswd" ]] || { red "无法提取旧密码，请检查 $config_file"; return 1; }

  local passwd
  read_confirmed_password passwd "设置 Hysteria 2 密码（回车随机）: " || return 1

  sed -i "/auth:/,/password:/s/^ *password: .*/  password: $passwd/" "$config_file"
  grep -q "password: $passwd" "$config_file" || { red "写入服务端密码失败"; return 1; }

  if grep -q "^auth: " "$client_file"; then
    sed -i "s/^auth: .*/auth: $passwd/" "$client_file"
  else
    echo "auth: $passwd" >> "$client_file"
  fi

  fix_hysteria_file_perms
  save_firewall_rules
  local hy_service
  hy_service=$(get_hysteria_service_name)
  systemctl restart "$hy_service" || { red "服务重启失败"; return 1; }

  green "密码已修改并生效"
  showconf
}

# -----------------------------
# 函数：修改证书类型或路径
# -----------------------------
change_cert() {
  local old_cert old_key old_host current_port current_first current_end current_cert_mode hy_service old_cert_esc old_key_esc cert_path_esc key_path_esc
  load_hy2_state >/dev/null 2>&1 || true
  old_cert=$(grep -E '^\s*cert:' /etc/hysteria/config.yaml 2>/dev/null | awk '{print $2}')
  old_key=$(grep -E '^\s*key:' /etc/hysteria/config.yaml 2>/dev/null | awk '{print $2}')
  old_host=$(get_hy2_client_host /root/hy/hy-client.yaml)
  current_port=$(get_hy2_listen_port /etc/hysteria/config.yaml)
  [[ -z "$current_port" ]] && current_port="${HY2_PORT:-443}"
  current_first="${HY2_FIRST_PORT:-}"
  current_end="${HY2_END_PORT:-}"

  inst_cert

  old_cert_esc=$(sed_escape_bang "$old_cert")
  old_key_esc=$(sed_escape_bang "$old_key")
  cert_path_esc=$(sed_escape_bang "$cert_path")
  key_path_esc=$(sed_escape_bang "$key_path")
  [[ -n "$old_cert" ]] && sed -i "s!$old_cert_esc!$cert_path_esc!g" /etc/hysteria/config.yaml
  [[ -n "$old_key"  ]] && sed -i "s!$old_key_esc!$key_path_esc!g" /etc/hysteria/config.yaml

  # 证书变更只更新 TLS/SNI，不擅自改 server host，避免把连接地址改成证书域名。
  if [[ -n "$old_host" ]]; then
    if [[ "$old_host" == *:* && "$old_host" != \[*\] ]]; then
      sed -i -E "s#^server:[[:space:]]*.*#server: [$old_host]:$current_port#" /root/hy/hy-client.yaml
    else
      sed -i -E "s#^server:[[:space:]]*.*#server: $old_host:$current_port#" /root/hy/hy-client.yaml
    fi
  fi
  grep -q '^ *sni:' /root/hy/hy-client.yaml 2>/dev/null && sed -i "s#^ *sni: .*#  sni: $hy_domain#" /root/hy/hy-client.yaml

  if grep -q '^ *insecure:' /root/hy/hy-client.yaml 2>/dev/null; then
    sed -i "s#^ *insecure: .*#  insecure: $tls_insecure#" /root/hy/hy-client.yaml
  else
    sed -i "/^tls:/a\  insecure: $tls_insecure" /root/hy/hy-client.yaml
  fi

  current_cert_mode="${cert_mode:-$(grep -E '^HY2_CERT_MODE=' "$HY2_STATE_FILE" 2>/dev/null | cut -d= -f2-)}"
  save_hy2_state "$current_port" "$current_first" "$current_end" "$hy_domain" "$current_cert_mode"
  fix_hysteria_file_perms
  save_firewall_rules
  hy_service=$(get_hysteria_service_name)
  systemctl restart "$hy_service" >/dev/null 2>&1 || true
  systemctl restart hysteria-boot-fix.service >/dev/null 2>&1 || true

  green "证书类型/路径已修改"
  showconf
}

# -----------------------------
# 函数：修改伪装站点
# -----------------------------
changeproxysite() {
  local current_port current_domain current_cert_mode hy_service target_url target_rewrite
  load_hy2_state >/dev/null 2>&1 || true

  inst_site || return 1
  target_url="${masquerade_url:-https://$proxysite}"
  target_rewrite="${masquerade_rewrite_host:-true}"

  python3 - "$target_url" "$target_rewrite" <<'PYC'
from pathlib import Path
import sys
p = Path('/etc/hysteria/config.yaml')
s = p.read_text()
url = sys.argv[1]
rewrite = sys.argv[2]
start = s.find('masquerade:')
block = f"""masquerade:
  type: proxy
  proxy:
    url: {url}
    rewriteHost: {rewrite}
  listenHTTPS: :443
"""
if start >= 0:
    before = s[:start].rstrip() + '\n\n'
else:
    before = s.rstrip() + '\n\n'
p.write_text(before + block)
PYC

  current_port=$(get_hy2_listen_port /etc/hysteria/config.yaml)
  current_domain=$(grep -E '^\s*sni:' /root/hy/hy-client.yaml 2>/dev/null | awk '{print $2}' | tr -d '\r')
  current_cert_mode=$(grep -E '^HY2_CERT_MODE=' "$HY2_STATE_FILE" 2>/dev/null | cut -d= -f2-)
  save_hy2_state "$current_port" "${HY2_FIRST_PORT:-}" "${HY2_END_PORT:-}" "$current_domain" "$current_cert_mode"
  fix_hysteria_file_perms
  save_firewall_rules
  hy_service=$(get_hysteria_service_name)
  systemctl restart "$hy_service" >/dev/null 2>&1 || true
  systemctl restart hysteria-boot-fix.service >/dev/null 2>&1 || true

  green "伪装网站已修改为：$target_url"
  showconf
}

# -----------------------------
# 函数：显示协议配置修改菜单
# -----------------------------
menu_hy_conf() {
  while true; do
    clear
    green "Hysteria 2 配置修改菜单："
    echo -e " ${GREEN}1.${tianlan} 修改监听端口"
    echo -e " ${GREEN}2.${tianlan} 修改跳变端口"
    echo -e " ${GREEN}3.${tianlan} 修改密码"
    echo -e " ${GREEN}4.${tianlan} 修改证书类型/路径"
    echo -e " ${GREEN}5.${tianlan} 修改伪装网站"
    echo " ---------------------------------------------------"
    echo -e " ${GREEN}0.${PLAIN} 返回"
    echo ""
    read -erp "请选择 [0-5]: " confAnswer

    case $confAnswer in
      1) changeport ;;
      2) changejump ;;
      3) changepasswd ;;
      4) change_cert ;;
      5) changeproxysite ;;
      0) break ;;
      *) yellow "无效选项"; sleep 1 ;;
    esac
  done
}

# -----------------------------
# 函数：查找 Hysteria 可执行文件
# -----------------------------
get_hysteria_bin() {
  if [[ -x /usr/local/bin/hysteria ]]; then
    echo "/usr/local/bin/hysteria"
  elif [[ -x /usr/bin/hysteria ]]; then
    echo "/usr/bin/hysteria"
  elif command -v hysteria >/dev/null 2>&1; then
    command -v hysteria
  else
    return 1
  fi
}

# -----------------------------
# 函数：读取当前内核版本
# -----------------------------
get_hysteria_current_version() {
  local bin out ver
  bin=$(get_hysteria_bin 2>/dev/null) || return 1
  out=$("$bin" version 2>&1 || true)
  ver=$(echo "$out" | grep -Eo 'v?[0-9]+(\.[0-9]+)+' | head -n1)
  [[ -n "$ver" ]] || return 1
  [[ "$ver" == v* ]] || ver="v$ver"
  echo "$ver"
}

# -----------------------------
# 函数：规范化内核版本号
# -----------------------------
normalize_hysteria_version() {
  local raw="$1" ver
  ver=$(echo "$raw" | grep -Eo 'v?[0-9]+(\.[0-9]+)+' | head -n1)
  [[ -n "$ver" ]] || return 1
  [[ "$ver" == v* ]] || ver="v$ver"
  echo "$ver"
}

# -----------------------------
# 函数：获取最新内核版本
# -----------------------------
get_hysteria_latest_version() {
  local latest
  latest=$(curl -fsSL --connect-timeout 10 --max-time 20 \
    https://api.github.com/repos/apernet/hysteria/releases/latest 2>/dev/null | \
    grep -m1 '"tag_name"' | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' | tr -d '\r')

  if [[ -z "$latest" ]]; then
    latest=$(curl -fsSI --connect-timeout 10 --max-time 20 \
      https://github.com/apernet/hysteria/releases/latest 2>/dev/null | \
      awk -F'/' 'tolower($1) ~ /^location:/ {print $NF}' | tr -d '\r')
  fi

  [[ -n "$latest" ]] || return 1
  normalize_hysteria_version "$latest"
}

# -----------------------------
# 函数：比较版本大小
# -----------------------------
version_lt() {
  local a b lowest
  a="${1#v}"
  b="${2#v}"
  [[ "$a" == "$b" ]] && return 1
  lowest=$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)
  [[ "$lowest" == "$a" ]]
}

# -----------------------------
# 函数：安装内核自动检测更新任务
# -----------------------------
install_hy2_core_update_job() {
  mkdir -p /usr/local/bin /etc/cron.d >/dev/null 2>&1 || true

  cat > "$HY2_CORE_UPDATE_BIN" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/hysteria-core-update.log"

# -----------------------------
# 函数：写入更新日志
# -----------------------------
log() {
  echo "[$(date '+%F %T')] $*" | tee -a "$LOG_FILE"
}

# -----------------------------
# 函数：更新脚本内获取服务名
# -----------------------------
get_service_name() {
  if systemctl list-unit-files 2>/dev/null | grep -q '^hysteria-server\.service'; then
    echo "hysteria-server"
  elif systemctl list-unit-files 2>/dev/null | grep -q '^hysteria\.service'; then
    echo "hysteria"
  else
    echo "hysteria-server"
  fi
}

# -----------------------------
# 函数：查找 Hysteria 可执行文件
# -----------------------------
get_hysteria_bin() {
  if [[ -x /usr/local/bin/hysteria ]]; then
    echo "/usr/local/bin/hysteria"
  elif [[ -x /usr/bin/hysteria ]]; then
    echo "/usr/bin/hysteria"
  elif command -v hysteria >/dev/null 2>&1; then
    command -v hysteria
  else
    return 1
  fi
}

# -----------------------------
# 函数：更新脚本内读取当前版本
# -----------------------------
get_current_version() {
  local bin out ver
  bin=$(get_hysteria_bin 2>/dev/null) || return 1
  out=$("$bin" version 2>&1 || true)
  ver=$(echo "$out" | grep -Eo 'v?[0-9]+(\.[0-9]+)+' | head -n1)
  [[ -n "$ver" ]] || return 1
  [[ "$ver" == v* ]] || ver="v$ver"
  echo "$ver"
}

# -----------------------------
# 函数：更新脚本内规范化版本号
# -----------------------------
normalize_version() {
  local raw="$1" ver
  ver=$(echo "$raw" | grep -Eo 'v?[0-9]+(\.[0-9]+)+' | head -n1)
  [[ -n "$ver" ]] || return 1
  [[ "$ver" == v* ]] || ver="v$ver"
  echo "$ver"
}

# -----------------------------
# 函数：更新脚本内获取最新版本
# -----------------------------
get_latest_version() {
  local latest
  latest=$(curl -fsSL --connect-timeout 10 --max-time 20 \
    https://api.github.com/repos/apernet/hysteria/releases/latest 2>/dev/null | \
    grep -m1 '"tag_name"' | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' | tr -d '\r')

  if [[ -z "$latest" ]]; then
    latest=$(curl -fsSI --connect-timeout 10 --max-time 20 \
      https://github.com/apernet/hysteria/releases/latest 2>/dev/null | \
      awk -F'/' 'tolower($1) ~ /^location:/ {print $NF}' | tr -d '\r')
  fi

  [[ -n "$latest" ]] || return 1
  normalize_version "$latest"
}

# -----------------------------
# 函数：比较版本大小
# -----------------------------
version_lt() {
  local a b lowest
  a="${1#v}"
  b="${2#v}"
  [[ "$a" == "$b" ]] && return 1
  lowest=$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)
  [[ "$lowest" == "$a" ]]
}

service_name=$(get_service_name)
current=$(get_current_version 2>/dev/null || echo "未安装")
latest=$(get_latest_version 2>/dev/null || true)

if [[ -z "$latest" ]]; then
  log "获取 Hysteria 最新版本失败，跳过更新。当前版本：$current"
  exit 0
fi

log "当前版本：$current，最新版本：$latest"

if [[ "$current" != "未安装" ]] && ! version_lt "$current" "$latest"; then
  log "当前已是最新版本，无需更新。"
  exit 0
fi

log "发现新版本，开始更新 Hysteria 内核。"
backup=""
bin=$(get_hysteria_bin 2>/dev/null || true)
if [[ -n "$bin" && -x "$bin" ]]; then
  backup="${bin}.bak.$(date +%Y%m%d%H%M%S)"
  cp -a "$bin" "$backup" 2>/dev/null || true
fi

systemctl stop "$service_name" >/dev/null 2>&1 || true
if bash <(curl -fsSL https://get.hy2.sh/); then
  systemctl enable --now "$service_name" >/dev/null 2>&1 || systemctl start "$service_name" >/dev/null 2>&1 || true
  systemctl restart "$service_name" >/dev/null 2>&1 || true

  if systemctl is-active --quiet "$service_name"; then
    new_version=$(get_current_version 2>/dev/null || echo "$latest")
    log "Hysteria 内核更新完成：$current -> $new_version"
    exit 0
  fi

  log "更新后服务未正常运行，尝试回滚。"
else
  log "官方安装脚本执行失败，尝试回滚。"
fi

if [[ -n "$backup" && -s "$backup" && -n "$bin" ]]; then
  cp -a "$backup" "$bin" 2>/dev/null || true
  chmod +x "$bin" 2>/dev/null || true
fi
systemctl restart "$service_name" >/dev/null 2>&1 || true
log "更新失败，已执行回滚尝试。请手动检查：journalctl -u $service_name -n 50 --no-pager"
exit 1
EOF

  chmod 700 "$HY2_CORE_UPDATE_BIN" >/dev/null 2>&1 || true

  cat > "$HY2_CORE_WEEKLY_CRON" <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# 每周日 04:20 自动检测 Hysteria 内核版本，只有发现新版才更新。
20 4 * * 0 root "$HY2_CORE_UPDATE_BIN" >/dev/null 2>&1
EOF
  chmod 644 "$HY2_CORE_WEEKLY_CRON" >/dev/null 2>&1 || true

  green "已安装每周一次内核检测更新任务：$HY2_CORE_WEEKLY_CRON"
  yellow "日志文件：$HY2_CORE_UPDATE_LOG"
}

# -----------------------------
# 函数：手动检测并更新内核
# -----------------------------
update_core() {
  local current latest hy_service backup bin new_version

  green "检测 Hysteria 2 内核版本..."
  current=$(get_hysteria_current_version 2>/dev/null || echo "未安装")
  latest=$(get_hysteria_latest_version 2>/dev/null || true)

  yellow "当前安装版本：$current"
  if [[ -z "$latest" ]]; then
    red "获取最新版本失败，请检查网络或 GitHub 访问。"
    read -erp "回车返回菜单..." _
    return 1
  fi
  yellow "GitHub 最新版本：$latest"

  install_hy2_core_update_job

  if [[ "$current" != "未安装" ]] && ! version_lt "$current" "$latest"; then
    green "当前已是最新版本，无需更新。"
    read -erp "回车返回菜单..." _
    return 0
  fi

  yellow "发现可更新版本，开始执行官方更新脚本。"
  hy_service=$(get_hysteria_service_name)
  bin=$(get_hysteria_bin 2>/dev/null || true)
  backup=""
  if [[ -n "$bin" && -x "$bin" ]]; then
    backup="${bin}.bak.$(date +%Y%m%d%H%M%S)"
    cp -a "$bin" "$backup" 2>/dev/null || true
  fi

  systemctl stop "$hy_service" >/dev/null 2>&1 || true
  if bash <(curl -fsSL https://get.hy2.sh/); then
    systemctl enable --now "$hy_service" >/dev/null 2>&1 || systemctl start "$hy_service" >/dev/null 2>&1 || true
    systemctl restart "$hy_service" >/dev/null 2>&1 || true

    if systemctl is-active --quiet "$hy_service"; then
      new_version=$(get_hysteria_current_version 2>/dev/null || echo "$latest")
      green "Hysteria 内核已更新并重启：$current -> $new_version"
      read -erp "回车返回菜单..." _
      return 0
    fi

    red "更新后服务未正常运行，尝试回滚。"
  else
    red "官方安装脚本执行失败，尝试回滚。"
  fi

  if [[ -n "$backup" && -s "$backup" && -n "$bin" ]]; then
    cp -a "$backup" "$bin" 2>/dev/null || true
    chmod +x "$bin" 2>/dev/null || true
  fi
  systemctl restart "$hy_service" >/dev/null 2>&1 || true
  red "更新失败，已尝试恢复旧内核。请检查：journalctl -u $hy_service -n 50 --no-pager"
  read -erp "回车返回菜单..." _
  return 1
}
# -----------------------------
# 函数：执行回程路由测试
# -----------------------------
besttrace() {
  local tmp="/tmp/besttrace.sh"
  download_with_retry "https://git.io/besttrace" "$tmp" || { red "下载 besttrace 失败"; read -erp "回车返回菜单..." _; return 1; }
  [[ -s "$tmp" ]] || { red "besttrace 脚本为空"; read -erp "回车返回菜单..." _; return 1; }
  bash "$tmp"
  rm -f "$tmp" >/dev/null 2>&1 || true
  read -erp "回车返回菜单..." _
}

# -----------------------------
# 函数：执行 IP 质量检测
# -----------------------------
ipquality() {
  local tmp="/tmp/check_place.sh"
  download_with_retry "https://Check.Place" "$tmp" || { red "下载 IP 质量检测脚本失败"; read -erp "回车返回菜单..." _; return 1; }
  [[ -s "$tmp" ]] || { red "IP 质量检测脚本为空"; read -erp "回车返回菜单..." _; return 1; }
  bash "$tmp" -I
  rm -f "$tmp" >/dev/null 2>&1 || true
  read -erp "回车返回菜单..." _
}

# -----------------------------
# 函数：显示系统信息总览
# -----------------------------
linux_ps() {
  clear

  local cpu_info cpu_arch hostname kernel_version hy2_core_version os_info current_time timezone
  cpu_info=$(lscpu 2>/dev/null | awk -F': +' '/Model name:/ {print $2; exit}')
  cpu_arch=$(uname -m)
  hostname=$(uname -n)
  kernel_version=$(uname -r)
  hy2_core_version=$(get_hysteria_current_version 2>/dev/null || echo "未安装")
  os_info=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d '=' -f2 | tr -d '"')
  timezone=$(timedatectl 2>/dev/null | awk -F': ' '/Time zone/ {print $2}' | awk '{print $1}')
  [[ -z "$timezone" ]] && timezone="unknown"
  current_time=$(date "+%Y-%m-%d %I:%M %p")

  local cpu_cores cpu_freq
  cpu_cores=$(nproc 2>/dev/null)
  cpu_freq=$(grep -m1 "MHz" /proc/cpuinfo 2>/dev/null | awk '{printf "%.1f GHz\n", $4/1000}')
  [[ -z "$cpu_freq" ]] && cpu_freq="unknown"

  local cpu_usage_percent
  cpu_usage_percent=$(
    awk '
      NR==1 {u=$2+$4; t=$2+$4+$5; u1=u; t1=t; next}
      NR==2 {u=$2+$4; t=$2+$4+$5; du=u-u1; dt=t-t1; if(dt>0) printf "%.0f\n", du*100/dt; else print "0"}
    ' <(grep 'cpu ' /proc/stat) <(sleep 1; grep 'cpu ' /proc/stat) 2>/dev/null
  )
  [[ -z "$cpu_usage_percent" ]] && cpu_usage_percent="0"

  local mem_info
  mem_info=$(awk '
    /MemTotal/{t=$2}
    /MemFree/{f=$2}
    /^Buffers:/{b=$2}
    /^Cached:/{c=$2}
    /SReclaimable/{r=$2}
    /Shmem:/{s=$2}
    END{
      used=t-f-b-c-r+s;
      if(used<0) used=0;
      if(t>0) printf "%.2f/%.2f MB (%.2f%%)", used/1024, t/1024, used*100/t;
      else print "unknown"
    }' /proc/meminfo 2>/dev/null
  )
  [[ -z "$mem_info" ]] && mem_info="unknown"

  local mem_pressure
  mem_pressure=$(
    awk '
      /MemTotal/     {t=$2}
      /MemAvailable/ {a=$2}
      END{
        if(t<=0){print "unknown"; exit}
        p = a*100/t;
        mb = a/1024;
        status="安全";
        if(p<5) status="高危";
        else if(p<10) status="警告";
        printf "%.0fMB available (%.0f%%) %s", mb, p, status
      }' /proc/meminfo 2>/dev/null
  )
  [[ -z "$mem_pressure" ]] && mem_pressure="unknown"

  local disk_info
  disk_info=$(df -h 2>/dev/null | awk '$NF=="/"{printf "%s/%s (%s)", $3, $2, $5}')
  [[ -z "$disk_info" ]] && disk_info="unknown"

  local load
  load=$(uptime 2>/dev/null | awk '{print $(NF-2), $(NF-1), $NF}' | tr -d ',')
  [[ -z "$load" ]] && load="unknown"

  local dns_addresses
  dns_addresses=""
  if [[ -f /etc/resolv.conf ]]; then
    dns_addresses=$(awk '/^nameserver[ \t]+/{printf "%s ", $2} END {print ""}' /etc/resolv.conf 2>/dev/null)
  fi
  if [[ -z "${dns_addresses// /}" ]]; then
    dns_addresses=$(resolvectl status 2>/dev/null | awk '
      /^ *DNS Servers:/ {for (i=3;i<=NF;i++) printf "%s ", $i}
      END {print ""}')
  fi
  [[ -z "${dns_addresses// /}" ]] && dns_addresses="unknown"

  local ipv4_address ipv6_address
  ipv4_address=$(curl -s4m6 ip.sb -k 2>/dev/null || true)
  ipv6_address=$(curl -s6m6 ip.sb -k 2>/dev/null || true)

  local ipinfo country city isp_info
  ipinfo=$(curl -s --max-time 4 ipinfo.io 2>/dev/null || true)
  country=$(echo "$ipinfo" | grep -m1 'country' | awk -F': ' '{print $2}' | tr -d '",')
  city=$(echo "$ipinfo" | grep -m1 'city' | awk -F': ' '{print $2}' | tr -d '",')
  isp_info=$(echo "$ipinfo" | grep -m1 'org' | awk -F': ' '{print $2}' | tr -d '",')
  [[ -z "$country" ]] && country="unknown"
  [[ -z "$city" ]] && city="unknown"
  [[ -z "$isp_info" ]] && isp_info="unknown"

  local congestion_algorithm queue_algorithm
  congestion_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
  queue_algorithm=$(sysctl -n net.core.default_qdisc 2>/dev/null)
  [[ -z "$congestion_algorithm" ]] && congestion_algorithm="unknown"
  [[ -z "$queue_algorithm" ]] && queue_algorithm="unknown"

  local swap_info
  swap_info=$(free -m 2>/dev/null | awk 'NR==3{used=$3; total=$2; if(total==0) pct=0; else pct=used*100/total; printf "%dMB/%dMB (%d%%)", used, total, pct}')
  [[ -z "$swap_info" ]] && swap_info="unknown"

  local runtime
  runtime=$(awk -F. '{
      run_days=int($1/86400);
      run_hours=int(($1%86400)/3600);
      run_minutes=int(($1%3600)/60);
      if (run_days>0) printf("%d天 ", run_days);
      if (run_hours>0) printf("%d时 ", run_hours);
      printf("%d分\n", run_minutes)
    }' /proc/uptime 2>/dev/null
  )
  [[ -z "$runtime" ]] && runtime="unknown"

  echo ""
  echo -e "系统信息查询"
  echo -e "${tianlan}-------------"
  echo -e "${tianlan}主机名:       ${hui}$hostname"
  echo -e "${tianlan}系统版本:     ${hui}$os_info"
  echo -e "${tianlan}Linux内核版本: ${hui}$kernel_version"
  echo -e "${tianlan}Hy2内核版本:   ${hui}$hy2_core_version"
  echo -e "${tianlan}-------------"
  echo -e "${tianlan}CPU架构:      ${hui}$cpu_arch"
  echo -e "${tianlan}CPU型号:      ${hui}$cpu_info"
  echo -e "${tianlan}CPU核心数:    ${hui}$cpu_cores"
  echo -e "${tianlan}CPU频率:      ${hui}$cpu_freq"
  echo -e "${tianlan}-------------"
  echo -e "${tianlan}CPU占用:      ${hui}${cpu_usage_percent}%"
  echo -e "${tianlan}系统负载:     ${hui}$load"
  echo -e "${tianlan}物理内存:     ${hui}$mem_info"
  echo -e "${tianlan}可用内存:     ${hui}$mem_pressure"
  echo -e "${tianlan}虚拟内存:     ${hui}$swap_info"
  echo -e "${tianlan}硬盘占用:     ${hui}$disk_info"
  echo -e "${tianlan}-------------"
  echo -e "${tianlan}网络算法:     ${hui}$congestion_algorithm $queue_algorithm"
  echo -e "${tianlan}-------------"
  echo -e "${tianlan}运营商:       ${hui}$isp_info"
  [[ -n "$ipv4_address" ]] && echo -e "${tianlan}IPv4地址:     ${hui}$ipv4_address"
  [[ -n "$ipv6_address" ]] && echo -e "${tianlan}IPv6地址:     ${hui}$ipv6_address"
  echo -e "${tianlan}DNS地址:      ${hui}$dns_addresses"
  echo -e "${tianlan}地理位置:     ${hui}$country $city"
  echo -e "${tianlan}系统时间:     ${hui}$timezone $current_time"
  echo -e "${tianlan}-------------"
  echo -e "${tianlan}运行时长:     ${hui}$runtime"
  echo
  read -erp "回车返回菜单..." _
}

# -----------------------------
# 函数：执行系统更新
# -----------------------------
linux_update() {
  if command -v apt-get >/dev/null 2>&1; then
    wait_for_apt_lock || true
    DEBIAN_FRONTEND=noninteractive apt-get update -y -o Dpkg::Use-Pty=0
    wait_for_apt_lock || true
    DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y -o Dpkg::Use-Pty=0
  elif command -v dnf >/dev/null 2>&1; then
    dnf -y update
  elif command -v yum >/dev/null 2>&1; then
    yum -y update
  else
    red "未知的包管理器"
    return 1
  fi
  green "系统更新完成"
  read -erp "回车返回菜单..." _
}

# -----------------------------
# 函数：下载并执行系统配置脚本
# -----------------------------
run_sys_conf() {
  local url="https://raw.githubusercontent.com/byilrq/vps/main/sys_conf.sh"
  local tmp="/tmp/sys_conf.sh"

  download_with_retry "$url" "$tmp" || { red "下载 sys_conf.sh 失败"; read -erp "回车返回..." _; return 1; }
  [[ -s "$tmp" ]] || { red "sys_conf.sh 文件为空"; read -erp "回车返回..." _; return 1; }
  bash "$tmp"
}

# -----------------------------
# 函数：显示主菜单
# -----------------------------
menu() {
  while true; do
    clear
    echo "#############################################################"
    echo -e "# ${tianlan}Hy2 一键安装脚本${PLAIN} #"
    echo "#############################################################"
    echo ""
    echo -e " ${GREEN}1.${GREEN} 安装 Hy2"
    echo -e " ${GREEN}2.${zi} 卸载 Hy2"
    echo " ---------------------------------------------------"
    echo -e " ${GREEN}3.${tianlan} 重启 Hy2"
    echo -e " ${GREEN}4.${tianlan} 修改协议配置"
    echo -e " ${GREEN}5.${tianlan} 修改系统配置"
    echo -e " ${GREEN}6.${tianlan} 打印协议链接"
    echo -e " ${GREEN}7.${tianlan} 协议运行状态"
    echo -e " ${GREEN}8.${tianlan} 内核更新 / 每周cron"
    echo -e " ${GREEN}9.${tianlan} 回程测试"
    echo -e " ${GREEN}10.${tianlan} IP质量检测"
    echo -e " ${GREEN}11.${tianlan} 系统查询"
    echo -e " ${GREEN}12.${tianlan} 系统更新"
    echo " ---------------------------------------------------"
    echo -e " ${GREEN}0.${PLAIN} 退出脚本"
    echo ""
    read -erp "请输入选项 [0-12]: " menuInput

    case $menuInput in
      1) insthysteria ;;
      2) unsthysteria ;;
      3) restarthy2 ;;
      4) menu_hy_conf ;;
      5) run_sys_conf ;;
      6) showconf ;;
      7) showstatus ;;
      8) update_core ;;
      9) besttrace ;;
      10) ipquality ;;
      11) linux_ps ;;
      12) linux_update ;;
      0) break ;;
      *) yellow "无效选项"; sleep 1 ;;
    esac
  done
}

need_root
detect_os
ensure_curl
menu
