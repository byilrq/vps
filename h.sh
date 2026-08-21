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
# 函数：检查已有 Let's Encrypt 证书是否可用
# -----------------------------
existing_official_cert_usable() {
  local expect_domain="$1"
  local cert_file="/etc/letsencrypt/live/${expect_domain}/fullchain.pem"
  local key_file="/etc/letsencrypt/live/${expect_domain}/privkey.pem"

  [[ -s "$cert_file" && -s "$key_file" ]] || return 1

  cert_matches_domain "$cert_file" "$expect_domain" || return 1
  cert_not_expiring_soon "$cert_file" 14 || return 1

  echo "$expect_domain"
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
# 函数：安装证书自动续签任务（使用 certbot）
# -----------------------------
install_hy2_cert_renew_job() {
  # certbot 自带自动续签（systemd timer），无需额外 cron
  # deploy hook: 续签后重启 hysteria 加载新证书
  local hy_service
  hy_service=$(get_hysteria_service_name)

  mkdir -p /etc/letsencrypt/renewal-hooks/deploy >/dev/null 2>&1 || true
  cat > "/etc/letsencrypt/renewal-hooks/deploy/hysteria-restart.sh" <<EOF
#!/usr/bin/env bash
systemctl restart ${hy_service} 2>/dev/null || true
EOF
  chmod 755 /etc/letsencrypt/renewal-hooks/deploy/hysteria-restart.sh 2>/dev/null || true

  # 移除老旧的 acme.sh 相关任务
  rm -f "$HY2_CERT_RENEW_BIN" "$HY2_CERT_WEEKLY_CRON" >/dev/null 2>&1 || true
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

# 若 cert.crt 是符号链接(旧安装残留)，拷贝一份确保 hysteria 用户可读
if [[ -L /etc/hysteria/cert.crt ]]; then
  cp -f /etc/hysteria/cert.crt /etc/hysteria/cert.crt.tmp 2>/dev/null && mv /etc/hysteria/cert.crt.tmp /etc/hysteria/cert.crt
fi
if [[ -L /etc/hysteria/private.key ]]; then
  cp -f /etc/hysteria/private.key /etc/hysteria/private.key.tmp 2>/dev/null && mv /etc/hysteria/private.key.tmp /etc/hysteria/private.key
fi
if [[ -f /etc/hysteria/cert.crt ]]; then
  chmod 644 /etc/hysteria/cert.crt 2>/dev/null || true
fi
if [[ -f /etc/hysteria/private.key ]]; then
  chmod 640 /etc/hysteria/private.key 2>/dev/null || true
fi
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

  chdir="/etc/hysteria"
  if [[ -d "$chdir" ]]; then
    chmod 755 "$chdir" 2>/dev/null || true
  fi

  chown root:"$g" "$dir" 2>/dev/null || chown root:root "$dir"
  chmod 755 "$dir" 2>/dev/null || true

  if [[ -f "$cfg" ]]; then
    chown root:"$g" "$cfg" 2>/dev/null || chown root:root "$cfg"
    chmod 640 "$cfg" 2>/dev/null || true
  fi

  if [[ -f "$key" ]]; then
    chown root:"$g" "$key" 2>/dev/null || chown root:root "$key"
    chmod 640 "$key" 2>/dev/null || true
  fi

  if [[ -f "$crt" ]]; then
    chown root:"$g" "$crt" 2>/dev/null || chown root:root "$crt"
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
  echo -e " ${GREEN}1.${PLAIN} Let's Encrypt 申请${YELLOW}（certbot，默认）${PLAIN}"
  echo -e " ${GREEN}2.${PLAIN} 必应自签证书${YELLOW}（客户端跳过证书校验）${PLAIN}"
  echo -e " ${GREEN}3.${PLAIN} 自定义证书路径${YELLOW}（强制校验）${PLAIN}"
  echo -e " ${GREEN}4.${PLAIN} Acme 脚本申请${YELLOW}（原 acme.sh 方式，路径统一到 LE）${PLAIN}"
  echo ""

  while true; do
    read_confirmed certInput "请输入选项 [1-4]（回车默认 1）: " "1" || return 1
    [[ "$certInput" =~ ^[1-4]$ ]] && break
    red "选项无效，请输入 1、2、3 或 4。"
  done

  mkdir -p /etc/hysteria >/dev/null 2>&1 || true

  tls_insecure="false"
  cert_mode="official"
  local le_domain=""

  if [[ $certInput == 1 ]]; then
    # === 1) Let's Encrypt（certbot + webroot，直接引用 LE 路径）===
    realip || return 1
    while true; do
      read_confirmed domain "请输入需要申请或复用证书的域名: " "" || return 1
      domain="$(normalize_host_input "$domain")"
      if is_valid_domain "$domain"; then
        break
      fi
      red "域名格式无效：$domain"
    done

    cert_path="/etc/letsencrypt/live/${domain}/fullchain.pem"
    key_path="/etc/letsencrypt/live/${domain}/privkey.pem"

    le_domain=$(existing_official_cert_usable "$domain" 2>/dev/null || true)
    if [[ -n "$le_domain" ]]; then
      green "检测到域名 $le_domain 的本地 Let's Encrypt 证书已存在且有效，跳过重复申请"
      echo "$le_domain" > "$ACME_DOMAIN_LOG"
      hy_domain="$le_domain"
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

    green "安装 certbot 和 nginx..."
    pkg_install certbot nginx openssl >/dev/null 2>&1 || true

    mkdir -p /var/www/acme /etc/nginx/sites-available /etc/nginx/sites-enabled
    cat > /etc/nginx/sites-available/acme-hy.conf <<EOF
server {
    listen 80;
    server_name ${domain};
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/acme;
        default_type "text/plain";
    }
    location / { return 404; }
}
EOF
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
    ln -sf /etc/nginx/sites-available/acme-hy.conf /etc/nginx/sites-enabled/acme-hy.conf
    systemctl start nginx 2>/dev/null || true
    sleep 1

    if ! nginx -t 2>/dev/null; then
      red "nginx 配置错误"
      rm -f /etc/nginx/sites-enabled/acme-hy.conf /etc/nginx/sites-available/acme-hy.conf
      return 1
    fi
    systemctl reload nginx

    green "开始签发证书..."
    if certbot certonly --webroot -w /var/www/acme --non-interactive --agree-tos --register-unsafely-without-email -d "$domain"; then
      rm -f /etc/nginx/sites-enabled/acme-hy.conf /etc/nginx/sites-available/acme-hy.conf
      systemctl reload nginx 2>/dev/null || true
      if [[ -s "$cert_path" && -s "$key_path" ]]; then
        echo "$domain" > "$ACME_DOMAIN_LOG"
        install_hy2_cert_renew_job
        green "证书申请成功：$cert_path"
        yellow "自动续签：certbot renew（无需额外配置）"
        hy_domain="$domain"
        tls_insecure="false"
        cert_mode="official"
      else
        red "证书文件生成异常"
        return 1
      fi
    else
      rm -f /etc/nginx/sites-enabled/acme-hy.conf /etc/nginx/sites-available/acme-hy.conf
      systemctl reload nginx 2>/dev/null || true
      red "证书签发失败"
      return 1
    fi

  elif [[ $certInput == 2 ]]; then
    # === 2) 必应自签证书 ===
    green "将使用必应自签证书作为 Hysteria 2 的节点证书"
    cert_path="/etc/letsencrypt/live/selfsigned/fullchain.pem"
    key_path="/etc/letsencrypt/live/selfsigned/privkey.pem"
    mkdir -p /etc/letsencrypt/live/selfsigned >/dev/null 2>&1 || true

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
    rm -f /etc/letsencrypt/renewal-hooks/deploy/hysteria-restart.sh 2>/dev/null || true
    yellow "当前为自签证书模式，客户端将跳过证书校验"

  elif [[ $certInput == 3 ]]; then
    # === 3) 自定义证书路径 ===
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
    # === 4) Acme 脚本申请（acme.sh，路径统一到 /etc/letsencrypt/live/）===

    realip || return 1
    while true; do
      read_confirmed domain "请输入需要申请证书的域名: " "" || return 1
      domain="$(normalize_host_input "$domain")"
      if is_valid_domain "$domain"; then
        break
      fi
      red "域名格式无效：$domain"
    done

    cert_path="/etc/letsencrypt/live/${domain}/fullchain.pem"
    key_path="/etc/letsencrypt/live/${domain}/privkey.pem"

    le_domain=$(existing_official_cert_usable "$domain" 2>/dev/null || true)
    if [[ -n "$le_domain" ]]; then
      green "检测到域名 $le_domain 的本地证书已存在，跳过申请"
      echo "$le_domain" > "$ACME_DOMAIN_LOG"
      hy_domain="$le_domain"
      tls_insecure="false"
      cert_mode="official"
      install_hy2_cert_renew_job
      return 0
    fi

    green "已输入的域名：$domain"
    green "检查域名解析..."
    check_domain_ready "$domain" || {
      red "当前域名解析的 IP 与当前 VPS 真实 IP 不匹配"
      return 1
    }

    green "检查 80 端口..."
    check_port_80_free || {
      red "80 端口被占用，acme standalone 模式会失败"
      yellow "请先停止占用 80 端口的服务（如 nginx/apache/caddy）后重试"
      return 1
    }

    green "安装 acme.sh 依赖..."
    pkg_install curl wget sudo socat openssl >/dev/null 2>&1 || true

    green "安装 acme.sh ..."
    curl -fsSL https://get.acme.sh | sh -s email="$(date +%s%N | md5sum | cut -c 1-16)@gmail.com" || {
      red "安装 acme.sh 失败"
      return 1
    }

    source ~/.bashrc >/dev/null 2>&1 || true
    bash ~/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1 || true
    bash ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true

    green "开始签发证书..."
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

    bash ~/.acme.sh/acme.sh --install-cert -d "${domain}" \
      --key-file "$key_path" \
      --fullchain-file "$cert_path" \
      --ecc \
      --reloadcmd "systemctl restart $(get_hysteria_service_name)" || {
        red "安装证书失败"
        return 1
    }

    if [[ -s "$cert_path" && -s "$key_path" ]]; then
      echo "$domain" > "$ACME_DOMAIN_LOG"
      install_hy2_cert_renew_job
      green "证书申请成功：$cert_path"
      hy_domain="$domain"
      tls_insecure="false"
      cert_mode="official"
    else
      red "证书文件生成异常"
      return 1
    fi
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
  # 检测端口 443 冲突：x-ui 也默认监听 443
  if ss -lntp 2>/dev/null | grep -q ':443 '; then
    local proc_443
    proc_443=$(ss -lntp 2>/dev/null | grep ':443 ' | head -1)
    if echo "$proc_443" | grep -qi "x-ui\|xray"; then
      red "检测到 x-ui/xray 正在占用端口 443。h.sh 和 x.sh 不能同时安装（均默认监听 443）。"
      red "请先卸载 x.sh（x-ui）后再安装 h.sh。"
      read -erp "回车返回菜单..." _
      return 1
    fi
  fi

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

  if [[ -n "$hy_domain" && "$cert_mode" != "selfsigned" ]]; then
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
server: $share_host:$port

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

  # 修改 systemd service 以 root 运行（避免证书权限问题）
  local svc_path=""
  if systemctl list-unit-files 2>/dev/null | grep -q '^hysteria-server\.service'; then
    svc_path="/etc/systemd/system/hysteria-server.service"
  else
    svc_path="/etc/systemd/system/hysteria.service"
  fi
  if [[ -f "$svc_path" ]]; then
    sed -i 's/^User=.*/User=root/' "$svc_path"
    sed -i 's/^Group=.*/Group=root/' "$svc_path"
    systemctl daemon-reload
  fi

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

  if [[ -f /etc/letsencrypt/live/*/fullchain.pem ]] 2>/dev/null || [[ -f /etc/hysteria/ca.log ]]; then
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
    rm -f /etc/hysteria/config.yaml /etc/hysteria/ca.log /etc/hysteria/cert.crt /etc/hysteria/private.key >/dev/null 2>&1 || true
    green "Hysteria 2 已卸载完成，已保留 Let's Encrypt 证书与域名记录（/etc/letsencrypt/live/），重装时可自动复用。"
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
# 每月 1 日 02:00 自动检测 Hysteria 内核版本，只有发现新版才更新。
0 2 1 * * root "$HY2_CORE_UPDATE_BIN" >/dev/null 2>&1
EOF
  chmod 644 "$HY2_CORE_WEEKLY_CRON" >/dev/null 2>&1 || true

  green "已安装每月一次内核检测更新任务：$HY2_CORE_WEEKLY_CRON"
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

  local cpu_info cpu_arch hostname kernel_version hy2_core_version hy2_latest_version os_info current_time timezone
  cpu_info=$(lscpu 2>/dev/null | awk -F': +' '/Model name:/ {print $2; exit}')
  cpu_arch=$(uname -m)
  hostname=$(uname -n)
  kernel_version=$(uname -r)
  hy2_core_version=$(get_hysteria_current_version 2>/dev/null || echo "未安装")
  hy2_latest_version=$(get_hysteria_latest_version 2>/dev/null || echo "")
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
  echo -e "${tianlan}Hy2内核版本:   ${hui}当前 $hy2_core_version${hy2_latest_version:+，最新 $hy2_latest_version}"
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
# 函数：校验 IPv4 地址
# -----------------------------
is_valid_ipv4() {
  local value="$1"
  local a b c d extra octet

  IFS='.' read -r a b c d extra <<< "$value"
  [[ -n "$a" && -n "$b" && -n "$c" && -n "$d" && -z "$extra" ]] || return 1

  for octet in "$a" "$b" "$c" "$d"; do
    [[ "$octet" =~ ^[0-9]{1,3}$ ]] || return 1
    ((10#$octet >= 0 && 10#$octet <= 255)) || return 1
  done

  return 0
}

# -----------------------------
# 函数：校验 IPv6 地址（支持标准 IPv6 文本，不接受域名）
# -----------------------------
is_valid_ipv6() {
  local value="$1"
  value="${value#[}"
  value="${value%]}"
  [[ -n "$value" && "$value" == *:* ]] || return 1

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$value" <<'PYC' >/dev/null 2>&1
import ipaddress
import sys
try:
    ipaddress.IPv6Address(sys.argv[1])
except Exception:
    raise SystemExit(1)
PYC
    return $?
  fi

  [[ "$value" =~ ^[0-9A-Fa-f:]+$ ]]
}

# -----------------------------
# 函数：读取必须填写的密码（可用 Backspace/方向键修改）
# -----------------------------
read_required_password() {
  local __var="$1"
  local prompt="$2"
  local value

  read -erp "$prompt" value
  if [[ -z "$value" ]]; then
    red "密码不能为空。"
    return 1
  fi

  if [[ ! "$value" =~ ^[A-Za-z0-9._~@%+-]+$ ]]; then
    red "密码仅支持字母、数字和 . _ ~ @ % + -"
    return 1
  fi

  printf -v "$__var" '%s' "$value"
  return 0
}

# -----------------------------
# 函数：获取本机公网 IPv6
# -----------------------------
get_public_ipv6() {
  local v6
  v6=$(curl -6fsS --max-time 8 ip.sb 2>/dev/null | tr -d '\r\n' || true)
  if ! is_valid_ipv6 "$v6"; then
    v6=$(ip -6 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -v '^fd' | head -n1)
  fi
  is_valid_ipv6 "$v6" || return 1
  printf '%s' "$v6"
}

# -----------------------------
# 函数：读取 Xray 可执行文件
# -----------------------------
get_xray_bin() {
  if [[ -x /usr/local/bin/xray ]]; then
    echo "/usr/local/bin/xray"
  elif [[ -x /usr/bin/xray ]]; then
    echo "/usr/bin/xray"
  elif command -v xray >/dev/null 2>&1; then
    command -v xray
  else
    return 1
  fi
}

# -----------------------------
# 函数：删除 Hysteria 2 顶层 outbounds 配置块
# -----------------------------
remove_hy2_outbounds_block() {
  local config_file="${1:-/etc/hysteria/config.yaml}"
  command -v python3 >/dev/null 2>&1 || return 1

  python3 - "$config_file" <<'PYC'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
lines = path.read_text().splitlines(keepends=True)
start = None
end = None
for index, line in enumerate(lines):
    if re.match(r'^outbounds:\s*(?:#.*)?$', line.rstrip('\r\n')):
        start = index
        for next_index in range(index + 1, len(lines)):
            candidate = lines[next_index]
            if candidate.strip() and not candidate.startswith((' ', '\t', '#')):
                end = next_index
                break
        if end is None:
            end = len(lines)
        break

if start is not None:
    del lines[start:end]

path.write_text(''.join(lines).rstrip() + '\n')
PYC
}

# -----------------------------
# 函数：通过 SOCKS5 测试落地出口
# -----------------------------
test_socks5_landing() {
  local host="$1" port="$2" user="$3" password="$4"
  local result=""

  result=$(curl -fsS --connect-timeout 5 --max-time 15 \
    --proxy "socks5h://[$host]:$port" \
    --proxy-user "$user:$password" \
    https://api.ipify.org 2>/dev/null | tr -d '\r\n' || true)

  if [[ -z "$result" ]]; then
    result=$(curl -fsS --connect-timeout 5 --max-time 15 \
      --socks5-hostname "[$host]:$port" \
      --proxy-user "$user:$password" \
      https://ip.sb 2>/dev/null | tr -d '\r\n' || true)
  fi

  [[ -n "$result" ]] || return 1
  printf '%s' "$result"
}

# -----------------------------
# 函数：最终测试 Hy2 中转与 SOCKS5 落地连通性
# -----------------------------
run_hy2_relay_connectivity_test() {
  local config_file="/etc/hysteria/config.yaml"
  local addr user password host port hy_service
  local ping_output ping_avg ping_loss
  local result_file curl_meta test_ip connect_s start_s total_s http_code
  local connect_ms start_ms total_ms
  local hy_ok="false" landing_ok="false"

  echo ""
  green "================ 最终连通性测试 ================"

  if [[ ! -s "$config_file" ]]; then
    red "[中转] Hysteria 2 配置不存在：$config_file"
    return 1
  fi

  hy_service=$(get_hysteria_service_name)
  if systemctl is-active --quiet "$hy_service"; then
    green "[中转] Hysteria 2 服务：正常运行"
    hy_ok="true"
  else
    red "[中转] Hysteria 2 服务：未正常运行"
  fi

  if ! grep -qE '^outbounds:[[:space:]]*$' "$config_file"; then
    yellow "[中转] 当前模式：日本本机直连，未配置 SOCKS5 落地。"
    return 1
  fi

  addr=$(awk '/^outbounds:/{f=1;next} f && /addr:/{sub(/^[[:space:]]*addr:[[:space:]]*/, ""); gsub(/^"|"$/, ""); print; exit}' "$config_file")
  user=$(awk '/^outbounds:/{f=1;next} f && /username:/{sub(/^[[:space:]]*username:[[:space:]]*/, ""); gsub(/^"|"$/, ""); print; exit}' "$config_file")
  password=$(awk '/^outbounds:/{f=1;next} f && /password:/{sub(/^[[:space:]]*password:[[:space:]]*/, ""); gsub(/^"|"$/, ""); print; exit}' "$config_file")

  if [[ ! "$addr" =~ ^\[([^]]+)\]:([0-9]+)$ ]]; then
    red "[中转] 无法解析 SOCKS5 地址：$addr"
    return 1
  fi

  host="${BASH_REMATCH[1]}"
  port="${BASH_REMATCH[2]}"

  yellow "[中转] 日本 -> 落地 IPv6：$host"
  yellow "[落地] SOCKS5：[$host]:$port"

  if command -v ping >/dev/null 2>&1; then
    ping_output=$(ping -6 -c 4 -W 2 "$host" 2>/dev/null || true)
    ping_avg=$(printf '%s\n' "$ping_output" | awk -F'=' '/rtt min|round-trip min/ {gsub(/ ms/,"",$2); gsub(/ /,"",$2); split($2,a,"/"); print a[2]; exit}')
    ping_loss=$(printf '%s\n' "$ping_output" | awk -F',' '/packet loss/ {for(i=1;i<=NF;i++) if($i ~ /packet loss/) {gsub(/^[[:space:]]+|[[:space:]]+$/,"",$i); print $i; exit}}')
    if [[ -n "$ping_avg" ]]; then
      green "[中转] IPv6 Ping：正常，平均 RTT ${ping_avg} ms${ping_loss:+，$ping_loss}"
    else
      yellow "[中转] IPv6 Ping：无响应（可能禁 ICMP），继续进行 SOCKS5 实际连接测试。"
    fi
  else
    yellow "[中转] 系统未安装 ping，跳过 ICMP 延迟测试。"
  fi

  result_file=$(mktemp /tmp/hy2-relay-test.XXXXXX)
  curl_meta=$(curl -fsS --connect-timeout 6 --max-time 20 \
    --proxy "socks5h://[$host]:$port" \
    --proxy-user "$user:$password" \
    -o "$result_file" \
    -w '%{time_connect}|%{time_starttransfer}|%{time_total}|%{http_code}' \
    https://api.ipify.org 2>/dev/null || true)
  test_ip=$(tr -d '\r\n ' < "$result_file" 2>/dev/null || true)

  if [[ -z "$test_ip" ]]; then
    : > "$result_file"
    curl_meta=$(curl -fsS --connect-timeout 6 --max-time 20 \
      --proxy "socks5h://[$host]:$port" \
      --proxy-user "$user:$password" \
      -o "$result_file" \
      -w '%{time_connect}|%{time_starttransfer}|%{time_total}|%{http_code}' \
      https://ip.sb 2>/dev/null || true)
    test_ip=$(tr -d '\r\n ' < "$result_file" 2>/dev/null || true)
  fi
  rm -f "$result_file" >/dev/null 2>&1 || true

  IFS='|' read -r connect_s start_s total_s http_code <<< "$curl_meta"
  if [[ "$connect_s" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    connect_ms=$(awk -v v="$connect_s" 'BEGIN {printf "%.1f", v*1000}')
  fi
  if [[ "$start_s" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    start_ms=$(awk -v v="$start_s" 'BEGIN {printf "%.1f", v*1000}')
  fi
  if [[ "$total_s" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    total_ms=$(awk -v v="$total_s" 'BEGIN {printf "%.1f", v*1000}')
  fi

  if [[ -n "$test_ip" ]]; then
    green "[中转] SOCKS5 连接：正常"
    [[ -n "$connect_ms" ]] && green "[中转] 日本 -> 落地 TCP 建连耗时：约 ${connect_ms} ms"
    [[ -n "$start_ms" ]] && yellow "[链路] 经落地到公网首包耗时：约 ${start_ms} ms"
    [[ -n "$total_ms" ]] && yellow "[链路] 本次公网请求总耗时：约 ${total_ms} ms"

    if is_valid_ipv4 "$test_ip"; then
      green "[落地] IPv4 出口：$test_ip（正常）"
      landing_ok="true"
    else
      red "[落地] 出口返回：$test_ip（不是 IPv4）"
      yellow "请检查 Xray Freedom 出站是否仍为 ForceIPv4。"
    fi
  else
    red "[中转] SOCKS5 实际连接：失败"
    yellow "请检查落地机 IPv6、SOCKS5 服务、端口、用户名/密码及安全组。"
  fi

  echo " ---------------------------------------------------"
  if [[ "$hy_ok" == "true" && "$landing_ok" == "true" ]]; then
    green "最终结果：中转正常，落地正常，IPv4 出口正常。"
    green "链路：用户 -> 日本 Hy2 -> IPv6 SOCKS5 -> 落地机 -> IPv4 Internet"
    return 0
  fi

  red "最终结果：链路存在异常，请根据上方失败项检查。"
  return 1
}

# -----------------------------
# 函数：从中转菜单手动执行连通性测试
# -----------------------------
test_hy2_relay_connectivity_menu() {
  clear
  run_hy2_relay_connectivity_test || true
  echo ""
  read -erp "回车返回菜单..." _
}

# -----------------------------
# 函数：配置现有 Hysteria 2 使用固定 IPv6 SOCKS5 落地
# -----------------------------
configure_hy2_relay_fixed() {
  local config_file="/etc/hysteria/config.yaml"
  local exit_host exit_port exit_user exit_password exit_addr
  local backup_file hy_service test_ip continue_anyway

  if [[ ! -s "$config_file" ]]; then
    red "未检测到 Hysteria 2 配置：$config_file"
    yellow "请先使用菜单 1 安装 Hy2，再执行中转配置。"
    read -erp "回车返回菜单..." _
    return 1
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    green "安装配置写入依赖 python3"
    pkg_install python3 >/dev/null 2>&1 || {
      red "安装 python3 失败。"
      read -erp "回车返回菜单..." _
      return 1
    }
  fi

  clear
  green "Hysteria 2 固定中转配置"
  echo ""
  yellow "链路：用户 -> 日本 Hy2 -> IPv6 SOCKS5 -> 落地机 -> IPv4 Internet"
  yellow "说明：该模式为固定出口；落地机故障时不会自动切回日本 IPv4。"
  yellow "需要恢复日本直连时，请回到“中转配置”菜单选择“恢复日本直连”。"
  echo ""

  while true; do
    read_confirmed exit_host "请输入落地机公网 IPv6（不带 [] 和端口）: " || return 1
    exit_host="${exit_host#[}"
    exit_host="${exit_host%]}"
    is_valid_ipv6 "$exit_host" && break
    red "IPv6 地址格式无效，请重新输入。"
  done

  while true; do
    read_confirmed exit_port "请输入 SOCKS5 端口（回车默认 1080）: " "1080" || return 1
    if [[ "$exit_port" =~ ^[0-9]+$ ]] && ((exit_port >= 1 && exit_port <= 65535)); then
      break
    fi
    red "端口必须是 1-65535 之间的数字。"
  done

  while true; do
    read_confirmed exit_user "请输入 SOCKS5 用户名（回车默认 hy2relay）: " "hy2relay" || return 1
    [[ "$exit_user" =~ ^[A-Za-z0-9._~-]+$ ]] && break
    red "用户名仅支持字母、数字和 . _ ~ -"
  done

  while true; do
    read_required_password exit_password "请输入落地机 SOCKS5 密码: " && break
  done

  exit_addr="[$exit_host]:$exit_port"

  echo ""
  green "正在测试日本机 -> 落地机 IPv6 SOCKS5..."
  if ping -6 -c 2 -W 2 "$exit_host" >/dev/null 2>&1; then
    green "IPv6 基础连通：正常"
  else
    yellow "IPv6 Ping 未响应（可能是 ICMP 被禁），继续测试 SOCKS5。"
  fi

  test_ip=$(test_socks5_landing "$exit_host" "$exit_port" "$exit_user" "$exit_password" || true)
  if [[ -n "$test_ip" ]]; then
    green "SOCKS5 连接测试：成功"
    if is_valid_ipv4 "$test_ip"; then
      green "落地出口测试：$test_ip（IPv4，符合预期）"
    else
      yellow "落地出口测试返回：$test_ip"
      yellow "未识别为 IPv4，请确认落地机是否已强制 IPv4 出口。"
    fi
  else
    red "SOCKS5 连接测试失败。"
    yellow "请检查落地机 IPv6、端口、用户名、密码及安全组/防火墙。"
    while true; do
      read_confirmed continue_anyway "仍然写入固定中转配置吗？[y/N]（回车默认 N）: " "N" || return 1
      case "$continue_anyway" in
        y|Y) break ;;
        n|N) yellow "已取消，中转配置未修改。"; read -erp "回车返回菜单..." _; return 1 ;;
        *) red "请输入 y 或 n。" ;;
      esac
    done
  fi

  backup_file="${config_file}.bak.relay.$(date +%Y%m%d%H%M%S)"
  cp -a "$config_file" "$backup_file" || {
    red "备份 Hysteria 2 配置失败。"
    read -erp "回车返回菜单..." _
    return 1
  }

  if ! python3 - "$config_file" "$exit_addr" "$exit_user" "$exit_password" <<'PYC'
from pathlib import Path
import json
import re
import sys

path = Path(sys.argv[1])
addr, username, password = sys.argv[2:5]
lines = path.read_text().splitlines(keepends=True)

start = None
end = None
for index, line in enumerate(lines):
    if re.match(r'^outbounds:\s*(?:#.*)?$', line.rstrip('\r\n')):
        start = index
        for next_index in range(index + 1, len(lines)):
            candidate = lines[next_index]
            if candidate.strip() and not candidate.startswith((' ', '\t', '#')):
                end = next_index
                break
        if end is None:
            end = len(lines)
        break

if start is not None:
    del lines[start:end]

content = ''.join(lines).rstrip() + '\n\n'
content += (
    'outbounds:\n'
    '  - name: landing\n'
    '    type: socks5\n'
    '    socks5:\n'
    f'      addr: {json.dumps(addr)}\n'
    f'      username: {json.dumps(username)}\n'
    f'      password: {json.dumps(password)}\n'
)
path.write_text(content)
PYC
  then
    cp -a "$backup_file" "$config_file" >/dev/null 2>&1 || true
    red "写入中转配置失败，已恢复原配置。"
    read -erp "回车返回菜单..." _
    return 1
  fi

  fix_hysteria_file_perms
  hy_service=$(get_hysteria_service_name)
  systemctl restart "$hy_service" >/dev/null 2>&1

  if ! systemctl is-active --quiet "$hy_service"; then
    cp -a "$backup_file" "$config_file" >/dev/null 2>&1 || true
    fix_hysteria_file_perms
    systemctl restart "$hy_service" >/dev/null 2>&1 || true
    red "中转配置启动失败，已恢复修改前配置。"
    yellow "请检查：journalctl -u $hy_service -n 50 --no-pager"
    read -erp "回车返回菜单..." _
    return 1
  fi

  red "======================================================================================"
  green "Hysteria 2 固定中转配置完成"
  yellow "中转方式：Hy2 -> IPv6 SOCKS5 -> 落地 IPv4"
  yellow "SOCKS5 地址：$exit_addr"
  yellow "SOCKS5 用户名：$exit_user"
  yellow "SOCKS5 密码：$exit_password"
  [[ -n "$test_ip" ]] && yellow "测试出口 IPv4：$test_ip"
  yellow "配置备份：$backup_file"
  echo ""
  green "当前所有 Hy2 代理流量将固定通过该 SOCKS5 落地机。"
  echo ""
  green "开始执行最终连通性测试..."
  run_hy2_relay_connectivity_test || true
  echo ""
  yellow "落地机不可用时，请在菜单 12 -> 2 手动恢复日本直连。"
  yellow "需要重新检测时，请在菜单 12 -> 4 执行连通性测试。"
  read -erp "回车返回菜单..." _
}

# -----------------------------
# 函数：恢复 Hysteria 2 日本本机直连
# -----------------------------
restore_hy2_direct() {
  local config_file="/etc/hysteria/config.yaml"
  local backup_file hy_service answer

  if [[ ! -s "$config_file" ]]; then
    red "未检测到 Hysteria 2 配置：$config_file"
    read -erp "回车返回菜单..." _
    return 1
  fi

  if ! grep -qE '^outbounds:[[:space:]]*$' "$config_file"; then
    green "当前未配置自定义 outbound，已经是日本本机直连模式。"
    read -erp "回车返回菜单..." _
    return 0
  fi

  while true; do
    read_confirmed answer "确认取消落地机并恢复日本本机直连？[y/N]（回车默认 N）: " "N" || return 1
    case "$answer" in
      y|Y) break ;;
      n|N) yellow "已取消。"; read -erp "回车返回菜单..." _; return 0 ;;
      *) red "请输入 y 或 n。" ;;
    esac
  done

  command -v python3 >/dev/null 2>&1 || pkg_install python3 >/dev/null 2>&1 || {
    red "安装 python3 失败。"
    read -erp "回车返回菜单..." _
    return 1
  }

  backup_file="${config_file}.bak.direct.$(date +%Y%m%d%H%M%S)"
  cp -a "$config_file" "$backup_file" || return 1

  if ! remove_hy2_outbounds_block "$config_file"; then
    cp -a "$backup_file" "$config_file" >/dev/null 2>&1 || true
    red "恢复直连配置失败。"
    read -erp "回车返回菜单..." _
    return 1
  fi

  fix_hysteria_file_perms
  hy_service=$(get_hysteria_service_name)
  systemctl restart "$hy_service" >/dev/null 2>&1
  if ! systemctl is-active --quiet "$hy_service"; then
    cp -a "$backup_file" "$config_file" >/dev/null 2>&1 || true
    systemctl restart "$hy_service" >/dev/null 2>&1 || true
    red "恢复直连后 Hy2 启动失败，已回滚。"
    read -erp "回车返回菜单..." _
    return 1
  fi

  green "已恢复：用户 -> 日本 Hy2 -> 日本本机 Internet"
  yellow "原中转配置备份：$backup_file"
  read -erp "回车返回菜单..." _
}

# -----------------------------
# 函数：查看 Hysteria 2 当前中转状态
# -----------------------------
show_hy2_relay() {
  local config_file="/etc/hysteria/config.yaml"
  local addr user password test_ip host port

  if [[ ! -s "$config_file" ]]; then
    red "未检测到 Hysteria 2 配置：$config_file"
    read -erp "回车返回菜单..." _
    return 1
  fi

  if ! grep -qE '^outbounds:[[:space:]]*$' "$config_file"; then
    green "当前模式：日本本机直连"
    read -erp "回车返回菜单..." _
    return 0
  fi

  addr=$(awk '/^outbounds:/{f=1;next} f && /addr:/{sub(/^[[:space:]]*addr:[[:space:]]*/, ""); gsub(/^"|"$/, ""); print; exit}' "$config_file")
  user=$(awk '/^outbounds:/{f=1;next} f && /username:/{sub(/^[[:space:]]*username:[[:space:]]*/, ""); gsub(/^"|"$/, ""); print; exit}' "$config_file")
  password=$(awk '/^outbounds:/{f=1;next} f && /password:/{sub(/^[[:space:]]*password:[[:space:]]*/, ""); gsub(/^"|"$/, ""); print; exit}' "$config_file")

  yellow "当前模式：固定 SOCKS5 落地"
  yellow "SOCKS5 地址：$addr"
  yellow "SOCKS5 用户名：$user"
  yellow "SOCKS5 密码：$password"

  if [[ "$addr" =~ ^\[([^]]+)\]:([0-9]+)$ ]]; then
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
    test_ip=$(test_socks5_landing "$host" "$port" "$user" "$password" || true)
    if [[ -n "$test_ip" ]]; then
      green "实时连通测试：正常，当前落地出口 $test_ip"
    else
      red "实时连通测试：失败"
    fi
  fi

  read -erp "回车返回菜单..." _
}

# -----------------------------
# 函数：Hysteria 2 中转配置菜单
# -----------------------------
menu_hy2_relay() {
  local relayAnswer
  while true; do
    clear
    green "Hy2 中转配置："
    echo ""
    echo -e " ${GREEN}1.${tianlan} 配置/更换 IPv6 SOCKS5 落地"
    echo -e " ${GREEN}2.${tianlan} 恢复日本本机直连"
    echo -e " ${GREEN}3.${tianlan} 查看当前中转状态"
    echo -e " ${GREEN}4.${tianlan} 中转/落地连通性测试"
    echo " ---------------------------------------------------"
    echo -e " ${GREEN}0.${PLAIN} 返回"
    echo ""
    read -erp "请选择 [0-4]: " relayAnswer

    case "$relayAnswer" in
      1) configure_hy2_relay_fixed ;;
      2) restore_hy2_direct ;;
      3) show_hy2_relay ;;
      4) test_hy2_relay_connectivity_menu ;;
      0) break ;;
      *) yellow "无效选项"; sleep 1 ;;
    esac
  done
}

# -----------------------------
# 函数：配置 Xray SOCKS5 IPv6 落地机（IPv4 出口）
# -----------------------------
install_xray_socks5_exit() {
  local relay_ipv6 landing_ipv6 detected_ipv6 socks_port socks_user socks_password
  local install_script="/tmp/xray-install.sh"
  local xray_bin config_dir config_file service_file current_port
  local exit_ipv4 test_ip backup_file old_sing_service answer

  clear
  green "Xray SOCKS5 落地配置"
  echo ""
  yellow "链路：日本中转机 --IPv6--> 本机 Xray SOCKS5 --IPv4--> Internet"
  yellow "SOCKS5 本身不加密，仅允许指定日本中转机 IPv6 访问。"
  echo ""

  detected_ipv6=$(get_public_ipv6 2>/dev/null || true)
  if [[ -z "$detected_ipv6" ]]; then
    red "未检测到可用公网 IPv6。"
    yellow "该落地模式要求落地机具有公网 IPv6。"
    read -erp "回车返回菜单..." _
    return 1
  fi

  while true; do
    read_confirmed landing_ipv6 "请输入本机公网 IPv6（回车默认 $detected_ipv6）: " "$detected_ipv6" || return 1
    landing_ipv6="${landing_ipv6#[}"
    landing_ipv6="${landing_ipv6%]}"
    is_valid_ipv6 "$landing_ipv6" && break
    red "IPv6 地址格式无效，请重新输入。"
  done

  while true; do
    read_confirmed relay_ipv6 "请输入日本中转机公网 IPv6（用于防火墙白名单）: " || return 1
    relay_ipv6="${relay_ipv6#[}"
    relay_ipv6="${relay_ipv6%]}"
    is_valid_ipv6 "$relay_ipv6" && break
    red "IPv6 地址格式无效，请重新输入。"
  done

  config_dir="/etc/xray-socks5-exit"
  config_file="$config_dir/config.json"
  service_file="/etc/systemd/system/xray-socks5-exit.service"
  current_port=""
  [[ -f "$config_file" ]] && current_port=$(grep -m1 '"port"[[:space:]]*:' "$config_file" | grep -Eo '[0-9]+' | head -n1)

  while true; do
    read_confirmed socks_port "请输入 SOCKS5 监听端口（回车默认 1080）: " "${current_port:-1080}" || return 1
    if [[ "$socks_port" =~ ^[0-9]+$ ]] && ((socks_port >= 1 && socks_port <= 65535)); then
      if ss -lntup 2>/dev/null | grep -Eq ":${socks_port}([^0-9]|$)" && [[ "$socks_port" != "$current_port" ]]; then
        red "端口 $socks_port 已被其他程序占用，请更换。"
        continue
      fi
      break
    fi
    red "端口必须是 1-65535 之间的数字。"
  done

  while true; do
    read_confirmed socks_user "请输入 SOCKS5 用户名（回车默认 hy2relay）: " "hy2relay" || return 1
    [[ "$socks_user" =~ ^[A-Za-z0-9._~-]+$ ]] && break
    red "用户名仅支持字母、数字和 . _ ~ -"
  done

  read_confirmed_password socks_password "请输入 SOCKS5 密码（回车随机）: " || return 1

  echo ""
  yellow "即将配置："
  yellow "落地 IPv6：$landing_ipv6"
  yellow "允许中转 IPv6：$relay_ipv6"
  yellow "SOCKS5：[$landing_ipv6]:$socks_port"
  yellow "用户名：$socks_user"
  yellow "密码：$socks_password"
  yellow "出口：强制 IPv4"
  echo ""

  while true; do
    read_confirmed answer "确认继续？[Y/n]（回车默认 Y）: " "Y" || return 1
    case "$answer" in
      y|Y) break ;;
      n|N) yellow "已取消。"; read -erp "回车返回菜单..." _; return 0 ;;
      *) red "请输入 y 或 n。" ;;
    esac
  done

  green "安装基础依赖"
  pkg_install curl ca-certificates unzip iptables >/dev/null 2>&1 || {
    red "安装基础依赖失败。"
    read -erp "回车返回菜单..." _
    return 1
  }

  # 兼容旧版脚本：如果曾安装过本脚本专用的 sing-box 落地服务，仅停止并删除该专用 service/config。
  # 不卸载 sing-box 二进制，避免影响用户其它用途。
  if systemctl list-unit-files 2>/dev/null | grep -q '^sing-box-socks5\.service'; then
    yellow "检测到旧版 sing-box-socks5 落地服务，正在迁移到 Xray..."
    systemctl disable --now sing-box-socks5.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/sing-box-socks5.service /etc/sing-box/socks5-exit.json >/dev/null 2>&1 || true
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi

  xray_bin=$(get_xray_bin 2>/dev/null || true)
  if [[ -z "$xray_bin" ]]; then
    green "未检测到 Xray，使用 XTLS 官方安装脚本安装 Xray-core"
    download_with_retry "https://github.com/XTLS/Xray-install/raw/main/install-release.sh" "$install_script" || {
      red "下载 Xray 官方安装脚本失败。"
      read -erp "回车返回菜单..." _
      return 1
    }

    bash "$install_script" install -u root --without-geodata --without-logfiles || {
      rm -f "$install_script" >/dev/null 2>&1 || true
      red "Xray-core 安装失败。"
      read -erp "回车返回菜单..." _
      return 1
    }
    rm -f "$install_script" >/dev/null 2>&1 || true

    # 官方安装会创建默认 xray.service。本脚本使用独立的 xray-socks5-exit.service，避免混用配置。
    systemctl disable --now xray.service >/dev/null 2>&1 || true
    xray_bin=$(get_xray_bin 2>/dev/null || true)
  else
    green "检测到现有 Xray-core：$xray_bin，将复用内核，不修改已有 xray.service 配置。"
  fi

  if [[ -z "$xray_bin" || ! -x "$xray_bin" ]]; then
    red "未检测到可用 Xray-core。"
    read -erp "回车返回菜单..." _
    return 1
  fi

  mkdir -p "$config_dir"
  if [[ -f "$config_file" ]]; then
    backup_file="${config_file}.bak.$(date +%Y%m%d%H%M%S)"
    cp -a "$config_file" "$backup_file" >/dev/null 2>&1 || true
  fi

  cat > "$config_file" <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "socks6-in",
      "listen": "::",
      "port": $socks_port,
      "protocol": "socks",
      "settings": {
        "auth": "password",
        "accounts": [
          {
            "user": "$socks_user",
            "pass": "$socks_password"
          }
        ],
        "udp": true,
        "ip": "$landing_ipv6"
      },
      "streamSettings": {
        "sockopt": {
          "V6Only": true
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct4",
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "ForceIPv4"
      },
      "streamSettings": {
        "sockopt": {
          "domainStrategy": "ForceIPv4"
        }
      }
    },
    {
      "tag": "block6",
      "protocol": "blackhole",
      "settings": {}
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": ["::/0"],
        "outboundTag": "block6"
      }
    ]
  }
}
EOF

  chmod 700 "$config_dir" >/dev/null 2>&1 || true
  chmod 600 "$config_file" >/dev/null 2>&1 || true

  if ! "$xray_bin" run -test -config "$config_file" >/dev/null 2>&1; then
    red "Xray SOCKS5 配置校验失败。"
    "$xray_bin" run -test -config "$config_file" || true
    if [[ -n "$backup_file" && -f "$backup_file" ]]; then
      cp -a "$backup_file" "$config_file" >/dev/null 2>&1 || true
    fi
    read -erp "回车返回菜单..." _
    return 1
  fi

  cat > "$service_file" <<EOF
[Unit]
Description=Xray IPv6 SOCKS5 landing -> IPv4 exit
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$xray_bin run -config $config_file
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  chmod 644 "$service_file" >/dev/null 2>&1 || true
  systemctl daemon-reload
  systemctl enable xray-socks5-exit.service >/dev/null 2>&1 || true
  systemctl restart xray-socks5-exit.service >/dev/null 2>&1

  if ! systemctl is-active --quiet xray-socks5-exit.service; then
    red "Xray SOCKS5 落地服务启动失败，请检查："
    systemctl status xray-socks5-exit.service --no-pager -l || true
    journalctl -u xray-socks5-exit.service --no-pager -n 40 || true
    read -erp "回车返回菜单..." _
    return 1
  fi

  green "配置 IPv6 防火墙白名单"
  install_firewall_persistent >/dev/null 2>&1 || true
  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -N XRAY_SOCKS5_INPUT >/dev/null 2>&1 || true
    ip6tables -F XRAY_SOCKS5_INPUT >/dev/null 2>&1 || true
    ip6tables -C INPUT -j XRAY_SOCKS5_INPUT >/dev/null 2>&1 || ip6tables -I INPUT 1 -j XRAY_SOCKS5_INPUT >/dev/null 2>&1 || true
    ip6tables -A XRAY_SOCKS5_INPUT -i lo -p tcp --dport "$socks_port" -j ACCEPT >/dev/null 2>&1 || true
    ip6tables -A XRAY_SOCKS5_INPUT -i lo -p udp --dport "$socks_port" -j ACCEPT >/dev/null 2>&1 || true
    ip6tables -A XRAY_SOCKS5_INPUT -s "$relay_ipv6/128" -p tcp --dport "$socks_port" -j ACCEPT >/dev/null 2>&1 || true
    ip6tables -A XRAY_SOCKS5_INPUT -s "$relay_ipv6/128" -p udp --dport "$socks_port" -j ACCEPT >/dev/null 2>&1 || true
    ip6tables -A XRAY_SOCKS5_INPUT -p tcp --dport "$socks_port" -j DROP >/dev/null 2>&1 || true
    ip6tables -A XRAY_SOCKS5_INPUT -p udp --dport "$socks_port" -j DROP >/dev/null 2>&1 || true
    save_firewall_rules
  else
    red "未检测到 ip6tables，无法写入本机 IPv6 白名单。"
    yellow "请务必在云平台安全组中仅允许 $relay_ipv6/128 访问 TCP/UDP $socks_port。"
  fi

  exit_ipv4=$(curl -4fsS --max-time 8 ip.sb 2>/dev/null | tr -d '\r\n' || true)
  test_ip=$(curl -fsS --connect-timeout 5 --max-time 15 \
    --proxy "socks5h://[::1]:$socks_port" \
    --proxy-user "$socks_user:$socks_password" \
    https://api.ipify.org 2>/dev/null | tr -d '\r\n' || true)

  red "======================================================================================"
  green "Xray SOCKS5 落地配置完成"
  yellow "落地机 IPv6：$landing_ipv6"
  yellow "SOCKS5 地址：[$landing_ipv6]:$socks_port"
  yellow "SOCKS5 用户名：$socks_user"
  yellow "SOCKS5 密码：$socks_password"
  yellow "允许连接的日本中转机 IPv6：$relay_ipv6"
  yellow "入站协议：SOCKS5 TCP + UDP，仅 IPv6"
  yellow "Internet 出口：强制 IPv4"
  [[ -n "$exit_ipv4" ]] && yellow "本机公网 IPv4：$exit_ipv4"
  if is_valid_ipv4 "$test_ip"; then
    green "SOCKS5 实际出口测试：$test_ip（IPv4，正常）"
  elif [[ -n "$test_ip" ]]; then
    yellow "SOCKS5 实际出口测试返回：$test_ip"
  else
    yellow "SOCKS5 本机出口测试未返回结果，请稍后手动测试。"
  fi
  echo ""
  green "请在日本中转机的“中转配置 -> 配置/更换 IPv6 SOCKS5 落地”中填写："
  green "落地 IPv6：$landing_ipv6"
  green "端口：$socks_port"
  green "用户名：$socks_user"
  green "密码：$socks_password"
  echo ""
  yellow "云平台安全组建议：仅允许来源 $relay_ipv6/128 访问 TCP $socks_port 和 UDP $socks_port。"
  yellow "配置文件：$config_file"
  yellow "服务：xray-socks5-exit.service"
  read -erp "回车返回菜单..." _
}

# -----------------------------
# 函数：查看/管理落地配置
# -----------------------------
menu_landing() {
  local landingAnswer
  while true; do
    clear
    green "落地配置："
    echo ""
    echo -e " ${GREEN}1.${tianlan} 安装/重新配置 Xray SOCKS5 落地"
    echo -e " ${GREEN}2.${tianlan} 查看落地服务状态"
    echo -e " ${GREEN}3.${tianlan} 重启落地服务"
    echo " ---------------------------------------------------"
    echo -e " ${GREEN}0.${PLAIN} 返回"
    echo ""
    read -erp "请选择 [0-3]: " landingAnswer

    case "$landingAnswer" in
      1) install_xray_socks5_exit ;;
      2)
        systemctl status xray-socks5-exit.service --no-pager -l 2>/dev/null || yellow "尚未安装 xray-socks5-exit.service"
        read -erp "回车返回菜单..." _
        ;;
      3)
        if systemctl restart xray-socks5-exit.service >/dev/null 2>&1; then
          green "落地服务已重启。"
        else
          red "落地服务重启失败或尚未安装。"
        fi
        read -erp "回车返回菜单..." _
        ;;
      0) break ;;
      *) yellow "无效选项"; sleep 1 ;;
    esac
  done
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
    echo -e " ${GREEN}8.${tianlan} 回程测试"
    echo -e " ${GREEN}9.${tianlan} IP质量检测"
    echo -e " ${GREEN}10.${tianlan} 系统查询"
    echo -e " ${GREEN}11.${tianlan} 系统更新"
    echo -e " ${GREEN}12.${tianlan} 中转配置"
    echo -e " ${GREEN}13.${tianlan} 落地配置"
    echo " ---------------------------------------------------"
    echo -e " ${GREEN}0.${PLAIN} 退出脚本"
    echo ""
    read -erp "请输入选项 [0-13]: " menuInput

    case $menuInput in
      1) insthysteria ;;
      2) unsthysteria ;;
      3) restarthy2 ;;
      4) menu_hy_conf ;;
      5) run_sys_conf ;;
      6) showconf ;;
      7) showstatus ;;
      8) besttrace ;;
      9) ipquality ;;
      10) linux_ps ;;
      11) linux_update ;;
      12) menu_hy2_relay ;;
      13) menu_landing ;;
      0) break ;;
      *) yellow "无效选项"; sleep 1 ;;
    esac
  done
}

need_root
detect_os
ensure_curl
menu
