#!/usr/bin/env bash
# ============================================================
# Reality 管理脚本
# ============================================================

set -Eeuo pipefail

# -----------------------------
#  颜色/常量
# -----------------------------
red='\033[31m'
green='\033[32m'
yellow='\033[33m'
magenta='\033[35m'
cyan='\033[36m'
none='\033[0m'
bold='\033[1m'
dim='\033[2m'
gray='\033[90m'

CONFIG="/etc/sing-box/config.json"
SERVICE="sing-box"
INFO_FILE="$HOME/_singbox_vless_reality_url_"
CACHE_FILE="/etc/sing-box/.config_cache"
REALITY_PUB_FILE="/etc/sing-box/.reality_pub"
PROTOCOL_FILE="/etc/sing-box/.protocols"
SOURCES_LIST="/etc/apt/sources.list"
SOURCES_BAK="/etc/apt/sources.list.bak.xray_reality"
# 与你原来打印保持一致（可自行改）
FLOW="xtls-rprx-vision"
ENCRYPTION="none"
NETWORK="tcp"
HEADER_TYPE="none"
TLS_MODE="reality"
FINGERPRINT="chrome"
SPIDERX=""

# -----------------------------
#  通用函数
# -----------------------------
error() { echo -e "\n${red}输入错误!${none}\n"; }
warn() { echo -e "\n${yellow}$1${none}\n"; }
ok() { echo -e "${green}$1${none}"; }
pause() {
  read -rsp "$(echo -e "按 ${green}Enter${none} 继续.... 或 ${red}Ctrl+C${none} 取消")" -d $'\n'
  echo
}
on_err() {
  echo -e "\n${red}脚本出错：${none}第 ${yellow}${BASH_LINENO[0]}${none} 行：${cyan}${BASH_COMMAND}${none}\n"
}
trap on_err ERR
need_root() {
  if [[ $EUID -ne 0 ]]; then
    warn "请使用 root 运行：sudo bash $0"
    exit 1
  fi
}
need_cmd() { command -v "$1" >/dev/null 2>&1 || { warn "缺少命令：$1"; return 1; }; }

# -----------------------------
#  强制从 /dev/tty 读取交互输入
# -----------------------------
read_tty() {
  local prompt="$1"
  local __varname="$2"
  local _line=""
  printf "%s" "$prompt" > /dev/tty
  IFS= read -r _line < /dev/tty
  printf -v "$__varname" "%s" "$_line"
}

# ============================================================
#  Sing-box / 系统检测 / 版本检测
# ============================================================
detect_os() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_ID="${ID:-}"
    OS_ID_LIKE="${ID_LIKE:-}"
  else
    OS_ID=""
    OS_ID_LIKE=""
  fi

  if echo "$OS_ID $OS_ID_LIKE" | grep -qi "alpine"; then
    OS="alpine"
  elif echo "$OS_ID $OS_ID_LIKE" | grep -Eqi "debian|ubuntu"; then
    OS="debian"
  elif echo "$OS_ID $OS_ID_LIKE" | grep -Eqi "centos|rhel|fedora"; then
    OS="redhat"
  else
    OS="unknown"
  fi
}

detect_os

get_current_singbox_version() {
  local cur_raw="" cur_ver=""
  if command -v sing-box >/dev/null 2>&1; then
    cur_raw="$(sing-box version 2>/dev/null | head -n1 || true)"
    cur_ver="$(echo "$cur_raw" | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
    [[ -n "$cur_ver" && "$cur_ver" != v* ]] && cur_ver="v${cur_ver}"
    [[ -n "$cur_ver" ]] && { echo "$cur_ver"; return 0; }
  fi
  return 1
}

get_latest_singbox_version() {
  local tag=""
  tag="$(curl -fsSL "https://api.github.com/repos/SagerNet/sing-box/releases/latest" 2>/dev/null | jq -r '.tag_name // empty' 2>/dev/null || true)"
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  echo "$tag"
}

show_singbox_version_hint() {
  local cur="未安装" latest="获取失败"
  cur="$(get_current_singbox_version 2>/dev/null || echo '未安装')"
  latest="$(get_latest_singbox_version 2>/dev/null || echo '获取失败')"
  echo -e "${yellow}当前版本：${cyan}${cur}${none}"
  echo -e "${yellow}GitHub 最新：${cyan}${latest}${none}"
}

install_base_deps() {
  case "$OS" in
    alpine)
      apk update || { warn "apk update 失败"; return 1; }
      apk add --no-cache bash curl ca-certificates openssl openrc jq wget sudo qrencode net-tools lsof xxd || return 1
      ;;
    debian)
      if declare -F apt_update_safe >/dev/null 2>&1; then
        apt_update_safe || return 1
        apt_install_safe curl wget sudo jq net-tools lsof qrencode openssl xxd ca-certificates || return 1
      else
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y || return 1
        apt-get install -y curl wget sudo jq net-tools lsof qrencode openssl xxd ca-certificates || return 1
      fi
      ;;
    redhat)
      yum install -y curl wget sudo jq net-tools lsof qrencode openssl which xxd ca-certificates || return 1
      ;;
    *)
      warn "未识别系统，尝试继续。"
      ;;
  esac
}

service_start() {
  case "$OS" in
    alpine) rc-service "$SERVICE" start ;;
    *) systemctl start "$SERVICE" ;;
  esac
}
service_stop() {
  case "$OS" in
    alpine) rc-service "$SERVICE" stop ;;
    *) systemctl stop "$SERVICE" ;;
  esac
}
service_restart() {
  case "$OS" in
    alpine) rc-service "$SERVICE" restart ;;
    *) systemctl daemon-reload >/dev/null 2>&1 || true; systemctl restart "$SERVICE" ;;
  esac
}
service_status() {
  case "$OS" in
    alpine) rc-service "$SERVICE" status ;;
    *) systemctl status "$SERVICE" --no-pager -l ;;
  esac
}

install_or_update_singbox_backend() {
  local mode="${1:-install}"
  detect_os
  install_base_deps || return 1

  case "$OS" in
    alpine)
      if [[ "$mode" == "update" ]]; then
        apk update && apk upgrade sing-box || apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community sing-box || return 1
      else
        apk update || return 1
        apk add --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community sing-box || return 1
      fi
      ;;
    debian|redhat)
      bash <(curl -fsSL https://sing-box.app/install.sh) || return 1
      ;;
    *)
      warn "未支持的系统，无法安装 sing-box"
      return 1
      ;;
  esac

  command -v sing-box >/dev/null 2>&1 || { warn "安装后未找到 sing-box 可执行文件"; return 1; }
}

# -----------------------------
#  随机与校验
# -----------------------------
rand_hex() {
  local n="${1:?}"   # n = bytes
  openssl rand -hex "$n" 2>/dev/null
}

rand_uuid() { cat /proc/sys/kernel/random/uuid; }
rand_shortid() { rand_hex 8; } # 16 hex

is_uuid() { [[ "$1" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; }
is_b64url_key() { [[ "$1" =~ ^[A-Za-z0-9_-]{43}$|^[A-Za-z0-9_-]{44}$ ]]; }

is_shortid() {
  local s="$1"
  [[ "${#s}" -le 16 ]] || return 1
  (( ${#s} % 2 == 0 )) || return 1
  [[ "${s}" =~ ^[0-9a-fA-F]+$ ]] || return 1
}
is_domain_like() { [[ "$1" =~ ^([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$ ]]; }

# -----------------------------
#  APT（锁等待/加固/镜像轮询）
# -----------------------------
wait_apt_lock() {
  local lock1="/var/lib/dpkg/lock-frontend"
  local lock2="/var/lib/dpkg/lock"
  local lock3="/var/cache/apt/archives/lock"
  local max_wait=300 waited=0
  while fuser "$lock1" "$lock2" "$lock3" >/dev/null 2>&1; do
    sleep 3
    waited=$((waited + 3))
    (( waited < max_wait )) || { warn "[APT] 等待锁超时"; return 1; }
  done
}
write_apt_hardening_conf() {
  mkdir -p /etc/apt/apt.conf.d
  cat >/etc/apt/apt.conf.d/99xray-reality-hardening <<'EOF'
Acquire::Languages "none";
Acquire::Retries "5";
Acquire::http::Timeout "10";
Acquire::https::Timeout "10";
Acquire::CompressionTypes::Order { "gz"; "xz"; };
EOF
}
backup_sources() { [[ -f "$SOURCES_LIST" ]] && cp -f "$SOURCES_LIST" "$SOURCES_BAK"; }
restore_sources(){ [[ -f "$SOURCES_BAK" ]] && cp -f "$SOURCES_BAK" "$SOURCES_LIST"; }
apt_clean_lists() {
  wait_apt_lock
  DEBIAN_FRONTEND=noninteractive apt-get clean || true
  rm -rf /var/lib/apt/lists/*
}
UBUNTU_MIRRORS=(
  "http://archive.ubuntu.com/ubuntu"
  "http://security.ubuntu.com/ubuntu"
  "http://ftp.jaist.ac.jp/pub/Linux/ubuntu"
  "http://ftp.riken.jp/Linux/ubuntu"
  "http://mirrors.edge.kernel.org/ubuntu"
  "http://mirrors.mit.edu/ubuntu"
)
switch_ubuntu_mirror() {
  local new="$1"
  sed -i "s#http://archive.ubuntu.com/ubuntu#${new}#g" "$SOURCES_LIST" || true
  sed -i "s#https://archive.ubuntu.com/ubuntu#${new}#g" "$SOURCES_LIST" || true
  sed -i "s#http://security.ubuntu.com/ubuntu#${new}#g" "$SOURCES_LIST" || true
  sed -i "s#https://security.ubuntu.com/ubuntu#${new}#g" "$SOURCES_LIST" || true
  sed -i "s#http://mirrors.ubuntu.com/ubuntu#${new}#g" "$SOURCES_LIST" || true
  sed -i "s#https://mirrors.ubuntu.com/ubuntu#${new}#g" "$SOURCES_LIST" || true
}
apt_update_safe() {
  wait_apt_lock
  write_apt_hardening_conf
  backup_sources
  local os_id=""
  os_id="$(. /etc/os-release && echo "${ID:-}")"
  if [[ -f "$SOURCES_LIST" ]] && grep -q "mirrors.ubuntu.com/ubuntu" "$SOURCES_LIST"; then
    warn "[APT] 检测到坏源 mirrors.ubuntu.com（会 404），自动修正为 archive.ubuntu.com"
    sed -i "s#http://mirrors.ubuntu.com/ubuntu#http://archive.ubuntu.com/ubuntu#g" "$SOURCES_LIST" || true
    sed -i "s#https://mirrors.ubuntu.com/ubuntu#https://archive.ubuntu.com/ubuntu#g" "$SOURCES_LIST" || true
  fi
  for attempt in 1 2; do
    echo -e "${yellow}[APT] apt-get update（尝试 ${attempt}/2）${none}"
    if DEBIAN_FRONTEND=noninteractive apt-get update; then
      return 0
    fi
    warn "[APT] update 失败：clean + 删除lists 后重试"
    apt_clean_lists
  done
  if [[ "$os_id" == "ubuntu" ]]; then
    warn "[APT] 仍失败：开始轮询可用镜像源（日本/美国）"
    for m in "${UBUNTU_MIRRORS[@]}"; do
      restore_sources
      switch_ubuntu_mirror "$m"
      apt_clean_lists
      echo -e "${yellow}[APT] 切换镜像：${cyan}${m}${none}"
      if DEBIAN_FRONTEND=noninteractive apt-get update; then
        ok "[APT] 镜像可用：$m"
        return 0
      fi
    done
    warn "[APT] 所有镜像尝试失败，恢复原 sources.list"
    restore_sources
    return 1
  fi
  return 1
}
apt_install_safe() { wait_apt_lock; DEBIAN_FRONTEND=noninteractive apt-get -y install "$@"; }

# -----------------------------
#  更新内核
# -----------------------------
update_xray_reality() {
  echo -e "${yellow}开始更新 sing-box VLESS Reality...${none}"
  show_singbox_version_hint
  if ! install_or_update_singbox_backend update; then
    warn "sing-box 更新失败。"
    return 1
  fi
  echo
  show_singbox_version_hint
  ok "sing-box 更新完成。"
}

# -----------------------------
#  获取公网 IP
# -----------------------------
get_public_ips() {
  IPv4=""
  IPv6=""

  IPv4="$(curl -4s --max-time 5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null \
        | awk -F= '/^ip=/{print $2; exit}' || true)"

  IPv6="$(curl -6s --max-time 5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null \
        | awk -F= '/^ip=/{print $2; exit}' || true)"
}


# -----------------------------
#  读取配置（sing-box VLESS Reality）
# -----------------------------
read_current_config() {
  port=""; uuid=""; private_key=""; public_key=""; shortid=""; domain=""; custom_ip=""; node_suffix=""
  [[ -f "$CONFIG" ]] || return 1
  need_cmd jq >/dev/null 2>&1 || return 1

  port="$(jq -r '.inbounds[] | select(.type=="vless" and .tls.reality.enabled==true) | .listen_port // empty' "$CONFIG" | head -n1)"
  uuid="$(jq -r '.inbounds[] | select(.type=="vless" and .tls.reality.enabled==true) | .users[0].uuid // empty' "$CONFIG" | head -n1)"
  private_key="$(jq -r '.inbounds[] | select(.type=="vless" and .tls.reality.enabled==true) | .tls.reality.private_key // empty' "$CONFIG" | head -n1)"
  shortid="$(jq -r '.inbounds[] | select(.type=="vless" and .tls.reality.enabled==true) | .tls.reality.short_id[0] // empty' "$CONFIG" | head -n1)"
  domain="$(jq -r '.inbounds[] | select(.type=="vless" and .tls.reality.enabled==true) | .tls.server_name // empty' "$CONFIG" | head -n1)"
  if [[ -f "$REALITY_PUB_FILE" ]]; then
    public_key="$(tr -d $'\r\n[:space:]' < "$REALITY_PUB_FILE" 2>/dev/null || true)"
  fi
  if [[ -f "$CACHE_FILE" ]]; then
    custom_ip="$(grep -E '^CUSTOM_IP=' "$CACHE_FILE" | tail -n1 | cut -d= -f2- || true)"
    node_suffix="$(grep -E '^NODE_SUFFIX=' "$CACHE_FILE" | tail -n1 | cut -d= -f2- || true)"
    [[ -z "$public_key" ]] && public_key="$(grep -E '^REALITY_PUB=' "$CACHE_FILE" | tail -n1 | cut -d= -f2- || true)"
  fi
  [[ -n "$port" && -n "$uuid" && -n "$private_key" && -n "$shortid" && -n "$domain" ]]
}

# ============================================================
#  X25519 / Reality：正确生成私钥 & 计算公钥（纯净输出）
# ============================================================
_b64_to_b64url() { base64 -w0 | tr '+/' '-_' | tr -d '='; }

_b64url_to_b64() {
  local s="$1"
  s="$(printf '%s' "$s" | tr '_-' '/+')"
  local mod=$(( ${#s} % 4 ))
  if [[ $mod -eq 1 ]]; then
    return 1
  elif [[ $mod -eq 2 ]]; then
    s="${s}=="
  elif [[ $mod -eq 3 ]]; then
    s="${s}="
  fi
  printf '%s' "$s"
}

_decode_priv_to_bin() {
  local input="$1"
  if [[ "$input" =~ ^[0-9a-fA-F]{64}$ ]]; then
    printf '%s' "$input" | xxd -r -p
    return 0
  fi
  local b64
  b64="$(_b64url_to_b64 "$input" 2>/dev/null || true)"
  [[ -n "$b64" ]] || return 1
  printf '%s' "$b64" | base64 -d 2>/dev/null
}

_derive_pub_from_priv_bin() {
  local tmpdir=""
  tmpdir="$(mktemp -d)"
  trap '[[ -n "${tmpdir:-}" && -d "${tmpdir:-}" ]] && rm -rf "${tmpdir:-}"' RETURN

  local priv_bin="$tmpdir/priv.bin"
  local priv_der="$tmpdir/priv.der"
  local pub_der="$tmpdir/pub.der"

  cat >"$priv_bin"
  local sz
  sz="$(wc -c <"$priv_bin" | tr -d ' ')"
  [[ "$sz" -eq 32 ]] || return 1

  local prefix_hex="302e020100300506032b656e04220420"
  {
    printf '%s' "$prefix_hex"
    xxd -p -c 256 "$priv_bin" | tr -d '\n'
  } | xxd -r -p >"$priv_der"

  openssl pkey -inform DER -in "$priv_der" -pubout -outform DER >"$pub_der" 2>/dev/null || return 1
  tail -c 32 "$pub_der"
}

calc_public_from_private() {
  local priv="$1"
  priv="$(echo -n "$priv" | tr -d '\n\r[:space:]' | sed 's/\x1b\[[0-9;]*m//g')"
  [[ -n "$priv" ]] || return 1

  local priv_bin pub_bin
  priv_bin="$(_decode_priv_to_bin "$priv" 2>/dev/null || true)"
  [[ -n "$priv_bin" ]] || return 1

  local sz
  sz="$(printf '%s' "$priv_bin" | wc -c | tr -d ' ')"
  [[ "$sz" -eq 32 ]] || return 1

  pub_bin="$(printf '%s' "$priv_bin" | _derive_pub_from_priv_bin 2>/dev/null || true)"
  [[ -n "$pub_bin" ]] || return 1

  printf '%s' "$pub_bin" | _b64_to_b64url
}

generate_keys() {
  local priv_bin priv_b64url pub_b64url
  priv_bin="$(openssl rand 32 2>/dev/null || true)"
  [[ -n "$priv_bin" ]] || return 1

  local sz
  sz="$(printf '%s' "$priv_bin" | wc -c | tr -d ' ')"
  [[ "$sz" -eq 32 ]] || return 1

  priv_b64url="$(printf '%s' "$priv_bin" | _b64_to_b64url)"
  pub_b64url="$(calc_public_from_private "$priv_b64url" 2>/dev/null || true)"
  [[ -n "$pub_b64url" ]] || return 1

  echo "${priv_b64url}|${pub_b64url}"
}

generate_reality_keypair() {
  if command -v sing-box >/dev/null 2>&1; then
    local out priv pub
    out="$(sing-box generate reality-keypair 2>/dev/null || true)"
    priv="$(echo "$out" | awk '/PrivateKey/ {print $NF; exit}')"
    pub="$(echo "$out" | awk '/PublicKey/ {print $NF; exit}')"
    if [[ -n "$priv" && -n "$pub" ]]; then
      echo "${priv}|${pub}"
      return 0
    fi
  fi
  generate_keys
}

# -----------------------------
#  写入配置并重启（sing-box VLESS Reality）
# -----------------------------
write_config_and_restart() {
  local port="$1" uuid="$2" private_key="$3" shortid="$4" domain="$5"
  local public_key="${6:-}"
  local custom_ip_in="${7:-${custom_ip:-}}"
  local node_suffix_in="${8:-${node_suffix:-}}"

  mkdir -p "$(dirname "$CONFIG")"
  mkdir -p /etc/sing-box

  cat > "$CONFIG" <<EOF
{
  "log": {
    "level": "warn",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": ${port},
      "users": [
        {
          "uuid": "${uuid}",
          "flow": "${FLOW}"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${domain}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${domain}",
            "server_port": 443
          },
          "private_key": "${private_key}",
          "short_id": ["${shortid}"]
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct-out"
    }
  ]
}
EOF

  echo -n "$public_key" > "$REALITY_PUB_FILE"
  cat > "$CACHE_FILE" <<EOF
ENABLE_REALITY=true
REALITY_PORT=${port}
REALITY_UUID=${uuid}
REALITY_PK=${private_key}
REALITY_PUB=${public_key}
REALITY_SID=${shortid}
REALITY_SNI=${domain}
CUSTOM_IP=${custom_ip_in}
NODE_SUFFIX=${node_suffix_in}
EOF
  echo 'ENABLE_REALITY=true' > "$PROTOCOL_FILE"

  if [[ "$OS" == "alpine" ]]; then
    cat > /etc/init.d/sing-box <<'OPENRC'
#!/sbin/openrc-run
name="sing-box"
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/run/sing-box.pid"
supervisor=supervise-daemon
supervise_daemon_args="--respawn-max 0 --respawn-delay 5"

depend() { need net; }
OPENRC
    chmod +x /etc/init.d/sing-box
    rc-update add sing-box default >/dev/null 2>&1 || true
  else
    cat > /etc/systemd/system/sing-box.service <<'SYSTEMD'
[Unit]
Description=Sing-box Proxy Server
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/sing-box
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SYSTEMD
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable sing-box >/dev/null 2>&1 || true
  fi

  if command -v sing-box >/dev/null 2>&1; then
    sing-box check -c "$CONFIG" >/dev/null 2>&1 || warn "配置校验失败，但仍尝试重启服务。"
  fi

  service_restart >/dev/null 2>&1 || service_restart || true
}

# -----------------------------
#  输入（回车随机/默认）
# -----------------------------
input_port() {
  local out=""
  while :; do
    read_tty "端口 Port（回车随机 10000-60000）：" out
    if [[ -z "${out}" ]]; then
      out=$(( (RANDOM % 50001) + 10000 ))
      echo -e "${yellow} 端口 (Port) [随机] = ${cyan}${out}${none}" >&2
      echo "----------------------------------------------------------------" >&2
      echo "${out}"
      return 0
    fi
    case "${out}" in
      [1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9]|[1-5][0-9][0-9][0-9][0-9]|6[0-4][0-9][0-9][0-9]|65[0-4][0-9][0-9]|655[0-3][0-5])
        echo -e "${yellow} 端口 (Port) = ${cyan}${out}${none}" >&2
        echo "----------------------------------------------------------------" >&2
        echo "${out}"
        return 0
      ;;
      *) error ;;
    esac
  done
}

input_uuid() {
  local out=""
  while :; do
    read_tty "(User ID / UUID)（回车随机）: " out
    if [[ -z "${out}" ]]; then
      out="$(rand_uuid)"
      echo -e "${yellow} 用户ID (User ID / UUID) [随机] = ${cyan}${out}${none}" >&2
      echo "----------------------------------------------------------------" >&2
      echo "${out}"
      return 0
    fi
    out="$(echo -n "${out}" | tr 'A-F' 'a-f')"
    if is_uuid "${out}"; then
      echo -e "${yellow} 用户ID (User ID / UUID) = ${cyan}${out}${none}" >&2
      echo "----------------------------------------------------------------" >&2
      echo "${out}"
      return 0
    fi
    error
    echo -e "${yellow}UUID 必须：xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx（0-9 a-f）${none}"
  done
}

input_shortid() {
  local out=""
  while :; do
    read_tty "ShortID（回车随机 16hex）: " out
    if [[ -z "${out}" ]]; then
      out="$(rand_shortid)"
      echo -e "${yellow} ShortId [随机] = ${cyan}${out}${none}" >&2
      echo "----------------------------------------------------------------" >&2
      echo "${out}"
      return 0
    fi
    out="$(echo -n "${out}" | tr 'A-F' 'a-f')"
    if is_shortid "${out}"; then
      echo -e "${yellow} ShortId = ${cyan}${out}${none}" >&2
      echo "----------------------------------------------------------------" >&2
      echo "${out}"
      return 0
    fi
    error
    echo -e "${yellow}ShortID：hex、<=16、且必须偶数长度（如 8/10/12/14/16）${none}"
  done
}

input_domain() {
  local out=""
  local def="www.japan.travel"
  while :; do
    read_tty "SNI（回车默认 ${def}）: " out
    if [[ -z "${out}" ]]; then
      out="${def}"
      echo -e "${yellow} SNI [默认] = ${cyan}${out}${none}" >&2
      echo "----------------------------------------------------------------" >&2
      echo "${out}"
      return 0
    fi
    if is_domain_like "${out}"; then
      echo -e "${yellow} SNI = ${cyan}${out}${none}" >&2
      echo "----------------------------------------------------------------" >&2
      echo "${out}"
      return 0
    fi
    error
    echo -e "${yellow}域名示例：www.japan.travel${none}"
  done
}
# -----------------------------
#  域名合理性检测
# -----------------------------
detect_reality_target() {
  local domain=""
  local out=""
  local proto=""
  local alpn=""
  local http_code=""
  local server_hdr=""
  local via_hdr=""
  local location_hdr=""
  local connect_t=""
  local tls_t=""
  local ttfb_t=""
  local total_t=""
  local ok_tls13="no"
  local ok_h2="no"
  local score=0

  echo
  read_tty "请输入要检测的目标域名（如 www.yahoo.co.jp）: " domain
  domain="$(echo -n "$domain" | tr -d '\r\n[:space:]')"

  if [[ -z "$domain" ]]; then
    warn "域名不能为空。"
    return 1
  fi

  if ! is_domain_like "$domain"; then
    warn "域名格式不合法：${domain}"
    return 1
  fi

  if ! need_cmd curl || ! need_cmd openssl; then
    warn "缺少 curl 或 openssl，无法检测。"
    return 1
  fi

  echo
  echo -e "${cyan}${bold}══════════════════════════════════════════${none}"
  echo -e "${cyan}${bold}   REALITY 目标站检测: ${domain}${none}"
  echo -e "${cyan}${bold}══════════════════════════════════════════${none}"

  echo
  echo -e "${yellow}[1/4] TLS 1.3 + ALPN(h2) 握手检测...${none}"
  out="$(openssl s_client -connect "${domain}:443" -servername "${domain}" -tls1_3 -alpn h2 </dev/null 2>/dev/null || true)"

  proto="$(printf '%s\n' "$out" | awk -F': ' '/Protocol/ {print $2; exit}')"
  alpn="$(printf '%s\n' "$out" | awk -F': ' '/ALPN protocol/ {print $2; exit}')"

  if [[ -n "$out" ]]; then
    if printf '%s\n' "$out" | grep -q 'TLSv1.3'; then
      ok_tls13="yes"
      score=$((score + 1))
    fi
    if [[ "$alpn" == "h2" ]]; then
      ok_h2="yes"
      score=$((score + 1))
    fi
  fi

  echo -e "  TLS 1.3: ${cyan}${ok_tls13}${none}"
  echo -e "  ALPN(h2): ${cyan}${ok_h2}${none}"
  [[ -n "$proto" ]] && echo -e "  Protocol: ${cyan}${proto}${none}"
  [[ -n "$alpn"  ]] && echo -e "  ALPN: ${cyan}${alpn}${none}"

  echo
  echo -e "${yellow}[2/4] HTTP/2 响应头检测...${none}"
  out="$(curl -I --http2 --tlsv1.3 -sS "https://${domain}/" 2>/dev/null || true)"
  http_code="$(printf '%s\n' "$out" | awk 'toupper($1) ~ /^HTTP\/2$/ {print $2; exit}')"
  server_hdr="$(printf '%s\n' "$out" | awk 'BEGIN{IGNORECASE=1} /^server:/ {sub(/\r$/,""); print substr($0,9); exit}')"
  via_hdr="$(printf '%s\n' "$out" | awk 'BEGIN{IGNORECASE=1} /^via:/ {sub(/\r$/,""); print substr($0,6); exit}')"
  location_hdr="$(printf '%s\n' "$out" | awk 'BEGIN{IGNORECASE=1} /^location:/ {sub(/\r$/,""); print substr($0,11); exit}')"

  [[ -n "$http_code" ]] && echo -e "  HTTP 状态: ${cyan}${http_code}${none}" || echo -e "  HTTP 状态: ${red}获取失败${none}"
  [[ -n "$server_hdr" ]] && echo -e "  Server: ${cyan}${server_hdr}${none}"
  [[ -n "$via_hdr" ]] && echo -e "  Via/CDN: ${cyan}${via_hdr}${none}"
  [[ -n "$location_hdr" ]] && echo -e "  Location: ${cyan}${location_hdr}${none}"

  echo
  echo -e "${yellow}[3/4] 单次时延检测...${none}"
  out="$(curl -o /dev/null -s --http2 --tlsv1.3 \
    -w 'connect=%{time_connect} tls=%{time_appconnect} ttfb=%{time_starttransfer} total=%{time_total}' \
    "https://${domain}/" 2>/dev/null || true)"
  echo -e "  ${cyan}${out}${none}"

  connect_t="$(printf '%s\n' "$out" | sed -n 's/.*connect=\([0-9.]*\).*/\1/p')"
  tls_t="$(printf '%s\n' "$out" | sed -n 's/.*tls=\([0-9.]*\).*/\1/p')"
  ttfb_t="$(printf '%s\n' "$out" | sed -n 's/.*ttfb=\([0-9.]*\).*/\1/p')"
  total_t="$(printf '%s\n' "$out" | sed -n 's/.*total=\([0-9.]*\).*/\1/p')"

  echo
  echo -e "${yellow}[4/4] 连续 3 次稳定性测试...${none}"
  local i
  for i in 1 2 3; do
    out="$(curl -o /dev/null -s --http2 --tlsv1.3 \
      -w "第${i}次: connect=%{time_connect} tls=%{time_appconnect} ttfb=%{time_starttransfer} total=%{time_total}" \
      "https://${domain}/" 2>/dev/null || true)"
    echo -e "  ${cyan}${out}${none}"
  done

  echo
  echo -e "${yellow}结论：${none}"
  if [[ "$ok_tls13" == "yes" && "$ok_h2" == "yes" ]]; then
    score=$((score + 1))
    if awk "BEGIN{exit !(${total_t:-9} < 0.20)}"; then
      echo -e "  ${green}适合做 REALITY 候选目标站${none}"
      echo -e "  ${green}理由：TLS 1.3 正常、h2 正常、总耗时较低。${none}"
    elif awk "BEGIN{exit !(${total_t:-9} < 0.50)}"; then
      echo -e "  ${yellow}可以作为 REALITY 候选，但不算特别优秀${none}"
      echo -e "  ${yellow}理由：TLS 1.3 / h2 正常，但时延表现一般。${none}"
    else
      echo -e "  ${yellow}协议层合格，但延迟偏高，建议再对比其他站点${none}"
    fi
  else
    echo -e "  ${red}不推荐作为 REALITY 目标站${none}"
    echo -e "  ${red}原因：TLS 1.3 或 h2 不满足。${none}"
  fi

  echo
}
# -----------------------------
#  全量打印 + vless URL + QR
# -----------------------------
print_full_info_and_qr() {
  if ! read_current_config; then
    warn "未找到或无法解析 ${CONFIG}（可能未安装/配置被污染/写入失败）。"
    return 1
  fi
  if ! command -v qrencode >/dev/null 2>&1; then
    install_base_deps >/dev/null 2>&1 || true
  fi

  get_public_ips
  local ip show_ip
  ip="${custom_ip:-}"
  if [[ -z "$ip" ]]; then
    if [[ -n "${IPv4}" ]]; then ip="${IPv4}"
    elif [[ -n "${IPv6}" ]]; then ip="${IPv6}"
    else ip="YOUR_SERVER_IP"
    fi
  fi
  show_ip="$ip"
  [[ "$ip" == *:* && "$ip" != \[*\] ]] && show_ip="[$ip]"

  local tag="#reality${node_suffix:-}"
  local vless="vless://${uuid}@${show_ip}:${port}?encryption=${ENCRYPTION}&flow=${FLOW}&security=reality&sni=${domain}&fp=${FINGERPRINT}&pbk=${public_key}&sid=${shortid}${tag}"

  echo
  echo "---------- Sing-box 配置信息 -------------"
  echo -e "${green} ---提示..这是 VLESS Reality 服务器配置--- ${none}"
  echo -e "${yellow} 地址 (Address) = ${cyan}${ip}${none}"
  echo -e "${yellow} 端口 (Port) = ${cyan}${port}${none}"
  echo -e "${yellow} 用户ID (User ID / UUID) = ${cyan}${uuid}${none}"
  echo -e "${yellow} 流控 (Flow) = ${cyan}${FLOW}${none}"
  echo -e "${yellow} 加密 (Encryption) = ${cyan}${ENCRYPTION}${none}"
  echo -e "${yellow} 传输协议 (Network) = ${cyan}${NETWORK}${none}"
  echo -e "${yellow} 底层传输安全 (TLS) = ${cyan}${TLS_MODE}${none}"
  echo -e "${yellow} SNI = ${cyan}${domain}${none}"
  echo -e "${yellow} 指纹 (Fingerprint) = ${cyan}${FINGERPRINT}${none}"
  echo -e "${yellow} 公钥 (PublicKey) = ${cyan}${public_key}${none}"
  echo -e "${yellow} ShortId = ${cyan}${shortid}${none}"
  echo
  echo "---------- VLESS Reality URL ----------"
  echo -e "${cyan}${vless}${none}"
  echo
  if command -v qrencode >/dev/null 2>&1; then
    echo "二维码（UTF8）"
    qrencode -t UTF8 "${vless}"
  fi

  {
    echo "---------- Sing-box 配置信息 -------------"
    echo " ---提示..这是 VLESS Reality 服务器配置--- "
    echo " 地址 (Address) = ${ip}"
    echo " 端口 (Port) = ${port}"
    echo " 用户ID (User ID / UUID) = ${uuid}"
    echo " 流控 (Flow) = ${FLOW}"
    echo " 加密 (Encryption) = ${ENCRYPTION}"
    echo " 传输协议 (Network) = ${NETWORK}"
    echo " 底层传输安全 (TLS) = ${TLS_MODE}"
    echo " SNI = ${domain}"
    echo " 指纹 (Fingerprint) = ${FINGERPRINT}"
    echo " 公钥 (PublicKey) = ${public_key}"
    echo " ShortId = ${shortid}"
    echo
    echo "---------- VLESS Reality URL ----------"
    echo "${vless}"
    if command -v qrencode >/dev/null 2>&1; then
      echo
      echo "二维码（UTF8）"
      qrencode -t UTF8 "${vless}"
    fi
  } > "${INFO_FILE}"

  ok "已保存到：${INFO_FILE}"
}

# showconf 与“打印节点信息”合并：只保留一个
showconf() { print_full_info_and_qr; }

# -----------------------------
#  安装/重装
# -----------------------------
install_xray() {
  echo -e "${yellow}开始安装/重装 sing-box VLESS Reality...${none}"
  show_singbox_version_hint

  if command -v sing-box >/dev/null 2>&1; then
    local ans=""
    read_tty "检测到已安装 sing-box，是否继续重装? [y/N]: " ans
    if [[ ! "$ans" =~ ^[Yy]$ ]]; then
      warn "已取消安装/重装。"
      return 0
    fi
  fi

  if ! install_or_update_singbox_backend install; then
    warn "sing-box 安装失败。"
    return 1
  fi

  echo
  echo -e "${yellow}初始化配置（回车随机化/输入需合法格式）${none}"
  echo "----------------------------------------------------------------"

  local suffix_input="" custom_input="" p u sid d key_pair pk pub
  read_tty "节点名称后缀（留空则不追加）: " suffix_input
  [[ -n "$suffix_input" ]] && suffix_input="-${suffix_input}"
  read_tty "节点连接 IP 或 DDNS 域名（留空默认自动探测）: " custom_input
  custom_input="$(echo -n "$custom_input" | tr -d $'\r\n[:space:]')"

  p="$(input_port)"
  u="$(input_uuid)"
  sid="$(input_shortid)"
  d="$(input_domain)"

  echo -e "${yellow}正在生成 Reality 私钥和公钥...${none}"
  key_pair="$(generate_reality_keypair || true)"
  pk="${key_pair%%|*}"
  pub="${key_pair##*|}"
  if [[ -z "$pk" || -z "$pub" ]]; then
    warn "生成 Reality 私钥/公钥失败。"
    return 1
  fi

  echo
  echo -e "${green}========== 本次最终配置（即将写入服务器） ==========${none}"
  echo -e "${yellow} Address(节点地址) = ${cyan}${custom_input:-自动探测}${none}"
  echo -e "${yellow} 端口 (Port) = ${cyan}${p}${none}"
  echo -e "${yellow} 用户ID (UUID) = ${cyan}${u}${none}"
  echo -e "${yellow} SNI = ${cyan}${d}${none}"
  echo -e "${yellow} ShortId = ${cyan}${sid}${none}"
  echo -e "${yellow} 私钥 (PrivateKey/服务器) = ${cyan}${pk}${none}"
  echo -e "${yellow} 公钥 (PublicKey/客户端) = ${cyan}${pub}${none}"
  echo "----------------------------------------------------------------"

  write_config_and_restart "$p" "$u" "$pk" "$sid" "$d" "$pub" "$custom_input" "$suffix_input"
  ok "安装/配置完成，已重启 sing-box。"
  print_full_info_and_qr
}

# -----------------------------
#  卸载
# -----------------------------
uninstall_xray() {
  warn "即将卸载 sing-box（停止服务、移除配置、移除程序）。"
  pause
  service_stop >/dev/null 2>&1 || true
  rm -f "$CONFIG" "$INFO_FILE" "$CACHE_FILE" "$REALITY_PUB_FILE" "$PROTOCOL_FILE" >/dev/null 2>&1 || true
  rm -rf /etc/sing-box/certs >/dev/null 2>&1 || true
  case "$OS" in
    alpine)
      apk del sing-box >/dev/null 2>&1 || true
      rc-update del sing-box default >/dev/null 2>&1 || true
      rm -f /etc/init.d/sing-box
      ;;
    debian|redhat)
      bash <(curl -fsSL https://sing-box.app/install.sh) uninstall >/dev/null 2>&1 || true
      rm -f /etc/systemd/system/sing-box.service
      systemctl daemon-reload >/dev/null 2>&1 || true
      ;;
  esac
  ok "已卸载完成。"
}

# -----------------------------
#  修改端口
# -----------------------------
change_port_only() {
  if ! read_current_config; then
    warn "未找到或无法解析 ${CONFIG}，请先安装/重装。"
    return 1
  fi
  echo -e "${yellow}当前端口 (Port) = ${cyan}${port}${none}"
  local new_port
  new_port="$(input_port)"
  write_config_and_restart "$new_port" "$uuid" "$private_key" "$shortid" "$domain" "$public_key" "$custom_ip" "$node_suffix"
  ok "已更新端口并重启 sing-box（其它参数保持不变）。"
  print_full_info_and_qr
}

# -----------------------------
#  修改 UUID + ShortID
# -----------------------------
change_uuid_shortid_only() {
  if ! read_current_config; then
    warn "未找到或无法解析 ${CONFIG}，请先安装/重装。"
    return 1
  fi
  echo -e "${yellow}当前 UUID = ${cyan}${uuid}${none}"
  echo -e "${yellow}当前 ShortId = ${cyan}${shortid}${none}"
  local new_uuid new_sid
  new_uuid="$(input_uuid)"
  new_sid="$(input_shortid)"
  write_config_and_restart "$port" "$new_uuid" "$private_key" "$new_sid" "$domain" "$public_key" "$custom_ip" "$node_suffix"
  ok "已更新 UUID + ShortID 并重启 sing-box（其它参数保持不变）。"
  print_full_info_and_qr
}

# -----------------------------
#  重置私钥 + 公钥
# -----------------------------
reset_keypair() {
  if ! read_current_config; then
    warn "未找到或无法解析 ${CONFIG}，请先安装/重装。"
    return 1
  fi

  echo -e "${yellow}将重置 Reality 私钥/公钥（port/uuid/sni/shortid 不变）${none}"
  pause

  echo -e "${yellow}正在生成新的私钥和公钥...${none}"
  local pk_pair pk pub
  pk_pair="$(generate_reality_keypair || true)"
  pk="${pk_pair%%|*}"
  pub="${pk_pair##*|}"

  if [[ -z "$pk" || -z "$pub" ]]; then
    warn "生成 Reality 私钥/公钥失败。"
    return 1
  fi

  write_config_and_restart "$port" "$uuid" "$pk" "$shortid" "$domain" "$pub" "$custom_ip" "$node_suffix" || return 1
  ok "已重置私钥/公钥并重启 sing-box。"
  echo -e "${yellow}新的 PublicKey（客户端用）= ${cyan}${pub}${none}"

  print_full_info_and_qr
}

# -----------------------------
#  xray 状态
# -----------------------------
status_xray() {
  echo
  echo -e "${yellow}sing-box 服务状态：${none}"
  service_status 2>/dev/null || true
  echo
  show_singbox_version_hint
  echo

  if [[ -f "$CONFIG" ]]; then
    if read_current_config; then
      echo -e "${yellow}当前配置摘要：${none}"
      echo -e " Port : ${cyan}${port}${none}"
      echo -e " UUID : ${cyan}${uuid}${none}"
      echo -e " SNI : ${cyan}${domain}${none}"
      echo -e " ShortID : ${cyan}${shortid}${none}"
      echo -e " PublicKey : ${cyan}${public_key}${none}"
      echo -e " Config : ${cyan}${CONFIG}${none}"
    else
      warn "配置存在但解析失败：${CONFIG}"
    fi
  else
    warn "未找到配置文件：${CONFIG}"
  fi
}

# ============================================================
#  系统配置/工具（整合：端口/UUID/重置密钥 + DNS/Swap/BBR/防火墙等）
# ============================================================

get_ssh_port() {
  local p
  p="$(grep -E '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config 2>/dev/null | tail -n1 | awk '{print $2}')"
  [[ -z "$p" ]] && p=22
  echo "$p"
}

besttrace() {
  apt_install_safe wget curl >/dev/null 2>&1 || true
  wget -qO- git.io/besttrace | bash
}

ipquality() {
  apt_install_safe curl >/dev/null 2>&1 || true
  echo "检查 IP 质量中..."

  if ! curl -fsSL --max-time 15 https://Check.Place | bash -s -- -I; then
    warn "ipquality 执行失败：可能无法访问 Check.Place，或脚本返回非 0。你可以手动测试：curl -vL https://Check.Place"
    return 0
  fi
}
# ============================================================
#  系统信息显示
# ============================================================
linux_ps() {
  clear || true
  apt_install_safe curl >/dev/null 2>&1 || true

  local cpu_info cpu_cores cpu_freq mem_info mem_pressure disk_info load os_info kernel_version cpu_arch hostname now runtime dns_addresses

  cpu_info="$(lscpu 2>/dev/null | awk -F': +' '/Model name:/ {print $2; exit}')"
  cpu_cores="$(nproc 2>/dev/null || echo 1)"
  cpu_freq="$(awk -F': ' '/cpu MHz/ {printf "%.1f GHz\n",$2/1000; exit}' /proc/cpuinfo 2>/dev/null || true)"

  # 物理内存：面板口径（nocache used）= total - free - buffers - cached - sreclaimable + shmem
  mem_info="$(awk '
    /MemTotal/     {t=$2}
    /MemFree/      {f=$2}
    /^Buffers:/    {b=$2}
    /^Cached:/     {c=$2}
    /SReclaimable/ {r=$2}
    /Shmem:/       {s=$2}
    END{
      used = t - f - b - c - r + s
      if (used < 0) used = 0
      printf "%.2f/%.2f MB (%.2f%%)", used/1024, t/1024, used*100/t
    }' /proc/meminfo)"

  # 可用内存 / OOM 风险参考：MemAvailable（百分比阈值：<10% 黄、<5% 红）
  local mem_total_kb mem_avail_kb mem_avail_mb mem_avail_pct mem_status mem_color
  mem_total_kb="$(awk '/MemTotal/ {print $2; exit}' /proc/meminfo)"
  mem_avail_kb="$(awk '/MemAvailable/ {print $2; exit}' /proc/meminfo)"

  mem_avail_mb=$(( mem_avail_kb / 1024 ))
  mem_avail_pct=$(( mem_total_kb > 0 ? mem_avail_kb * 100 / mem_total_kb : 0 ))

  if (( mem_avail_pct < 5 )); then
    mem_status="高危"
    mem_color="${red}"
  elif (( mem_avail_pct < 10 )); then
    mem_status="警告"
    mem_color="${yellow}"
  else
    mem_status="安全"
    mem_color="${green}"
  fi

  mem_pressure="${mem_color}${mem_avail_mb}MB available (${mem_avail_pct}%) ${mem_status}${none}"

  disk_info="$(df -h | awk '$NF=="/"{printf "%s/%s (%s)", $3, $2, $5}')"
  load="$(uptime | awk -F'load average:' '{print $2}' | xargs)"
  os_info="$(grep PRETTY_NAME /etc/os-release | cut -d '=' -f2 | tr -d '"')"
  kernel_version="$(uname -r)"

  # --- 补充：拥塞控制/队列算法/内核headers匹配 ---
  local cc_algo qdisc_algo headers_status

  cc_algo="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
  qdisc_algo="$(
    ip -o route get 1.1.1.1 2>/dev/null \
      | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' \
      | xargs -I{} tc qdisc show dev {} 2>/dev/null \
      | awk 'NR==1{print $2; exit}'
  )"
  [[ -z "$qdisc_algo" ]] && qdisc_algo="$(tc qdisc show 2>/dev/null | awk 'NR==1{print $2; exit}')"

  if [[ -d "/lib/modules/${kernel_version}/build" || -e "/usr/src/linux-headers-${kernel_version}" ]]; then
    headers_status="已匹配"
  else
    headers_status="未匹配"
  fi

  cpu_arch="$(uname -m)"
  hostname="$(uname -n)"
  now="$(date '+%Y-%m-%d %H:%M:%S')"
  runtime="$(awk -F. '{d=int($1/86400);h=int(($1%86400)/3600);m=int(($1%3600)/60); printf("%d天 %d时 %d分",d,h,m)}' /proc/uptime)"

  if [[ -f /etc/resolv.conf ]]; then
    dns_addresses="$(awk '/^nameserver[ \t]+/{printf "%s ", $2} END{print ""}' /etc/resolv.conf)"
  fi
  [[ -z "${dns_addresses// /}" ]] && dns_addresses="$(resolvectl status 2>/dev/null | awk '/DNS Servers:/ {for(i=3;i<=NF;i++) printf "%s ",$i} END{print ""}')"

  get_public_ips
  local ipv4="${IPv4:-}"
  local ipv6="${IPv6:-}"

  local ipinfo country city isp
  ipinfo="$(curl -s --max-time 3 ipinfo.io 2>/dev/null || true)"
  country="$(echo "$ipinfo" | awk -F'"' '/"country"/{print $4; exit}')"
  city="$(echo "$ipinfo" | awk -F'"' '/"city"/{print $4; exit}')"
  isp="$(echo "$ipinfo" | awk -F'"' '/"org"/{print $4; exit}')"

  echo ""
  echo -e "${cyan}系统信息查询${none}"
  echo -e "${cyan}------------------------------${none}"
  echo -e "主机名:       ${hostname}"
  echo -e "系统版本:     ${os_info}"
  echo -e "Linux版本:    ${kernel_version}"
  echo -e "${cyan}------------------------------${none}"
  echo -e "CPU架构:      ${cpu_arch}"
  echo -e "CPU型号:      ${cpu_info}"
  echo -e "CPU核心数:    ${cpu_cores}"
  [[ -n "$cpu_freq" ]] && echo -e "CPU频率:      ${cpu_freq}"
  echo -e "${cyan}------------------------------${none}"
  echo -e "系统负载:     ${load}"
  echo -e "物理内存:     ${mem_info}"
  echo -e "可用内存:     ${mem_pressure}"
  echo -e "硬盘占用:     ${disk_info}"
  echo -e "${cyan}------------------------------${none}"
  [[ -n "$isp" ]] && echo -e "运营商:       ${isp}"
  [[ -n "$ipv4" ]] && echo -e "IPv4地址:     ${ipv4}"
  [[ -n "$ipv6" ]] && echo -e "IPv6地址:     ${ipv6}"
  echo -e "DNS地址:      ${dns_addresses}"
  [[ -n "$country$city" ]] && echo -e "地理位置:     ${country} ${city}"
  echo -e "拥塞控制算法: ${cc_algo:-未知} 队列算法: ${qdisc_algo:-未知} 内核headers：${headers_status}"
  echo -e "系统时间:     ${now}"
  echo -e "运行时长:     ${runtime}"
  echo ""
}

# -----------------------------
#  设置时区
# -----------------------------

change_tz() {
  local tz=""
  read_tty "请输入时区（回车默认 Asia/Shanghai，例如 Asia/Shanghai）: " tz
  [[ -z "$tz" ]] && tz="Asia/Shanghai"
  timedatectl set-timezone "$tz" && ok "系统时区已设置为：$tz" || warn "设置失败：请检查 timedatectl / 时区名是否存在"
}
# -----------------------------
#  设置DNS
# -----------------------------
set_dns_ui() {
  apt_install_safe curl sudo >/dev/null 2>&1 || true
  echo -e "${yellow}正在配置 DNS（8.8.8.8 / 1.1.1.1）并锁定 /etc/resolv.conf ...${none}"

  if [[ -L /etc/resolv.conf ]]; then
    rm -f /etc/resolv.conf
    touch /etc/resolv.conf
  fi
  chattr -i /etc/resolv.conf 2>/dev/null || true

  cat >/etc/resolv.conf <<'EOF'
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF

  chattr +i /etc/resolv.conf 2>/dev/null || true
  ok "resolv.conf 已写入并尝试加锁（chattr +i）"

  if systemctl list-unit-files 2>/dev/null | grep -q '^systemd-resolved\.service'; then
    systemctl disable --now systemd-resolved >/dev/null 2>&1 || true
  fi
}
# -----------------------------
#  设置SWAP缓存（确保最终只保留 /swapfile 这一份）
# -----------------------------
swap_cache() {
  local size_mb confirm fs_type SUDO
  local keep="/swapfile"

  # 判断是否需要 sudo
  if [[ $EUID -ne 0 ]]; then
    SUDO="sudo"
  else
    SUDO=""
  fi

  echo "当前 Swap："
  free -h | awk 'NR==1 || /Swap:/ {print}'
  echo ""

  read_tty "请输入 Swap 大小（MB，建议 >=512）: " size_mb
  [[ "$size_mb" =~ ^[0-9]+$ ]] || { warn "请输入有效数字"; return 1; }

  read_tty "确认创建/重建 Swap=${size_mb}MB ? (y/n): " confirm
  [[ "$confirm" == "y" || "$confirm" == "Y" ]] || { warn "已取消"; return 0; }

  # 1) 禁用并清理除 /swapfile 之外的所有 swap（比如 /swap、分区 swap 等）
  #    同时把 /etc/fstab 里对应条目注释掉，避免重启恢复
  while read -r sw; do
    [[ -z "$sw" ]] && continue
    [[ "$sw" == "$keep" ]] && continue

    # 关闭 swap
    $SUDO swapoff "$sw" >/dev/null 2>&1 || true

    # fstab 里注释掉该 swap 条目（匹配第一列为该路径）
    if [[ -f /etc/fstab ]]; then
      $SUDO sed -i -E "s|^(\s*${sw//\//\\/}\s+.*\s+swap\s+.*)$|# disabled_by_swap_cache: \1|g" /etc/fstab >/dev/null 2>&1 || true
    fi

    # 如果是文件 swap（绝对路径文件），删除掉（如 /swap）
    if [[ "$sw" == /* && -f "$sw" ]]; then
      $SUDO rm -f "$sw" >/dev/null 2>&1 || true
    fi
  done < <(swapon --noheadings --raw --show=NAME 2>/dev/null)

  # 2) 如果已有 /swapfile，先卸载删除（重建）
  if swapon --noheadings --raw --show=NAME 2>/dev/null | grep -qx "$keep"; then
    $SUDO swapoff "$keep" >/dev/null 2>&1 || true
  fi
  $SUDO rm -f "$keep" >/dev/null 2>&1 || true

  # 3) 检测文件系统类型（用于 btrfs 特殊处理）
  fs_type="$(stat -f -c %T / 2>/dev/null || true)"

  # 4) 创建 swapfile：优先 fallocate，失败降级 dd
  if ! $SUDO touch "$keep" 2>/dev/null; then
    warn "无法创建 $keep（权限不足？）"
    return 1
  fi

  # btrfs：尽量关闭 COW；不可用则忽略
  if [[ "$fs_type" == "btrfs" ]] && command -v chattr >/dev/null 2>&1; then
    $SUDO chattr +C "$keep" >/dev/null 2>&1 || true
  fi

  if command -v fallocate >/dev/null 2>&1; then
    if ! $SUDO fallocate -l "${size_mb}M" "$keep" 2>/dev/null; then
      warn "fallocate 不支持或失败，改用 dd 写零创建 swapfile（会慢一点）"
      if ! $SUDO dd if=/dev/zero of="$keep" bs=1M count="${size_mb}" conv=fsync status=progress; then
        warn "dd 创建 swapfile 失败（可能磁盘空间不足、权限受限或文件系统限制）"
        $SUDO rm -f "$keep" >/dev/null 2>&1 || true
        return 1
      fi
    fi
  else
    warn "系统无 fallocate，使用 dd 写零创建 swapfile（会慢一点）"
    if ! $SUDO dd if=/dev/zero of="$keep" bs=1M count="${size_mb}" conv=fsync status=progress; then
      warn "dd 创建 swapfile 失败（可能磁盘空间不足、权限受限或文件系统限制）"
      $SUDO rm -f "$keep" >/dev/null 2>&1 || true
      return 1
    fi
  fi

  # 5) 权限与启用
  $SUDO chmod 600 "$keep" || { warn "chmod 600 失败"; $SUDO rm -f "$keep" >/dev/null 2>&1 || true; return 1; }

  $SUDO mkswap "$keep" >/dev/null 2>&1 || {
    warn "mkswap 失败（文件系统可能不支持 swapfile）"
    $SUDO rm -f "$keep" >/dev/null 2>&1 || true
    return 1
  }

  $SUDO swapon "$keep" >/dev/null 2>&1 || {
    warn "swapon 失败（可能是容器/虚拟化限制或文件系统限制）"
    $SUDO rm -f "$keep" >/dev/null 2>&1 || true
    return 1
  }

  # 6) 写入 fstab（幂等：存在就不重复写）
  if ! grep -qE '^\s*/swapfile\s' /etc/fstab 2>/dev/null; then
    echo "/swapfile none swap sw 0 0" | $SUDO tee -a /etc/fstab >/dev/null
  fi

  ok "Swap 已启用（只保留 /swapfile）："
  $SUDO swapon --show
  free -h | awk 'NR==1 || /Swap:/ {print}'
}



# -----------------------------
#  设置IP优先级
# -----------------------------
set_ip_priority() {
  while :; do
    clear || true
    local v6_disabled
    v6_disabled="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 0)"
    echo "设置 v4/v6 优先级"
    echo "------------------------"
    if [[ "$v6_disabled" == "1" ]]; then
      echo "当前：IPv4 优先（IPv6 已禁用）"
    else
      echo "当前：IPv6 可用（未禁用）"
    fi
    echo "------------------------"
    echo "1) IPv4 优先（禁用 IPv6）"
    echo "2) IPv6 优先（启用 IPv6）"
    echo "0) 返回"
    echo "------------------------"
    local c=""
    read_tty "请选择: " c
    case "$c" in
      1) sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1; sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1; ok "已切换为 IPv4 优先"; pause ;;
      2) sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1; sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1; ok "已切换为 IPv6 优先"; pause ;;
      0) return 0 ;;
      *) error; pause ;;
    esac
  done
}

# -----------------------------
#  定时重启设置
# -----------------------------
cron_reboot() {
  apt_install_safe cron >/dev/null 2>&1 || true
  systemctl enable --now cron >/dev/null 2>&1 || true

  local hh mm
  read_tty "每天定时重启-小时（0-23，回车默认 4）: " hh
  read_tty "每天定时重启-分钟（0-59，回车默认 0）: " mm
  [[ -z "$hh" ]] && hh=4
  [[ -z "$mm" ]] && mm=0

  cat >/etc/cron.d/xray_reboot <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
${mm} ${hh} * * * root /sbin/reboot
EOF

  ok "已设置每天 ${hh}:$(printf '%02d' "$mm") 定时重启（/etc/cron.d/xray_reboot）"
}

# -----------------------------
# 端口设置
# -----------------------------
ssh_port() {
  local new_port="$1"
  [[ -z "$new_port" ]] && { warn "缺少端口参数"; return 1; }

  local SSH_CONFIG="/etc/ssh/sshd_config"
  if grep -qE '^[[:space:]]*Port[[:space:]]+' "$SSH_CONFIG"; then
    sed -i "s/^[[:space:]]*Port[[:space:]]\+[0-9]\+/Port ${new_port}/" "$SSH_CONFIG"
  elif grep -q "^#Port 22" "$SSH_CONFIG"; then
    sed -i "s/^#Port 22/Port ${new_port}/" "$SSH_CONFIG"
  else
    echo "Port ${new_port}" >> "$SSH_CONFIG"
  fi

  systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true
  ok "SSH 端口已修改为 ${new_port}（请确保防火墙已放行，否则可能断连）"
}

# -----------------------------
#  防火墙设置
# -----------------------------
firewall() {
  apt_install_safe ufw >/dev/null 2>&1 || true

  while :; do
    clear || true
    echo "---------------- 防火墙设置 (ufw) ----------------"
    echo "1) 开启防火墙并放行端口"
    echo "2) 关闭防火墙"
    echo "3) 查看状态"
    echo "0) 返回"
    echo "-------------------------------------------------"
    local ans=""
    read_tty "请选择 [0-3]: " ans
    case "$ans" in
      1)
        local sshp extra=""
        sshp="$(get_ssh_port)"

        local xport=""
        if read_current_config; then xport="$port"; fi

        read_tty "额外放行端口（可空；例：2222 52000-53000）: " extra

        ufw --force enable >/dev/null 2>&1 || true
        ufw allow "${sshp}/tcp" >/dev/null 2>&1 || true
        ufw allow "${sshp}/udp" >/dev/null 2>&1 || true

        if [[ -n "$xport" ]]; then
          ufw allow "${xport}/tcp" >/dev/null 2>&1 || true
          ufw allow "${xport}/udp" >/dev/null 2>&1 || true
        fi

        for p in $extra; do
          if [[ "$p" =~ ^[0-9]+-[0-9]+$ ]]; then
            local s e
            IFS='-' read -r s e <<<"$p"
            ufw allow "${s}:${e}/tcp" >/dev/null 2>&1 || true
            ufw allow "${s}:${e}/udp" >/dev/null 2>&1 || true
          elif [[ "$p" =~ ^[0-9]+$ ]]; then
            ufw allow "${p}/tcp" >/dev/null 2>&1 || true
            ufw allow "${p}/udp" >/dev/null 2>&1 || true
          fi
        done

        echo ""
        ufw status numbered
        pause
        ;;
      2) ufw disable; ufw status; pause ;;
      3) ufw status numbered; pause ;;
      0) return 0 ;;
      *) error; pause ;;
    esac
  done
}

# -----------------------------
#  BBR设置
# -----------------------------
bbrx() {
  local url="https://raw.githubusercontent.com/byilrq/vps/main/tcpx.sh"
  local tmp="/tmp/tcpx.sh"
  apt_install_safe curl wget >/dev/null 2>&1 || true

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$tmp" || { warn "下载失败"; return 1; }
  else
    wget -qO "$tmp" "$url" || { warn "下载失败"; return 1; }
  fi
  chmod +x "$tmp"
  bash "$tmp"
}

# -----------------------------
#  添加秘钥登录
# -----------------------------
auth_key() {
  set -e

  # ===== 可改参数 =====
  local target_user="${1:-root}"     # auth_key root / auth_key ubuntu
  # ===================

  if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: 请用 root 执行（需要写 /etc/ssh/sshd_config 并重启 ssh）。"
    return 1
  fi

  # ---------- 检测：是否 SSH 会话 ----------
  local is_ssh_session="no"
  if [ -n "${SSH_CONNECTION:-}" ] || [ -n "${SSH_TTY:-}" ]; then
    is_ssh_session="yes"
  fi

  # ---------- 检测：当前 sshd 生效配置 ----------
  # 用 sshd -T 读取“最终生效值”，比看配置文件准
  local pubkeyauth passwordauth kbdauth
  pubkeyauth="$(sshd -T 2>/dev/null | awk '/^pubkeyauthentication /{print $2; exit}')"
  passwordauth="$(sshd -T 2>/dev/null | awk '/^passwordauthentication /{print $2; exit}')"
  kbdauth="$(sshd -T 2>/dev/null | awk '/^kbdinteractiveauthentication /{print $2; exit}')"

  # 容错：万一没读到（极少）
  pubkeyauth="${pubkeyauth:-unknown}"
  passwordauth="${passwordauth:-unknown}"
  kbdauth="${kbdauth:-unknown}"

  # 你要的“当前登录状态”我按“系统当前是否允许端口/口令登录”来判断：
  # - passwordauthentication=yes => 允许口令（你称“端口登录”）
  # - passwordauthentication=no  => 仅密钥
  local mode="unknown"
  if [ "$passwordauth" = "no" ]; then
    mode="key_only"
  elif [ "$passwordauth" = "yes" ]; then
    mode="password_allowed"
  fi

  echo "=== 当前检测结果 ==="
  echo "会话类型: ${is_ssh_session}"
  echo "sshd生效配置: PubkeyAuthentication=${pubkeyauth}, PasswordAuthentication=${passwordauth}, KbdInteractiveAuthentication=${kbdauth}"
  echo "模式判断: ${mode}"
  echo "===================="

  # ---------- 分支询问 ----------
  if [ "$mode" = "password_allowed" ]; then
    # 你说的“端口登录则询问是否开启密钥登录”
    read -r -p "当前允许密码/端口登录。是否开启密钥登录流程？[y/N] " yn
    case "$yn" in
      y|Y|yes|YES) ;;
      *) echo "未执行任何更改，退出。"; return 0 ;;
    esac
  elif [ "$mode" = "key_only" ]; then
    # “如果当前已经是秘钥登录了，则询问是否开启端口登录”
    read -r -p "当前已是仅密钥登录（密码登录关闭）。是否开启端口/密码登录？[y/N] " yn
    case "$yn" in
      y|Y|yes|YES)
        # 开启端口/密码登录：直接改 sshd_config 并重启，然后退出（按你描述：是就继续执行；这里继续执行=完成开启端口登录动作）
        local cfg="/etc/ssh/sshd_config"
        if [ ! -f "$cfg" ]; then
          echo "ERROR: 找不到 $cfg"
          return 1
        fi
        local bak="${cfg}.bak.$(date +%Y%m%d-%H%M%S)"
        cp -a "$cfg" "$bak"
        echo "已备份：$bak"

        _set_sshd_kv() {
          local k="$1" v="$2"
          local tmp
          tmp="$(mktemp)"
          awk -v K="$k" -v V="$v" '
            BEGIN { done=0 }
            {
              if (!done && $0 ~ "^[[:space:]]*#?[[:space:]]*" K "[[:space:]]+") {
                print K " " V
                done=1
              } else {
                print $0
              }
            }
            END {
              if (!done) { print ""; print K " " V }
            }
          ' "$cfg" > "$tmp" && cat "$tmp" > "$cfg"
          rm -f "$tmp"
        }

        _set_sshd_kv "PasswordAuthentication" "yes"
        _set_sshd_kv "KbdInteractiveAuthentication" "yes"
        # 也可以显式确保 pubkey 仍然可用
        _set_sshd_kv "PubkeyAuthentication" "yes"
        _set_sshd_kv "AuthorizedKeysFile" ".ssh/authorized_keys"

        if command -v systemctl >/dev/null 2>&1; then
          systemctl restart ssh 2>/dev/null || systemctl restart sshd
        else
          service ssh restart 2>/dev/null || service sshd restart
        fi
        echo "已开启密码/端口登录并重启 SSH。退出。"
        return 0
        ;;
      *)
        echo "未执行任何更改，退出。"
        return 0
        ;;
    esac
  else
    # unknown 模式：保守处理
    read -r -p "无法判定当前模式。是否继续执行“开启密钥登录”流程？[y/N] " yn
    case "$yn" in
      y|Y|yes|YES) ;;
      *) echo "退出。"; return 0 ;;
    esac
  fi

  # ========== 下面是“开启密钥登录流程”（沿用你现有实现）==========

  # 获取用户家目录
  local user_home
  user_home="$(getent passwd "$target_user" | cut -d: -f6)"
  if [ -z "$user_home" ] || [ ! -d "$user_home" ]; then
    echo "ERROR: 找不到用户或家目录：$target_user"
    return 1
  fi

  echo "请输入公钥字符串（一整行，以 ssh-ed25519/ssh-rsa/ecdsa... 开头），回车结束："
  read -r pubkey

  if ! echo "$pubkey" | grep -Eq '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/=]+(\s.*)?$'; then
    echo "ERROR: 公钥格式不正确。示例：ssh-ed25519 AAAAC3... comment"
    return 1
  fi

  # 创建 .ssh 和 authorized_keys
  local ssh_dir="$user_home/.ssh"
  local ak="$ssh_dir/authorized_keys"
  mkdir -p "$ssh_dir"
  chmod 700 "$ssh_dir"

  touch "$ak"
  chmod 600 "$ak"
  chown -R "$target_user:$target_user" "$ssh_dir"

  # 去重写入（只比较前两段：type + base64）
  local key_two
  key_two="$(echo "$pubkey" | awk '{print $1" "$2}')"
  if awk '{print $1" "$2}' "$ak" | grep -Fxq "$key_two"; then
    echo "公钥已存在：未重复写入 $ak"
  else
    echo "$pubkey" >> "$ak"
    echo "公钥已写入：$ak"
  fi

  # 备份 sshd_config
  local cfg="/etc/ssh/sshd_config"
  if [ ! -f "$cfg" ]; then
    echo "ERROR: 找不到 $cfg"
    return 1
  fi
  local bak="${cfg}.bak.$(date +%Y%m%d-%H%M%S)"
  cp -a "$cfg" "$bak"
  echo "已备份：$bak"

  # 设置/追加配置项的 helper（awk版，避免 / 转义问题）
  _set_sshd_kv() {
    local k="$1" v="$2"
    local tmp
    tmp="$(mktemp)"
    awk -v K="$k" -v V="$v" '
      BEGIN { done=0 }
      {
        if (!done && $0 ~ "^[[:space:]]*#?[[:space:]]*" K "[[:space:]]+") {
          print K " " V
          done=1
        } else {
          print $0
        }
      }
      END {
        if (!done) { print ""; print K " " V }
      }
    ' "$cfg" > "$tmp" && cat "$tmp" > "$cfg"
    rm -f "$tmp"
  }

  _set_sshd_kv "PubkeyAuthentication" "yes"
  _set_sshd_kv "AuthorizedKeysFile" ".ssh/authorized_keys"

  # 关闭“端口访问功能”——按你的历史约定：关闭密码登录
  read -r -p "是否关闭密码登录（仅允许密钥登录）？[y/N] " dis_pw
  case "$dis_pw" in
    y|Y|yes|YES)
      _set_sshd_kv "PasswordAuthentication" "no"
      _set_sshd_kv "KbdInteractiveAuthentication" "no"
      echo "已关闭密码登录。"
      ;;
    *)
      echo "保留密码登录。"
      ;;
  esac

  # 重启 SSH 服务
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart ssh 2>/dev/null || systemctl restart sshd
  else
    service ssh restart 2>/dev/null || service sshd restart
  fi
  echo "SSH 服务已重启。"

  # 最后再打印一次生效状态
  echo "=== 更新后生效配置 ==="
  sshd -T | egrep -i 'pubkeyauthentication|authorizedkeysfile|passwordauthentication|kbdinteractiveauthentication' || true
  echo "======================"

  echo "完成。建议：打开新终端测试密钥登录成功后，再退出当前会话。"
}
# -----------------------------
#  系统清理
# -----------------------------
sys_cle() {
  local url="https://raw.githubusercontent.com/byilrq/vps/main/sys_cle.sh"
  local script="/root/sys_cle.sh"
  local cron_line='0 0 * * * /bin/bash /root/sys_cle.sh >> /root/sys_cle.cron.log 2>&1'
  local cron_d_file="/etc/cron.d/sys_cle"

  _ensure_downloader() {
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
      apt-get update -y >/dev/null 2>&1 || true
      apt-get install -y curl wget >/dev/null 2>&1 || true
    fi
    return 0
  }

  _download_script() {
    _ensure_downloader
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL "$url" -o "$script" || { echo "下载失败"; return 1; }
    else
      wget -qO "$script" "$url" || { echo "下载失败"; return 1; }
    fi
    chmod +x "$script" >/dev/null 2>&1 || true
    return 0
  }

  _restart_cron_service() {
    # 尽量重启 cron/crond（不同发行版名字不同）
    systemctl restart cron  >/dev/null 2>&1 && return 0
    systemctl restart crond >/dev/null 2>&1 && return 0
    service cron restart    >/dev/null 2>&1 && return 0
    service crond restart   >/dev/null 2>&1 && return 0
    /etc/init.d/cron restart  >/dev/null 2>&1 && return 0
    /etc/init.d/crond restart >/dev/null 2>&1 && return 0
    return 0
  }

  _install_cron_via_crontab() {
    # 用临时文件安装，避免 crontab - 在某些环境/实现下出问题
    local tmp
    tmp="$(mktemp /tmp/sys_cle_cron.XXXXXX)" || return 1

    # 取出现有 crontab，去掉包含 sys_cle 的行，追加新行
    # 同时清理 CRLF（删掉 \r），避免 bad minute
    {
      crontab -l 2>/dev/null | tr -d '\r' | grep -Fv "/root/sys_cle.sh" || true
      printf "%s\n" "$cron_line" | tr -d '\r'
    } >"$tmp"

    # 安装
    if crontab "$tmp" >/dev/null 2>&1; then
      rm -f "$tmp"
      return 0
    fi

    # 失败时输出错误并返回失败
    echo "WARN: 使用 crontab 安装失败，尝试降级到 /etc/cron.d ..."
    crontab "$tmp" 2>&1 | sed 's/^/crontab: /' >&2 || true
    rm -f "$tmp"
    return 1
  }

  _remove_cron_via_crontab() {
    local tmp
    tmp="$(mktemp /tmp/sys_cle_cron.XXXXXX)" || return 1
    crontab -l 2>/dev/null | tr -d '\r' | grep -Fv "/root/sys_cle.sh" >"$tmp" || true
    crontab "$tmp" >/dev/null 2>&1 || true
    rm -f "$tmp"
    return 0
  }

  _install_cron_via_cron_d() {
    # /etc/cron.d 方式（更通用/更稳）：需要 root 字段
    cat >"$cron_d_file" <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

0 0 * * * root /bin/bash /root/sys_cle.sh >> /root/sys_cle.cron.log 2>&1
EOF
    chmod 644 "$cron_d_file" >/dev/null 2>&1 || true
    _restart_cron_service
    return 0
  }

  _remove_cron_via_cron_d() {
    rm -f "$cron_d_file" >/dev/null 2>&1 || true
    _restart_cron_service
    return 0
  }

  _show_status() {
    echo "---- crontab 中与 sys_cle 相关的条目 ----"
    crontab -l 2>/dev/null | tr -d '\r' | grep -F "/root/sys_cle.sh" || echo "（crontab 未设置）"
    echo ""
    echo "---- /etc/cron.d/sys_cle ----"
    if [ -f "$cron_d_file" ]; then
      echo "存在：$cron_d_file"
      sed 's/^/  /' "$cron_d_file"
    else
      echo "（不存在）"
    fi
  }

  # 1) 先下载/更新脚本
  _download_script || return 1

  # 2) 对话菜单
  echo ""
  echo "=============================="
  echo "sys_cle 管理菜单（已更新脚本）"
  echo "脚本位置: $script"
  echo "=============================="
  echo "1) 添加 cron：每天 00:00 执行"
  echo "2) 删除 cron：移除该定时任务"
  echo "3) 立即执行一次清理"
  echo "4) 查看当前 cron 状态"
  echo "0) 退出"
  echo "------------------------------"
  read -r -p "请选择 [0-4]: " choice

  case "$choice" in
    1)
      # 优先用 crontab 安装；失败则写 /etc/cron.d
      if _install_cron_via_crontab; then
        echo "OK: 已添加每日 00:00 cron（crontab）"
      else
        _install_cron_via_cron_d
        echo "OK: 已添加每日 00:00 cron（/etc/cron.d 降级方案）"
      fi
      ;;
    2)
      _remove_cron_via_crontab
      _remove_cron_via_cron_d
      echo "OK: 已删除 sys_cle 的 cron（crontab + /etc/cron.d）"
      ;;
    3)
      /bin/bash "$script"
      echo "OK: 已执行一次清理"
      ;;
    4)
      _show_status
      ;;
    0)
      echo "已退出"
      ;;
    *)
      echo "输入无效：$choice（只允许 0-4）"
      return 1
      ;;
  esac
}

# -----------------------------
#  参数修改
# -----------------------------
changeconf() {
  while :; do
    clear || true
    echo -e "${cyan}系统配置${none}"
    echo "---------------- Xray 相关 ----------------"
    echo "1) 重置端口"
    echo "2) 重置UUID和ShortID"
    echo "3) 重置私钥和公钥"
    echo "---------------- 系统相关 ----------------"
    echo "5) 修改时区"
    echo "6) 修改DNS"
    echo "7) 设置Swap缓存"
    echo "8) 设置IPv4/IPv6优先级"
    echo "9) BBR/TCP 优化"
    echo "10) 设置定时重启"
    echo "11) 修改SSH端口2222"
    echo "12) 设置ufw"
    echo "13) 设置SSH秘钥"
    echo "14) 设置系统清理"
    echo "0) 返回"
    echo "--------------------------------------------------"
    local c=""
    read_tty "请选择: " c
    case "$c" in
      1) change_port_only; pause ;;
      2) change_uuid_shortid_only; pause ;;
      3) reset_keypair; pause ;;
      5) change_tz; pause ;;
      6) set_dns_ui; pause ;;
      7) swap_cache; pause ;;
      8) set_ip_priority; pause ;;
      9) bbrx; pause ;;
      10) cron_reboot; pause ;;
      11) ssh_port 2222; pause ;;
      12) firewall; pause ;;
      13) auth_key ;;
      14) sys_cle ;;
      0) return 0 ;;
      *) error; pause ;;
    esac
  done
}

# -----------------------------
#  命令行参数模式（保持你原逻辑）
# -----------------------------
install_with_params() {
  local netstack="$1"
  local port="$2"
  local domain="$3"
  local uuid="$4"

  echo -e "${yellow}开始安装 sing-box VLESS Reality（参数模式）...${none}"
  if ! install_or_update_singbox_backend install; then
    warn "sing-box 安装失败"
    return 1
  fi

  local key_pair private_key public_key shortid
  key_pair="$(generate_reality_keypair || true)"
  private_key="${key_pair%%|*}"
  public_key="${key_pair##*|}"
  [[ -n "$private_key" && -n "$public_key" ]] || { warn "生成私钥/公钥失败"; return 1; }

  shortid="$(rand_shortid)"
  write_config_and_restart "$port" "$uuid" "$private_key" "$shortid" "$domain" "$public_key" "" ""
  ok "安装/配置完成，已重启 sing-box。"
  print_full_info_and_qr
}

# -----------------------------
#  主菜单
# -----------------------------
menu() {
  while :; do
    clear >/dev/null 2>&1 || true

    # 仅用于美化：不要求你全局必须有
    local bold='\033[1m'
    local dim='\033[2m'
    local gray='\033[90m'

# ========= 菜单 UI =========
echo -e "${cyan}${bold}══════════════════════════════════════════${none}"
echo -e "${cyan}${bold}   🚀  Sing-box Reality 管理界面"${none}
echo -e "${cyan}${bold}══════════════════════════════════════════${none}"
echo -e "${gray}──────────────────────────────────────────────────${none}"
    local cur_ver_menu latest_ver_menu
    cur_ver_menu="$(get_current_singbox_version 2>/dev/null || echo 未安装)"
    latest_ver_menu="$(get_latest_singbox_version 2>/dev/null || echo 获取失败)"
    echo -e "${gray}当前：${cyan}${cur_ver_menu}${none}  ${gray}GitHub：${cyan}${latest_ver_menu}${none}"
    echo -e "${gray}──────────────────────────────────────────────────${none}"
echo -e "  ${green}${bold}1)${none} ${green}安装"
echo -e "  ${yellow}${bold}2)${none} ${yellow}更新"
echo -e "  ${red}${bold}3)${none} ${red}卸载"
echo -e "${gray}──────────────────────────────────────────────────${none}"
echo -e "  ${yellow}${bold}4)${none} ${yellow}打印节点信息"
echo -e "  ${yellow}${bold}5)${none} ${yellow}目标网站检测"
echo -e "  ${yellow}${bold}6)${none} ${yellow}系统参数配置"
echo -e "  ${yellow}${bold}7)${none} ${yellow}回程路由测试"
echo -e "  ${yellow}${bold}8)${none} ${yellow}IP质量检测"
echo -e "  ${yellow}${bold}9)${none} ${yellow}系统查询"
echo -e "  ${yellow}${bold}10)${none} ${yellow}查看状态"
echo -e "  ${red}${bold}0)${none} ${red}${bold}退出${none}"
echo -e "${gray}提示：输入对应数字并回车${none}"
echo -e "${gray}──────────────────────────────────────────────────${none}"
echo -ne "${green}${bold}请选择 [0-9]${none}${green}: ${none}"

    local choice=""
    read_tty "" choice

    case "${choice}" in
      1) install_xray; pause ;;
      2) update_xray_reality; pause ;;
      3) uninstall_xray; pause ;;
      4) showconf; pause ;;
	  5)detect_reality_target ;;
      6) changeconf ;;
      7) besttrace; pause ;;
      8) ipquality; pause ;;
      9) linux_ps; pause ;;
      10) status_xray; pause ;;
      0) exit 0 ;;
      *) error; pause ;;
    esac
  done
}



# -----------------------------
#  主程序入口
# -----------------------------
need_root
menu
