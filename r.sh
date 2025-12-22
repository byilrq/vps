#!/usr/bin/env bash
# ============================================================
# Xray VLESS Reality 管理脚本（整合版）
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

CONFIG="/usr/local/etc/xray/config.json"
SERVICE="xray"
INFO_FILE="$HOME/_vless_reality_url_"
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
#  Xray 安装版本选择（必须在 install_xray 前定义）
# ============================================================
get_latest_xray_version() {
  # 需要 curl + jq
  local tag=""
  tag="$(curl -fsSL "https://api.github.com/repos/XTLS/Xray-core/releases/latest" 2>/dev/null \
    | jq -r '.tag_name // empty' 2>/dev/null || true)"
  if [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "$tag"
    return 0
  fi
  return 1
}

choose_xray_version() {
  local default_ver="${1:-v25.10.15}"
  local chosen="" latest=""

  # 非交互（比如被管道/后台跑），直接默认
  if [[ ! -r /dev/tty || ! -w /dev/tty ]]; then
    echo "$default_ver"
    return 0
  fi

  latest="$(get_latest_xray_version 2>/dev/null || true)"
  if [[ -n "$latest" ]]; then
    echo -e "${yellow}检测到最新 Release：${cyan}${latest}${none}" > /dev/tty
  else
    echo -e "${yellow}未能获取最新 Release（将使用默认/手动输入）${none}" > /dev/tty
  fi

  read_tty "安装版本（回车默认 ${default_ver} / 输入 latest 安装最新 / 或输入如 v25.10.15）: " chosen
  chosen="$(echo -n "$chosen" | tr -d '\n\r[:space:]')"

  if [[ -z "$chosen" ]]; then
    echo "$default_ver"
    return 0
  fi

  if [[ "$chosen" == "latest" ]]; then
    if [[ -n "$latest" ]]; then
      echo "$latest"
      return 0
    fi
    warn "获取最新版本失败，回退到默认 ${default_ver}"
    echo "$default_ver"
    return 0
  fi

  if [[ "$chosen" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "$chosen"
    return 0
  fi

  warn "版本格式不合法：${chosen}（应为 latest 或 vX.Y.Z），回退默认 ${default_ver}"
  echo "$default_ver"
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
#  读取配置（只读 inbounds）
# -----------------------------
read_current_config() {
  port=""; uuid=""; private_key=""; shortid=""; domain=""
  [[ -f "$CONFIG" ]] || return 1
  local block
  block="$(awk '
    BEGIN{p=0}
    /"inbounds"[[:space:]]*:/ {p=1}
    p==1 {print}
    /"outbounds"[[:space:]]*:/ {exit}
  ' "$CONFIG")"
  port="$(echo "$block" | grep -oP '"port"\s*:\s*\K[0-9]+' | head -n1 || true)"
  uuid="$(echo "$block" | grep -oP '"id"\s*:\s*"\K[^"]+' | head -n1 || true)"
  private_key="$(echo "$block" | grep -oP '"privateKey"\s*:\s*"\K[^"]+' | head -n1 || true)"
  shortid="$(echo "$block" | grep -oP '"shortIds"\s*:\s*\[\s*"\K[^"]+' | head -n1 || true)"
  domain="$(echo "$block" | grep -oP '"serverNames"\s*:\s*\[\s*"\K[^"]+' | head -n1 || true)"
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

# -----------------------------
#  写入配置并重启（合法 JSON）
# -----------------------------
write_config_and_restart() {
  local port="$1" uuid="$2" private_key="$3" shortid="$4" domain="$5"

  private_key="$(echo -n "$private_key" | tr -d '\n\r[:space:]' | sed 's/\x1b\[[0-9;]*m//g')"
  if ! is_b64url_key "$private_key"; then
    warn "privateKey 格式不合法（必须是 Base64URL 43/44 字符）。"
    return 1
  fi

  mkdir -p "$(dirname "$CONFIG")"
  cat > "$CONFIG" <<-EOF
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": ${port},
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "${uuid}", "flow": "${FLOW}" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "${NETWORK}",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${domain}:443",
          "xver": 0,
          "serverNames": ["${domain}"],
          "privateKey": "${private_key}",
          "shortIds": ["${shortid}"]
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "freedom", "settings": { "domainStrategy": "UseIPv4" }, "tag": "force-ipv4" },
    { "protocol": "freedom", "settings": { "domainStrategy": "UseIPv6" }, "tag": "force-ipv6" },
    {
      "protocol": "socks",
      "settings": { "servers": [ { "address": "127.0.0.1", "port": 40000 } ] },
      "tag": "socks5-warp"
    },
    { "protocol": "blackhole", "tag": "block" }
  ],
  "dns": {
    "servers": [
      "8.8.8.8",
      "1.1.1.1",
      "2001:4860:4860::8888",
      "2606:4700:4700::1111",
      "localhost"
    ]
  },
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "block" }
    ]
  }
}
EOF
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl restart "$SERVICE" >/dev/null 2>&1 || service "$SERVICE" restart
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
  local def="www.cloudflare.com"
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
    echo -e "${yellow}域名示例：www.cloudflare.com${none}"
  done
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
    if ! apt_update_safe; then
      warn "APT update 失败，无法安装 qrencode"
      return 1
    fi
    apt_install_safe qrencode
  fi

  private_key="$(echo -n "$private_key" | tr -d '\n\r[:space:]' | sed 's/\x1b\[[0-9;]*m//g')"

  local public_key
  public_key="$(calc_public_from_private "${private_key}" 2>/dev/null || true)"
  if [[ -z "${public_key}" ]]; then
    warn "私钥无法计算出公钥（私钥可能被污染/长度不对）。请重新生成密钥对。"
    return 1
  fi

  get_public_ips
  local ip netstack show_ip
  if [[ -n "${IPv4}" ]]; then netstack=4; ip="${IPv4}"
  elif [[ -n "${IPv6}" ]]; then netstack=6; ip="${IPv6}"
  else netstack=4; ip="YOUR_SERVER_IP"
  fi
  show_ip="${ip}"
  [[ "${netstack}" == "6" ]] && show_ip="[${ip}]"

  local vless
  vless="vless://${uuid}@${show_ip}:${port}?flow=${FLOW}&encryption=${ENCRYPTION}&type=${NETWORK}&security=reality&sni=${domain}&fp=${FINGERPRINT}&pbk=${public_key}&sid=${shortid}&spx=${SPIDERX}#R_${show_ip}"

  echo
  echo "---------- Xray 配置信息 -------------"
  echo -e "${green} ---提示..这是 VLESS Reality 服务器配置--- ${none}"
  echo -e "${yellow} 地址 (Address) = ${cyan}${ip}${none}"
  echo -e "${yellow} 端口 (Port) = ${cyan}${port}${none}"
  echo -e "${yellow} 用户ID (User ID / UUID) = ${cyan}${uuid}${none}"
  echo -e "${yellow} 流控 (Flow) = ${cyan}${FLOW}${none}"
  echo -e "${yellow} 加密 (Encryption) = ${cyan}${ENCRYPTION}${none}"
  echo -e "${yellow} 传输协议 (Network) = ${cyan}${NETWORK}${none}"
  echo -e "${yellow} 伪装类型 (header type) = ${cyan}${HEADER_TYPE}${none}"
  echo -e "${yellow} 底层传输安全 (TLS) = ${cyan}${TLS_MODE}${none}"
  echo -e "${yellow} SNI = ${cyan}${domain}${none}"
  echo -e "${yellow} 指纹 (Fingerprint) = ${cyan}${FINGERPRINT}${none}"
  echo -e "${yellow} 公钥 (PublicKey) = ${cyan}${public_key}${none}"
  echo -e "${yellow} ShortId = ${cyan}${shortid}${none}"
  echo -e "${yellow} SpiderX = ${cyan}${SPIDERX}${none}"
  echo
  echo "---------- VLESS Reality URL ----------"
  echo -e "${cyan}${vless}${none}"
  echo
  echo "二维码（UTF8）"
  qrencode -t UTF8 "${vless}"

  {
    echo "---------- Xray 配置信息 -------------"
    echo " ---提示..这是 VLESS Reality 服务器配置--- "
    echo " 地址 (Address) = ${ip}"
    echo " 端口 (Port) = ${port}"
    echo " 用户ID (User ID / UUID) = ${uuid}"
    echo " 流控 (Flow) = ${FLOW}"
    echo " 加密 (Encryption) = ${ENCRYPTION}"
    echo " 传输协议 (Network) = ${NETWORK}"
    echo " 伪装类型 (header type) = ${HEADER_TYPE}"
    echo " 底层传输安全 (TLS) = ${TLS_MODE}"
    echo " SNI = ${domain}"
    echo " 指纹 (Fingerprint) = ${FINGERPRINT}"
    echo " 公钥 (PublicKey) = ${public_key}"
    echo " ShortId = ${shortid}"
    echo " SpiderX = ${SPIDERX}"
    echo
    echo "---------- VLESS Reality URL ----------"
    echo "${vless}"
    echo
    echo "二维码（UTF8）"
    qrencode -t UTF8 "${vless}"
  } > "${INFO_FILE}"

  ok "已保存到：${INFO_FILE}"
}

# showconf 与“打印节点信息”合并：只保留一个
showconf() { print_full_info_and_qr; }

# -----------------------------
#  安装/重装
# -----------------------------
install_xray() {


  echo -e "${yellow}开始安装/重装 Xray Reality...${none}"
  if ! apt_update_safe; then
    warn "APT update 失败：请先修复 sources.list 再运行脚本。"
    return 1
  fi

  apt_install_safe curl wget sudo jq net-tools lsof qrencode openssl xxd

  local XRAY_VER
  XRAY_VER="$(choose_xray_version "v25.10.15")"

  echo -e "${yellow}安装 Xray ${XRAY_VER}${none}"
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --version "${XRAY_VER}"
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install-geodata

  echo
  echo -e "${yellow}初始化配置（回车随机化/输入需合法格式）${none}"
  echo "----------------------------------------------------------------"

  local p u sid d
  p="$(input_port)"
  u="$(input_uuid)"
  sid="$(input_shortid)"
  d="$(input_domain)"

  echo -e "${yellow}正在生成私钥和公钥...${none}"
  local pk_pair pk pub
  pk_pair="$(generate_keys || true)"
  pk="${pk_pair%%|*}"
  pub="${pk_pair##*|}"

  if [[ -z "$pk" || -z "$pub" ]]; then
    warn "生成私钥/公钥失败（openssl/xxd/base64 环境异常）。"
    return 1
  fi

  echo
  echo -e "${green}========== 本次最终配置（即将写入服务器） ==========${none}"
  echo -e "${yellow} Address(自动探测) = ${cyan}(安装后打印时显示)${none}"
  echo -e "${yellow} 端口 (Port) = ${cyan}${p}${none}"
  echo -e "${yellow} 用户ID (UUID) = ${cyan}${u}${none}"
  echo -e "${yellow} SNI = ${cyan}${d}${none}"
  echo -e "${yellow} ShortId = ${cyan}${sid}${none}"
  echo -e "${yellow} 私钥 (PrivateKey/服务器) = ${cyan}${pk}${none}"
  echo -e "${yellow} 公钥 (PublicKey/客户端) = ${cyan}${pub}${none}"
  echo "----------------------------------------------------------------"

  write_config_and_restart "$p" "$u" "$pk" "$sid" "$d"
  ok "安装/配置完成，已重启 Xray。"
  echo -e "${yellow}客户端请使用 PublicKey：${cyan}${pub}${none}"

  print_full_info_and_qr
}

# -----------------------------
#  卸载
# -----------------------------
uninstall_xray() {
  warn "即将卸载 Xray（停止服务、移除配置、移除程序）。"
  pause
  systemctl stop "$SERVICE" >/dev/null 2>&1 || service "$SERVICE" stop || true
  rm -f "$CONFIG" "$INFO_FILE" >/dev/null 2>&1 || true
  if command -v xray >/dev/null 2>&1; then
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove || true
  fi
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
  write_config_and_restart "$new_port" "$uuid" "$private_key" "$shortid" "$domain"
  ok "已更新端口并重启 Xray（其它参数保持不变）。"
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
  write_config_and_restart "$port" "$new_uuid" "$private_key" "$new_sid" "$domain"
  ok "已更新 UUID + ShortID 并重启 Xray（其它参数保持不变）。"
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
  pk_pair="$(generate_keys || true)"
  pk="${pk_pair%%|*}"
  pub="${pk_pair##*|}"

  if [[ -z "$pk" || -z "$pub" ]]; then
    warn "生成私钥/公钥失败（openssl/xxd/base64 环境异常）。"
    return 1
  fi

  write_config_and_restart "$port" "$uuid" "$pk" "$shortid" "$domain" || return 1
  ok "已重置私钥/公钥并重启 Xray。"
  echo -e "${yellow}新的 PublicKey（客户端用）= ${cyan}${pub}${none}"

  print_full_info_and_qr
}

# -----------------------------
#  状态
# -----------------------------
status_xray() {
  echo
  echo -e "${yellow}Xray 服务状态：${none}"
  systemctl status "$SERVICE" --no-pager -l 2>/dev/null || service "$SERVICE" status || true
  echo
  if [[ -f "$CONFIG" ]]; then
    if read_current_config; then
      echo -e "${yellow}当前配置摘要：${none}"
      echo -e " Port : ${cyan}${port}${none}"
      echo -e " UUID : ${cyan}${uuid}${none}"
      echo -e " SNI : ${cyan}${domain}${none}"
      echo -e " ShortID : ${cyan}${shortid}${none}"
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



change_tz() {
  local tz=""
  read_tty "请输入时区（回车默认 Asia/Shanghai，例如 Asia/Tokyo）: " tz
  [[ -z "$tz" ]] && tz="Asia/Shanghai"
  timedatectl set-timezone "$tz" && ok "系统时区已设置为：$tz" || warn "设置失败：请检查 timedatectl / 时区名是否存在"
}

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

swap_cache() {
  local size_mb confirm
  echo "当前 Swap："
  free -h | awk 'NR==1 || /Swap:/ {print}'
  echo ""

  read_tty "请输入 Swap 大小（MB，建议 >=512）: " size_mb
  [[ "$size_mb" =~ ^[0-9]+$ ]] || { warn "请输入有效数字"; return 1; }

  read_tty "确认创建/重建 Swap=${size_mb}MB ? (y/n): " confirm
  [[ "$confirm" == "y" || "$confirm" == "Y" ]] || { warn "已取消"; return 0; }

  if swapon --show | grep -q "/swapfile"; then
    swapoff /swapfile || true
    rm -f /swapfile || true
  fi

  fallocate -l "${size_mb}M" /swapfile || { warn "创建 swapfile 失败（磁盘空间不足？）"; return 1; }
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  swapon /swapfile
  grep -q "^/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab

  ok "Swap 已启用："
  swapon --show
  free -h | awk 'NR==1 || /Swap:/ {print}'
}

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

bbrv3() {
  if [[ ! -r /etc/os-release ]]; then
    warn "无法判断系统类型"
    return 1
  fi
  . /etc/os-release
  if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
    warn "BBRv3（XanMod）仅支持 Debian/Ubuntu"
    return 1
  fi

  apt_install_safe wget gnupg ca-certificates >/dev/null 2>&1 || true
  wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
  echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' >/etc/apt/sources.list.d/xanmod-release.list

  apt_update_safe || true

  local version
  version="$(wget -qO- https://dl.xanmod.org/check_x86-64_psabi.sh | bash 2>/dev/null | grep -oE 'x86-64-v[0-9]+' | head -n1 | sed 's/x86-64-v//')"
  [[ -z "$version" ]] && version=3

  apt_install_safe "linux-xanmod-x64v${version}" || { warn "安装 XanMod 内核失败"; return 1; }

  cat >/etc/sysctl.d/99-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl --system >/dev/null 2>&1 || true

  ok "XanMod 内核已安装并写入 BBR 配置。请重启后生效。"
}

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


auth_key() {
  set -e

  # ===== 可改参数 =====
  local target_user="${1:-root}"     # auth_key root / auth_key ubuntu
  local ssh_port="${2:-22}"          # 预留：如果你要改端口可用
  # ===================

  if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: 请用 root 执行（需要写 /etc/ssh/sshd_config 并重启 ssh）。"
    return 1
  fi

  read -r -p "是否设置密钥登录方式？[y/N] " yn
  case "$yn" in
    y|Y|yes|YES) ;;
    *) echo "已取消。"; return 0 ;;
  esac

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

  # 设置/追加配置项的 helper
  _set_sshd_kv() {
    local k="$1" v="$2"
    if grep -Eq "^[[:space:]]*#?[[:space:]]*$k[[:space:]]+" "$cfg"; then
      # 替换第一处匹配
      sed -i "0,/^[[:space:]]*#\?[[:space:]]*$k[[:space:]].*/s//${k} ${v}/" "$cfg"
    else
      printf "\n%s %s\n" "$k" "$v" >> "$cfg"
    fi
  }

  _set_sshd_kv "PubkeyAuthentication" "yes"
  _set_sshd_kv "AuthorizedKeysFile" ".ssh/authorized_keys"

  # “关闭端口访问功能”——这里实现为关闭密码登录
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

  echo "完成。建议：打开新终端测试密钥登录成功后，再退出当前会话。"
}


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
    echo "9) 安装BBR3"
    echo "10) BBR/TCP 优化"
    echo "11) 设置定时重启"
    echo "12) 修改SSH端口2222"
    echo "13) 设置ufw"
    echo "14) 设置SSH秘钥"
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
      9) bbrv3; pause ;;
      10) bbrx; pause ;;
      11) cron_reboot; pause ;;
      12) ssh_port 2222; pause ;;
      13) firewall; pause ;;
      14) auth_key ;;
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

  echo -e "${yellow}开始安装 Xray Reality（参数模式）...${none}"
  if ! apt_update_safe; then
    warn "APT update 失败"
    return 1
  fi

  apt_install_safe curl wget sudo jq net-tools lsof qrencode openssl xxd

  local XRAY_VER
  XRAY_VER="$(choose_xray_version "v25.10.15")"

  echo -e "${yellow}安装 Xray ${XRAY_VER}${none}"
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --version "${XRAY_VER}"
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install-geodata

  local private_key public_key shortid
  local key_pair
  key_pair="$(generate_keys || true)"
  private_key="${key_pair%%|*}"
  public_key="${key_pair##*|}"

  if [[ -z "$private_key" || -z "$public_key" ]]; then
    warn "生成私钥/公钥失败（openssl/xxd/base64 环境异常）。"
    return 1
  fi

  shortid="$(rand_shortid)"

  echo
  echo -e "${yellow} 私钥 (PrivateKey) = ${cyan}${private_key}${none}"
  echo -e "${yellow} 公钥 (PublicKey) = ${cyan}${public_key}${none}"
  echo -e "${yellow} ShortId = ${cyan}${shortid}${none}"
  echo "----------------------------------------------------------------"

  write_config_and_restart "$port" "$uuid" "$private_key" "$shortid" "$domain"
  ok "安装/配置完成，已重启 Xray。"

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

    echo -e "${cyan}${bold}╔══════════════════════════════════════════════╗${none}"
    echo -e "${cyan}${bold}║            Xray Reality 管理界面            ║${none}"
    echo -e "${cyan}${bold}╚══════════════════════════════════════════════╝${none}"
    echo -e "${gray}--------------------------------------------------${none}"

    echo -e " ${yellow}${bold}1)${none} 安装"
    echo -e " ${yellow}${bold}2)${none} 卸载"
    echo -e " ${yellow}${bold}3)${none} 打印节点信息"
    echo -e " ${yellow}${bold}4)${none} 系统参数配置"
    echo -e " ${yellow}${bold}5)${none} 回程路由测试"
    echo -e " ${yellow}${bold}6)${none} IP质量检测）"
    echo -e " ${yellow}${bold}7)${none} 系统查询"
    echo -e " ${yellow}${bold}8)${none} 查看状态"
    echo -e " ${red}${bold}0)${none} Exit"

    echo -e "${gray}--------------------------------------------------${none}"
    echo -e "${dim}${gray}提示：输入数字后回车${none}"
    echo -ne "${green}${bold}请选择 [0-8]${none}${green}: ${none}"

    local choice=""
    read_tty "" choice

    case "${choice}" in
      1) install_xray; pause ;;
      2) uninstall_xray; pause ;;
      3) showconf; pause ;;
      4) changeconf ;;
      5) besttrace; pause ;;
      6) ipquality; pause ;;
      7) linux_ps; pause ;;
      8) status_xray; pause ;;
      0) exit 0 ;;
      *) error; pause ;;
    esac
  done
}



# -----------------------------
#  主程序入口
# -----------------------------
need_root

if [[ $# -ge 1 ]]; then
  netstack=4
  case "${1:-}" in
    4) netstack=4 ;;
    6) netstack=6 ;;
    *) netstack=4 ;;
  esac

  get_public_ips

  ip=""
  if [[ "$netstack" == "4" && -n "${IPv4:-}" ]]; then
    ip="${IPv4}"
  elif [[ "$netstack" == "6" && -n "${IPv6:-}" ]]; then
    ip="${IPv6}"
  elif [[ -n "${IPv4:-}" ]]; then
    ip="${IPv4}"
    netstack=4
  elif [[ -n "${IPv6:-}" ]]; then
    ip="${IPv6}"
    netstack=6
  else
    warn "没有获取到公共 IP"
    exit 1
  fi

  port="${2:-$(( (RANDOM % 50001) + 10000 ))}"
  domain="${3:-www.cloudflare.com}"
  uuid="${4:-$(rand_uuid)}"

  echo -e "${yellow} netstack = ${cyan}${netstack}${none}"
  echo -e "${yellow} 本机IP = ${cyan}${ip}${none}"
  echo -e "${yellow} 端口 (Port) = ${cyan}${port}${none}"
  echo -e "${yellow} 用户ID (User ID / UUID) = ${cyan}${uuid}${none}"
  echo -e "${yellow} SNI = ${cyan}${domain}${none}"
  echo "----------------------------------------------------------------"

  install_with_params "$netstack" "$port" "$domain" "$uuid"
else
  menu
fi
