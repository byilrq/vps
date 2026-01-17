#!/bin/bash
# h.sh - Hysteria 2 installer + separate menus:
# 4) Modify Hysteria config
# 5) Modify system config (calls sys_conf.sh)

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"
hui='\e[37m'
zi='\033[35m'
tianlan='\033[96m'

red(){ echo -e "${RED}\033[01m$1${PLAIN}"; }
green(){ echo -e "${GREEN}\033[01m$1${PLAIN}"; }
yellow(){ echo -e "${YELLOW}\033[01m$1${PLAIN}"; }
skyblue(){ echo -e "\033[1;36m$1\033[0m"; }

need_root() {
  [[ $EUID -ne 0 ]] && red "注意: 请在root用户下运行脚本" && exit 1
}

# -----------------------------
# Wait apt locks (Debian/Ubuntu)
# -----------------------------
wait_for_apt_lock() {
  local max_attempts=60
  local attempt=0
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
    if [ $attempt -ge $max_attempts ]; then
      red "apt 锁等待超时，请手动检查进程并释放锁（例如 kill <PID>），然后重试。"
      exit 1
    fi
    yellow "apt 锁被占用（可能有其他更新进程），等待中... ($attempt/$max_attempts)"
    sleep 1
    attempt=$((attempt + 1))
  done
}

# -----------------------------
# OS detect + package arrays
# -----------------------------
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'" "fedora")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS" "Fedora")
PACKAGE_UPDATE=("apt-get update -y" "apt-get update -y" "yum -y update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt-get install -y" "apt-get install -y" "yum -y install" "yum -y install" "yum -y install")
PACKAGE_REMOVE=("apt-get remove -y" "apt-get remove -y" "yum -y remove" "yum -y remove" "yum -y remove")
PACKAGE_UNINSTALL=("apt-get autoremove -y" "apt-get autoremove -y" "yum -y autoremove" "yum -y autoremove" "yum -y autoremove")

CMD=(
  "$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)"
  "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)"
  "$(lsb_release -sd 2>/dev/null)"
  "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)"
  "$(grep . /etc/redhat-release 2>/dev/null)"
  "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')"
)

detect_os() {
  for i in "${CMD[@]}"; do
    SYS="$i" && [[ -n $SYS ]] && break
  done
  for ((int = 0; int < ${#REGEX[@]}; int++)); do
    if [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]]; then
      SYSTEM="${RELEASE[int]}"
      [[ -n $SYSTEM ]] && break
    fi
  done
  [[ -z $SYSTEM ]] && red "目前暂不支持你的VPS的操作系统！" && exit 1
}

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
# Real IP
# -----------------------------
realip(){
  ip=$(curl -s4m8 ip.sb -k) || ip=$(curl -s6m8 ip.sb -k)
}

# -----------------------------
# Cert install
# -----------------------------
inst_cert(){
  green "Hysteria 2 协议证书申请方式如下："
  echo ""
  echo -e " ${GREEN}1.${PLAIN} 必应自签证书 ${YELLOW}（默认）${PLAIN}"
  echo -e " ${GREEN}2.${PLAIN} Acme 脚本自动申请"
  echo -e " ${GREEN}3.${PLAIN} 自定义证书路径"
  echo ""
  read -rp "请输入选项 [1-3]: " certInput

  if [[ $certInput == 2 ]]; then
    cert_path="/root/cert.crt"
    key_path="/root/private.key"
    chmod a+x /root >/dev/null 2>&1 || true

    if [[ -f /root/cert.crt && -f /root/private.key && -s /root/cert.crt && -s /root/private.key && -f /root/ca.log ]]; then
      domain=$(cat /root/ca.log)
      green "检测到原有域名：$domain 的证书，正在应用"
      hy_domain=$domain
    else
      realip
      read -rp "请输入需要申请证书的域名: " domain
      [[ -z $domain ]] && red "未输入域名，无法执行操作！" && exit 1
      green "已输入的域名：$domain" && sleep 1

      domainIP=$(curl -sm8 ipget.net/?ip="${domain}")
      if [[ $domainIP == $ip ]]; then
        ${PACKAGE_INSTALL[int]} curl wget sudo socat openssl cron || true
        curl https://get.acme.sh | sh -s email=$(date +%s%N | md5sum | cut -c 1-16)@gmail.com || { red "安装 acme.sh 失败"; exit 1; }
        source ~/.bashrc >/dev/null 2>&1 || true
        bash ~/.acme.sh/acme.sh --upgrade --auto-upgrade
        bash ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

        if [[ -n $(echo $ip | grep ":") ]]; then
          bash ~/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --listen-v6 --insecure || { red "签发失败"; exit 1; }
        else
          bash ~/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --insecure || { red "签发失败"; exit 1; }
        fi

        bash ~/.acme.sh/acme.sh --install-cert -d "${domain}" --key-file /root/private.key --fullchain-file /root/cert.crt --ecc || {
          red "安装证书失败"
          exit 1
        }

        if [[ -f /root/cert.crt && -f /root/private.key && -s /root/cert.crt && -s /root/private.key ]]; then
          echo "$domain" > /root/ca.log
          sed -i '/--cron/d' /etc/crontab >/dev/null 2>&1 || true
          echo "0 0 * * * root bash /root/.acme.sh/acme.sh --cron -f >/dev/null 2>&1" >> /etc/crontab

          green "证书申请成功! 已保存到 /root/"
          yellow "证书路径: /root/cert.crt"
          yellow "私钥路径: /root/private.key"
          hy_domain=$domain
        fi
      else
        red "当前域名解析的IP与当前VPS使用的真实IP不匹配"
        yellow "建议：关闭 Cloudflare 小云朵（仅DNS）、检查解析IP是否为真实IP。"
        exit 1
      fi
    fi

  elif [[ $certInput == 3 ]]; then
    read -rp "请输入公钥文件 crt 的路径: " cert_path
    read -rp "请输入密钥文件 key 的路径: " key_path
    read -rp "请输入证书的域名: " domain
    [[ -z "$cert_path" || -z "$key_path" || -z "$domain" ]] && red "参数不完整" && exit 1
    [[ ! -s "$cert_path" || ! -s "$key_path" ]] && red "证书/私钥文件不存在或为空" && exit 1
    hy_domain=$domain

  else
    green "将使用必应自签证书作为 Hysteria 2 的节点证书"
    mkdir -p /etc/hysteria

    cert_path="/etc/hysteria/cert.crt"
    key_path="/etc/hysteria/private.key"

    openssl ecparam -genkey -name prime256v1 -out "$key_path"
    openssl req -new -x509 -days 36500 -key "$key_path" -out "$cert_path" -subj "/CN=www.bing.com"

    chmod 644 "$cert_path"
    chmod 600 "$key_path"

    hy_domain="www.bing.com"
    domain="www.bing.com"
  fi
}

# -----------------------------
# Port + hopping
# -----------------------------
inst_jump(){
  green "Hysteria 2 端口使用模式如下："
  echo ""
  echo -e " ${GREEN}1.${PLAIN} 单端口 ${YELLOW}（默认）${PLAIN}"
  echo -e " ${GREEN}2.${PLAIN} 端口跳跃"
  echo ""
  read -rp "请输入选项 [1-2]: " jumpInput

  if [[ $jumpInput == 2 ]]; then
    read -rp "设置范围端口的起始端口 (建议10000-65535之间): " firstport
    read -rp "设置范围端口的末尾端口 (必须大于起始端口): " endport

    while [[ -z "$firstport" || -z "$endport" || "$firstport" -ge "$endport" ]]; do
      red "范围无效：起始端口必须小于末尾端口"
      read -rp "起始端口: " firstport
      read -rp "末尾端口: " endport
    done

    iptables -t nat -A PREROUTING -p udp --dport "$firstport:$endport" -j DNAT --to-destination ":$port" >/dev/null 2>&1 || true
    ip6tables -t nat -A PREROUTING -p udp --dport "$firstport:$endport" -j DNAT --to-destination ":$port" >/dev/null 2>&1 || true
    netfilter-persistent save >/dev/null 2>&1 || true
    green "已启用端口跳跃：$firstport-$endport -> $port"
  else
    yellow "将继续使用单端口模式"
    firstport=""
    endport=""
  fi
}

inst_port(){
  iptables -t nat -F PREROUTING >/dev/null 2>&1 || true
  read -rp "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）: " port
  [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)

  until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
    red "端口 $port 已被占用，请更换"
    read -rp "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）: " port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
  done

  yellow "Hysteria 2 使用端口：$port"
  inst_jump
}

inst_pwd(){
  read -rp "设置 Hysteria 2 密码（回车随机）: " auth_pwd
  [[ -z $auth_pwd ]] && auth_pwd=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)
  yellow "密码：$auth_pwd"
}

inst_site(){
  read -rp "请输入伪装网站地址（去除https://） [回车:video.unext.jp]: " proxysite
  [[ -z $proxysite ]] && proxysite="video.unext.jp"
  yellow "伪装站点：$proxysite"
}

# -----------------------------
# Install Hysteria2
# -----------------------------
insthysteria(){
  realip

  if [[ "$SYSTEM" != "CentOS" ]]; then
    wait_for_apt_lock || true
  fi
  ${PACKAGE_UPDATE[int]} || true
  if [[ "$SYSTEM" != "CentOS" ]]; then
    wait_for_apt_lock || true
  fi

  ${PACKAGE_INSTALL[int]} curl wget sudo qrencode procps iptables iptables-persistent netfilter-persistent || {
    red "依赖安装失败"
    exit 1
  }

  local url="https://raw.githubusercontent.com/byilrq/vps/main/install_server.sh"
  wget -qO /tmp/install_server.sh "$url" || { red "下载 install_server.sh 失败"; exit 1; }
  [[ -s /tmp/install_server.sh ]] || { red "install_server.sh 文件为空"; exit 1; }
  bash /tmp/install_server.sh
  rm -f /tmp/install_server.sh

  [[ -f "/usr/local/bin/hysteria" ]] || { red "Hysteria 2 安装失败！"; exit 1; }
  green "Hysteria 2 安装成功！"

  inst_cert
  inst_port
  inst_pwd
  inst_site

  mkdir -p /etc/hysteria /root/hy

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
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false

auth:
  type: password
  password: $auth_pwd

speedTest: true

masquerade:
  type: proxy
  proxy:
    url: https://$proxysite
    rewriteHost: true
EOF

  if [[ -n $(echo $ip | grep ":") ]]; then
    last_ip="[$ip]"
  else
    last_ip="$ip"
  fi

  # client server always use real listening port
  cat > /root/hy/hy-client.yaml <<EOF
server: $last_ip:$port

auth: $auth_pwd

tls:
  sni: $hy_domain
  insecure: true

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
  udp:
    hopInterval: 15s
EOF

  if [[ -n "$firstport" && -n "$endport" ]]; then
    echo "    portRange: \"$firstport-$endport\"" >> /root/hy/hy-client.yaml
    port_range="$firstport-$endport"
  else
    port_range="$port"
  fi

  ur1="hysteria2://$auth_pwd@$last_ip:$port/?sni=$hy_domain&peer=$last_ip&insecure=1&mport=$port_range#H"
  echo "$ur1" > /root/hy/ur1.txt

  systemctl daemon-reload
  systemctl enable hysteria-server >/dev/null 2>&1 || true
  systemctl start hysteria-server

  if systemctl is-active --quiet hysteria-server && [[ -f '/etc/hysteria/config.yaml' ]]; then
    green "Hysteria 2 服务启动成功"
  else
    red "Hysteria 2 服务启动失败，请运行 systemctl status hysteria-server 查看状态"
    exit 1
  fi

  red "======================================================================================"
  green "Hysteria 2 代理服务安装完成"
  yellow "服务端配置 /etc/hysteria/config.yaml："
  green "$(cat /etc/hysteria/config.yaml)"
  yellow "客户端配置 /root/hy/hy-client.yaml："
  green "$(cat /root/hy/hy-client.yaml)"
  yellow "分享链接 /root/hy/ur1.txt："
  green "$(cat /root/hy/ur1.txt)"
  yellow "二维码："
  qrencode -o - -t ANSIUTF8 "$(cat /root/hy/ur1.txt)" || true
}

# -----------------------------
# Uninstall / start / stop
# -----------------------------
unsthysteria(){
  systemctl stop hysteria-server.service >/dev/null 2>&1 || true
  systemctl disable hysteria-server.service >/dev/null 2>&1 || true
  rm -f /lib/systemd/system/hysteria-server.service /lib/systemd/system/hysteria-server@.service >/dev/null 2>&1 || true
  rm -rf /usr/local/bin/hysteria /etc/hysteria /root/hy /root/hysteria.sh >/dev/null 2>&1 || true
  iptables -t nat -F PREROUTING >/dev/null 2>&1 || true
  netfilter-persistent save >/dev/null 2>&1 || true
  green "Hysteria 2 已彻底卸载完成！"
}

starthysteria(){ systemctl enable --now hysteria-server >/dev/null 2>&1 || systemctl start hysteria-server; }
stophysteria(){ systemctl disable --now hysteria-server >/dev/null 2>&1 || systemctl stop hysteria-server; }

hysteriaswitch(){
  yellow "请选择你需要的操作："
  echo ""
  echo -e " ${GREEN}1.${PLAIN} 启动 Hysteria 2"
  echo -e " ${GREEN}2.${PLAIN} 关闭 Hysteria 2"
  echo -e " ${GREEN}3.${PLAIN} 重启 Hysteria 2"
  echo ""
  read -rp "请输入选项 [0-3]: " switchInput
  case $switchInput in
    1 ) starthysteria ;;
    2 ) stophysteria ;;
    3 ) stophysteria && starthysteria ;;
    * ) return 1 ;;
  esac
}

# -----------------------------
# Show status / config
# -----------------------------
showstatus(){ systemctl status hysteria-server.service; }

showconf(){
  yellow "服务端配置 /etc/hysteria/config.yaml："
  green "$(cat /etc/hysteria/config.yaml 2>/dev/null)"
  yellow "客户端配置 /root/hy/hy-client.yaml："
  green "$(cat /root/hy/hy-client.yaml 2>/dev/null)"
  yellow "分享链接 /root/hy/ur1.txt："
  green "$(cat /root/hy/ur1.txt 2>/dev/null)"
  yellow "二维码："
  [[ -f /root/hy/ur1.txt ]] && qrencode -o - -t ANSIUTF8 "$(cat /root/hy/ur1.txt)" || true
  systemctl restart hysteria-server.service >/dev/null 2>&1 || true
}

# -----------------------------
# Hysteria config changes
# -----------------------------
changeport(){
  local oldport
  oldport=$(awk -F':' 'NR==1{gsub(/ /,"",$2); print $2}' /etc/hysteria/config.yaml 2>/dev/null | tr -d '\r')

  read -rp "设置 Hysteria 2 端口[1-65535]（回车随机）: " port
  [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)

  until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
    red "端口 $port 已被占用，请更换"
    read -rp "设置 Hysteria 2 端口[1-65535]（回车随机）: " port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
  done

  sed -i "1s/:$oldport/:$port/g" /etc/hysteria/config.yaml 2>/dev/null || true
  sed -i "s/:$oldport/:$port/g" /root/hy/hy-client.yaml 2>/dev/null || true
  [[ -f /root/hy/ur1.txt ]] && sed -i "s/:$oldport\/?/:$port\/?/g" /root/hy/ur1.txt 2>/dev/null || true

  stophysteria && starthysteria

  green "Hysteria 2 端口已成功修改为：$port"
  showconf
}

update_hysteria_link() {
  local newpasswd="$1"
  local link_file="${2:-/root/hy/ur1.txt}"
  local link new_link

  [[ -f "$link_file" ]] || { red "链接文件不存在：$link_file"; return 1; }
  link=$(cat "$link_file")
  [[ -n "$link" ]] || { red "链接文件为空：$link_file"; return 1; }

  new_link=$(echo "$link" | sed "s#\(hysteria2://\)[^@]*@#\1${newpasswd}@#")
  echo "$new_link" > "$link_file"
  skyblue "$new_link"
  skyblue "Hysteria 2 二维码如下"
  qrencode -o - -t ANSIUTF8 "$new_link" || true
}

changepasswd() {
  local config_file="/etc/hysteria/config.yaml"
  local client_file="/root/hy/hy-client.yaml"
  local link_file="/root/hy/ur1.txt"

  [[ -f $config_file ]] || { red "配置文件不存在：$config_file"; return 1; }
  [[ -f $client_file ]] || { red "客户端配置不存在：$client_file"; return 1; }
  [[ -f $link_file ]] || { red "分享链接不存在：$link_file"; return 1; }

  cp "$config_file" "${config_file}.bak" >/dev/null 2>&1 || true

  local oldpasswd
  oldpasswd=$(awk '/auth:/,/password:/ {if ($1 ~ /password:/) print $2}' "$config_file" | xargs)
  [[ -n "$oldpasswd" ]] || { red "无法提取旧密码，请检查 $config_file"; return 1; }

  local passwd
  read -rp "设置 Hysteria 2 密码（回车随机）: " passwd
  passwd=${passwd:-$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)}

  sed -i "/auth:/,/password:/s/^ *password: .*/  password: $passwd/" "$config_file"
  grep -q "password: $passwd" "$config_file" || { red "写入服务端密码失败"; return 1; }

  if grep -q "^auth: " "$client_file"; then
    sed -i "s/^auth: .*/auth: $passwd/" "$client_file"
  else
    echo "auth: $passwd" >> "$client_file"
  fi

  update_hysteria_link "$passwd" "$link_file" || true

  systemctl restart hysteria-server.service || { red "服务重启失败"; return 1; }
  green "密码已修改并生效"
  showconf
}

change_cert(){
  local old_cert old_key old_hydomain
  old_cert=$(grep -E '^\s*cert:' /etc/hysteria/config.yaml 2>/dev/null | awk '{print $2}')
  old_key=$(grep -E '^\s*key:' /etc/hysteria/config.yaml 2>/dev/null | awk '{print $2}')
  old_hydomain=$(grep -E '^\s*sni:' /root/hy/hy-client.yaml 2>/dev/null | awk '{print $2}')

  inst_cert

  [[ -n "$old_cert" ]] && sed -i "s!$old_cert!$cert_path!g" /etc/hysteria/config.yaml
  [[ -n "$old_key" ]] && sed -i "s!$old_key!$key_path!g" /etc/hysteria/config.yaml
  [[ -n "$old_hydomain" ]] && sed -i "s/$old_hydomain/$hy_domain/g" /root/hy/hy-client.yaml

  stophysteria && starthysteria
  green "证书类型/路径已修改"
  showconf
}

changeproxysite(){
  local oldproxysite
  oldproxysite=$(grep -E '^\s*url:\s*https://' /etc/hysteria/config.yaml 2>/dev/null | awk -F'https://' '{print $2}')

  inst_site

  if [[ -n "$oldproxysite" ]]; then
    sed -i "s#https://$oldproxysite#https://$proxysite#g" /etc/hysteria/config.yaml
  else
    sed -i "s#url: https://.*#url: https://$proxysite#g" /etc/hysteria/config.yaml 2>/dev/null || true
  fi

  stophysteria && starthysteria
  green "伪装网站已修改为：$proxysite"
  showconf
}

menu_hy_conf(){
  while true; do
    clear
    green "Hysteria 2 配置变更选择如下:"
    echo -e " ${GREEN}1.${tianlan} 修改端口"
    echo -e " ${GREEN}2.${tianlan} 修改密码"
    echo -e " ${GREEN}3.${tianlan} 修改证书类型/路径"
    echo -e " ${GREEN}4.${tianlan} 修改伪装网站"
    echo " ---------------------------------------------------"
    echo -e " ${GREEN}0.${PLAIN} 返回"
    echo ""
    read -rp "请选择 [0-4]: " confAnswer
    case $confAnswer in
      1 ) changeport ;;
      2 ) changepasswd ;;
      3 ) change_cert ;;
      4 ) changeproxysite ;;
      0 ) break ;;
      * ) yellow "无效选项"; sleep 1 ;;
    esac
  done
}

# -----------------------------
# Core updates / tools
# -----------------------------
update_core1(){
  green "官方更新方式必须先脚本安装后使用，否则会失败。"
  systemctl stop hysteria-server.service >/dev/null 2>&1 || true
  rm -f /usr/local/bin/hysteria
  bash <(curl -fsSL https://get.hy2.sh/) || { red "更新失败"; return 1; }
  systemctl enable --now hysteria-server.service >/dev/null 2>&1 || true
  systemctl restart hysteria-server.service
  green "Hysteria 内核已更新并重启"
}

update_core2(){
  systemctl stop hysteria-server.service >/dev/null 2>&1 || true
  rm -f /usr/local/bin/hysteria
  wget -qO /tmp/install_server.sh https://raw.githubusercontent.com/byilrq/vps/main/install_server.sh || { red "下载失败"; return 1; }
  [[ -s /tmp/install_server.sh ]] || { red "文件为空"; return 1; }
  bash /tmp/install_server.sh
  rm -f /tmp/install_server.sh
  systemctl restart hysteria-server.service
  green "Hysteria 内核已更新并重启"
}

besttrace(){ wget -qO- git.io/besttrace | bash; }
ipquality(){ curl -sL https://Check.Place | bash -s - -I; }

linux_ps() {
  clear
  local os_info kernel cpu_model cpu_cores mem disk ipv4 ipv6 dns load uptime_str
  os_info=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d '=' -f2 | tr -d '"')
  kernel=$(uname -r)
  cpu_model=$(lscpu 2>/dev/null | awk -F': +' '/Model name:/ {print $2; exit}')
  cpu_cores=$(nproc 2>/dev/null)
  mem=$(free -h | awk '/Mem:/ {print $3 "/" $2}')
  disk=$(df -h / | awk 'NR==2{print $3 "/" $2 " (" $5 ")"}')
  ipv4=$(curl -s4m6 ip.sb -k 2>/dev/null || true)
  ipv6=$(curl -s6m6 ip.sb -k 2>/dev/null || true)
  dns=$(awk '/^nameserver[ \t]+/{printf "%s ", $2} END{print ""}' /etc/resolv.conf 2>/dev/null)
  load=$(uptime | awk -F'load average:' '{print $2}' | xargs)
  uptime_str=$(uptime -p 2>/dev/null)

  echo ""
  echo -e "系统信息查询"
  echo -e "${tianlan}-------------"
  echo -e "${tianlan}系统版本:     ${hui}${os_info}"
  echo -e "${tianlan}Linux版本:    ${hui}${kernel}"
  echo -e "${tianlan}CPU型号:      ${hui}${cpu_model}"
  echo -e "${tianlan}CPU核心数:    ${hui}${cpu_cores}"
  echo -e "${tianlan}内存使用:     ${hui}${mem}"
  echo -e "${tianlan}硬盘占用:     ${hui}${disk}"
  echo -e "${tianlan}系统负载:     ${hui}${load}"
  echo -e "${tianlan}运行时长:     ${hui}${uptime_str}"
  [[ -n "$ipv4" ]] && echo -e "${tianlan}IPv4:         ${hui}${ipv4}"
  [[ -n "$ipv6" ]] && echo -e "${tianlan}IPv6:         ${hui}${ipv6}"
  echo -e "${tianlan}DNS:          ${hui}${dns}"
  echo
  read -rp "回车返回菜单..." _
}

linux_update() {
  if command -v apt-get >/dev/null 2>&1; then
    wait_for_apt_lock || true
    DEBIAN_FRONTEND=noninteractive apt-get update -y
    wait_for_apt_lock || true
    DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y
  elif command -v dnf >/dev/null 2>&1; then
    dnf -y update
  elif command -v yum >/dev/null 2>&1; then
    yum -y update
  else
    red "未知的包管理器!"
    return 1
  fi
  green "系统更新完成"
  read -rp "回车返回菜单..." _
}

# -----------------------------
# Call sys_conf.sh (download + run)
# -----------------------------
run_sys_conf() {
  local url="https://raw.githubusercontent.com/byilrq/vps/main/sys_conf.sh"
  local tmp="/tmp/sys_conf.sh"
  wget -qO "$tmp" "$url" || { red "下载 sys_conf.sh 失败"; return 1; }
  [[ -s "$tmp" ]] || { red "sys_conf.sh 文件为空"; return 1; }
  bash "$tmp"
}

# -----------------------------
# Main menu
# -----------------------------
menu() {
  while true; do
    clear
    echo "#############################################################"
    echo -e "# ${tianlan}Hysteria 2 一键安装脚本 #"
    echo "#############################################################"
    echo ""
    echo -e " ${GREEN}1.${GREEN} 安装 Hysteria 2"
    echo -e " ${GREEN}2.${zi} 卸载 Hysteria 2"
    echo " ---------------------------------------------------"
    echo -e " ${GREEN}3.${tianlan} 关闭、开启、重启 Hysteria 2"
    echo -e " ${GREEN}4.${tianlan} 修改 Hysteria 配置"
    echo -e " ${GREEN}5.${tianlan} 修改 系统配置"
    echo -e " ${GREEN}6.${tianlan} 显示 配置文件"
    echo -e " ${GREEN}7.${tianlan} 查询 运行状态"
    echo -e " ${GREEN}8.${tianlan} 更新内核方式1（官方）"
    echo -e " ${GREEN}9.${tianlan} 更新内核方式2（脚本）"
    echo -e " ${GREEN}10.${tianlan} 回程测试"
    echo -e " ${GREEN}11.${tianlan} IP质量检测"
    echo -e " ${GREEN}12.${tianlan} 系统查询"
    echo -e " ${GREEN}13.${tianlan} 系统更新"
    echo " ---------------------------------------------------"
    echo -e " ${GREEN}0.${PLAIN} 退出脚本"
    echo ""
    read -rp "请输入选项 [0-13]: " menuInput
    case $menuInput in
      1 ) insthysteria ;;
      2 ) unsthysteria ;;
      3 ) hysteriaswitch ;;
      4 ) menu_hy_conf ;;
      5 ) run_sys_conf ;;
      6 ) showconf ;;
      7 ) showstatus ;;
      8 ) update_core1 ;;
      9 ) update_core2 ;;
      10 ) besttrace ;;
      11 ) ipquality ;;
      12 ) linux_ps ;;
      13 ) linux_update ;;
      0 ) break ;;
      * ) yellow "无效选项"; sleep 1 ;;
    esac
  done
}

need_root
detect_os
ensure_curl
menu
