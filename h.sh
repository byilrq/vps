#!/bin/bash

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"
hui='\e[37m'
lan='\033[34m'
zi='\033[35m'
tianlan='\033[96m'
chen="\033[38;5;214m\033[01m$1\033[0m"
skyblue() {
    echo -e "\033[1;36m$1\033[0m"
}



red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}

green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}

yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}

# 判断系统及定义系统安装依赖方式
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'" "fedora")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS" "Fedora")
PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "yum -y install")
PACKAGE_REMOVE=("apt -y remove" "apt -y remove" "yum -y remove" "yum -y remove" "yum -y remove")
PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "yum -y autoremove" "yum -y autoremove")

[[ $EUID -ne 0 ]] && red "注意: 请在root用户下运行脚本" && exit 1

CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

for i in "${CMD[@]}"; do
    SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
    [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
done

[[ -z $SYSTEM ]] && red "目前暂不支持你的VPS的操作系统！" && exit 1

if [[ -z $(type -P curl) ]]; then
    if [[ ! $SYSTEM == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl
fi

realip(){
    ip=$(curl -s4m8 ip.sb -k) || ip=$(curl -s6m8 ip.sb -k)
}

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

        chmod a+x /root # 让 Hysteria 主程序访问到 /root 目录

        if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]] && [[ -f /root/ca.log ]]; then
            domain=$(cat /root/ca.log)
            green "检测到原有域名：$domain 的证书，正在应用"
            hy_domain=$domain
        else
            WARPv4Status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            WARPv6Status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then
                wg-quick down wgcf >/dev/null 2>&1
                systemctl stop warp-go >/dev/null 2>&1
                realip
                wg-quick up wgcf >/dev/null 2>&1
                systemctl start warp-go >/dev/null 2>&1
            else
                realip
            fi
            
            read -p "请输入需要申请证书的域名：" domain
            [[ -z $domain ]] && red "未输入域名，无法执行操作！" && exit 1
            green "已输入的域名：$domain" && sleep 1
            domainIP=$(curl -sm8 ipget.net/?ip="${domain}")
            if [[ $domainIP == $ip ]]; then
                ${PACKAGE_INSTALL[int]} curl wget sudo socat openssl
                if [[ $SYSTEM == "CentOS" ]]; then
                    ${PACKAGE_INSTALL[int]} cronie
                    systemctl start crond
                    systemctl enable crond
                else
                    ${PACKAGE_INSTALL[int]} cron
                    systemctl start cron
                    systemctl enable cron
                fi
                curl https://get.acme.sh | sh -s email=$(date +%s%N | md5sum | cut -c 1-16)@gmail.com
                source ~/.bashrc
                bash ~/.acme.sh/acme.sh --upgrade --auto-upgrade
                bash ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
                if [[ -n $(echo $ip | grep ":") ]]; then
                    bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --listen-v6 --insecure
                else
                    bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --insecure
                fi
                bash ~/.acme.sh/acme.sh --install-cert -d ${domain} --key-file /root/private.key --fullchain-file /root/cert.crt --ecc
                if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]]; then
                    echo $domain > /root/ca.log
                    sed -i '/--cron/d' /etc/crontab >/dev/null 2>&1
                    echo "0 0 * * * root bash /root/.acme.sh/acme.sh --cron -f >/dev/null 2>&1" >> /etc/crontab
                    green "证书申请成功! 脚本申请到的证书 (cert.crt) 和私钥 (private.key) 文件已保存到 /root 文件夹下"
                    yellow "证书crt文件路径如下: /root/cert.crt"
                    yellow "私钥key文件路径如下: /root/private.key"
                    hy_domain=$domain
                fi
            else
                red "当前域名解析的IP与当前VPS使用的真实IP不匹配"
                green "建议如下："
                yellow "1. 请确保CloudFlare小云朵为关闭状态(仅限DNS), 其他域名解析或CDN网站设置同理"
                yellow "2. 请检查DNS解析设置的IP是否为VPS的真实IP"
                yellow "3. 脚本可能跟不上时代, 建议截图发布到GitHub Issues、GitLab Issues、论坛或TG群询问"
                exit 1
            fi
        fi
    elif [[ $certInput == 3 ]]; then
        read -p "请输入公钥文件 crt 的路径：" cert_path
        yellow "公钥文件 crt 的路径：$cert_path "
        read -p "请输入密钥文件 key 的路径：" key_path
        yellow "密钥文件 key 的路径：$key_path "
        read -p "请输入证书的域名：" domain
        yellow "证书域名：$domain"
        hy_domain=$domain
    else
        green "将使用必应自签证书作为 Hysteria 2 的节点证书"

        cert_path="/etc/hysteria/cert.crt"
        key_path="/etc/hysteria/private.key"
        openssl ecparam -genkey -name prime256v1 -out /etc/hysteria/private.key
        openssl req -new -x509 -days 36500 -key /etc/hysteria/private.key -out /etc/hysteria/cert.crt -subj "/CN=www.bing.com"
        chmod 777 /etc/hysteria/cert.crt
        chmod 777 /etc/hysteria/private.key
        hy_domain="www.bing.com"
        domain="www.bing.com"
    fi
}

inst_port(){
    iptables -t nat -F PREROUTING >/dev/null 2>&1

    read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} $port ${PLAIN} 端口已经被其他程序占用，请更换端口重试！"
            read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        fi
    done

    yellow "将在 Hysteria 2 节点使用的端口是：$port"
    inst_jump
}

inst_jump(){
    green "Hysteria 2 端口使用模式如下："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 单端口 ${YELLOW}（默认）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} 端口跳跃"
    echo ""
    read -rp "请输入选项 [1-2]: " jumpInput
    if [[ $jumpInput == 2 ]]; then
        read -p "设置范围端口的起始端口 (建议10000-65535之间)：" firstport
        read -p "设置一个范围端口的末尾端口 (建议10000-65535之间，一定要比上面起始端口大)：" endport
        if [[ $firstport -ge $endport ]]; then
            until [[ $firstport -le $endport ]]; do
                if [[ $firstport -ge $endport ]]; then
                    red "你设置的起始端口小于末尾端口，请重新输入起始和末尾端口"
                    read -p "设置范围端口的起始端口 (建议10000-65535之间)：" firstport
                    read -p "设置一个范围端口的末尾端口 (建议10000-65535之间，一定要比上面起始端口大)：" endport
                fi
            done
        fi
        iptables -t nat -A PREROUTING -p udp --dport $firstport:$endport  -j DNAT --to-destination :$port
        ip6tables -t nat -A PREROUTING -p udp --dport $firstport:$endport  -j DNAT --to-destination :$port
        netfilter-persistent save >/dev/null 2>&1
    else
        red "将继续使用单端口模式"
    fi
}

inst_pwd(){
    read -p "设置 Hysteria 2 密码（回车跳过为随机字符）：" auth_pwd
    [[ -z $auth_pwd ]] && auth_pwd=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)
    yellow "使用在 Hysteria 2 节点的密码为：$auth_pwd"
}

inst_site(){
    read -rp "请输入 Hysteria 2 的伪装网站地址 （去除https://） [回车:maimai.sega.jp]：" proxysite
    [[ -z $proxysite ]] && proxysite="maimai.sega.jp"
    yellow "使用在 Hysteria 2 节点的伪装网站为：$proxysite"
}

insthysteria(){
    warpv6=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    warpv4=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    if [[ $warpv4 =~ on|plus || $warpv6 =~ on|plus ]]; then
        wg-quick down wgcf >/dev/null 2>&1
        systemctl stop warp-go >/dev/null 2>&1
        realip
        systemctl start warp-go >/dev/null 2>&1
        wg-quick up wgcf >/dev/null 2>&1
    else
        realip
    fi

    if [[ ! ${SYSTEM} == "CentOS" ]]; then
        ${PACKAGE_UPDATE}
    fi
    ${PACKAGE_INSTALL} curl wget sudo qrencode procps iptables-persistent netfilter-persistent

    wget -N https://raw.githubusercontent.com/byilrq/vps/main/install_server.sh
    bash install_server.sh
    rm -f install_server.sh
      
    if [[ -f "/usr/local/bin/hysteria" ]]; then
        green "Hysteria 2 安装成功！"
    else
        red "Hysteria 2 安装失败！"
    fi

    # 询问用户 Hysteria 配置
    inst_cert
    inst_port
    inst_pwd
    inst_site

    # 设置 Hysteria 配置文件
    cat << EOF > /etc/hysteria/config.yaml
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
    url: https://$proxysite
    rewriteHost: true

EOF

    # 确定最终入站端口范围--ur1
    if [[ -n $firstport ]]; then
        last_port="$port,$firstport-$endport"
    else
        last_port=$port
    fi
    # 确定最终入站端口范围--ur2
    if [[ -n $firstport ]]; then
        port_range="$firstport-$endport"
    else
        last_port=$port
    fi
    # 给 IPv6 地址加中括号
    if [[ -n $(echo $ip | grep ":") ]]; then
        last_ip="[$ip]"
    else
        last_ip=$ip
    fi

    mkdir /root/hy
    
    cat << EOF > /root/hy/hy-client.yaml
server: $last_ip:$port_range

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
  
    ur1="hysteria2://$auth_pwd@$last_ip:$last_port/?insecure=1&sni=$hy_domain#Misaka-Hysteria2"
    ur2="hysteria2://$auth_pwd@$last_ip:$port/?sni=$hy_domain&peer=$last_ip&insecure=1&mport=$port_range#H"
    echo $ur1 > /root/hy/ur1.txt
    echo $ur2 > /root/hy/ur2.txt

    systemctl daemon-reload
    systemctl enable hysteria-server
    systemctl start hysteria-server
    if [[ -n $(systemctl status hysteria-server 2>/dev/null | grep -w active) && -f '/etc/hysteria/config.yaml' ]]; then
        green "Hysteria 2 服务启动成功"
    else
        red "Hysteria 2 服务启动失败，请运行 systemctl status hysteria-server 查看服务状态并反馈，脚本退出" && exit 1
    fi
    red "======================================================================================"
    green "Hysteria 2 代理服务安装完成"
    yellow "Hysteria 2 服务端 YAML 配置文件 hy-client.yaml 内容如下，并保存到 /etc/hysteria/config.yaml"
    green "$(cat /etc/hysteria/config.yaml)"
    yellow "Hysteria 2 客户端 YAML 配置文件 hy-client.yaml 内容如下，并保存到 /root/hy/hy-client.yaml"
    green "$(cat /root/hy/hy-client.yaml)"
    yellow "Hysteria 2 节点分享链接如下，并保存到 /root/hy/ur2.txt"
    green "$(cat /root/hy/ur2.txt)"
    yellow "Hysteria 2 分享二维码如下："
    qrencode -o - -t ANSIUTF8 "$(cat /root/hy/ur2.txt)"
 }
/etc/hysteria/config.yaml

unsthysteria(){
    systemctl stop hysteria-server.service >/dev/null 2>&1
    systemctl disable hysteria-server.service >/dev/null 2>&1
    rm -f /lib/systemd/system/hysteria-server.service /lib/systemd/system/hysteria-server@.service
    rm -rf /usr/local/bin/hysteria /etc/hysteria /root/hy /root/hysteria.sh
    iptables -t nat -F PREROUTING >/dev/null 2>&1
    netfilter-persistent save >/dev/null 2>&1

    green "Hysteria 2 已彻底卸载完成！"
}

starthysteria(){
    systemctl start hysteria-server
    systemctl enable hysteria-server >/dev/null 2>&1
}

stophysteria(){
    systemctl stop hysteria-server
    systemctl disable hysteria-server >/dev/null 2>&1
}

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
        * ) exit 1 ;;
    esac
}

changeport(){
    oldport=$(cat /etc/hysteria/config.yaml 2>/dev/null | sed -n 1p | awk '{print $2}' | awk -F ":" '{print $2}')
    
    read -p "设置 Hysteria 2 端口[1-65535]（回车则随机分配端口）：" port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)

    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} $port ${PLAIN} 端口已经被其他程序占用，请更换端口重试！"
            read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        fi
    done

    sed -i "1s#$oldport#$port#g" /etc/hysteria/config.yaml
    sed -i "1s#$oldport#$port#g" /root/hy/hy-client.yaml
    sed -i "2s#$oldport#$port#g" /root/hy/hy-client.json

    stophysteria && starthysteria

    green "Hysteria 2 端口已成功修改为：$port"
    yellow "请手动更新客户端配置文件以使用节点"
    showconf
}

#修改配置密码

changepasswd() {

    # 颜色
    local color="\033[1;32m"
    local reset="\033[0m"

    # 路径
    local config_file="/etc/hysteria/config.yaml"
    local client_file="/root/hy/hy-client.yaml"
    local link_file="/root/hy/ur2.txt"

    # 基础检查
    if [[ ! -f $config_file ]]; then
        echo -e "${color}配置文件不存在：$config_file${reset}" >&2
        return 1
    fi
    if [[ ! -f $client_file ]]; then
        echo -e "${color}客户端配置不存在：$client_file${reset}" >&2
        return 1
    fi
    if [[ ! -f $link_file ]]; then
        echo -e "${color}分享链接文件不存在：$link_file${reset}" >&2
        return 1
    fi

    # 备份服务端配置
    cp "$config_file" "${config_file}.bak"

    # 提取旧密码（auth: 到 password: 之间）
    oldpasswd=$(awk '/auth:/,/password:/ {if ($1 ~ /password:/) print $2}' "$config_file" | xargs)
    if [[ -z $oldpasswd ]]; then
        echo -e "${color}无法提取旧密码，请检查 ${config_file}！${reset}" >&2
        return 1
    fi

    # 新密码
    local length=${1:-16}  # 默认 16 位
    read -p "设置 Hysteria 2 密码（回车跳过为随机字符）：" passwd
    passwd=${passwd:-$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$length")}

    echo -e "${color}旧密码：${oldpasswd}${reset}"
    echo -e "${color}新密码：${passwd}${reset}"

    # 1) 更新服务端 config.yaml 中的 password 字段
    sed -i "/auth:/,/password:/s/^ *password: .*/  password: $passwd/" "$config_file"
    if ! grep -q "password: $passwd" "$config_file"; then
        echo -e "${color}密码写入 ${config_file} 失败，请检查！${reset}" >&2
        return 1
    fi

    # 2) 更新客户端 hy-client.yaml 中的 auth 行
    if grep -q "^auth: " "$client_file"; then
        sed -i "s/^auth: .*/auth: $passwd/" "$client_file"
    else
        # 万一没有 auth 行，就追加一行
        echo "auth: $passwd" >> "$client_file"
    fi

    # 3) 更新分享链接中的密码（只改密码，不动任何端口和参数）
    update_hysteria_link "$oldpasswd" "$passwd" "$link_file"

    # 4) 重启服务
    systemctl restart hysteria-server.service
    if [[ $? -eq 0 ]]; then
        green "新密码已经启用，Hysteria 2 已重启"
    else
        echo -e "${color}服务重启失败，请手动检查 systemctl status hysteria-server.service${reset}" >&2
        return 1
    fi

    green "Hysteria 2 节点密码已成功修改为：$passwd"
    yellow "showconf 显示的客户端配置和二维码已同步为新密码"
}



##更新密码后重新打印链接和二维码###
update_hysteria_link() {
    local oldpasswd="$1"
    local newpasswd="$2"
    local link_file="${3:-/root/hy/ur2.txt}"
    local link
    local new_link

    # 读取现有链接
    if [[ ! -f "$link_file" ]]; then
        echo "Error: 链接文件不存在：$link_file"
        return 1
    fi
    link=$(cat "$link_file")
    if [[ -z "$link" ]]; then
        echo "Error: 链接文件为空：$link_file"
        return 1
    fi

    # 只替换 hysteria2:// 和 @ 之间的内容为新密码
    # 例：hysteria2://旧密码@ → hysteria2://新密码@
    new_link=$(echo "$link" | sed "s#\(hysteria2://\)[^@]*@#\1${newpasswd}@#")

    if [[ "$new_link" == "$link" ]]; then
        echo "Warning: 链接中未发现可替换的密码段，可能格式不符预期。"
        return 1
    fi

    # 写回文件
    echo "$new_link" > "$link_file"

    # 输出新的链接和二维码
    skyblue "$new_link"
    skyblue "Hysteria 2 二维码如下"
    qrencode -o - -t ANSIUTF8 "$new_link"
}



############################
change_cert(){
    old_cert=$(cat /etc/hysteria/config.yaml | grep cert | awk -F " " '{print $2}')
    old_key=$(cat /etc/hysteria/config.yaml | grep key | awk -F " " '{print $2}')
    old_hydomain=$(cat /root/hy/hy-client.yaml | grep sni | awk '{print $2}')

    inst_cert

    sed -i "s!$old_cert!$cert_path!g" /etc/hysteria/config.yaml
    sed -i "s!$old_key!$key_path!g" /etc/hysteria/config.yaml
    sed -i "6s/$old_hydomain/$hy_domain/g" /root/hy/hy-client.yaml


    stophysteria && starthysteria

    green "Hysteria 2 节点证书类型已成功修改"
    yellow "请手动更新客户端配置文件以使用节点"
    showconf
}

changeproxysite(){
    oldproxysite=$(cat /etc/hysteria/config.yaml | grep url | awk -F " " '{print $2}' | awk -F "https://" '{print $2}')
    
    inst_site

    sed -i "s#$oldproxysite#$proxysite#g" /etc/caddy/Caddyfile

    stophysteria && starthysteria

    green "Hysteria 2 节点伪装网站已成功修改为：$proxysite"
}

change_tz(){
    sudo timedatectl set-timezone Asia/Shanghai
    green "系统时区已经改为Asia/Shanghai"
    timedatectl
}




showconf(){
    yellow "Hysteria 2 服务端 YAML 配置文件 config.yaml 内容如下，并保存到 /etc/hysteria/config.yaml"
    green "$(cat /etc/hysteria/config.yaml)"
    yellow "Hysteria 2 客户端 YAML 配置文件 hy-client.yaml 内容如下，并保存到 /root/hy/hy-client.yaml"
    green "$(cat /root/hy/hy-client.yaml)"
    yellow "Hysteria 2 节点分享链接如下，并保存到 /root/hy/ur2.txt"
    green "$(cat /root/hy/ur2.txt)"
    yellow "Hysteria 2 二维码如下"
    qrencode -o - -t ANSIUTF8 "$(cat /root/hy/ur2.txt)"
    systemctl restart hysteria-server.service
}

update_core1(){
        green "官方更新方式必须先脚本安装后使用，否则会失败。"        
        systemctl stop hysteria-server.service
        rm -f /usr/local/bin/hysteria
        bash <(curl -fsSL https://get.hy2.sh/)
        green "Hysteria 内核已更新到最新版本！" 
        systemctl enable --now hysteria-server.service
        green "Hysteria 内核设置开机自启， 并立即启动服务"   
        systemctl restart hysteria-server.service
        green "Hysteria 内核已重新启动！"  
}

update_core2(){
    systemctl stop hysteria-server.service
    rm -f /usr/local/bin/hysteria
    wget -N https://raw.githubusercontent.com/byilrq/vps/main/install_server.sh
    bash install_server.sh
    rm -f install_server.sh
    green "Hysteria 内核已更新到最新版本！"
    systemctl restart hysteria-server.service
    green "Hysteria 内核已经重新启动"
}

showstatus(){
    systemctl status hysteria-server.service
}

linux_update() {
	echo -e "${green}正在系统更新...${green}"
	if command -v dnf &>/dev/null; then
		dnf -y update
	elif command -v yum &>/dev/null; then
		yum -y update
	elif command -v apt &>/dev/null; then
		fix_dpkg
		DEBIAN_FRONTEND=noninteractive apt update -y
		DEBIAN_FRONTEND=noninteractive apt full-upgrade -y
	elif command -v apk &>/dev/null; then
		apk update && apk upgrade
	elif command -v pacman &>/dev/null; then
		pacman -Syu --noconfirm
	elif command -v zypper &>/dev/null; then
		zypper refresh
		zypper update
	elif command -v opkg &>/dev/null; then
		opkg update
	else
		echo "未知的包管理器!"
		return
	fi
}

swap_cache() {
    echo "=== 硬盘缓存设置工具 ==="

    # 检查是否是 root 用户
    if [ "$EUID" -ne 0 ]; then
        echo "错误：请以 root 权限运行此脚本。"
        exit 1
    fi

    # 检测当前的 Swap 配置
    echo "检测当前 Swap 缓存配置..."
    current_swap=$(free -m | awk '/Swap:/ {print $2}')
    echo "当前 Swap 缓存大小为：${current_swap} MB"
    echo ""

    # 获取用户输入的缓存大小
    read -p "请输入要设置的 Swap 缓存大小（单位：MB，建议值 >= 512）： " size_mb

    # 验证输入是否为正整数
    if ! [[ "$size_mb" =~ ^[0-9]+$ ]] || [ "$size_mb" -lt 1 ]; then
        echo "错误：请输入有效的正整数（单位：MB）。"
        exit 1
    fi

    # 确认用户输入
    echo "准备设置 Swap 缓存大小为 ${size_mb} MB..."
    read -p "是否继续操作？(y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo "操作已取消。"
        exit 0
    fi

    # 停用现有的 Swap 文件（如果存在）
    if swapon --show | grep -q "/swapfile"; then
        echo "检测到现有 Swap 文件，正在停用..."
        swapoff /swapfile
        echo "已停用现有 Swap 文件。"
        echo "正在删除旧的 Swap 文件..."
        rm -f /swapfile
    fi

    # 创建新的 Swap 文件
    echo "正在创建新的 Swap 文件 (${size_mb} MB)..."
    fallocate -l "${size_mb}M" /swapfile
    if [ $? -ne 0 ]; then
        echo "错误：无法创建 Swap 文件，请检查磁盘空间或权限。"
        exit 1
    fi

    # 设置权限和格式化
    chmod 600 /swapfile
    echo "正在格式化 Swap 文件..."
    mkswap /swapfile

    # 启用新的 Swap
    echo "正在启用 Swap 文件..."
    swapon /swapfile

    # 更新 /etc/fstab 以支持开机自动挂载
    if ! grep -q "^/swapfile" /etc/fstab; then
        echo "正在配置开机自动挂载..."
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
    fi

    # 显示新的 Swap 配置
    echo "新的 Swap 文件已启用。当前 Swap 配置："
    swapon --show
    free -h

    echo "操作完成！新的 Swap 缓存大小为 ${size_mb} MB。"
}

# 上海三网路由节点
besttrace() {
    url="https://raw.githubusercontent.com/chiakge/Linux-Optimize/master/besttrace.sh"

    curl -s $url -o /tmp/besttrace.sh
    chmod +x /tmp/besttrace.sh

    echo -e "\n🔵 上海电信"
    /tmp/besttrace.sh 101.227.14.1

    echo -e "\n🔴 上海联通"
    /tmp/besttrace.sh 139.226.226.1

    echo -e "\n🟢 上海移动"
    /tmp/besttrace.sh 211.136.112.200

    rm -f /tmp/besttrace.sh
}



linux_ps() {

	clear

	local cpu_info=$(lscpu | awk -F': +' '/Model name:/ {print $2; exit}')

	local cpu_usage_percent=$(awk '{u=$2+$4; t=$2+$4+$5; if (NR==1){u1=u; t1=t;} else printf "%.0f\n", (($2+$4-u1) * 100 / (t-t1))}' \
		<(grep 'cpu ' /proc/stat) <(sleep 1; grep 'cpu ' /proc/stat))

	local cpu_cores=$(nproc)

	local cpu_freq=$(cat /proc/cpuinfo | grep "MHz" | head -n 1 | awk '{printf "%.1f GHz\n", $4/1000}')

	local mem_info=$(free -b | awk 'NR==2{printf "%.2f/%.2f MB (%.2f%%)", $3/1024/1024, $2/1024/1024, $3*100/$2}')

	local disk_info=$(df -h | awk '$NF=="/"{printf "%s/%s (%s)", $3, $2, $5}')

	local ipinfo=$(curl -s ipinfo.io)
	local country=$(echo "$ipinfo" | grep 'country' | awk -F': ' '{print $2}' | tr -d '",')
	local city=$(echo "$ipinfo" | grep 'city' | awk -F': ' '{print $2}' | tr -d '",')
	local isp_info=$(echo "$ipinfo" | grep 'org' | awk -F': ' '{print $2}' | tr -d '",')

	local load=$(uptime | awk '{print $(NF-2), $(NF-1), $NF}')
	# local dns_addresses=$(awk '/^nameserver/{printf "%s ", $2} END {print ""}' /etc/resolv.conf)
	# 显示真实的dns
local dns_addresses=$(resolvectl status 2>/dev/null | awk '
/^ *DNS Servers:/ {
    for (i=3;i<=NF;i++) printf "%s ", $i
}
END {print ""}')

	local cpu_arch=$(uname -m)

	local hostname=$(uname -n)

	local kernel_version=$(uname -r)

	local congestion_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control)
	local queue_algorithm=$(sysctl -n net.core.default_qdisc)

	local os_info=$(grep PRETTY_NAME /etc/os-release | cut -d '=' -f2 | tr -d '"')

	local current_time=$(date "+%Y-%m-%d %I:%M %p")


	local swap_info=$(free -m | awk 'NR==3{used=$3; total=$2; if (total == 0) {percentage=0} else {percentage=used*100/total}; printf "%dMB/%dMB (%d%%)", used, total, percentage}')

	local runtime=$(cat /proc/uptime | awk -F. '{run_days=int($1 / 86400);run_hours=int(($1 % 86400) / 3600);run_minutes=int(($1 % 3600) / 60); if (run_days > 0) printf("%d天 ", run_days); if (run_hours > 0) printf("%d时 ", run_hours); printf("%d分\n", run_minutes)}')


	echo ""
	echo -e "系统信息查询"
	echo -e "${tianlan}-------------"
	echo -e "${tianlan}主机名:       ${hui}$hostname"
	echo -e "${tianlan}系统版本:     ${hui}$os_info"
	echo -e "${tianlan}Linux版本:    ${hui}$kernel_version"
	echo -e "${tianlan}-------------"
	echo -e "${tianlan}CPU架构:      ${hui}$cpu_arch"
	echo -e "${tianlan}CPU型号:      ${hui}$cpu_info"
	echo -e "${tianlan}CPU核心数:    ${hui}$cpu_cores"
	echo -e "${tianlan}CPU频率:      ${hui}$cpu_freq"
	echo -e "${tianlan}-------------"
	echo -e "${tianlan}CPU占用:      ${hui}$cpu_usage_percent%"
	echo -e "${tianlan}系统负载:     ${hui}$load"
	echo -e "${tianlan}物理内存:     ${hui}$mem_info"
	echo -e "${tianlan}虚拟内存:     ${hui}$swap_info"
	echo -e "${tianlan}硬盘占用:     ${hui}$disk_info"
	echo -e "${tianlan}-------------"
	echo -e "${tianlan}$output"
	echo -e "${tianlan}-------------"
	echo -e "${tianlan}网络算法:     ${hui}$congestion_algorithm $queue_algorithm"
	echo -e "${tianlan}-------------"
	echo -e "${tianlan}运营商:       ${hui}$isp_info"
	if [ -n "$ipv4_address" ]; then
		echo -e "${tianlan}IPv4地址:     ${hui}$ipv4_address"
	fi

	if [ -n "$ipv6_address" ]; then
		echo -e "${tianlan}IPv6地址:     ${hui}$ipv6_address"
	fi
	echo -e "${tianlan}DNS地址:      ${hui}$dns_addresses"
	echo -e "${tianlan}地理位置:     ${hui}$country $city"
	echo -e "${tianlan}系统时间:     ${hui}$timezone $current_time"
	echo -e "${tianlan}-------------"
	echo -e "${tianlan}运行时长:     ${hui}$runtime"
	echo



}
# -----------------------------------------
#  设置DNS并锁死 resolv.conf	
# -----------------------------------------

set_dns_ui() {

    # 必须用 root 执行
    if [ "$EUID" -ne 0 ]; then
        echo "⚠ 请使用 root 运行：sudo -i 然后再执行 set_dns_ui"
        return 1
    fi

    echo -e "\n🚀 开始执行【海外 VPS DNS 优化 + 永久锁死】\n"

    # -----------------------------------------
    # 1️⃣ 应急 DNS（强制网络立即恢复）
    # -----------------------------------------
    echo -e "📡 [1/6] 设置应急 DNS（1.1.1.1 + 8.8.8.8）……"
cat > /etc/resolv.conf << 'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF

    chattr +i /etc/resolv.conf 2>/dev/null || true
    sleep 2
    echo -e "✅ 应急 DNS 已生效！\n"


    # -----------------------------------------
    # 2️⃣ 修复 apt 并安装 systemd-resolved
    # -----------------------------------------
    echo -e "📦 [2/6] 安装 systemd-resolved……"
    export DEBIAN_FRONTEND=noninteractive
    apt-get clean >/dev/null 2>&1
    apt update --fix-missing -qq >/dev/null 2>&1
    apt install -y systemd-resolved libnss-resolve >/dev/null 2>&1 ||
    apt install -y --reinstall systemd-resolved >/dev/null 2>&1


    # -----------------------------------------
    # 3️⃣ 写入最优海外 DNS 配置
    # -----------------------------------------
    echo -e "⚙️ [3/6] 写入 Cloudflare + Google DNS 配置……"
cat > /etc/systemd/resolved.conf << 'EOF'
[Resolve]
DNS=1.1.1.1 8.8.8.8
FallbackDNS=1.0.0.1 8.8.4.4
DNSSEC=no
DNSOverTLS=no
MulticastDNS=no
LLMNR=no
Cache=yes
EOF


    # -----------------------------------------
    # 4️⃣ 启用 systemd 的 stub-resolv.conf
    # -----------------------------------------
    echo -e "🔧 [4/6] 切换为 127.0.0.53 本地 DNS……"
    chattr -i /etc/resolv.conf 2>/dev/null || true
    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null ||
    cp -f /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null


    # -----------------------------------------
    # 5️⃣ 重启 resolved
    # -----------------------------------------
    echo -e "🔄 [5/6] 重启 systemd-resolved ……"
    systemctl enable --now systemd-resolved >/dev/null 2>&1
    sleep 2


    # -----------------------------------------
    # 6️⃣ DNS 测试并锁死 resolv.conf
    # -----------------------------------------
    echo -e "🔍 [6/6] 测试 DNS 解析……"
    sleep 2

    if dig +short cloudflare.com @127.0.0.53 | grep -q "[0-9]"; then
        echo -e "🎉 DNS 测试成功！准备锁死 resolv.conf……"

        chattr -i /etc/resolv.conf 2>/dev/null || true
        echo "nameserver 127.0.0.53" > /etc/resolv.conf
        chattr +i /etc/resolv.conf 2>/dev/null && \
            echo -e "🔥 锁死成功！DNS 永久固定，不会再被云厂商修改。\n"
    else
        echo -e "⚠️ DNS 测试失败，本次不锁死 resolv.conf。\n"
    fi

    # 显示当前 DNS 状态
    echo -e "📡 当前 DNS 设置：\n"
    resolvectl status 2>/dev/null | grep -A 2 "DNS Servers" || cat /etc/resolv.conf

    echo -e "\n🧪 测试解析 cloudflare.com：\n"
    dig +short cloudflare.com | head -5

    echo -e "\n🎊 已完成！海外 VPS DNS = Cloudflare + Google，速度最优、重启不变！\n"
}

# 安装BBRV3

bbrv3() {
		  root_use
		  send_stats "bbrv3管理"

		  local cpu_arch=$(uname -m)
		  if [ "$cpu_arch" = "aarch64" ]; then
			bash <(curl -sL jhb.ovh/jb/bbrv3arm.sh)
			break_end
			linux_Settings
		  fi

		  if dpkg -l | grep -q 'linux-xanmod'; then
			while true; do
				  clear
				  local kernel_version=$(uname -r)
				  echo "您已安装xanmod的BBRv3内核"
				  echo "当前内核版本: $kernel_version"

				  echo ""
				  echo "内核管理"
				  echo "------------------------"
				  echo "1. 更新BBRv3内核              2. 卸载BBRv3内核"
				  echo "------------------------"
				  echo "0. 返回上一级选单"
				  echo "------------------------"
				  read -e -p "请输入你的选择: " sub_choice

				  case $sub_choice in
					  1)
						apt purge -y 'linux-*xanmod1*'
						update-grub

						# wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
						wget -qO - ${gh_proxy}https://raw.githubusercontent.com/kejilion/sh/main/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes

						# 步骤3：添加存储库
						echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list

						# version=$(wget -q https://dl.xanmod.org/check_x86-64_psabi.sh && chmod +x check_x86-64_psabi.sh && ./check_x86-64_psabi.sh | grep -oP 'x86-64-v\K\d+|x86-64-v\d+')
						local version=$(wget -q ${gh_proxy}https://raw.githubusercontent.com/kejilion/sh/main/check_x86-64_psabi.sh && chmod +x check_x86-64_psabi.sh && ./check_x86-64_psabi.sh | grep -oP 'x86-64-v\K\d+|x86-64-v\d+')

						apt update -y
						apt install -y linux-xanmod-x64v$version

						echo "XanMod内核已更新。重启后生效"
						rm -f /etc/apt/sources.list.d/xanmod-release.list
						rm -f check_x86-64_psabi.sh*

						server_reboot

						  ;;
					  2)
						apt purge -y 'linux-*xanmod1*'
						update-grub
						echo "XanMod内核已卸载。重启后生效"
						server_reboot
						  ;;
					  0)
						  break  # 跳出循环，退出菜单
						  ;;

					  *)
						  break  # 跳出循环，退出菜单
						  ;;

				  esac
			done
		else

		  clear
		  echo "设置BBR3加速"
		  echo "------------------------------------------------"
		  echo "仅支持Debian/Ubuntu"
		  echo "请备份数据，将为你升级Linux内核开启BBR3"
		  echo "VPS是512M内存的，请提前添加1G虚拟内存，防止因内存不足失联！"
		  echo "------------------------------------------------"
		  read -e -p "确定继续吗？(Y/N): " choice

		  case "$choice" in
			[Yy])
			if [ -r /etc/os-release ]; then
				. /etc/os-release
				if [ "$ID" != "debian" ] && [ "$ID" != "ubuntu" ]; then
					echo "当前环境不支持，仅支持Debian和Ubuntu系统"
					break_end
					linux_Settings
				fi
			else
				echo "无法确定操作系统类型"
				break_end
				linux_Settings
			fi

			check_swap
			install wget gnupg

			# wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes
			wget -qO - ${gh_proxy}https://raw.githubusercontent.com/kejilion/sh/main/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg --yes

			# 步骤3：添加存储库
			echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list

			# version=$(wget -q https://dl.xanmod.org/check_x86-64_psabi.sh && chmod +x check_x86-64_psabi.sh && ./check_x86-64_psabi.sh | grep -oP 'x86-64-v\K\d+|x86-64-v\d+')
			local version=$(wget -q ${gh_proxy}https://raw.githubusercontent.com/kejilion/sh/main/check_x86-64_psabi.sh && chmod +x check_x86-64_psabi.sh && ./check_x86-64_psabi.sh | grep -oP 'x86-64-v\K\d+|x86-64-v\d+')

			apt update -y
			apt install -y linux-xanmod-x64v$version

			bbr_on

			echo "XanMod内核安装并BBR3启用成功。重启后生效"
			rm -f /etc/apt/sources.list.d/xanmod-release.list
			rm -f check_x86-64_psabi.sh*
			
	                  ;;
			[Nn])
			  echo "已取消"
			  ;;
			*)
			  echo "无效的选择，请输入 Y 或 N。"
			  ;;
		  esac
		fi

}


# 设置IPv4/IPv6 优先级
set_ip_priority() {
    while true; do
        clear
        echo "设置v4/v6优先级"
        echo "------------------------"
        local ipv6_disabled=$(sysctl -n net.ipv6.conf.all.disable_ipv6)

        if [ "$ipv6_disabled" -eq 1 ]; then
            echo -e "当前网络优先级设置: ${gl_huang}IPv4${gl_bai} 优先"
        else
            echo -e "当前网络优先级设置: ${gl_huang}IPv6${gl_bai} 优先"
        fi
        echo ""
        echo "------------------------"
        echo "1. IPv4 优先          2. IPv6 优先          3. IPv6 修复工具          0. 退出"
        echo "------------------------"
        read -e -p "选择优先的网络: " choice

        case $choice in
            1)
                sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1
                echo "已切换为 IPv4 优先"
                send_stats "已切换为 IPv4 优先"
                ;;

            2)
                sysctl -w net.ipv6.conf.all.disable_ipv6=0 > /dev/null 2>&1
                echo "已切换为 IPv6 优先"
                send_stats "已切换为 IPv6 优先"
                ;;

            3)
                clear
                bash <(curl -L -s jhb.ovh/jb/v6.sh)
                echo "该功能由jhb大神提供，感谢他！"
                send_stats "IPv6 修复"
                ;;

            0)
                echo "退出..."
                break
                ;;

            *)
                echo "无效选择，请重新选择。"
                ;;
        esac
    done
}

cron() {
    wget -N --no-check-certificate https://raw.githubusercontent.com/byilrq/vps/main/mdadm -O /etc/cron.d/mdadm
    if [ $? -eq 0 ]; then
        echo "文件下载成功！"
    else
        echo "文件下载失败！"
    fi
    echo -e "#     ${tianlan}系统重启      #"
    reboot
}

ssh_port() {
  local new_port=$1

  # 检查是否传入了端口参数
  if [ -z "$new_port" ]; then
    echo "请提供新的端口号"
    return 1
  fi

  # 检查是否是 root 用户
  if [ "$(id -u)" -ne 0 ]; then
    echo "请使用 root 权限运行此脚本"
    return 1
  fi

  # 修改 sshd_config 文件
  SSH_CONFIG="/etc/ssh/sshd_config"
  if grep -q "^#Port 22" "$SSH_CONFIG"; then
    sed -i "s/^#Port 22/Port $new_port/" "$SSH_CONFIG"
  else
    sed -i "s/^Port 22/Port $new_port/" "$SSH_CONFIG"
  fi

  # 重启 SSH 服务
  systemctl restart ssh

  if [ $? -eq 0 ]; then
    echo "SSH 端口已经修改为 $new_port"
  else
    echo "重启 SSH 服务失败，请检查错误日志"
  fi
}

#IP质量检测
ipquality() {
    echo "检查 IP 质量中..."
    curl -sL https://Check.Place | bash -s - -I
}

#修改配置
changeconf(){
    green "Hysteria 2 配置变更选择如下:"
    echo -e " ${GREEN}1.${tianlan} 修改端口"
    echo -e " ${GREEN}2.${tianlan} 修改密码"
    echo -e " ${GREEN}3.${tianlan} 修改证书类型"
    echo -e " ${GREEN}4.${tianlan} 修改伪装网站"
    echo -e " ${GREEN}5.${tianlan} 修改时区"
    echo -e " ${GREEN}6.${tianlan} 修改DNS"
    echo -e " ${GREEN}7.${tianlan} 设置缓存" 
    echo -e " ${GREEN}8.${tianlan} 设置IPV4/6优先级" 
    echo -e " ${GREEN}9.${tianlan} 安装BBR3"
    echo -e " ${GREEN}10.${tianlan} 设置定时重启"  
    echo -e " ${GREEN}11.${tianlan} 修改SSH端口2222"  
    echo " ---------------------------------------------------"
    echo -e " ${GREEN}0.${PLAIN} 退出脚本"
    echo ""
    read -p " 请选择操作 [1-5]：" confAnswer
    case $confAnswer in
        1 ) changeport ;;
        2 ) changepasswd ;;
        3 ) change_cert ;;
        4 ) changeproxysite ;;
        5 ) change_tz ;;
        6 ) set_dns_ui ;;
        7 ) swap_cache ;;
        8 ) set_ip_priority ;;
        9 ) bbrv3 ;;
	10 ) cron ;;
        11 ) ssh_port 2222 ;;  # 修改SSH端口为2222
        * ) echo "无效选项，退出脚本"; exit 1 ;;
    esac
}


menu() {
    clear
    echo "#############################################################"
    echo -e "#         ${tianlan}Hysteria 2 一键安装脚本      #"
    echo "#############################################################"
    echo ""
    echo -e " ${GREEN}1.${GREEN}安装 Hysteria 2"
    echo -e " ${GREEN}2.${zi}卸载 Hysteria 2"
    echo " ---------------------------------------------------"
    echo -e " ${GREEN}3.${tianlan} 关闭、开启、重启 Hysteria 2"
    echo -e " ${GREEN}4.${tianlan} 修改 系统配置"
    echo -e " ${GREEN}5.${tianlan} 显示 配置文件"
    echo -e " ${GREEN}6.${tianlan} 查询 运行状态"
    echo -e " ${GREEN}7.${tianlan} 更新内核方式1（官方）"
    echo -e " ${GREEN}8.${tianlan} 更新内核方式2（脚本）"
    echo -e " ${GREEN}9.${tianlan} 回程测试"  
    echo -e " ${GREEN}10.${tianlan} IP质量检测"  
    echo -e " ${GREEN}11.${tianlan} 系统查询"  
    echo -e " ${GREEN}12.${tianlan} 系统更新" 
    echo " ---------------------------------------------------"
    echo -e " ${GREEN}0.${PLAIN} 退出脚本"
    echo ""
    read -rp "请输入选项 [0-9]: " menuInput
    case $menuInput in
        1 ) insthysteria ;;
        2 ) unsthysteria ;;
        3 ) hysteriaswitch ;;
        4 ) changeconf ;;
        5 ) showconf ;;
        6 ) showstatus ;;
        7 ) update_core1 ;;
        8 ) update_core2 ;;
        9 ) besttrace ;;
        10 ) ipquality ;;
        11)  linux_ps;;
        12)  linux_update;;
        * ) exit 1 ;;
    esac
}

menu
