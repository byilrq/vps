#!/usr/bin/env bash
# hysteria server install script
# Copyright (c) 2023 Aperture Internet Laboratory

set -e

# -----------------------------
# 执行策略 - 发生错误立即退出
# set -e：任一命令返回非0即退出脚本
# -----------------------------


###
# SCRIPT CONFIGURATION
###

# -----------------------------
# 脚本基础配置 - 名称/参数/安装路径/目录/仓库URL/curl默认参数
# -----------------------------

# Basename of this script
SCRIPT_NAME="$(basename "$0")"

# Command line arguments of this script
SCRIPT_ARGS=("$@")

# Path for installing executable
EXECUTABLE_INSTALL_PATH="/usr/local/bin/hysteria"

# Paths to install systemd files
SYSTEMD_SERVICES_DIR="/etc/systemd/system"

# Directory to store hysteria config file
CONFIG_DIR="/etc/hysteria"

# URLs of GitHub
REPO_URL="https://github.com/apernet/hysteria"
API_BASE_URL="https://api.github.com/repos/apernet/hysteria"

# curl command line flags.
# To using a proxy, please specify ALL_PROXY in the environ variable, such like:
# export ALL_PROXY=socks5h://192.0.2.1:1080
CURL_FLAGS=(-L -f -q --retry 5 --retry-delay 10 --retry-max-time 60)


###
# AUTO DETECTED GLOBAL VARIABLE
###

# -----------------------------
# 自动探测变量 - 包管理器/系统/架构/运行用户/证书存储目录
# 允许通过环境变量覆盖默认探测结果
# -----------------------------

# Package manager
PACKAGE_MANAGEMENT_INSTALL="${PACKAGE_MANAGEMENT_INSTALL:-}"

# Operating System of current machine, supported: linux
OPERATING_SYSTEM="${OPERATING_SYSTEM:-}"

# Architecture of current machine, supported: 386, amd64, arm, arm64, mipsle, s390x
ARCHITECTURE="${ARCHITECTURE:-}"

# User for running hysteria
HYSTERIA_USER="${HYSTERIA_USER:-}"

# Directory for ACME certificates storage
HYSTERIA_HOME_DIR="${HYSTERIA_HOME_DIR:-}"


###
# ARGUMENTS
###

# -----------------------------
# 命令行参数（解析结果）- 操作类型/版本/强制/本地二进制路径
# -----------------------------

# Supported operation: install, remove, check_update
OPERATION=

# User specified version to install
VERSION=

# Force install even if installed
FORCE=

# User specified binary to install
LOCAL_FILE=


###
# COMMAND REPLACEMENT & UTILITIES
###

# -----------------------------
# 命令封装与通用工具函数
# - 封装 curl/mktemp/tput/systemctl 等，统一参数/兼容无systemd环境
# - 输出彩色日志、错误提示、文件安装/删除等
# -----------------------------

# -----------------------------
# has_command - 判断命令是否存在
# 返回：0 存在；非0 不存在
# -----------------------------
has_command() {
  local _command=$1

  type -P "$_command" > /dev/null 2>&1
}

# -----------------------------
# curl - curl命令包装器
# 统一使用脚本预设的 CURL_FLAGS
# -----------------------------
curl() {
  command curl "${CURL_FLAGS[@]}" "$@"
}

# -----------------------------
# mktemp - 创建临时文件
# 固定前缀 /tmp/hyservinst.*
# -----------------------------
mktemp() {
  command mktemp "$@" "/tmp/hyservinst.XXXXXXXXXX"
}

# -----------------------------
# tput - 终端能力检测封装
# 若系统无tput则忽略（避免报错）
# -----------------------------
tput() {
  if has_command tput; then
    command tput "$@"
  fi
}

# -----------------------------
# tred/tgreen/tyellow/tblue/taoi - 设置终端字体颜色
# -----------------------------
tred() {
  tput setaf 1
}

tgreen() {
  tput setaf 2
}

tyellow() {
  tput setaf 3
}

tblue() {
  tput setaf 4
}

taoi() {
  tput setaf 6
}

# -----------------------------
# tbold/treset - 终端字体加粗/重置
# -----------------------------
tbold() {
  tput bold
}

treset() {
  tput sgr0
}

# -----------------------------
# note - 输出提示信息（note级别）
# -----------------------------
note() {
  local _msg="$1"

  echo -e "$SCRIPT_NAME: $(tbold)note: $_msg$(treset)"
}

# -----------------------------
# warning - 输出警告信息（warning级别，黄色）
# -----------------------------
warning() {
  local _msg="$1"

  echo -e "$SCRIPT_NAME: $(tyellow)warning: $_msg$(treset)"
}

# -----------------------------
# error - 输出错误信息（error级别，红色）
# -----------------------------
error() {
  local _msg="$1"

  echo -e "$SCRIPT_NAME: $(tred)error: $_msg$(treset)"
}

# -----------------------------
# has_prefix - 判断字符串是否以指定前缀开头
# 参数：字符串、前缀
# 返回：0 匹配；1 不匹配
# -----------------------------
has_prefix() {
    local _s="$1"
    local _prefix="$2"

    if [[ -z "$_prefix" ]]; then
        return 0
    fi

    if [[ -z "$_s" ]]; then
        return 1
    fi

    [[ "x$_s" != "x${_s#"$_prefix"}" ]]
}

# -----------------------------
# generate_random_password - 生成随机密码
# 来源：/dev/random 读取18字节 -> base64输出
# -----------------------------
generate_random_password() {
  dd if=/dev/random bs=18 count=1 status=none | base64
}

# -----------------------------
# systemctl - systemctl命令封装
# FORCE_NO_SYSTEMD=2 或系统无systemctl时跳过执行
# -----------------------------
systemctl() {
  if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]] || ! has_command systemctl; then
    warning "Ignored systemd command: systemctl $@"
    return
  fi

  command systemctl "$@"
}

# -----------------------------
# show_argument_error_and_exit - 参数错误提示并退出
# 退出码：22（EINVAL）
# -----------------------------
show_argument_error_and_exit() {
  local _error_msg="$1"

  error "$_error_msg"
  echo "Try \"$0 --help\" for usage." >&2
  exit 22
}

# -----------------------------
# install_content - 将给定内容写入目标文件并安装到指定位置
# 参数：
#  1) install flags（如 -Dm644）
#  2) content（文本内容）
#  3) destination（目标路径）
#  4) overwrite（非空则覆盖）
# -----------------------------
install_content() {
  local _install_flags="$1"
  local _content="$2"
  local _destination="$3"
  local _overwrite="$4"

  local _tmpfile="$(mktemp)"

  echo -ne "Install $_destination ... "
  echo "$_content" > "$_tmpfile"
  if [[ -z "$_overwrite" && -e "$_destination" ]]; then
    echo -e "exists"
  elif install "$_install_flags" "$_tmpfile" "$_destination"; then
    echo -e "ok"
  fi

  rm -f "$_tmpfile"
}

# -----------------------------
# remove_file - 删除指定文件并打印结果
# -----------------------------
remove_file() {
  local _target="$1"

  echo -ne "Remove $_target ... "
  if rm "$_target"; then
    echo -e "ok"
  fi
}

# -----------------------------
# exec_sudo - 使用sudo重新执行命令并保留关键环境变量
# 用途：root权限提升同时保留脚本探测/配置变量
# -----------------------------
exec_sudo() {
  # exec sudo with configurable environ preserved.
  local _saved_ifs="$IFS"
  IFS=$'\n'
  local _preserved_env=(
    $(env | grep "^PACKAGE_MANAGEMENT_INSTALL=" || true)
    $(env | grep "^OPERATING_SYSTEM=" || true)
    $(env | grep "^ARCHITECTURE=" || true)
    $(env | grep "^HYSTERIA_\w*=" || true)
    $(env | grep "^FORCE_\w*=" || true)
  )
  IFS="$_saved_ifs"

  exec sudo env \
    "${_preserved_env[@]}" \
    "$@"
}

# -----------------------------
# detect_package_manager - 探测可用包管理器并设置安装命令
# 支持：apt/dnf/yum/zypper/pacman
# 返回：0 成功；1 未探测到
# -----------------------------
detect_package_manager() {
  if [[ -n "$PACKAGE_MANAGEMENT_INSTALL" ]]; then
    return 0
  fi

  if has_command apt; then
    PACKAGE_MANAGEMENT_INSTALL='apt -y --no-install-recommends install'
    return 0
  fi

  if has_command dnf; then
    PACKAGE_MANAGEMENT_INSTALL='dnf -y install'
    return 0
  fi

  if has_command yum; then
    PACKAGE_MANAGEMENT_INSTALL='yum -y install'
    return 0
  fi

  if has_command zypper; then
    PACKAGE_MANAGEMENT_INSTALL='zypper install -y --no-recommends'
    return 0
  fi

  if has_command pacman; then
    PACKAGE_MANAGEMENT_INSTALL='pacman -Syu --noconfirm'
    return 0
  fi

  return 1
}

# -----------------------------
# install_software - 安装缺失依赖软件包
# 未探测到包管理器或安装失败则退出（65）
# -----------------------------
install_software() {
  local _package_name="$1"

  if ! detect_package_manager; then
    error "Supported package manager is not detected, please install the following package manually:"
    echo
    echo -e "\t* $_package_name"
    echo
    exit 65
  fi

  echo "Installing missing dependence '$_package_name' with '$PACKAGE_MANAGEMENT_INSTALL' ... "
  if $PACKAGE_MANAGEMENT_INSTALL "$_package_name"; then
    echo "ok"
  else
    error "Cannot install '$_package_name' with detected package manager, please install it manually."
    exit 65
  fi
}

# -----------------------------
# is_user_exists - 判断系统用户是否存在
# 返回：0 存在；非0 不存在
# -----------------------------
is_user_exists() {
  local _user="$1"

  id "$_user" > /dev/null 2>&1
}

# -----------------------------
# rerun_with_sudo - 使用sudo重新运行脚本
# 特殊情况：若从 /dev/fd/* 执行，则重新下载脚本到临时文件后再sudo执行
# 返回：13 无sudo；127 无curl/wget
# -----------------------------
rerun_with_sudo() {
  if ! has_command sudo; then
    return 13
  fi

  local _target_script

  if has_prefix "$0" "/dev/fd/"; then
    local _tmp_script="$(mktemp)"
    chmod +x "$_tmp_script"

    if has_command curl; then
      curl -o "$_tmp_script" 'https://get.hy2.sh/'
    elif has_command wget; then
      wget -O "$_tmp_script" 'https://get.hy2.sh'
    else
      return 127
    fi

    _target_script="$_tmp_script"
  else
    _target_script="$0"
  fi

  note "Re-running this script with sudo. You can also specify FORCE_NO_ROOT=1 to force this script to run as the current user."
  exec_sudo "$_target_script" "${SCRIPT_ARGS[@]}"
}

# -----------------------------
# check_permission - 检查是否root执行
# 非root：尝试sudo重跑，或 FORCE_NO_ROOT=1 继续执行
# -----------------------------
check_permission() {
  if [[ "$UID" -eq '0' ]]; then
    return
  fi

  note "The user running this script is not root."

  case "$FORCE_NO_ROOT" in
    '1')
      warning "FORCE_NO_ROOT=1 detected, we will proceed without root, but you may get insufficient privileges errors."
      ;;
    *)
      if ! rerun_with_sudo; then
        error "Please run this script with root or specify FORCE_NO_ROOT=1 to force this script to run as the current user."
        exit 13
      fi
      ;;
  esac
}

# -----------------------------
# check_environment_operating_system - 检测操作系统
# 默认仅支持Linux；可通过 OPERATING_SYSTEM 绕过检测
# -----------------------------
check_environment_operating_system() {
  if [[ -n "$OPERATING_SYSTEM" ]]; then
    warning "OPERATING_SYSTEM=$OPERATING_SYSTEM detected, operating system detection will not be performed."
    return
  fi

  if [[ "x$(uname)" == "xLinux" ]]; then
    OPERATING_SYSTEM=linux
    return
  fi

  error "This script only supports Linux."
  note "Specify OPERATING_SYSTEM=[linux|darwin|freebsd|windows] to bypass this check and force this script to run on this $(uname)."
  exit 95
}

# -----------------------------
# check_environment_architecture - 检测CPU架构
# 支持：386/amd64/arm/arm64/mipsle/s390x；可通过 ARCHITECTURE 绕过
# -----------------------------
check_environment_architecture() {
  if [[ -n "$ARCHITECTURE" ]]; then
    warning "ARCHITECTURE=$ARCHITECTURE detected, architecture detection will not be performed."
    return
  fi

  case "$(uname -m)" in
    'i386' | 'i686')
      ARCHITECTURE='386'
      ;;
    'amd64' | 'x86_64')
      ARCHITECTURE='amd64'
      ;;
    'armv5tel' | 'armv6l' | 'armv7' | 'armv7l')
      ARCHITECTURE='arm'
      ;;
    'armv8' | 'aarch64')
      ARCHITECTURE='arm64'
      ;;
    'mips' | 'mipsle' | 'mips64' | 'mips64le')
      ARCHITECTURE='mipsle'
      ;;
    's390x')
      ARCHITECTURE='s390x'
      ;;
    *)
      error "The architecture '$(uname -a)' is not supported."
      note "Specify ARCHITECTURE=<architecture> to bypass this check and force this script to run on this $(uname -m)."
      exit 8
      ;;
  esac
}

# -----------------------------
# check_environment_systemd - 检测systemd环境
# 不存在systemd：默认报错；可通过 FORCE_NO_SYSTEMD=1/2 绕过或跳过
# -----------------------------
check_environment_systemd() {
  if [[ -d "/run/systemd/system" ]] || grep -q systemd <(ls -l /sbin/init); then
    return
  fi

  case "$FORCE_NO_SYSTEMD" in
    '1')
      warning "FORCE_NO_SYSTEMD=1, we will proceed as normal even if systemd is not detected."
      ;;
    '2')
      warning "FORCE_NO_SYSTEMD=2, we will proceed but skip all systemd related commands."
      ;;
    *)
      error "This script only supports Linux distributions with systemd."
      note "Specify FORCE_NO_SYSTEMD=1 to disable this check and force this script to run as if systemd exists."
      note "Specify FORCE_NO_SYSTEMD=2 to disable this check and skip all systemd related commands."
      ;;
  esac
}

# -----------------------------
# check_environment_curl - 确保curl存在
# 若缺失则尝试自动安装
# -----------------------------
check_environment_curl() {
  if has_command curl; then
    return
  fi

  install_software curl
}

# -----------------------------
# check_environment_grep - 确保grep存在
# 若缺失则尝试自动安装
# -----------------------------
check_environment_grep() {
  if has_command grep; then
    return
  fi

  install_software grep
}

# -----------------------------
# check_environment - 统一环境检测入口
# -----------------------------
check_environment() {
  check_environment_operating_system
  check_environment_architecture
  check_environment_systemd
  check_environment_curl
  check_environment_grep
}

# -----------------------------
# vercmp_segment - 版本号片段比较
# 比较数字部分与后缀（如rc/beta等）
# 返回：<0 lhs小；0 相等；>0 lhs大
# -----------------------------
vercmp_segment() {
  local _lhs="$1"
  local _rhs="$2"

  if [[ "x$_lhs" == "x$_rhs" ]]; then
    echo 0
    return
  fi
  if [[ -z "$_lhs" ]]; then
    echo -1
    return
  fi
  if [[ -z "$_rhs" ]]; then
    echo 1
    return
  fi

  local _lhs_num="${_lhs//[A-Za-z]*/}"
  local _rhs_num="${_rhs//[A-Za-z]*/}"

  if [[ "x$_lhs_num" == "x$_rhs_num" ]]; then
    echo 0
    return
  fi
  if [[ -z "$_lhs_num" ]]; then
    echo -1
    return
  fi
  if [[ -z "$_rhs_num" ]]; then
    echo 1
    return
  fi
  local _numcmp=$(($_lhs_num - $_rhs_num))
  if [[ "$_numcmp" -ne 0 ]]; then
    echo "$_numcmp"
    return
  fi

  local _lhs_suffix="${_lhs#"$_lhs_num"}"
  local _rhs_suffix="${_rhs#"$_rhs_num"}"

  if [[ "x$_lhs_suffix" == "x$_rhs_suffix" ]]; then
    echo 0
    return
  fi
  if [[ -z "$_lhs_suffix" ]]; then
    echo 1
    return
  fi
  if [[ -z "$_rhs_suffix" ]]; then
    echo -1
    return
  fi
  if [[ "$_lhs_suffix" < "$_rhs_suffix" ]]; then
    echo -1
    return
  fi
  echo 1
}

# -----------------------------
# vercmp - 版本号比较（按.分段）
# 参数：lhs/rhs（可带v前缀）
# 返回：<0 lhs小；0 相等；>0 lhs大
# -----------------------------
vercmp() {
  local _lhs=${1#v}
  local _rhs=${2#v}

  while [[ -n "$_lhs" && -n "$_rhs" ]]; do
    local _clhs="${_lhs/.*/}"
    local _crhs="${_rhs/.*/}"

    local _segcmp="$(vercmp_segment "$_clhs" "$_crhs")"
    if [[ "$_segcmp" -ne 0 ]]; then
      echo "$_segcmp"
      return
    fi

    _lhs="${_lhs#"$_clhs"}"
    _lhs="${_lhs#.}"
    _rhs="${_rhs#"$_crhs"}"
    _rhs="${_rhs#.}"
  done

  if [[ "x$_lhs" == "x$_rhs" ]]; then
    echo 0
    return
  fi

  if [[ -z "$_lhs" ]]; then
    echo -1
    return
  fi

  if [[ -z "$_rhs" ]]; then
    echo 1
    return
  fi

  return
}

# -----------------------------
# check_hysteria_user - 确定hysteria运行用户
# 若已有service文件则从User=读取，否则使用默认值
# -----------------------------
check_hysteria_user() {
  local _default_hysteria_user="$1"

  if [[ -n "$HYSTERIA_USER" ]]; then
    return
  fi

  if [[ ! -e "$SYSTEMD_SERVICES_DIR/hysteria-server.service" ]]; then
    HYSTERIA_USER="$_default_hysteria_user"
    return
  fi

  HYSTERIA_USER="$(grep -o '^User=\w*' "$SYSTEMD_SERVICES_DIR/hysteria-server.service" | tail -1 | cut -d '=' -f 2 || true)"

  if [[ -z "$HYSTERIA_USER" ]]; then
    HYSTERIA_USER="$_default_hysteria_user"
  fi
}

# -----------------------------
# check_hysteria_homedir - 确定hysteria用户家目录
# 用户不存在则使用默认目录；存在则读取实际home
# -----------------------------
check_hysteria_homedir() {
  local _default_hysteria_homedir="$1"

  if [[ -n "$HYSTERIA_HOME_DIR" ]]; then
    return
  fi

  if ! is_user_exists "$HYSTERIA_USER"; then
    HYSTERIA_HOME_DIR="$_default_hysteria_homedir"
    return
  fi

  HYSTERIA_HOME_DIR="$(eval echo ~"$HYSTERIA_USER")"
}


###
# ARGUMENTS PARSER
###

# -----------------------------
# 参数解析 - 显示帮助信息并退出
# -----------------------------
show_usage_and_exit() {
  echo
  echo -e "\t$(tbold)$SCRIPT_NAME$(treset) - hysteria server install script"
  echo
  echo -e "Usage:"
  echo
  echo -e "$(tbold)Install hysteria$(treset)"
  echo -e "\t$0 [ -f | -l <file> | --version <version> ]"
  echo -e "Flags:"
  echo -e "\t-f, --force\tForce re-install latest or specified version even if it has been installed."
  echo -e "\t-l, --local <file>\tInstall specified hysteria binary instead of download it."
  echo -e "\t--version <version>\tInstall specified version instead of the latest."
  echo
  echo -e "$(tbold)Remove hysteria$(treset)"
  echo -e "\t$0 --remove"
  echo
  echo -e "$(tbold)Check for the update$(treset)"
  echo -e "\t$0 -c"
  echo -e "\t$0 --check"
  echo
  echo -e "$(tbold)Show this help$(treset)"
  echo -e "\t$0 -h"
  echo -e "\t$0 --help"
  exit 0
}

# -----------------------------
# parse_arguments - 解析命令行参数并校验合法性
# 支持：install（默认）/ remove / check_update
# -----------------------------
parse_arguments() {
  while [[ "$#" -gt '0' ]]; do
    case "$1" in
      '--remove')
        if [[ -n "$OPERATION" && "$OPERATION" != 'remove' ]]; then
          show_argument_error_and_exit "Option '--remove' is in conflict with other options."
        fi
        OPERATION='remove'
        ;;
      '--version')
        VERSION="$2"
        if [[ -z "$VERSION" ]]; then
          show_argument_error_and_exit "Please specify the version for option '--version'."
        fi
        shift
        if ! has_prefix "$VERSION" 'v'; then
          show_argument_error_and_exit "Version numbers should begin with 'v' (such as 'v2.0.0'), got '$VERSION'"
        fi
        ;;
      '-c' | '--check')
        if [[ -n "$OPERATION" && "$OPERATION" != 'check' ]]; then
          show_argument_error_and_exit "Option '-c' or '--check' is in conflict with other options."
        fi
        OPERATION='check_update'
        ;;
      '-f' | '--force')
        FORCE='1'
        ;;
      '-h' | '--help')
        show_usage_and_exit
        ;;
      '-l' | '--local')
        LOCAL_FILE="$2"
        if [[ -z "$LOCAL_FILE" ]]; then
          show_argument_error_and_exit "Please specify the local binary to install for option '-l' or '--local'."
        fi
        break
        ;;
      *)
        show_argument_error_and_exit "Unknown option '$1'"
        ;;
    esac
    shift
  done

  if [[ -z "$OPERATION" ]]; then
    OPERATION='install'
  fi

  # validate arguments
  case "$OPERATION" in
    'install')
      if [[ -n "$VERSION" && -n "$LOCAL_FILE" ]]; then
        show_argument_error_and_exit '--version and --local cannot be used together.'
      fi
      ;;
    *)
      if [[ -n "$VERSION" ]]; then
        show_argument_error_and_exit "--version is only valid for install operation."
      fi
      if [[ -n "$LOCAL_FILE" ]]; then
        show_argument_error_and_exit "--local is only valid for install operation."
      fi
      ;;
  esac
}


###
# FILE TEMPLATES
###

# -----------------------------
# 文件模板 - systemd service 与示例配置文件内容生成
# -----------------------------

# -----------------------------
# tpl_hysteria_server_service_base - 生成systemd service基础模板
# 参数：config名（用于拼接配置文件名）
# -----------------------------
tpl_hysteria_server_service_base() {
  local _config_name="$1"

  cat << EOF
[Unit]
Description=Hysteria Server Service (${_config_name}.yaml)
After=network.target

[Service]
Type=simple
ExecStart=$EXECUTABLE_INSTALL_PATH server --config ${CONFIG_DIR}/${_config_name}.yaml
WorkingDirectory=$HYSTERIA_HOME_DIR
User=$HYSTERIA_USER
Group=$HYSTERIA_USER
Environment=HYSTERIA_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
}

# -----------------------------
# tpl_hysteria_server_service - 生成默认service文件模板（config.yaml）
# -----------------------------
tpl_hysteria_server_service() {
  tpl_hysteria_server_service_base 'config'
}

# -----------------------------
# tpl_hysteria_server_x_service - 生成实例化service模板（hysteria-server@.service）
# -----------------------------
tpl_hysteria_server_x_service() {
  tpl_hysteria_server_service_base '%i'
}

# -----------------------------
# tpl_etc_hysteria_config_yaml - 生成 /etc/hysteria/config.yaml 示例配置
# 包含ACME与password认证的示例，并生成随机密码
# -----------------------------
tpl_etc_hysteria_config_yaml() {
  cat << EOF
# listen: :443

acme:
  domains:
    - your.domain.net
  email: your@email.com

auth:
  type: password
  password: $(generate_random_password)

masquerade:
  type: proxy
  proxy:
    url: https://news.ycombinator.com/
    rewriteHost: true
EOF
}


###
# SYSTEMD
###

# -----------------------------
# systemd 相关 - 查询运行中服务/重启/停止
# -----------------------------

# -----------------------------
# get_running_services - 获取当前运行中的 hysteria-server 服务实例列表
# FORCE_NO_SYSTEMD=2 时跳过
# -----------------------------
get_running_services() {
  if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
    return
  fi

  systemctl list-units --state=active --plain --no-legend \
    | grep -o "hysteria-server@*[^\s]*.service" || true
}

# -----------------------------
# restart_running_services - 重启当前运行中的服务实例
# -----------------------------
restart_running_services() {
  if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
    return
  fi

  echo "Restarting running service ... "

  for service in $(get_running_services); do
    echo -ne "Restarting $service ... "
    systemctl restart "$service"
    echo "done"
  done
}

# -----------------------------
# stop_running_services - 停止当前运行中的服务实例
# -----------------------------
stop_running_services() {
  if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
    return
  fi

  echo "Stopping running service ... "

  for service in $(get_running_services); do
    echo -ne "Stopping $service ... "
    systemctl stop "$service"
    echo "done"
  done
}


###
# HYSTERIA & GITHUB API
###

# -----------------------------
# hysteria 与 GitHub API - 安装检测/版本检测/下载/更新检查
# -----------------------------

# -----------------------------
# is_hysteria_installed - 判断hysteria是否已安装
# 返回：0 已安装；1 未安装
# -----------------------------
is_hysteria_installed() {
  # RETURN VALUE
  # 0: hysteria is installed
  # 1: hysteria is not installed

  if [[ -f "$EXECUTABLE_INSTALL_PATH" || -h "$EXECUTABLE_INSTALL_PATH" ]]; then
    return 0
  fi
  return 1
}

# -----------------------------
# is_hysteria1_version - 判断是否为Hysteria 1版本号（v1.* 或 v0.*）
# -----------------------------
is_hysteria1_version() {
  local _version="$1"

  has_prefix "$_version" "v1." || has_prefix "$_version" "v0."
}

# -----------------------------
# get_installed_version - 获取已安装hysteria版本号
# 兼容 Hysteria 2（hysteria version）与 Hysteria 1（hysteria -v）
# -----------------------------
get_installed_version() {
  if is_hysteria_installed; then
    if "$EXECUTABLE_INSTALL_PATH" version > /dev/null 2>&1; then
      "$EXECUTABLE_INSTALL_PATH" version | grep Version | grep -o 'v[.0-9]*'
    elif "$EXECUTABLE_INSTALL_PATH" -v > /dev/null 2>&1; then
      # hysteria 1
      "$EXECUTABLE_INSTALL_PATH" -v | cut -d ' ' -f 3
    fi
  fi
}

# -----------------------------
# get_latest_version - 获取最新版本号
# 若用户指定 VERSION 则直接返回，否则通过 GitHub API 读取 releases/latest
# -----------------------------
get_latest_version() {
  if [[ -n "$VERSION" ]]; then
    echo "$VERSION"
    return
  fi

  local _tmpfile=$(mktemp)
  if ! curl -sS -H 'Accept: application/vnd.github.v3+json' "$API_BASE_URL/releases/latest" -o "$_tmpfile"; then
    error "Failed to get the latest version from GitHub API, please check your network and try again."
    exit 11
  fi

  local _latest_version=$(grep 'tag_name' "$_tmpfile" | head -1 | grep -o '"app/v.*"')
  _latest_version=${_latest_version#'"app/'}
  _latest_version=${_latest_version%'"'}

  if [[ -n "$_latest_version" ]]; then
    echo "$_latest_version"
  fi

  rm -f "$_tmpfile"
}

# -----------------------------
# download_hysteria - 下载hysteria二进制到指定路径
# 参数：版本号、目标文件路径
# -----------------------------
download_hysteria() {
  local _version="$1"
  local _destination="$2"

  local _download_url="$REPO_URL/releases/download/app/$_version/hysteria-$OPERATING_SYSTEM-$ARCHITECTURE"
  echo "Downloading hysteria binary: $_download_url ..."
  if ! curl -R -H 'Cache-Control: no-cache' "$_download_url" -o "$_destination"; then
    error "Download failed, please check your network and try again."
    return 11
  fi
  return 0
}

# -----------------------------
# check_update - 检查是否有更新
# 返回：0 有更新；1 已是最新或获取失败
# 副作用：若成功获取最新版本，会把 VERSION 设为最新版本
# -----------------------------
check_update() {
  # RETURN VALUE
  # 0: update available
  # 1: installed version is latest

  echo -ne "Checking for installed version ... "
  local _installed_version="$(get_installed_version)"
  if [[ -n "$_installed_version" ]]; then
    echo "$_installed_version"
  else
    echo "not installed"
  fi

  echo -ne "Checking for latest version ... "
  local _latest_version="$(get_latest_version)"
  if [[ -n "$_latest_version" ]]; then
    echo "$_latest_version"
    VERSION="$_latest_version"
  else
    echo "failed"
    return 1
  fi

  local _vercmp="$(vercmp "$_installed_version" "$_latest_version")"
  if [[ "$_vercmp" -lt 0 ]]; then
    return 0
  fi

  return 1
}


###
# ENTRY
###

# -----------------------------
# 执行入口 - 安装/卸载/更新检查的具体流程实现
# -----------------------------

# -----------------------------
# perform_install_hysteria_binary - 安装hysteria可执行文件
# 支持本地文件安装（--local），否则从GitHub下载后安装
# -----------------------------
perform_install_hysteria_binary() {
  if [[ -n "$LOCAL_FILE" ]]; then
    note "Performing local install: $LOCAL_FILE"

    echo -ne "Installing hysteria executable ... "

    if install -Dm755 "$LOCAL_FILE" "$EXECUTABLE_INSTALL_PATH"; then
      echo "ok"
    else
      exit 2
    fi

    return
  fi

  local _tmpfile=$(mktemp)

  if ! download_hysteria "$VERSION" "$_tmpfile"; then
    rm -f "$_tmpfile"
    exit 11
  fi

  echo -ne "Installing hysteria executable ... "

  if install -Dm755 "$_tmpfile" "$EXECUTABLE_INSTALL_PATH"; then
    echo "ok"
  else
    exit 13
  fi

  rm -f "$_tmpfile"
}

# -----------------------------
# perform_remove_hysteria_binary - 卸载hysteria可执行文件
# -----------------------------
perform_remove_hysteria_binary() {
  remove_file "$EXECUTABLE_INSTALL_PATH"
}

# -----------------------------
# perform_install_hysteria_example_config - 安装示例配置文件到 /etc/hysteria/config.yaml
# -----------------------------
perform_install_hysteria_example_config() {
  install_content -Dm644 "$(tpl_etc_hysteria_config_yaml)" "$CONFIG_DIR/config.yaml" ""
}

# -----------------------------
# perform_install_hysteria_systemd - 安装systemd服务文件并daemon-reload
# FORCE_NO_SYSTEMD=2 时跳过
# -----------------------------
perform_install_hysteria_systemd() {
  if [[ "x$FORCE_NO_SYSTEMD" == "x2" ]]; then
    return
  fi

  install_content -Dm644 "$(tpl_hysteria_server_service)" "$SYSTEMD_SERVICES_DIR/hysteria-server.service" "1"
  install_content -Dm644 "$(tpl_hysteria_server_x_service)" "$SYSTEMD_SERVICES_DIR/hysteria-server@.service" "1"

  systemctl daemon-reload
}

# -----------------------------
# perform_remove_hysteria_systemd - 删除systemd服务文件并daemon-reload
# -----------------------------
perform_remove_hysteria_systemd() {
  remove_file "$SYSTEMD_SERVICES_DIR/hysteria-server.service"
  remove_file "$SYSTEMD_SERVICES_DIR/hysteria-server@.service"

  systemctl daemon-reload
}

# -----------------------------
# perform_install_hysteria_home_legacy - legacy行为：创建运行用户（若不存在）
# 仅在用户不存在时创建 system user，并设置home目录
# -----------------------------
perform_install_hysteria_home_legacy() {
  if ! is_user_exists "$HYSTERIA_USER"; then
    echo -ne "Creating user $HYSTERIA_USER ... "
    useradd -r -d "$HYSTERIA_HOME_DIR" -m "$HYSTERIA_USER"
    echo "ok"
  fi
}

# -----------------------------
# perform_install - 执行安装/升级主流程
# - 判断是否首次安装/从Hysteria1升级
# - 判断是否需要更新（或--force强制）
# - 安装二进制、示例配置、用户、systemd文件
# - 根据场景输出后续操作指引
# -----------------------------
perform_install() {
  local _is_frash_install
  local _is_upgrade_from_hysteria1
  if ! is_hysteria_installed; then
    _is_frash_install=1
  elif is_hysteria1_version "$(get_installed_version)"; then
    _is_upgrade_from_hysteria1=1
  fi

  local _is_update_required

  if [[ -n "$LOCAL_FILE" ]] || [[ -n "$VERSION" ]] || check_update; then
    _is_update_required=1
  fi

  if [[ "x$FORCE" == "x1" ]]; then
    if [[ -z "$_is_update_required" ]]; then
      note "Option '--force' detected, re-install even if installed version is the latest."
    fi
    _is_update_required=1
  fi

  if [[ -z "$_is_update_required" ]]; then
    echo "$(tgreen)Installed version is up-to-date, there is nothing to do.$(treset)"
    return
  fi

  if is_hysteria1_version "$VERSION"; then
    error "This script can only install Hysteria 2."
    exit 95
  fi

  perform_install_hysteria_binary
  perform_install_hysteria_example_config
  perform_install_hysteria_home_legacy
  perform_install_hysteria_systemd

  if [[ -n "$_is_frash_install" ]]; then
    echo
    echo -e "$(tbold)Congratulation! Hysteria 2 has been successfully installed on your server.$(treset)"
    echo
    echo -e "What's next?"
    echo
    echo -e "\t+ Take a look at the differences between Hysteria 2 and Hysteria 1 at https://hysteria.network/docs/misc/2-vs-1/"
    echo -e "\t+ Check out the quick server config guide at $(tblue)https://hysteria.network/docs/getting-started/Server/$(treset)"
    echo -e "\t+ Edit server config file at $(tred)$CONFIG_DIR/config.yaml$(treset)"
    echo -e "\t+ Start your hysteria server with $(tred)systemctl start hysteria-server.service$(treset)"
    echo -e "\t+ Configure hysteria start on system boot with $(tred)systemctl enable hysteria-server.service$(treset)"
    echo
  elif [[ -n "$_is_upgrade_from_hysteria1" ]]; then
    echo -e "Skip automatic service restart due to $(tred)incompatible$(treset) upgrade."
    echo
    echo -e "$(tbold)Hysteria has been successfully update to $VERSION from Hysteria 1.$(treset)"
    echo
    echo -e "$(tred)Hysteria 2 uses a completely redesigned protocol & config, which is NOT compatible with the version 1.x.x in any way.$(treset)"
    echo
    echo -e "\t+ Take a look at the behavior changes in Hysteria 2 at $(tblue)https://hysteria.network/docs/misc/2-vs-1/$(treset)"
    echo -e "\t+ Check out the quick server configuration guide for Hysteria 2 at $(tblue)https://hysteria.network/docs/getting-started/Server/$(treset)"
    echo -e "\t+ Migrate server config file to the Hysteria 2 at $(tred)$CONFIG_DIR/config.yaml$(treset)"
    echo -e "\t+ Start your hysteria server with $(tred)systemctl restart hysteria-server.service$(treset)"
    echo -e "\t+ Configure hysteria start on system boot with $(tred)systemctl enable hysteria-server.service$(treset)"
  else
    restart_running_services

    echo
    echo -e "$(tbold)Hysteria has been successfully update to $VERSION.$(treset)"
    echo
    echo -e "Check out the latest changelog $(tblue)https://github.com/apernet/hysteria/blob/master/CHANGELOG.md$(treset)"
    echo
  fi
}

# -----------------------------
# perform_remove - 执行卸载流程
# - 删除二进制
# - 停止服务
# - 删除systemd文件
# - 输出残留文件/用户清理指引
# -----------------------------
perform_remove() {
  perform_remove_hysteria_binary
  stop_running_services
  perform_remove_hysteria_systemd

  echo
  echo -e "$(tbold)Congratulation! Hysteria has been successfully removed from your server.$(treset)"
  echo
  echo -e "You still need to remove configuration files and ACME certificates manually with the following commands:"
  echo
  echo -e "\t$(tred)rm -rf "$CONFIG_DIR"$(treset)"
  if [[ "x$HYSTERIA_USER" != "xroot" ]]; then
    echo -e "\t$(tred)userdel -r "$HYSTERIA_USER"$(treset)"
  fi
  if [[ "x$FORCE_NO_SYSTEMD" != "x2" ]]; then
    echo
    echo -e "You still might need to disable all related systemd services with the following commands:"
    echo
    echo -e "\t$(tred)rm -f /etc/systemd/system/multi-user.target.wants/hysteria-server.service$(treset)"
    echo -e "\t$(tred)rm -f /etc/systemd/system/multi-user.target.wants/hysteria-server@*.service$(treset)"
    echo -e "\t$(tred)systemctl daemon-reload$(treset)"
  fi
  echo
}

# -----------------------------
# perform_check_update - 执行更新检查并输出提示
# -----------------------------
perform_check_update() {
  if check_update; then
    echo
    echo -e "$(tbold)Update available: $VERSION$(treset)"
    echo
    echo -e "$(tgreen)You can download and install the latest version by execute this script without any arguments.$(treset)"
    echo
  else
    echo
    echo "$(tgreen)Installed version is up-to-date.$(treset)"
    echo
  fi
}

# -----------------------------
# main - 脚本主入口
# - 解析参数
# - 权限与环境检测
# - 确定运行用户与home目录
# - 按操作分发到 install/remove/check_update
# -----------------------------
main() {
  parse_arguments "$@"

  check_permission
  check_environment
  check_hysteria_user "hysteria"
  check_hysteria_homedir "/var/lib/$HYSTERIA_USER"

  case "$OPERATION" in
    "install")
      perform_install
      ;;
    "remove")
      perform_remove
      ;;
    "check_update")
      perform_check_update
      ;;
    *)
      error "Unknown operation '$OPERATION'."
      ;;
  esac
}

# -----------------------------
# 程序执行入口 - 调用main并传入脚本参数
# -----------------------------
main "$@"

# vim:set ft=bash ts=2 sw=2 sts=2 et:
