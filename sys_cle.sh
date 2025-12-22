#!/bin/bash
set -u

# =========================
# sys_cle.sh - 系统清理脚本
# 输出日志: /root/sys_cle.log
# =========================

LOG_FILE="/root/sys_cle.log"
MAX_LOG_LINES=100

log() {
  echo "$(date '+%F %T') - $*" >> "$LOG_FILE"
}

# 保证日志文件只保留 MAX_LOG_LINES 行
limit_log_size() {
  [ -f "$LOG_FILE" ] || touch "$LOG_FILE"
  tail -n "$MAX_LOG_LINES" "$LOG_FILE" > "${LOG_FILE}.tmp" 2>/dev/null && mv -f "${LOG_FILE}.tmp" "$LOG_FILE"
}

# ========== 清理项 ==========

clean_apt_cache() {
  if command -v apt-get >/dev/null 2>&1; then
    log "清理 apt 缓存 (apt-get clean)..."
    apt-get clean >/dev/null 2>&1 || true
  fi
}

clean_apt_more() {
  if command -v apt-get >/dev/null 2>&1; then
    log "清理无用依赖 (autoremove) & 旧包缓存 (autoclean)..."
    apt-get autoremove -y >/dev/null 2>&1 || true
    apt-get autoclean -y >/dev/null 2>&1 || true
  fi
}

clean_journal_logs() {
  if command -v journalctl >/dev/null 2>&1; then
    log "清理 systemd 日志 (vacuum-size=100M)..."
    journalctl --vacuum-size=100M >/dev/null 2>&1 || true
  fi
}

clean_journal_more() {
  if command -v journalctl >/dev/null 2>&1; then
    log "清理 systemd 日志 (vacuum-time=7d)..."
    journalctl --vacuum-time=7d >/dev/null 2>&1 || true
  fi
}

clean_tmp_files() {
  log "清理临时文件 /tmp /var/tmp ..."
  rm -rf /tmp/* /var/tmp/* >/dev/null 2>&1 || true
}

clean_pip_cache() {
  log "清理 pip/pip3 缓存..."
  command -v pip  >/dev/null 2>&1 && pip  cache purge >/dev/null 2>&1 || true
  command -v pip3 >/dev/null 2>&1 && pip3 cache purge >/dev/null 2>&1 || true
}

clean_user_cache() {
  log "清理 /root/.cache ..."
  rm -rf /root/.cache/* >/dev/null 2>&1 || true
}

clean_other_caches() {
  log "清理其他常见工具缓存(存在才清理)..."
  command -v npm >/dev/null 2>&1 && npm cache clean --force >/dev/null 2>&1 || true
  command -v yarn >/dev/null 2>&1 && yarn cache clean >/dev/null 2>&1 || true
  command -v composer >/dev/null 2>&1 && composer clear-cache >/dev/null 2>&1 || true
}

# 注意：此项会删除 docker 未使用镜像/容器/网络/卷（不会删正在运行的容器）
# 若你不想动 docker，把 main_cleanup 里的 clean_docker 注释掉即可
clean_docker() {
  if command -v docker >/dev/null 2>&1; then
    log "清理 Docker 未使用资源 (docker system prune -af --volumes)..."
    docker system prune -af --volumes >/dev/null 2>&1 || true
  fi
}

# 清理旧日志：更安全的做法是只清空 *.log 和 *.log.*，避免误伤非日志文件
clean_old_logs() {
  log "清理系统旧日志(截断 *.log / *.log.*)..."
  find /var/log -type f \( -name "*.log" -o -name "*.log.*" \) -exec truncate -s 0 {} \; >/dev/null 2>&1 || true
}

check_disk_usage() {
  local usage
  usage=$(df -h / 2>/dev/null | awk 'NR==2 {print $3 " / " $2 "  (used: " $5 ")"}')
  log "硬盘使用情况: ${usage:-unknown}"
}

# ========== 主流程 ==========

main_cleanup() {
  log "开始系统清理..."

  clean_apt_cache
  clean_apt_more
  clean_journal_logs
  clean_journal_more
  clean_tmp_files
  clean_pip_cache
  clean_other_caches
  clean_user_cache
  clean_old_logs
  check_disk_usage
  limit_log_size
  log "系统清理完成。"
}

main_cleanup
