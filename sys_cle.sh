#!/bin/bash

# 日志文件路径
LOG_FILE="/var/log/sys_cle.log"

# 保留日志的最大行数
MAX_LOG_LINES=100

# 清理功能定义
clean_apt_cache() {
  echo "$(date) - 清理 apt 缓存..." >> $LOG_FILE
  apt clean -y
}

clean_journal_logs() {
  echo "$(date) - 清理 systemd 日志..." >> $LOG_FILE
  journalctl --vacuum-size=100M
}

clean_tmp_files() {
  echo "$(date) - 清理临时文件..." >> $LOG_FILE
  rm -rf /tmp/*
  rm -rf /var/tmp/*
}

clean_pip_cache() {
  echo "$(date) - 清理 pip 缓存..." >> $LOG_FILE
  pip cache purge -y
}

clean_old_logs() {
  echo "$(date) - 清理系统旧日志..." >> $LOG_FILE
  find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;
}

check_disk_usage() {
  # 获取当前系统硬盘使用情况
  DISK_USAGE=$(df -h / | awk 'NR==2 {print $3 " / " $5 " used"}')
  echo "$(date) - 硬盘使用情况: $DISK_USAGE" >> $LOG_FILE
}

# 保证日志文件只保留 100 行
limit_log_size() {
  # 保留最新的 100 行日志
  tail -n $MAX_LOG_LINES $LOG_FILE > $LOG_FILE.tmp && mv $LOG_FILE.tmp $LOG_FILE
}

# 执行所有清理任务
main_cleanup() {
  echo "$(date) - 开始系统清理..." >> $LOG_FILE

  clean_apt_cache
  clean_journal_logs
  clean_tmp_files
  clean_pip_cache
  clean_old_logs
  check_disk_usage

  # 限制日志文件大小为 100 行
  limit_log_size

  echo "$(date) - 系统清理完成。" >> $LOG_FILE
}

# 调用清理函数
main_cleanup