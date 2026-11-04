#!/usr/bin/env bash
# Patch an existing wol.sh in place without changing its other WOL features.
# Usage: bash patch_wol.sh [/root/wol.sh]
set -euo pipefail
TARGET="${1:-/root/wol.sh}"
if [[ ! -f "$TARGET" ]]; then
    printf '[ERROR] wol.sh not found: %s\n' "$TARGET" >&2
    exit 1
fi
command -v python3 >/dev/null || { echo '[ERROR] python3 is required.' >&2; exit 1; }
python3 - "$TARGET" <<'PY_PATCH'
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

path = Path(sys.argv[1]).resolve()
source = path.read_text(encoding='utf-8')
if not re.search(r'^VERSION="[0-9][^"]*"$', source, re.M):
    raise SystemExit('[ERROR] No wol.sh VERSION found; will not patch an unknown script.')
start_match = re.search(r'^download_wol_program\(\)\s*\{\s*$', source, re.M)
if not start_match:
    raise SystemExit('[ERROR] download_wol_program() not found; nothing changed.')
rest = source[start_match.end():]
next_function = re.search(r'^[_a-zA-Z][_a-zA-Z0-9]*\(\)\s*\{\s*$', rest, re.M)
if not next_function:
    raise SystemExit('[ERROR] Cannot locate next function safely; nothing changed.')
start = start_match.start()
end = start_match.end() + next_function.start()

replacement = r'''download_wol_program() {
    # Fetch the actual Python source (not GitHub's HTML /blob/ page).
    # Only install after checking size, Python syntax and matching app version.
    local url="https://raw.githubusercontent.com/byilrq/vps/main/wol/wol.py"
    local tmp="" candidate="" download_ok=0
    mkdir -p "$APP_DIR" || return 1
    tmp="$(mktemp "${APP_DIR}/.wol.py.download.XXXXXXXX")" || {
        err "无法创建临时下载文件：$APP_DIR"
        return 1
    }

    verify_wol_python() {
        local file="$1"
        [[ -s "$file" ]] || return 1
        (( $(wc -c < "$file") >= 256 )) || return 1
        "$VENV_PY" - "$file" "$VERSION" <<'PY_WOL_VERIFY'
import ast, sys
path, expected = sys.argv[1:]
try:
    with open(path, 'r', encoding='utf-8') as f:
        tree = ast.parse(f.read(), filename=path)
except (OSError, SyntaxError, UnicodeError):
    raise SystemExit(1)
found = None
for statement in tree.body:
    if isinstance(statement, (ast.Assign, ast.AnnAssign)):
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        if any(isinstance(x, ast.Name) and x.id == 'WOL_WEB_APP_VERSION' for x in targets):
            try:
                found = ast.literal_eval(statement.value)
            except (ValueError, TypeError):
                pass
            break
raise SystemExit(0 if found == expected else 1)
PY_WOL_VERIFY
    }

    info "正在从 GitHub 自动获取 wol.py ..."
    if command -v curl >/dev/null 2>&1; then
        curl --fail --silent --show-error --location --retry 3 --retry-delay 2 \
             --connect-timeout 10 --max-time 120 "$url" --output "$tmp" && download_ok=1
    elif command -v wget >/dev/null 2>&1; then
        wget -q --timeout=30 --tries=3 -O "$tmp" "$url" && download_ok=1
    else
        warn "系统未安装 curl 或 wget，无法在线下载 wol.py。"
    fi

    if (( download_ok == 1 )) && verify_wol_python "$tmp"; then
        # Same-filesystem atomic replacement: never overwrite a working file
        # with an empty, partial, malformed or mismatched source file.
        chown root:root "$tmp" 2>/dev/null || true
        chmod 644 "$tmp" || { rm -f "$tmp"; return 1; }
        if mv -f "$tmp" "${APP_DIR}/wol.py"; then
            info "已将 GitHub 上匹配 v${VERSION} 的 wol.py 安装到 ${APP_DIR}/wol.py。"
            return 0
        fi
        rm -f "$tmp"
        err "wol.py 安装失败。"
        return 1
    fi
    rm -f "$tmp"
    warn "GitHub wol.py 下载失败、文件太小、Python 语法异常或版本与 wol.sh(v${VERSION}) 不一致。"
    warn "远端地址：${url}"

    # Re-installation / offline fallback only: keep an existing matching copy.
    for candidate in "${APP_DIR}/wol.py" "${SCRIPT_DIR}/wol.py"; do
        if [[ -f "$candidate" ]] && verify_wol_python "$candidate"; then
            if [[ "$candidate" != "${APP_DIR}/wol.py" ]]; then
                install -o root -g root -m 644 "$candidate" "${APP_DIR}/wol.py" || return 1
            fi
            info "使用现有匹配版本的 wol.py：${APP_DIR}/wol.py。"
            return 0
        fi
    done
    err "未找到可用的 wol.py。请先将完整且版本匹配的 wol.py 上传至 GitHub：wol/wol.py。"
    err "注意：GitHub 上 0~1 字节的占位文件无法安装。"
    return 1
}

'''
updated = source[:start] + replacement + source[end:]
# Ensure a fixed installation directory independent of where wol.sh is located.
old = 'APP_DIR="${SCRIPT_DIR}/wol"'
new = 'APP_DIR="/root/wol"'
if old in updated:
    updated = updated.replace(old, new, 1)
elif new not in updated:
    raise SystemExit('[ERROR] APP_DIR layout is unknown; refusing to patch.')

fd, staging_path = tempfile.mkstemp(prefix='.wol-patch-', suffix='.sh', dir=str(path.parent))
os.close(fd)
try:
    staging = Path(staging_path)
    staging.write_text(updated, encoding='utf-8')
    shutil.copymode(path, staging)
    check = subprocess.run(['bash', '-n', str(staging)], capture_output=True, text=True)
    if check.returncode:
        raise SystemExit('[ERROR] New wol.sh failed bash -n: ' + check.stderr)
    backup = path.with_name(path.name + '.bak.' + datetime.now().strftime('%Y%m%d_%H%M%S') + '.' + str(os.getpid()))
    shutil.copy2(path, backup)
    os.replace(staging, path)
    print('[OK] Updated:', path)
    print('[OK] Original backed up:', backup)
    print('[OK] Application destination: /root/wol/wol.py')
    print('[INFO] Only download/install and application path were changed.')
finally:
    if os.path.exists(staging_path):
        os.remove(staging_path)
PY_PATCH
