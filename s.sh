#!/usr/bin/env bash
# s.sh - Standalone S-UI + sing-box manager, independent of xpro.sh / 3X-UI.
# User owned /etc/nginx/sites-enabled/wow and /www/wow/public are never edited.
# Embedded Python helpers are extracted locally on demand; only s.sh is required.
set -Eeuo pipefail
umask 077

SUI_MANAGER_VERSION='2026.10.25-isolated-1'
SUI_VERSION='v1.6.5'
SUI_DOMAIN_DEFAULT='wow.xyrq.de'
SUI_HOME='/root/sui-pro'
SUI_LIB="$SUI_HOME/internal"
SUI_API_MANAGER="$SUI_LIB/sui_manage.py"
SUI_NGINX_INSPECTOR="$SUI_LIB/nginx_legacy_cleanup.py"
SUI_NGINX_BRIDGE='/etc/nginx/conf.d/sui-managed-reality-bridge.conf'
SUI_LOG="$SUI_HOME/install.log"
SUI_HTTP_BACKEND_PORT=8080
SUI_BRIDGE_PORT=''
SUI_DOMAIN=''
SUI_USER_SITE=''
SUI_CERT=''
SUI_KEY=''
SUI_NEW_INSTALL=0
SUI_NEW_BRIDGE=0
SUI_TRANSACTION=0
SUI_COMMITTED=0
SUI_LEGACY_BACKUP=''

info() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
ok() { printf '[OK] %s\n' "$*"; }
fail() { printf '[ERROR] %s\n' "$*" >&2; return 1; }
need_root() { (( EUID == 0 )) || fail '请以 root 身份运行'; }
read_console() {
    local name="$1" prompt="$2" value=''
    if [[ -t 0 ]]; then IFS= read -e -r -p "$prompt" value; else IFS= read -r -p "$prompt" value; fi
    printf -v "$name" '%s' "$value"
}
valid_domain() {
    [[ "$1" =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]] && [[ "$1" != *..* ]]
}
require_cmds() {
    local exe
    for exe in bash python3 curl nginx openssl ss systemctl tar sha256sum; do
        command -v "$exe" >/dev/null 2>&1 || fail "缺少命令: $exe；Debian/Ubuntu 可安装：apt-get install -y python3 curl nginx openssl iproute2 ca-certificates"
    done
}
port_listening() {
    local port="$1"
    ss -lntH 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$"
}
port_owner() { ss -lntp 2>/dev/null | grep -E "(^|:)${1}[[:space:]]" || true; }
site_http_code() {
    curl --noproxy '*' -sS -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 8 "http://127.0.0.1:${SUI_HTTP_BACKEND_PORT}/" 2>/dev/null || true
}
http_ok() { [[ "$1" =~ ^[1-4][0-9][0-9]$ ]]; }
bridge_http_code() {
    local port="$1"
    curl --noproxy '*' --silent --show-error --max-time 8 --connect-timeout 3 \
        --resolve "${SUI_DOMAIN}:${port}:127.0.0.1" \
        --output /dev/null --write-out '%{http_code}' \
        "https://${SUI_DOMAIN}:${port}/" 2>/dev/null || true
}
set_domain() {
    SUI_DOMAIN="${1:-$SUI_DOMAIN_DEFAULT}"
    valid_domain "$SUI_DOMAIN" || fail "非法域名: $SUI_DOMAIN"
    SUI_USER_SITE="/etc/nginx/sites-enabled/${SUI_DOMAIN%%.*}"
    SUI_CERT="${SUI_CERT_FULLCHAIN:-/etc/letsencrypt/live/${SUI_DOMAIN}/fullchain.pem}"
    SUI_KEY="${SUI_CERT_PRIVKEY:-/etc/letsencrypt/live/${SUI_DOMAIN}/privkey.pem}"
}

# Inlined helpers are written only to S-UI's private application data directory.
# They have no dependency on xpro.sh, /root/x.sh or another downloaded package.
extract_helpers() {
    need_root
    mkdir -p "$SUI_LIB"
    chmod 700 "$SUI_HOME" "$SUI_LIB"
    cat > "$SUI_API_MANAGER" <<'SUI_EMBED_MANAGER_PY'
#!/usr/bin/env python3
"""Provision S-UI v1.6.5 through its first-party, session-authenticated local API.
No direct modification of S-UI's SQLite database.
"""
import argparse
import getpass
import http.cookiejar
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

API_ROOT = os.environ.get('SUI_LOCAL_API', 'http://127.0.0.1:2095/app/api').rstrip('/')
SB_BIN = os.environ.get('SUI_SINGBOX_BIN', '/usr/local/s-ui/bin/sing-box')
STATE = Path(os.environ.get('SUI_STATE_FILE', '/root/sui-pro/node-state.json'))

class SetupError(RuntimeError):
    pass

class SuiAPI:
    def __init__(self, root=API_ROOT):
        self.root = root.rstrip('/')
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), urllib.request.ProxyHandler({}))

    def call(self, path, fields=None, timeout=12):
        url = self.root + '/' + path.lstrip('/')
        payload = None if fields is None else urllib.parse.urlencode(fields).encode('utf-8')
        req = urllib.request.Request(url, data=payload, headers={'User-Agent': 'SUI-Migration-Manager/1.0', 'Origin': 'http://127.0.0.1:2095', 'Referer': 'http://127.0.0.1:2095/app/'})
        try:
            with self.opener.open(req, timeout=timeout) as response:
                obj = json.loads(response.read().decode('utf-8'))
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise SetupError(f'S-UI API 请求失败: {path}: {exc}') from exc
        if not isinstance(obj, dict) or obj.get('success') is not True:
            raise SetupError(f'S-UI API 返回错误: {path}: {obj.get("msg", obj) if isinstance(obj, dict) else obj}')
        return obj.get('obj')

    def login(self, user, password):
        self.call('login', {'user':user, 'pass':password})
        self.get('tls')  # Check that the session cookie really works

    def get(self, object_type):
        result = self.call(object_type)
        if not isinstance(result, dict):
            raise SetupError(f'{object_type} 返回结构异常: {result!r}')
        value = result.get(object_type)
        return value if isinstance(value, list) else []

    def save(self, object_type, data, action='new'):
        return self.call('save', {'object': object_type, 'action': action, 'data': json.dumps(data, ensure_ascii=False, separators=(',',':'))})

    def get_generated_config(self):
        url = self.root + '/singbox-config'
        req = urllib.request.Request(url, headers={
            'Origin': 'http://127.0.0.1:2095',
            'Referer': 'http://127.0.0.1:2095/app/',
            'User-Agent': 'SUI-Migration-Manager/1.0'})
        try:
            with self.opener.open(req, timeout=12) as response:
                return json.loads(response.read().decode('utf-8'))
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise SetupError(f'无法读取 sing-box 生成配置: {exc}') from exc

    def get_first_id(self, object_type, match_field, match_value):
        for obj in self.get(object_type):
            if obj.get(match_field) == match_value:
                return obj.get('id')
        return None


def reality_keys(sing_box=SB_BIN):
    if not os.path.isfile(sing_box) or not os.access(sing_box, os.X_OK):
        raise SetupError(f'找不到 sing-box 可执行文件: {sing_box}')
    p = subprocess.run([sing_box, 'generate', 'reality-keypair'], text=True, capture_output=True, timeout=12)
    if p.returncode:
        raise SetupError(f'sing-box 生成密钥失败: {p.stderr.strip()}')
    priv = re.search(r'(?im)^\s*PrivateKey:\s*(\S+)', p.stdout)
    pub = re.search(r'(?im)^\s*PublicKey:\s*(\S+)', p.stdout)
    if not priv or not pub or len(priv.group(1)) != 43 or len(pub.group(1)) != 43:
        raise SetupError('sing-box 密钥输出格式不符合预期')
    return priv.group(1), pub.group(1)


def pick_id(before, after, match_field, match_val):
    matches = [x['id'] for x in after if x.get(match_field)==match_val and x.get('id') is not None]
    if len(matches)!=1:
        raise SetupError(f'创建 {match_val} 后未找到唯一记录: {matches}')
    return matches[0]


def save_new(api, object_type, data, match_field):
    key=data[match_field]
    if api.get_first_id(object_type,match_field,key) is not None:
        raise SetupError(f'已有同名 {object_type}: {key}；为了保护已有配置，不覆盖')
    api.save(object_type,data)
    return pick_id(None,api.get(object_type),match_field,key)


def fresh_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0))
        return s.getsockname()[1]


class Health(BaseHTTPRequestHandler):
    def do_GET(self):
        raw=b'sui-reality-authenticated-ok\n'
        self.send_response(200)
        self.send_header('Content-Type','text/plain')
        self.send_header('Content-Length',str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def log_message(self,*args):
        pass


def test_reality(node, sing_box=SB_BIN, mode='reality'):
    """Authenticate through REALITY or WS+TLS and relay an HTTP request."""
    if mode not in ('reality','ws'):
        raise SetupError('未知代理验收类型')
    echo = HTTPServer(('127.0.0.1',0),Health)
    echoport=echo.server_port
    worker=threading.Thread(target=echo.serve_forever, daemon=True)
    worker.start()
    socksport=fresh_port()
    if mode=='reality':
        outbound={'type':'vless','tag':'proxy','server':'127.0.0.1','server_port':443,
                  'uuid':node['uuid'],'flow':'xtls-rprx-vision',
                  'tls':{'enabled':True,'server_name':node['domain'],
                         'utls':{'enabled':True,'fingerprint':'chrome'},
                         'reality':{'enabled':True,'public_key':node['public_key'],
                                    'short_id':node['short_id']}}}
    else:
        outbound={'type':'vless','tag':'proxy','server':'127.0.0.1','server_port':2053,
                  'uuid':node['uuid'],
                  'tls':{'enabled':True,'server_name':node['domain']},
                  'transport':{'type':'ws','path':'/xian','headers':{'Host':node['domain']}}}
    cfg={
      'log':{'level':'info'},
      'inbounds':[{'type':'socks','tag':'probe','listen':'127.0.0.1','listen_port':socksport}],
      'outbounds':[outbound],
      'route':{'final':'proxy','auto_detect_interface':True}
    }
    with tempfile.TemporaryDirectory(prefix='sui-reality-probe-') as td:
        path=os.path.join(td,'probe.json')
        with open(path,'w',encoding='utf8') as out:
            json.dump(cfg,out)
        check=subprocess.run([sing_box,'check','-c',path],capture_output=True,text=True,timeout=15)
        if check.returncode:
            raise SetupError('本地认证测试配置错误: '+(check.stderr.strip() or check.stdout.strip())[-700:])
        logpath=os.path.join(td,'probe.log')
        try:
            with open(logpath,'w',encoding='utf8') as logfile:
                proc=subprocess.Popen([sing_box,'run','-c',path],stdout=logfile,stderr=subprocess.STDOUT)
                try:
                    started=False
                    for _ in range(30):
                        if proc.poll() is not None:
                            break
                        try:
                            with socket.create_connection(('127.0.0.1',socksport),timeout=.15):
                                started=True;break
                        except OSError:
                            time.sleep(.2)
                    if not started:
                        raise SetupError('临时 sing-box 客户端没有启动')
                    command=['curl','--noproxy','','-sS','-f','--max-time','9',
                             '--socks5-hostname',f'127.0.0.1:{socksport}',
                             f'http://127.0.0.1:{echoport}/health']
                    answer=subprocess.run(command,capture_output=True,text=True,timeout=14)
                    if answer.returncode != 0 or answer.stdout != 'sui-reality-authenticated-ok\n':
                        raise SetupError(f'{mode} 真实代理测试失败: '+(answer.stderr.strip() or answer.stdout.strip())[:300])
                    return True
                finally:
                    proc.terminate()
                    try: proc.wait(timeout=3)
                    except subprocess.TimeoutExpired: proc.kill();proc.wait(timeout=3)
        except SetupError as ex:
            with open(logpath,encoding='utf8') as handle:
                last=''.join(handle.readlines()[-12:])
            raise SetupError(f'{ex}\n临时客户端日志:\n{last[-2200:]}') from ex
        finally:
            echo.shutdown()
            echo.server_close()


def build_objects(domain, bridgeport, cert, key, private_key, pub, short_id, client_uuid):
    tr={
      'name':'sui-managed-reality-'+domain,
      'server':{'enabled':True,'server_name':domain,
                'reality':{'enabled':True,'handshake':{'server':'127.0.0.1','server_port':int(bridgeport)},
                           'private_key':private_key,'short_id':[short_id]}},
      'client':{'enabled':True,'server_name':domain,
                'utls':{'enabled':True,'fingerprint':'chrome'},
                'reality':{'enabled':True,'public_key':pub,'short_id':short_id}}
    }
    tw={
      'name':'sui-managed-ws-'+domain,
      'server':{'enabled':True,'server_name':domain,'certificate_path':cert,'key_path':key},
      'client':{'enabled':True,'server_name':domain,'insecure':False}
    }
    reality={
      'type':'vless','tag':'sui-managed-reality-443','listen':'0.0.0.0','listen_port':443,
      'addrs':[{'server':domain,'server_port':443}],
      'out_json':{'type':'vless','server':domain,'server_port':443,'flow':'xtls-rprx-vision'}
    }
    ws={
      'type':'vless','tag':'sui-managed-ws-2053','listen':'0.0.0.0','listen_port':2053,
      'transport':{'type':'ws','path':'/xian'},
      'addrs':[{'server':domain,'server_port':2053}],
      'out_json':{'type':'vless','server':domain,'server_port':2053,'transport':{'type':'ws','path':'/xian'}}
    }
    client_name='node-'+client_uuid.replace('-','')
    client={
      'enable':True,'name':client_name,'remark':'SUI','volume':0,'expiry':0,
      'config':{'vless':{'name':client_name,'uuid':client_uuid,'flow':'xtls-rprx-vision'}},
      'links':[]
    }
    return tr,tw,reality,ws,client


def write_state(node):
    STATE.parent.mkdir(parents=True,exist_ok=True)
    os.chmod(STATE.parent,0o700)
    temp=STATE.with_suffix('.json.tmp')
    with open(temp,'w',encoding='utf8') as f:
        json.dump(node,f,ensure_ascii=False,indent=2)
        f.write('\n')
    os.chmod(temp,0o600)
    os.replace(temp,STATE)
    # No private key stored by this tool; it lives in S-UI's TLS object.
    import urllib.parse as up
    domain=node['domain'];uid=node['uuid'];pub=node['public_key'];sid=node['short_id']
    params=up.urlencode({'encryption':'none','security':'reality','sni':domain,'fp':'chrome','pbk':pub,'sid':sid,'spx':'/','type':'tcp','flow':'xtls-rprx-vision'})
    r=f'vless://{uid}@{domain}:443?{params}#SUI-REALITY'
    wsparams=up.urlencode({'encryption':'none','security':'tls','sni':domain,'host':domain,'type':'ws','path':'/xian'})
    w=f'vless://{uid}@{domain}:2053?{wsparams}#SUI-WS-TLS'
    links=STATE.parent/'nodes.txt'
    links.write_text(r+'\n'+w+'\n',encoding='utf8')
    links.chmod(0o600)
    print('REALITY 链接：\n'+r)
    print('WS+TLS 链接：\n'+w)
    print(f'保存位置：{links}（权限 600）')


def verify_https_panel(domain):
    """Require a live HTTPS management page after the panel has restarted."""
    import ssl
    ctx=ssl._create_unverified_context()
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        urllib.request.HTTPSHandler(context=ctx))
    url='https://127.0.0.1:8443/app/'
    for _ in range(35):
        try:
            req=urllib.request.Request(url,headers={'Host':domain})
            with opener.open(req,timeout=3) as res:
                if 200 <= res.status < 400:
                    return True
        except urllib.error.HTTPError as ex:
            if 300 <= ex.code < 400:
                return True
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(1)
    raise SetupError('S-UI HTTPS 管理面板 8443 未能在配置后正常启动')


def provision(args):
    username=args.user or input('请输入 S-UI 管理员用户名: ').strip()
    password=os.environ.get('SUI_ADMIN_PASS') or getpass.getpass('请输入 S-UI 管理员密码（不会回显）: ')
    if not username or not password:
        raise SetupError('用户名或密码不能为空')
    api=SuiAPI()
    api.login(username,password)
    print('[OK] 已登录 S-UI 官方本地 API')
    if STATE.exists():
        raise SetupError(f'已有 SUI 托管节点记录: {STATE}。请先检查，避免重复创建')
    tls_entries=api.get('tls')
    inb_entries=api.get('inbounds')
    for tag in ('sui-managed-reality-443','sui-managed-ws-2053'):
        if any(x.get('tag')==tag for x in inb_entries):
            raise SetupError(f'存在已有节点 {tag}；为了避免覆盖，拒绝重复部署')
    for name in (f'sui-managed-reality-{args.domain}',f'sui-managed-ws-{args.domain}'):
        if any(x.get('name')==name for x in tls_entries):
            raise SetupError(f'存在已有 TLS 记录 {name}；拒绝重复部署')
    private, pub=reality_keys()
    uid=str(uuid.uuid4()); sid=os.urandom(4).hex()
    tr,tw,ir,iw,cl=build_objects(args.domain,args.bridgeport,args.cert,args.key,private,pub,sid,uid)
    print('[INFO] 创建两个 TLS 配置...')
    tr_id=save_new(api,'tls',tr,'name')
    tw_id=save_new(api,'tls',tw,'name')
    ir['tls_id']=tr_id; iw['tls_id']=tw_id
    print('[INFO] 创建 VLESS+REALITY 443 和 WS+TLS 2053 入站...')
    ir_id=save_new(api,'inbounds',ir,'tag')
    iw_id=save_new(api,'inbounds',iw,'tag')
    cl['inbounds']=[ir_id,iw_id]
    print('[INFO] 创建并关联 VLESS 客户端...')
    cl_id=save_new(api,'clients',cl,'name')
    # Read-back validation: catches omissions in client/inbound associations.
    stored_client=[c for c in api.get('clients') if c.get('id')==cl_id]
    if len(stored_client)!=1 or not set(map(str,[ir_id,iw_id])).issubset(set(map(str,stored_client[0].get('inbounds',[])))):
        raise SetupError('S-UI 客户端入站关联校验失败')
    print('[OK] TLS、入站、客户端记录已写入官方 S-UI API')
    # The generated core configuration must contain this UUID on BOTH inbounds.
    # This specifically guards against a panel saving the client but omitting it
    # when constructing the sing-box runtime configuration.
    generated = api.get_generated_config()
    if not isinstance(generated, dict):
        raise SetupError('S-UI 返回的 sing-box 配置不是 JSON 对象')
    inbound_map={x.get('listen_port'):x for x in generated.get('inbounds',[]) if isinstance(x,dict)}
    for port in (443,2053):
        ib=inbound_map.get(port)
        if not ib:
            raise SetupError(f'实际 sing-box 配置缺少 {port} 入站')
        users=ib.get('users',[])
        if not any(u.get('uuid')==uid for u in users if isinstance(u,dict)):
            raise SetupError(f'实际 sing-box {port} 入站缺少 UUID；停止切换，不能仅看面板用户列表')
    print('[OK] sing-box 实际生成配置含 443 和 2053 的有效 UUID')
    # Keep panel at HTTP localhost only until node test; HTTPS cutover is done afterward.
    node={'domain':args.domain,'uuid':uid,'public_key':pub,'short_id':sid,
          'bridgeport':args.bridgeport,'reality_inbound_id':ir_id,
          'ws_inbound_id':iw_id,'client_id':cl_id}
    print('[INFO] 检测真实 REALITY 认证和代理链路...')
    last_err=None
    for attempt in range(5):
        try:
            if test_reality(node):
                last_err=None
                break
        except SetupError as exc:
            last_err=exc
            time.sleep(1)
    if last_err:
        raise SetupError(str(last_err))
    print('[PASS] REALITY 已完成认证并成功转发测试 HTTP 请求')
    print('[INFO] 检测 WS+TLS 2053 的真实认证和代理链路...')
    last_err=None
    for attempt in range(5):
        try:
            if test_reality(node,mode='ws'):
                last_err=None
                break
        except SetupError as exc:
            last_err=exc
            time.sleep(1)
    if last_err:
        raise SetupError(str(last_err))
    print('[PASS] WS+TLS 已完成认证并成功转发测试 HTTP 请求')
    # Switch web panel to HTTPS 8443 and subscription to HTTPS 2096, preserving other settings.
    # Saving settings may restart S-UI; no subsequent API writes occur.
    print('[INFO] 设置 HTTPS 面板 8443、HTTPS 订阅 2096 ...')
    api.save('settings',{'webPort':'8443','webCertFile':args.cert,'webKeyFile':args.key,
                         'subPort':'2096','subCertFile':args.cert,'subKeyFile':args.key},'set')
    # The panel may restart asynchronously after the settings change.
    verify_https_panel(args.domain)
    write_state(node)
    print(f'[PASS] S-UI + sing-box 双协议部署完成。管理页面：https://{args.domain}:8443/app/')
    print('提示：REALITY 主机名必须使用 DNS only；WS+TLS 此处为直连节点，不能自动等同 CDN。')


def show_links(args):
    if not STATE.exists():
        raise SetupError('未找到已验收节点记录。请先部署。')
    data=json.loads(STATE.read_text(encoding='utf8'))
    write_state(data)


def inspect(args):
    print('S-UI API：',API_ROOT)
    if STATE.exists():
        data=json.loads(STATE.read_text(encoding='utf8'))
        print('节点信息（不显示私钥）：',json.dumps(data,ensure_ascii=False,indent=2))
    else:
        print('当前没有 SUI 托管节点验收记录')


def health(args):
    if not STATE.exists():
        raise SetupError('没有已完成验收的节点记录')
    node=json.loads(STATE.read_text(encoding='utf-8'))
    for mode in ('reality', 'ws'):
        if test_reality(node,mode=mode):
            print('[PASS] %s 实际代理连接通过' % ('REALITY' if mode=='reality' else 'WS+TLS'))


def main():
    p=argparse.ArgumentParser(description='SUI API 配置与验收')
    sub=p.add_subparsers(dest='action',required=True)
    a=sub.add_parser('provision')
    a.add_argument('--domain',required=True)
    a.add_argument('--bridgeport',required=True,type=int)
    a.add_argument('--cert',required=True)
    a.add_argument('--key',required=True)
    a.add_argument('--user')
    sub.add_parser('show-links')
    sub.add_parser('inspect')
    sub.add_parser('health')
    args=p.parse_args()
    try:
        if args.action=='provision': provision(args)
        elif args.action=='show-links':show_links(args)
        elif args.action=='health': health(args)
        else:inspect(args)
    except (SetupError, OSError, subprocess.SubprocessError) as e:
        print(f'[FAIL] {e}',file=sys.stderr)
        sys.exit(1)

if __name__=='__main__': main()
SUI_EMBED_MANAGER_PY
    cat > "$SUI_NGINX_INSPECTOR" <<'SUI_EMBED_NGINX_PY'
#!/usr/bin/env python3
"""Safely quarantine ONLY recognizable old X.sh SSL:8080 configs.

Never edits original HTTP site, certificates, /www, PHP-FPM, or unrelated vhosts.
The cleanup is optional, and invoked only during explicitly confirmed S-UI migration.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def nginx_test() -> subprocess.CompletedProcess:
    return subprocess.run(['nginx', '-t'], text=True, capture_output=True, timeout=20)


def site_is_user_http(site: Path, domain: str) -> bool:
    if not site.is_file():
        return False
    src = site.read_text(errors='replace')
    names = re.findall(r'(?m)^\s*server_name\s+([^;]+);', src)
    if not any(domain in n.split() for n in names):
        return False
    return bool(re.search(r'(?m)^\s*listen\s+127\.0\.0\.1:8080\s*;', src)) and not bool(
        re.search(r'(?m)^\s*listen\s+[^;]*8080\s+ssl\b', src))


def has_tls_8080(src: str) -> bool:
    return bool(re.search(
        r'(?m)^\s*listen\s+(?:(?:127\.0\.0\.1|\[::1\]):)?8080\b[^;]*\bssl\b[^;]*;', src))


def owned_legacy_candidates(domain: str, root: Path) -> list[Path]:
    """Only old X.sh generated files with distinctive path/content fingerprints."""
    result = []
    # This file is generated by original X.sh and enabled as a symlink.
    symlink = root / 'sites-enabled' / domain
    expected = root / 'sites-available' / domain
    if symlink.is_symlink() and symlink.resolve() == expected.resolve() and expected.is_file():
        src = expected.read_text(errors='replace')
        if (has_tls_8080(src)
                and re.search(r'\bserver_tokens\s+off\s*;', src)
                and re.search(r'\broot\s+/var/www/html/?\s*;', src)
                and re.search(r'\binclude\s+/etc/nginx/snippets/includes\.conf\s*;', src)
                and domain in src):
            result.append(symlink)
    # V9+ X.sh-created configs are identified by the exact management marker.
    managed = root / 'conf.d' / f'xui-pro-fallback-{domain}.conf'
    if managed.is_file() and not managed.is_symlink():
        src = managed.read_text(errors='replace')
        if (src.startswith('# XUI_PRO_MANAGED_FALLBACK_V9\n') or
                src.startswith('# XUI_PRO_MANAGED_FALLBACK_V12\n')) and has_tls_8080(src):
            result.append(managed)
    return result


def inspect(domain: str, root: Path, user_site: Path) -> tuple[str, list[Path], str]:
    if not site_is_user_http(user_site, domain):
        raise RuntimeError(f'未确认原网站是属于用户的 HTTP 127.0.0.1:8080，保持原样：{user_site}')
    t = nginx_test()
    if t.returncode == 0:
        print('[OK] Nginx 现有配置有效，不进行旧配置迁移')
        return 'valid', [], ''
    error = (t.stdout or '') + (t.stderr or '')
    items = owned_legacy_candidates(domain, root)
    if ('no "ssl_certificate" is defined' not in error or
            f'/sites-enabled/{user_site.name}:' not in error or not items):
        print('[ERROR] Nginx 配置检查失败，且未能确认可安全清理的旧 X.sh 配置。', file=sys.stderr)
        print(error[-1400:], file=sys.stderr)
        if items:
            print('[INFO] 已识别旧文件但错误原因不匹配，出于安全考虑不自动移动。', file=sys.stderr)
        else:
            print('[HINT] 请检查 8080 端口上是否还有其他 SSL 配置；原网站不应加证书。', file=sys.stderr)
        return 'blocked', [], error
    print(f'[INFO] 原用户网站保持不变：{user_site}')
    print('[INFO] 已识别以下由旧 X.sh 生成、与 HTTP 8080 冲突的 SSL 配置：')
    for path in items:
        print(f'  {path}')
    print('[INFO] 可在迁移确认后备份并暂时移出 Nginx 加载目录；其他站点完全不动')
    return 'fixable', items, error


def reconcile(domain: str, root: Path, site: Path, backup_root: Path) -> int:
    state, items, _ = inspect(domain, root, site)
    if state == 'valid':
        return 0
    if state != 'fixable':
        return 2
    backup = backup_root / ('nginx-legacy-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    backup.mkdir(mode=0o700, parents=True, exist_ok=False)
    moved = []
    try:
        for i, src in enumerate(items):
            dst = backup / f'{i}-{src.name}'
            os.replace(src, dst)
            moved.append((src, dst))
            print(f'[BACKUP] 仅旧 X.sh SSL 配置：{src} -> {dst}')
        t = nginx_test()
        if t.returncode != 0:
            raise RuntimeError('清理后 nginx -t 仍然失败：\n' + ((t.stdout or '') + (t.stderr or ''))[-1200:])
        action = 'reload' if subprocess.run(['systemctl', 'is-active', '--quiet', 'nginx'], timeout=10).returncode == 0 else 'start'
        p = subprocess.run(['systemctl', action, 'nginx'], text=True, capture_output=True, timeout=25)
        if p.returncode:
            raise RuntimeError(f'执行 systemctl {action} nginx 失败：{p.stderr[-450:]}')
        (backup / 'moved.json').write_text(json.dumps([
            {'original':str(a),'backup':str(b)} for a,b in moved], indent=2), encoding='utf-8')
        os.chmod(backup / 'moved.json', 0o600)
        print('[OK] 已解决由旧 X.sh SSL:8080 引起的 Nginx 冲突；原 wow 网站文件未修改')
        print(f'[INFO] 冲突文件备份：{backup}')
        return 0
    except Exception:
        # Put files back exactly as before: this is a failure, not a forced edit.
        for src, dst in reversed(moved):
            if dst.exists() or dst.is_symlink():
                os.replace(dst, src)
        print('[ROLLBACK] 已恢复移动过的旧 X.sh 配置；用户网站始终未被修改', file=sys.stderr)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--domain', default='wow.xyrq.de')
    parser.add_argument('--site', default='/etc/nginx/sites-enabled/wow')
    parser.add_argument('--nginx-root', default='/etc/nginx')
    parser.add_argument('--backup-root', default='/root/sui-pro/backups')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--inspect', action='store_true')
    mode.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}', args.domain):
        raise RuntimeError('域名格式不合法')
    root = Path(args.nginx_root)
    site = Path(args.site)
    if args.inspect:
        state, _, _ = inspect(args.domain, root, site)
        return 0 if state != 'blocked' else 2
    if os.geteuid() != 0:
        raise RuntimeError('执行 --apply 需要 root')
    return reconcile(args.domain, root, site, Path(args.backup_root))


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print('[ERROR] ' + str(exc), file=sys.stderr)
        sys.exit(1)
SUI_EMBED_NGINX_PY
    chmod 600 "$SUI_API_MANAGER" "$SUI_NGINX_INSPECTOR"
    python3 -m py_compile "$SUI_API_MANAGER" "$SUI_NGINX_INSPECTOR" || fail '内嵌 Python 模块语法检查失败'
}

inspect_nginx() {
    extract_helpers
    [[ -f "$SUI_CERT" && -f "$SUI_KEY" ]] || fail "缺少现有证书，请检查 $SUI_CERT 和 $SUI_KEY"
    openssl x509 -in "$SUI_CERT" -noout -checkend 86400 >/dev/null || fail '证书过期或有效期不足 24 小时'
    openssl x509 -in "$SUI_CERT" -noout -checkhost "$SUI_DOMAIN" >/dev/null || fail "证书不匹配域名: $SUI_DOMAIN"
    openssl pkey -in "$SUI_KEY" -noout >/dev/null 2>&1 || fail '证书私钥无法解析'
    python3 "$SUI_NGINX_INSPECTOR" --inspect --domain "$SUI_DOMAIN" --site "$SUI_USER_SITE" ||
      fail '原站检查失败：不更改原 wow 网站；请先检查 Nginx 旧冲突配置'
}
ports_free() {
    local p
    # Never disable X-UI from this program. A stopped-but-enabled old
    # x-ui service or its daily restart cron can reclaim 443 after reboot.
    if systemctl is-enabled --quiet x-ui 2>/dev/null; then
        fail '旧 x-ui.service 仍设置为开机启动。s.sh 不修改旧面板；请先用 xpro.sh 独立卸载，或自行停用 x-ui 服务。'
    fi
    if command -v crontab >/dev/null 2>&1 &&
        crontab -l 2>/dev/null | grep -Eq '(# XUI_PRO_MANAGED_CRON_V9|--xui-guard|--xui-monthly)'; then
        fail '发现旧 X-UI 的自动重启或健康检查任务，可能占用 443。请先通过 xpro.sh 独立卸载或手动停用旧任务。'
    fi
    for p in 443 2053 8443 2095 2096; do
        if port_listening "$p"; then
            warn "端口 $p 被占用：$(port_owner "$p" | head -n 1)"
            fail 'S-UI 不会停止/卸载 3X-UI 或其他服务。请先通过 xpro.sh 菜单 2 独立卸载 3X-UI，或自行停用占用端口的服务，然后重试。'
        fi
    done
    # The official S-UI installer may own the standard sing-box service name.
    if systemctl cat sing-box >/dev/null 2>&1; then
        fail '检测到 sing-box.service，为避免覆盖已有独立内核，已终止安装'
    fi
}
site_live() {
    nginx -t >/dev/null 2>&1 || fail 'Nginx 配置检查失败，不能继续部署'
    local code
    code="$(site_http_code)"
    http_ok "$code" || fail "原 HTTP 网站 127.0.0.1:${SUI_HTTP_BACKEND_PORT} 不可访问（HTTP ${code:-unknown}）"
    ok "原网站 HTTP ${SUI_HTTP_BACKEND_PORT} 正常 (HTTP $code)，未修改原配置"
}
choose_bridge() {
    local p conf
    [[ ! -e "$SUI_NGINX_BRIDGE" && ! -L "$SUI_NGINX_BRIDGE" ]] || fail "S-UI 自建回落配置已存在，请先查看 --status：$SUI_NGINX_BRIDGE"
    conf="$(nginx -T 2>/dev/null || true)"
    for p in $(seq 8081 8099); do
        port_listening "$p" && continue
        if grep -Eq "(^|[;{])[[:space:]]*listen[[:space:]]+([0-9A-Za-z_.:\[\]-]+:)?${p}([[:space:];]|$)" <<< "$conf"; then
            continue
        fi
        SUI_BRIDGE_PORT="$p"; return 0
    done
    fail '无法找到空闲的独立 HTTPS 回落端口 (8081..8099)'
}
create_bridge() {
    choose_bridge
    local tmp code
    info "创建 S-UI 独立 HTTPS 127.0.0.1:${SUI_BRIDGE_PORT} -> 原网站 HTTP 127.0.0.1:${SUI_HTTP_BACKEND_PORT}"
    tmp="$(mktemp /etc/nginx/conf.d/.sui-private-XXXXXXXX)" || return 1
    cat > "$tmp" <<EOF_NGINX
# SUI-MANAGED-BRIDGE; may be removed ONLY by s.sh.
# Original site file and PHP files are never touched.
server {
    listen 127.0.0.1:${SUI_BRIDGE_PORT} ssl;
    server_name ${SUI_DOMAIN};
    ssl_certificate ${SUI_CERT};
    ssl_certificate_key ${SUI_KEY};
    ssl_protocols TLSv1.2 TLSv1.3;
    location / {
        proxy_pass http://127.0.0.1:${SUI_HTTP_BACKEND_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF_NGINX
    chmod 600 "$tmp"
    if ! mv -- "$tmp" "$SUI_NGINX_BRIDGE"; then rm -f -- "$tmp"; return 1; fi
    SUI_NEW_BRIDGE=1
    if ! nginx -t; then
        rm -f -- "$SUI_NGINX_BRIDGE"; SUI_NEW_BRIDGE=0
        fail 'S-UI 独立 HTTPS 桥接 Nginx 语法失败；已撤销新增文件'
    fi
    if systemctl is-active --quiet nginx; then
        systemctl reload nginx || fail 'Nginx reload 失败'
    else
        systemctl start nginx || fail 'Nginx start 失败'
    fi
    code="$(bridge_http_code "$SUI_BRIDGE_PORT")"
    http_ok "$code" || fail "HTTPS 回落 ${SUI_BRIDGE_PORT} 不可用（HTTP ${code:-none}）"
    ok "HTTPS 回落 ${SUI_BRIDGE_PORT} -> HTTP ${SUI_HTTP_BACKEND_PORT} 测试通过"
}
install_sui_official() {
    [[ ! -e /usr/local/s-ui && ! -e /etc/systemd/system/s-ui.service ]] || fail '发现已有 S-UI 安装，拒绝覆盖'
    local installer
    installer="$(mktemp /tmp/sui-official-XXXXXXXX.sh)" || return 1
    info "安装官方 S-UI ${SUI_VERSION}（不自动跟随 latest）..."
    if ! curl -fLsS --retry 3 --connect-timeout 15 --max-time 60 \
        -o "$installer" "https://raw.githubusercontent.com/alireza0/s-ui/${SUI_VERSION}/install.sh"; then
        rm -f "$installer"; fail '官方安装脚本下载失败'; return 1
    fi
    if ! bash -n "$installer"; then rm -f "$installer"; fail '官方安装脚本语法有误'; return 1; fi
    # The upstream installer's default path asks whether to modify settings;
    # decline, then configure API and HTTPS after sing-box is healthy.
    # The target was absent before this call, so even partial installation
    # belongs to the current transaction and may be removed on failure.
    SUI_NEW_INSTALL=1
    if ! printf 'n\n' | SUI_LANG=zhcn bash "$installer" "$SUI_VERSION"; then
        rm -f "$installer"; fail 'S-UI 官方安装失败'; return 1
    fi
    rm -f -- "$installer"
    [[ -x /usr/local/s-ui/sui ]] || fail '未安装 S-UI 可执行文件'
    systemctl is-active --quiet s-ui || fail 'S-UI 服务未运行'
    [[ -x /usr/local/s-ui/bin/sing-box ]] || fail '官方包中未找到 sing-box 内核'
    ok 'S-UI 安装成功，sing-box 内核存在'
}
set_sui_admin() {
    local admin='admin' password code attempt
    password="$(openssl rand -hex 18)"
    /usr/local/s-ui/sui admin -username "$admin" -password "$password" >/dev/null || fail 'S-UI 管理员账号更新失败'
    systemctl restart s-ui
    code=''
    for attempt in $(seq 1 25); do
        code="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 3 'http://127.0.0.1:2095/app/' || true)"
        if http_ok "$code"; then break; fi
        sleep 1
    done
    http_ok "$code" || fail 'S-UI 默认本地管理端口 2095 不可用'
    printf '管理地址: https://%s:8443/app/\n账号: %s\n密码: %s\n' "$SUI_DOMAIN" "$admin" "$password" > "$SUI_HOME/admin.txt"
    chmod 600 "$SUI_HOME/admin.txt"
    export SUI_ADMIN_PASS="$password"
    SUI_ADMIN_USER="$admin"
}
rollback_self_owned() {
    warn 'S-UI 安装没有通过最终验收，撤销本次创建的 S-UI 文件；不操作 3X-UI 或原 wow 站。'
    systemctl stop s-ui >/dev/null 2>&1 || true
    if systemctl cat sing-box 2>/dev/null | grep -Fq /usr/local/s-ui/; then
        systemctl stop sing-box >/dev/null 2>&1 || true
    fi
    if (( SUI_NEW_INSTALL == 1 )); then
        systemctl disable s-ui >/dev/null 2>&1 || true
        rm -f -- /etc/systemd/system/s-ui.service /usr/bin/s-ui
        if systemctl cat sing-box 2>/dev/null | grep -Fq /usr/local/s-ui/; then
            rm -f -- /etc/systemd/system/sing-box.service
        fi
        rm -rf -- /usr/local/s-ui
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    if (( SUI_NEW_BRIDGE == 1 )) && [[ -f "$SUI_NGINX_BRIDGE" ]] &&
            grep -Fq '# SUI-MANAGED-BRIDGE;' "$SUI_NGINX_BRIDGE"; then
        rm -f -- "$SUI_NGINX_BRIDGE"
        nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
    fi
    warn '未停止/重启/卸载旧 3X-UI；独立 Nginx 老配置备份如有生成，保留在 /root/sui-pro/backups/'
}
on_exit() {
    local rc="$?"
    trap - EXIT
    if (( rc != 0 && SUI_TRANSACTION == 1 && SUI_COMMITTED == 0 )); then rollback_self_owned; fi
    exit "$rc"
}
trap on_exit EXIT

precheck_action() {
    need_root
    set_domain "${1:-$SUI_DOMAIN_DEFAULT}"
    require_cmds
    inspect_nginx
    ports_free
    ok '部署前检查通过；不改变任何系统服务'
}
install_action() {
    need_root
    local domain="${1:-$SUI_DOMAIN_DEFAULT}" flag="${2:-}" choice code
    set_domain "$domain"
    require_cmds
    [[ -f /etc/debian_version ]] || fail '目前只支持 Debian/Ubuntu + systemd'
    [[ ! -e /usr/local/s-ui && ! -e /etc/systemd/system/s-ui.service ]] || fail '已有 S-UI，拒绝覆盖；请使用 --status'
    [[ ! -f "$SUI_HOME/node-state.json" ]] || fail '已有 S-UI 节点记录，拒绝覆盖'
    [[ ! -e "$SUI_NGINX_BRIDGE" && ! -L "$SUI_NGINX_BRIDGE" ]] || fail '已有本工具的 HTTPS 回落配置，拒绝覆盖'
    ports_free
    inspect_nginx
    echo
    info "待安装：S-UI ${SUI_VERSION} + sing-box，REALITY 443，WS+TLS 2053，面板 HTTPS 8443"
    info '只管理 S-UI；不会停用/卸载 3X-UI，不修改 wow 原网站或证书。'
    if [[ "$flag" == --yes ]]; then choice=INSTALL; else
        read_console choice '输入 INSTALL 确认开始（其他输入取消）: '
    fi
    [[ "$choice" == INSTALL ]] || { info '已取消，系统未更改'; return 0; }
    mkdir -p "$SUI_HOME/backups"; chmod 700 "$SUI_HOME" "$SUI_HOME/backups"
    touch "$SUI_LOG"; chmod 600 "$SUI_LOG"
    exec > >(tee -a "$SUI_LOG") 2>&1
    SUI_TRANSACTION=1
    # Keep logs without exposing private REALITY keys.
    info "安装日志：$SUI_LOG"
    # Only known old X.sh SSL:8080 generated config can be moved, after explicit INSTALL.
    python3 "$SUI_NGINX_INSPECTOR" --apply --domain "$SUI_DOMAIN" --site "$SUI_USER_SITE" ||
      fail 'Nginx 老配置无法安全处理；原 wow 文件不受影响'
    if ! systemctl is-active --quiet nginx; then systemctl start nginx || fail 'Nginx 未能启动'; fi
    site_live
    create_bridge
    install_sui_official
    set_sui_admin
    info '通过官方 S-UI API 创建 REALITY、WS+TLS 入站，并执行实际代理验收...'
    python3 "$SUI_API_MANAGER" provision --domain "$SUI_DOMAIN" --bridgeport "$SUI_BRIDGE_PORT" \
        --cert "$SUI_CERT" --key "$SUI_KEY" --user "$SUI_ADMIN_USER" ||
        fail 'S-UI 官方 API 写入或真实代理验收失败'
    port_listening 443 || fail 'sing-box REALITY 443 没有监听'
    port_listening 2053 || fail 'sing-box WS+TLS 2053 没有监听'
    printf 'SUI_DOMAIN=%q\nSUI_BRIDGE_PORT=%q\n' "$SUI_DOMAIN" "$SUI_BRIDGE_PORT" > "$SUI_HOME/installed.env"
    chmod 600 "$SUI_HOME/installed.env"
    SUI_COMMITTED=1
    SUI_TRANSACTION=0
    ok "安装验收完成；面板 https://${SUI_DOMAIN}:8443/app/"
    info "管理账号：$SUI_HOME/admin.txt；节点：$SUI_HOME/nodes.txt"
    info '只需使用 s.sh 管理 S-UI，原 xpro.sh 与本工具没有调用关系。'
}
status_action() {
    printf 'S-UI 独立管理脚本：%s；S-UI 固定版本：%s\n' "$SUI_MANAGER_VERSION" "$SUI_VERSION"
    printf 'S-UI 服务：'; systemctl is-active s-ui 2>/dev/null || true
    printf 'Nginx 服务：'; systemctl is-active nginx 2>/dev/null || true
    if command -v ss >/dev/null 2>&1; then
        printf '相关端口：\n'; ss -lntp 2>/dev/null | grep -E ':(443|2053|8443|8080|8081|8082|2095|2096)([[:space:]]|$)' || true
    fi
    [[ ! -f "$SUI_HOME/node-state.json" ]] || {
        extract_helpers
        python3 "$SUI_API_MANAGER" inspect
    }
    if [[ -f "$SUI_NGINX_BRIDGE" ]]; then
        grep -Fq '# SUI-MANAGED-BRIDGE;' "$SUI_NGINX_BRIDGE" &&
          ok "本脚本独立回落配置：$SUI_NGINX_BRIDGE"
    fi
    if command -v nginx >/dev/null 2>&1; then nginx -t 2>&1 || true; fi
}
links_action() {
    [[ -f "$SUI_HOME/nodes.txt" ]] || fail '尚未有 S-UI 生成并通过验收的节点'
    cat "$SUI_HOME/nodes.txt"
}
probe_action() {
    [[ -f "$SUI_HOME/node-state.json" ]] || fail '没有 S-UI 节点状态，先安装并验收'
    extract_helpers
    python3 "$SUI_API_MANAGER" health
}
control_action() {
    need_root
    local action="$1"
    if [[ "$action" == stop ]]; then
        systemctl stop s-ui || fail 'S-UI 停止失败'
        if systemctl cat sing-box 2>/dev/null | grep -Fq /usr/local/s-ui/; then
            systemctl stop sing-box >/dev/null 2>&1 || true
        fi
    else
        systemctl "$action" s-ui || fail "S-UI ${action} 失败；请检查端口与日志"
    fi
    ok "S-UI 已执行 $action；没有操作 3X-UI"
}
uninstall_action() {
    need_root
    local answer='' backup conf_saved='' db=''
    if [[ ! -e /usr/local/s-ui && ! -f /etc/systemd/system/s-ui.service ]]; then
        info '没有检测到 S-UI 面板，无需卸载；其他服务和网站未改变'
        return 0
    fi
    printf '仅卸载 S-UI 及其自带 sing-box。不会卸载 3X-UI，也不会删除原网站、证书、PHP 或 Nginx 原站配置。\n'
    read_console answer '确认卸载 S-UI？(y/N): '
    [[ "$answer" =~ ^[Yy]$ ]] || { info '已取消卸载'; return 0; }
    backup="$SUI_HOME/backups/sui-before-uninstall-$(date +%Y%m%d_%H%M%S)-$$"
    mkdir -p "$backup"; chmod 700 "$backup"
    db='/usr/local/s-ui/db/s-ui.db'
    if [[ -f "$db" ]]; then
        python3 - "$db" "$backup/s-ui.db" <<'SUI_SQLITE_BACKUP'
import sqlite3,sys
src=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True,timeout=10)
dst=sqlite3.connect(sys.argv[2],timeout=10)
src.backup(dst)
dst.close();src.close()
SUI_SQLITE_BACKUP
        [[ -s "$backup/s-ui.db" ]] || fail 'S-UI 数据库备份失败，已中止卸载'
        chmod 600 "$backup/s-ui.db"
    fi
    [[ ! -f "$SUI_HOME/node-state.json" ]] || cp -a "$SUI_HOME/node-state.json" "$backup/"
    [[ ! -f "$SUI_HOME/nodes.txt" ]] || cp -a "$SUI_HOME/nodes.txt" "$backup/"
    [[ ! -f "$SUI_HOME/admin.txt" ]] || cp -a "$SUI_HOME/admin.txt" "$backup/"
    systemctl stop s-ui >/dev/null 2>&1 || true
    systemctl disable s-ui >/dev/null 2>&1 || true
    if systemctl cat sing-box 2>/dev/null | grep -Fq /usr/local/s-ui/; then
        systemctl stop sing-box >/dev/null 2>&1 || true
        systemctl disable sing-box >/dev/null 2>&1 || true
        rm -f -- /etc/systemd/system/sing-box.service
    fi
    rm -f -- /etc/systemd/system/s-ui.service /usr/bin/s-ui
    rm -rf -- /usr/local/s-ui
    systemctl daemon-reload >/dev/null 2>&1 || true
    if [[ -f "$SUI_NGINX_BRIDGE" ]] && grep -Fq '# SUI-MANAGED-BRIDGE;' "$SUI_NGINX_BRIDGE"; then
        conf_saved="$backup/bridge.conf"
        cp -a "$SUI_NGINX_BRIDGE" "$conf_saved"
        rm -f -- "$SUI_NGINX_BRIDGE"
        if nginx -t >/dev/null 2>&1; then
            systemctl reload nginx >/dev/null 2>&1 || warn 'Nginx reload 未成功，网站配置没有被改动'
        else
            cp -a "$conf_saved" "$SUI_NGINX_BRIDGE"
            warn '移除 S-UI 私有回落后 Nginx 检查失败，已还原私有回落配置'
        fi
    fi
    rm -f -- "$SUI_HOME/node-state.json" "$SUI_HOME/nodes.txt" "$SUI_HOME/admin.txt" "$SUI_HOME/installed.env"
    ok 'S-UI + 其自带 sing-box 已独立卸载。未操作 3X-UI 或原 wow 网站。'
    info "备份目录：$backup"
}
menu() {
    while :; do
        printf '\n============ S-UI + sing-box ============\n'
        printf '1) 安装 S-UI / 创建 REALITY + WS+TLS\n'
        printf '2) 卸载 S-UI（独立）\n'
        printf '3) 查看状态\n4) 显示节点链接\n5) 代理真实连接测试\n'
        printf '6) 启动 S-UI\n7) 停止 S-UI\n8) 重启 S-UI\n9) 安装前检查\n0) 退出\n'
        local choice='' rc=0
        read_console choice '请选择 [0-9]: ' || return 0
        case "$choice" in
            1) bash "$0" --install "$SUI_DOMAIN_DEFAULT" || rc=$? ;;
            2) bash "$0" --uninstall || rc=$? ;;
            3) bash "$0" --status || rc=$? ;;
            4) bash "$0" --links || rc=$? ;;
            5) bash "$0" --test || rc=$? ;;
            6) bash "$0" --start || rc=$? ;;
            7) bash "$0" --stop || rc=$? ;;
            8) bash "$0" --restart || rc=$? ;;
            9) bash "$0" --precheck "$SUI_DOMAIN_DEFAULT" || rc=$? ;;
            0) return 0 ;;
            *) warn '无效输入' ;;
        esac
        if (( rc != 0 )); then warn "本次操作未完成 (exit=${rc})，未自动执行其他菜单操作"; fi
    done
}

main() {
    case "${1:-}" in
        --install) shift; install_action "${1:-$SUI_DOMAIN_DEFAULT}" "${2:-}" ;;
        --precheck) shift; precheck_action "${1:-$SUI_DOMAIN_DEFAULT}" ;;
        --uninstall) uninstall_action ;;
        --status) status_action ;;
        --links) links_action ;;
        --test) probe_action ;;
        --start) control_action start ;;
        --stop) control_action stop ;;
        --restart) control_action restart ;;
        --help|-h)
            printf '用法: bash s.sh [--install [domain] [--yes]|--precheck [domain]|--uninstall|--status|--links|--test|--start|--stop|--restart]\n'
            ;;
        '') menu ;;
        *) fail "不支持的参数：$1" ;;
    esac
}
main "$@"
