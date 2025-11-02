#!/bin/bash
# main.sh - 单文件运行版：包含完整 Go 源码 + 弱口令 + 守护进程
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

if ! command -v go >/dev/null 2>&1; then
    err "未找到 Go，请先安装（apt install golang-go -y）"
    exit 1
fi

# ---------------- 输入 ----------------
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

echo -e "${YELLOW}端口（默认: 1080,8080,8888,3128）:${NC}"
read -r PORT_INPUT
PORT_INPUT=${PORT_INPUT:-1080,8080,8888,3128}
succ "端口: $PORT_INPUT"

echo -e "${YELLOW}Telegram Bot Token（可选）:${NC}"; read -r TELEGRAM_TOKEN
echo -e "${YELLOW}Telegram Chat ID（可选）:${NC}"; read -r TELEGRAM_CHATID
if [[ -n $TELEGRAM_TOKEN && -n $TELEGRAM_CHATID ]]; then
    succ "Telegram 通知启用"
else
    TELEGRAM_TOKEN=""; TELEGRAM_CHATID=""
fi

# ---------------- 弱口令文件 ----------------
cat >  " $WEAK_FILE "  << ' EOF '
#完整弱口令列表（内嵌）
管理员:admin
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
密码：密码
代理：代理
q:q
qaq:qaq
qaq:qwq
QQ:QQ
QQQ:QQQ
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
根:root
s:s
s5:s5
ss:ss
sss:sss
ssss:ssss
sssss:sssss
ssssss:ssssss
袜子：袜子
袜子5：袜子5
t:t
测试：测试
test123:test123
tt:tt
ttt:ttt
tttt:tttt
ttttt:ttttt
tttttt:tttttt
u:u
用户：123
用户：1234
用户：12345
用户：123456
用户名：密码
用户名：密码
用户:密码
用户：用户
用户名：username
uu:uu
呜呜呜：呜呜呜
呜呜呜：呜呜呜
呜呜呜呜：呜呜呜呜
呜呜呜呜呜：呜呜呜呜
v:v
vv:vv
vvv:vvv
vvvv:vvvv
vvvvv:vvvvv
vvvvvv:vvvvvv
w:w
wsnd:wsnd
www:ww
www:www
www:wwww
www:wwwww
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
succ "弱口令文件写入：$WEAK_FILE"

# ---------------- scamnet.go ----------------
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

var (
	startIP, endIP, portsStr, tgToken, tgChat string
	maxConc, timeoutSec, retries int
	validFile = "socks5_valid.txt"
	weakFile  = "logs/weak.txt"
	weakPairs [][2]string
)

func loadWeakPairs() {
	data, err := ioutil.ReadFile(weakFile)
	if err != nil {
		weakPairs = append(weakPairs, [2]string{"admin", "admin"})
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") { continue }
		p := strings.SplitN(line, ":", 2)
		if len(p) == 2 { weakPairs = append(weakPairs, [2]string{p[0], p[1]}) }
	}
}

func ipToInt(ip string) uint32 {
	p := strings.Split(ip, ".")
	a, _ := strconv.Atoi(p[0]); b, _ := strconv.Atoi(p[1]); c, _ := strconv.Atoi(p[2]); d, _ := strconv.Atoi(p[3])
	return uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
}
func intToIP(n uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", n>>24&255, n>>16&255, n>>8&255, n&255)
}
func parsePorts(s string) []int {
	var ports []int
	for _, x := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if strings.Contains(x, "-") {
			a := strings.SplitN(x, "-", 2)
			start, _ := strconv.Atoi(a[0]); end, _ := strconv.Atoi(a[1])
			for i := start; i <= end; i++ { ports = append(ports, i) }
		} else { i, _ := strconv.Atoi(x); ports = append(ports, i) }
	}
	return ports
}

func testSocks5(ip string, port int, user, pass string) bool {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeoutSec)*time.Second)
	if err != nil { return false }
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
	conn.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil { return false }
	return buf[1] != 0xFF
}

func sendTelegram(msg string) {
	if tgToken == "" || tgChat == "" { return }
	http.PostForm("https://api.telegram.org/bot"+tgToken+"/sendMessage",
		url.Values{"chat_id":{tgChat},"text":{msg}})
}

func saveValid(result string) {
	f, _ := os.OpenFile(validFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	defer f.Close()
	fmt.Fprintln(f, result)
}

func main() {
	flag.StringVar(&startIP, "start", "", "start ip")
	flag.StringVar(&endIP, "end", "", "end ip")
	flag.StringVar(&portsStr, "ports", "1080", "ports")
	flag.StringVar(&tgToken, "tg-token", "", "telegram token")
	flag.StringVar(&tgChat, "tg-chat", "", "telegram chat")
	flag.IntVar(&maxConc, "conc", 100, "max concurrent")
	flag.IntVar(&timeoutSec, "timeout", 5, "timeout sec")
	flag.IntVar(&retries, "retries", 1, "retries")
	flag.Parse()

	if startIP == "" || endIP == "" { fmt.Println("need -start and -end"); os.Exit(1) }

	loadWeakPairs()
	ports := parsePorts(portsStr)
	start := ipToInt(startIP)
	end := ipToInt(endIP)
	sem := semaphore.NewWeighted(int64(maxConc))
	ctx := context.Background()
	var wg sync.WaitGroup

	for i := start; i <= end; i++ {
		ip := intToIP(i)
		for _, port := range ports {
			if err := sem.Acquire(ctx, 1); err != nil { continue }
			wg.Add(1)
			go func(ip string, port int) {
				defer sem.Release(1); defer wg.Done()
				for _, p := range weakPairs {
					if testSocks5(ip, port, p[0], p[1]) {
						r := fmt.Sprintf("socks5://%s:%s@%s:%d", p[0], p[1], ip, port)
						fmt.Println("[+]", r)
						saveValid(r)
						sendTelegram(r)
						break
					}
				}
			}(ip, port)
		}
	}
	wg.Wait()
	fmt.Println("[*] 扫描完成 →", validFile)
}
GOEOF

# ---------------- 构建 ----------------
go mod init scamnet >/dev/null 2>&1 || true
go get golang.org/x/sync/semaphore >/dev/null 2>&1 || true
go build -ldflags="-s -w" -o "$GO_BIN" scamnet.go
succ "Go 程序编译完成：$GO_BIN"

# ---------------- 守护脚本 ----------------
GUARD_SCRIPT="$LOG_DIR/scamnet_guard.sh"
cat > "$GUARD_SCRIPT" <<EOF
#!/bin/bash
MAX_LINES=500
LOG="$LATEST_LOG"
> "\$LOG"
while :; do
  echo "[GUARD] \$(date '+%F %T') 开始扫描..." | tee -a "\$LOG"
  "$GO_BIN" -start "$START_IP" -end "$END_IP" -ports "$PORT_INPUT" \
    -tg-token "$TELEGRAM_TOKEN" -tg-chat "$TELEGRAM_CHATID" \
    -conc 300 -timeout 6 -retries 2 | tee -a "\$LOG"
  tail -n "\$MAX_LINES" "\$LOG" > "\$LOG.tmp" && mv "\$LOG.tmp" "\$LOG"
  echo "[GUARD] \$(date '+%F %T') 完成一轮，3秒后继续..." | tee -a "\$LOG"
  sleep 3
done
EOF

chmod +x "$GUARD_SCRIPT"

pkill -f scamnet_guard.sh >/dev/null 2>&1 || true
nohup bash "$GUARD_SCRIPT" > "$GUARD_STDOUT" 2>&1 &
succ "守护进程已启动！日志: tail -f $LATEST_LOG"
succ "结果: $VALID_FILE"
