#!/bin/bash
# scamnet 纯单文件版 - 仅扫描 SOCKS5 连通性（多线程保存通的代理）
# 功能: 高并发300、超时6s、延迟<=15000ms、去重排序
# 输出: socks5_connected.txt (socks5://ip:port)
# 无外部依赖，一键运行: bash main.sh
# 修复: 完整错误处理、兼容Go 1.16+、自动go.mod

set -euo pipefail
IFS=$'\n\t'

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; NC='\033[0m'
log() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $*"; }
err() { echo -e "${RED}[$(date '+%H:%M:%S')] [!] $*${NC}" >&2; }
succ() { echo -e "${GREEN}[$(date '+%H:%M:%Ｓ')] [+] $*${NC}"; }

LOG_DIR="logs"
mkdir -p "$LOG_DIR"
LATEST_LOG="$LOG_DIR/latest.log"
CONNECTED_FILE="socks5_connected.txt"

log "写入纯 Go 内核到 main.go"
cat > main.go << 'EOF'
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
	connectedFile      = "socks5_connected.txt"
	muConnected        sync.Mutex
	connectedCount     int64
	done               int64
)

func main() {
	_ = os.Remove(connectedFile)
	_ = os.WriteFile(connectedFile, []byte("# SOCKS5 Connected Proxies\n# Generated: "+time.Now().Format("2006-01-02 15:04:05")+"\n"), 0644)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("起始 IP (默认 47.80.0.0): ")
	startIP, _ := reader.ReadString('\n')
	startIP = strings.TrimSpace(startIP)
	if startIP == "" { startIP = "47.80.0.0" }
	if !validIP(startIP) { fmt.Println("[!] 无效起始 IP"); return }

	fmt.Print("结束 IP (默认 47.86.255.255): ")
	endIP, _ := reader.ReadString('\n')
	endIP = strings.TrimSpace(endIP)
	if endIP == "" { endIP = "47.86.255.255" }
	if !validIP(endIP) { fmt.Println("[!] 无效结束 IP"); return }

	startI := ipToInt(startIP)
	endI := ipToInt(endIP)
	if startI > endI { startIP, endIP = endIP, startIP; startI, endI = endI, startI }

	fmt.Print("端口 (默认 1080,8080,8888,3128): ")
	portsStr, _ := reader.ReadString('\n')
	portsStr = strings.TrimSpace(portsStr)
	if portsStr == "" { portsStr = "1080,8080,8888,3128" }
	ports := parsePorts(portsStr)
	if len(ports) == 0 { fmt.Println("[!] 无效端口"); return }

	ipCount := int(endI - startI + 1)
	total := uint64(ipCount) * uint64(len(ports))
	batchCount := (total + uint64(batchSize) - 1) / uint64(batchSize)

	fmt.Printf("[*] 范围: %s ~ %s (%d IP)\n", startIP, endIP, ipCount)
	fmt.Printf("[*] 端口: %v (%d)\n", ports, len(ports))
	fmt.Printf("[*] 总任务: %d | 批次: %d | 并发: %d | 超时: %ds\n", total, batchCount, concurrency, timeOutSeconds)
	fmt.Println("[*] 开始扫描连通性...")

	go progressBar(total)

	for b := uint64(0); b < total; b += uint64(batchSize) {
		e := b + uint64(batchSize)
		if e > total { e = total }
		fmt.Printf("\n[*] 批次 %d/%d (%d tasks)\n", b/uint64(batchSize)+1, batchCount, e-b)
		scanBatch(uint32(startI), uint32(endI), ports, b, e)
	}

	time.Sleep(2 * time.Second)
	dedup(connectedFile)
	fmt.Printf("\n[+] 完成！连通: %d 条 → %s\n", atomic.LoadInt64(&connectedCount), connectedFile)
}

func scanBatch(start, end uint32, ports []int, b, e uint64) {
	sem := semaphore.NewWeighted(concurrency)
	ctx := context.Background()
	var wg sync.WaitGroup
	idx := b
	for i := start; i <= end && idx < e; i++ {
		ip := intToIP(i)
		for _, p := range ports {
			if idx >= e { goto done }
			wg.Add(1)
			go func(ip string, port int) {
				defer wg.Done()
				sem.Acquire(ctx, 1)
				defer sem.Release(1)
				if test(ip, port) { save(ip, port) }
				atomic.AddInt64(&done, 1)
			}(ip, p)
			idx++
		}
	}
done:
	wg.Wait()
}

func test(ip string, port int) bool {
	proxy := fmt.Sprintf("socks5://%s:%d", ip, port)
	u, _ := url.Parse(proxy)
	tr := &http.Transport{Proxy: http.ProxyURL(u),
		DialContext: (&net.Dialer{Timeout: 4*time.Second}).DialContext,
		TLSHandshakeTimeout: 4*time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: time.Duration(timeOutSeconds)*time.Second}
	start := time.Now()
	resp, err := client.Get("http://ifconfig.me")
	lat := int(time.Since(start).Milliseconds())
	if err != nil || resp.StatusCode != 200 {
		if resp != nil { resp.Body.Close() }
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	origin := strings.TrimSpace(string(body))
	return origin != "" && strings.Contains(origin, ".") && lat <= 15000
}

func save(ip string, port int) {
	muConnected.Lock()
	defer muConnected.Unlock()
	f, _ := os.OpenFile(connectedFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	defer f.Close()
	line := fmt.Sprintf("socks5://%s:%d", ip, port)
	fmt.Fprintln(f, line)
	c := atomic.AddInt64(&connectedCount, 1)
	fmt.Printf("[+] 通 #%d %s\n", c, line)
}

func progressBar(total uint64) {
	for atomic.LoadInt64(&done) < int64(total) {
		cur := atomic.LoadInt64(&done)
		r := float64(cur)/float64(total)
		bar := strings.Repeat("█", int(r*50)) + strings.Repeat("░", 50-int(r*50))
		fmt.Printf("\r进度: [%s] %.1f%% (%d/%d)", bar, r*100, cur, total)
		time.Sleep(300*time.Millisecond)
	}
	fmt.Printf("\r进度: [%s] 100.0%% (%d/%d)\n", strings.Repeat("█", 50), total, total)
}

func dedup(file string) {
	data, _ := os.ReadFile(file)
	lines := strings.Split(string(data), "\n")
	seen := map[string]bool{}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") { seen[l] = true }
	}
	var uniq []string
	for l := range seen { uniq = append(uniq, l) }
	sort.Strings(uniq)
	out := "# Deduped " + time.Now().Format("2006-01-02 15:04") + "\n"
	for _, l := range uniq { out += l + "\n" }
	os.WriteFile(file, []byte(out), 0644)
	fmt.Printf("[+] 去重: %d 条\n", len(uniq))
}

func validIP(s string) bool { return net.ParseIP(strings.TrimSpace(s)) != nil && net.ParseIP(s).To4() != nil }
func ipToInt(ip string) uint32 {
	p := strings.Split(ip, ".")
	a, _ := strconv.Atoi(p[0]); b, _ := strconv.Atoi(p[1]); c, _ := strconv.Atoi(p[2]); d, _ := strconv.Atoi(p[3])
	return uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
}
func intToIP(n uint32) string { return fmt.Sprintf("%d.%d.%d.%d", n>>24&255, n>>16&255, n>>8&255, n&255) }
func parsePorts(s string) []int {
	var res []int; seen := map[int]bool{}
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		if strings.Contains(t, "-") {
			r := strings.Split(t, "-")
			st, _ := strconv.Atoi(r[0]); en, _ := strconv.Atoi(r[1])
			for i := st; i <= en && i <= 65535; i++ { if !seen[i] { res = append(res, i); seen[i] = true } }
		} else if p, err := strconv.Atoi(t); err == nil && p > 0 && p <= 65535 && !seen[p] {
			res = append(res, p); seen[p] = true
		}
	}
	sort.Ints(res); return res
}
EOF

log "创建 go.mod"
cat > go.mod << 'EOF'
module scamnet

go 1.16

require golang.org/x/sync v0.8.0
EOF

log "下载依赖"
go mod tidy

log "编译"
go build -ldflags="-s -w" -o scamnet main.go

> "$LATEST_LOG"

succ "启动"
ulimit -n 999999 || true
./scamnet 2>&1 | tee -a "$LATEST_LOG"

succ "完成！"
echo "结果: cat $CONNECTED_FILE"
echo "命中: grep '^\\[+]' $LATEST_LOG"
echo "清理: rm -f main.go go.mod go.sum scamnet $CONNECTED_FILE logs/latest.log"
