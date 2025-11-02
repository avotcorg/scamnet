#!/bin/bash
# scamnet 简化版 - 仅扫描连通性（多线程）+ 保存通的代理
# 功能: 高并发测试 SOCKS5 是否通（无弱口令、无国家识别、无 Telegram）
# 输出: socks5_connected.txt (socks5://ip:port) 只保存连通的
# 并发: 300 | 超时: 6s | 延迟放宽: 15000ms
# 一键运行: bash this_script.sh

set -euo pipefail
IFS=$'\n\t'

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; NC='\033[0m'
log() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $*"; }
err() { echo -e "${RED}[$(date '+%H:%M:%S')] [!] $*${NC}" >&2; }
succ() { echo -e "${GREEN}[$(date '+%H:%M:%S')] [+] $*${NC}"; }

LOG_DIR="logs"
mkdir -p "$LOG_DIR"
LATEST_LOG="$LOG_DIR/latest.log"
CONNECTED_FILE="socks5_connected.txt"
GO_FILE="scamnet_simple.go"

log "写入简化 Go 内核（仅连通性测试） → $GO_FILE"
cat > "$GO_FILE" << 'EOF'
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
	// 初始化文件
	_ = os.WriteFile(connectedFile, []byte("# SOCKS5 Connected Proxies (socks5://ip:port)\n"), 0644)

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
	fmt.Printf("[*] 端口: %v (%d 个)\n", ports, len(ports))
	fmt.Printf("[*] 总任务: %d | 批次: %d | 并发: %d | 超时: %ds\n", total, batchCount, concurrency, timeOutSeconds)
	fmt.Println("[*] 开始扫描连通性 (Ctrl+C 停止)...")

	go progressBar(total)

	for bstart := uint64(0); bstart < total; bstart += uint64(batchSize) {
		bend := bstart + uint64(batchSize)
		if bend > total {
			bend = total
		}
		fmt.Printf("\n[*] 批次 %d/%d → %d tasks\n", bstart/uint64(batchSize)+1, batchCount, bend-bstart)
		scanBatch(uint32(startI), uint32(endI), ports, bstart, bend)
	}

	time.Sleep(2 * time.Second)
	dedupAndSort(connectedFile)
	fmt.Printf("\n[+] 扫描完成！连通代理: %d 条 → %s\n", atomic.LoadInt64(&connectedCount), connectedFile)
}

func scanBatch(startIP, endIP uint32, ports []int, batchStart, batchEnd uint64) {
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
				if testConnected(ipStr, port) {
					saveConnected(ipStr, port)
				}
				atomic.AddInt64(&done, 1)
			}(ip, p)
			taskIdx++
		}
	}
batchdone:
	wg.Wait()
}

func testConnected(ip string, port int) bool {
	proxyStr := fmt.Sprintf("socks5://%s:%d", ip, port)
	u, parseErr := url.Parse(proxyStr)
	if parseErr != nil {
		return false
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyURL(u),
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		ResponseHeaderTimeout: 3 * time.Second,
	}
	client := &http.Client{
		Transport:     tr,
		Timeout:       time.Duration(timeOutSeconds) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	start := time.Now()
	resp, err := client.Get("http://ifconfig.me")
	lat := int(time.Since(start).Milliseconds())
	if err != nil || resp == nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return false
	}
	defer resp.Body.Close()
	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return false
	}
	origin := strings.TrimSpace(string(bodyBytes))
	if origin == "" || !strings.Contains(origin, ".") || lat > 15000 {
		return false
	}
	return true
}

func saveConnected(ip string, port int) {
	muConnected.Lock()
	defer muConnected.Unlock()
	f, openErr := os.OpenFile(connectedFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if openErr != nil {
		return
	}
	defer f.Close()
	line := fmt.Sprintf("socks5://%s:%d", ip, port)
	fmt.Fprintln(f, line)
	count := atomic.AddInt64(&connectedCount, 1)
	fmt.Printf("[+] 通 #%d %s\n", count, line)
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

func dedupAndSort(filename string) {
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
	fmt.Fprintf(out, "# Deduped & Sorted at %s\n", time.Now().Format("2006-01-02 15:04:05"))
	for _, l := range lines {
		fmt.Fprintln(out, l)
	}
	out.Close()
	os.Rename(tmpFile, filename)
	newCount := len(lines)
	fmt.Printf("[+] 去重排序完成: %d 条\n", newCount)
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
go mod init scamnet_simple >/dev/null 2>&1
go get golang.org/x/sync/semaphore >/dev/null 2>&1
go mod tidy >/dev/null 2>&1

log "编译简化内核..."
if go build -ldflags="-s -w" -o scamnet_simple scamnet_simple.go; then
	succ "编译成功！"
else
	err "编译失败，请检查 Go 环境 (go version >=1.16)"
	go version || true
	exit 1
fi

> "$LATEST_LOG"

succ "启动简化扫描（仅连通性）..."
ulimit -n 999999 2>/dev/null || true
./scamnet_simple 2>&1 | tee -a "$LATEST_LOG"

succ "完成！"
echo "========================================"
echo "连通结果: cat $CONNECTED_FILE"
echo "实时命中: tail -f $LATEST_LOG | grep '^\\[+] 通'"
echo "清理: rm -rf scamnet_simple.go scamnet_simple logs $CONNECTED_FILE"
echo "========================================"
