#!/bin/bash
# scamnet 自动构建与运行脚本（单文件最终版）
# 含进度条 + 日志轮换 + 自动编译

echo "[启动] scamnet 扫描器初始化..."

# 写入 Go 源码
cat > scamnet.go <<'EOF'
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ProxyResult struct {
	Proxy   string `json:"proxy"`
	Working bool   `json:"working"`
	Country string `json:"country"`
}

var (
	inputFile   string
	outputFile  string
	concurrency int
	timeout     int
	passwords   []string
	total       int64
	done        int64
)

func init() {
	flag.StringVar(&inputFile, "i", "proxies.txt", "Input file containing proxy list")
	flag.StringVar(&outputFile, "o", "working.txt", "Output file for working proxies")
	flag.IntVar(&concurrency, "t", 100, "Number of concurrent workers")
	flag.IntVar(&timeout, "timeout", 5, "Connection timeout (seconds)")

	passwords := []string{
	"admin:admin",
	"::",
	"0:0",
	"00:00",
	"000:000",
	"0000:0000",
	"00000:00000",
	"000000:000000",
	"1:1",
	"11:11",
	"111:111",
	"1111:1111",
	"11111:11111",
	"111111:111111",
	"2:2",
	"22:22",
	"222:222",
	"2222:2222",
	"22222:22222",
	"222222:222222",
	"3:3",
	"33:33",
	"333:333",
	"3333:3333",
	"33333:33333",
	"333333:333333",
	"4:4",
	"44:44",
	"444:444",
	"4444:4444",
	"44444:44444",
	"444444:444444",
	"5:5",
	"55:55",
	"555:555",
	"5555:5555",
	"55555:55555",
	"555555:555555",
	"6:6",
	"66:66",
	"666:666",
	"6666:6666",
	"66666:66666",
	"666666:666666",
	"7:7",
	"77:77",
	"777:777",
	"7777:7777",
	"77777:77777",
	"777777:777777",
	"8:8",
	"88:88",
	"888:888",
	"8888:8888",
	"88888:88888",
	"888888:888888",
	"9:9",
	"99:99",
	"999:999",
	"9999:9999",
	"99999:99999",
	"999999:999999",
	"1080:1080",
	"123:123",
	"123:321",
	"123:456",
	"123:abc",
	"123:qwe",
	"1234:1234",
	"1234:4321",
	"1234:5678",
	"1234:abcd",
	"1234:qwer",
	"12345:12345",
	"12345:54321",
	"12345:67890",
	"12345:678910",
	"12345:abcde",
	"12345:qwert",
	"123456:123456",
	"123456:654321",
	"123456:abcdef",
	"123456:qwerty",
	"123456:qwert",
	"12345678:12345678",
	"12345678:87654321",
	"123456789:123456789",
	"123456789:987654321",
	"123459:123459",
	"12349:12349",
	"1239:1239",
	"321:321",
	"520:520",
	"520:1314",
	"69:69",
	"6969:6969",
	"696969:696969",
	"a:a",
	"a:b",
	"aa:aa",
	"aaa:aaa",
	"aaaa:aaaa",
	"aaaaa:aaaaa",
	"aaaaaa:aaaaaa",
	"aaa:111",
	"aaa:123",
	"aaa:bbb",
	"a123:a123",
	"aa123:aa123",
	"aaa123:aaa123",
	"aa123456:aa123456",
	"a123456:a123456",
	"123aa:123aa",
	"123aaa:123aaa",
	"123abc:123abc",
	"ab:ab",
	"ab:cd",
	"abc:123",
	"abc:abc",
	"abc:cba",
	"abc:def",
	"abcdefg:abcdefg",
	"abc123:abc123",
	"abcde:abcde",
	"admin:",
	"admin:123",
	"admin:123456",
	"admin123:admin",
	"as:df",
	"asd:asd",
	"asd:fgh",
	"awsl:awsl",
	"b:b",
	"bb:bb",
	"bbb:bbb",
	"bbbb:bbbb",
	"bbbbb:bbbbb",
	"bbbbbb:bbbbbb",
	"c:c",
	"cc:cc",
	"ccc:ccc",
	"cccc:cccc",
	"ccccc:ccccc",
	"cccccc:cccccc",
	"cnmb:cnmb",
	"d:d",
	"dd:dd",
	"ddd:ddd",
	"dddd:dddd",
	"ddddd:ddddd",
	"dddddd:dddddd",
	"demo:demo",
	"e:e",
	"ee:ee",
	"eee:eee",
	"eeee:eeee",
	"eeeee:eeeee",
	"eeeeee:eeeeee",
	"f:f",
	"ff:ff",
	"fff:fff",
	"ffff:ffff",
	"fffff:fffff",
	"ffffff:ffffff",
	"fuckyou:fuckyou",
	"g:g",
	"gg:gg",
	"ggg:ggg",
	"gggg:gggg",
	"ggggg:ggggg",
	"gggggg:gggggg",
	"guest:guest",
	"h:h",
	"hh:hh",
	"hhh:hhh",
	"hhhh:hhhh",
	"hhhhh:hhhhh",
	"hhhhhh:hhhhhh",
	"hello:hello",
	"i:i",
	"ii:ii",
	"iii:iii",
	"iiii:iiii",
	"iiiii:iiiii",
	"iiiiii:iiiiii",
	"j:j",
	"jj:jj",
	"jjj:jjj",
	"jjjj:jjjj",
	"jjjjj:jjjjj",
	"jjjjjj:jjjjjj",
	"k:k",
	"kk:kk",
	"kkk:kkk",
	"kkkk:kkkk",
	"kkkkk:kkkkk",
	"kkkkkk:kkkkkk",
	"l:l",
	"ll:ll",
	"lll:lll",
	"llll:llll",
	"lllll:lllll",
	"llllll:llllll",
	"love:love",
	"m:m",
	"mm:mm",
	"mmm:mmm",
	"mmmm:mmmm",
	"mmmmm:mmmmm",
	"mmmmmm:mmmmmm",
	"n:n",
	"nn:nn",
	"nnn:nnn",
	"nnnn:nnnn",
	"nnnnn:nnnnn",
	"nnnnnn:nnnnnn",
	"nmsl:nmsl",
	"o:o",
	"oo:oo",
	"ooo:ooo",
	"oooo:oooo",
	"ooooo:ooooo",
	"oooooo:oooooo",
	"p:p",
	"pp:pp",
	"ppp:ppp",
	"pppp:pppp",
	"ppppp:ppppp",
	"pppppp:pppppp",
	"password:password",
	"proxy:proxy",
	"q:q",
	"qaq:qaq",
	"qaq:qwq",
	"qq:qq",
	"qqq:qqq",
	"qqqq:qqqq",
	"qqqqq:qqqqq",
	"qqqqqq:qqqqqq",
	"qwe:123",
	"qwe:asd",
	"qwe:qwe",
	"qwe123:qwe123",
	"qweasd:qweasd",
	"qwer:1234",
	"qwer:qwer",
	"qwert:12345",
	"qwert:qwert",
	"qwerty:123456",
	"qwerty:qwerty",
	"qwq:qaq",
	"qwq:qwe",
	"qwq:qwq",
	"r:r",
	"rr:rr",
	"rrr:rrr",
	"rrrr:rrrr",
	"rrrrr:rrrrr",
	"rrrrrr:rrrrrr",
	"root:root",
	"s:s",
	"s5:s5",
	"ss:ss",
	"sss:sss",
	"ssss:ssss",
	"sssss:sssss",
	"ssssss:ssssss",
	"socks:socks",
	"socks5:socks5",
	"t:t",
	"test:test",
	"test123:test123",
	"tt:tt",
	"ttt:ttt",
	"tttt:tttt",
	"ttttt:ttttt",
	"tttttt:tttttt",
	"u:u",
	"user:123",
	"user:1234",
	"user:12345",
	"user:123456",
	"user:pass",
	"user:password",
	"user:pwd",
	"user:user",
	"username:username",
	"uu:uu",
	"uuu:uuu",
	"uuuu:uuuu",
	"uuuuu:uuuuu",
	"uuuuuu:uuuuuu",
	"v:v",
	"vv:vv",
	"vvv:vvv",
	"vvvv:vvvv",
	"vvvvv:vvvvv",
	"vvvvvv:vvvvvv",
	"w:w",
	"wsnd:wsnd",
	"ww:ww",
	"www:www",
	"wwww:wwww",
	"wwwww:wwwww",
	"wwwwww:wwwwww",
	"x:x",
	"xx:xx",
	"xxx:xxx",
	"xxxx:xxxx",
	"xxxxx:xxxxx",
	"xxxxxx:xxxxxx",
	"y:y",
	"yy:yy",
	"yyy:yyy",
	"yyyy:yyyy",
	"yyyyy:yyyyy",
	"yyyyyy:yyyyyy",
	"z:z",
	"zz:zz",
	"zzz:zzz",
	"zzzz:zzzz",
	"zzzzz:zzzzz",
	"zzzzzz:zzzzzz",
}
}

func main() {
	flag.Parse()

	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Println("[错误] 无法读取代理列表:", err)
		return
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			proxies = append(proxies, line)
		}
	}

	if len(proxies) == 0 {
		fmt.Println("[警告] 没有发现可扫描的代理.")
		return
	}

	total = int64(len(proxies))
	fmt.Printf("[信息] 共加载 %d 条代理，开始检测...\n", len(proxies))

	results := make(chan ProxyResult, len(proxies))
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	// 启动进度条显示协程
	go progressBar()

	for _, proxy := range proxies {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ok := checkProxy(p)
			country := ""
			if ok {
				country = getCountry(p)
				results <- ProxyResult{Proxy: p, Working: true, Country: country}
			} else {
				results <- ProxyResult{Proxy: p, Working: false}
			}
			atomic.AddInt64(&done, 1)
		}(proxy)
	}

	wg.Wait()
	close(results)
	saveResults(outputFile, results)
	fmt.Println("\n[完成] 扫描结果已保存至", outputFile)
}

func checkProxy(proxy string) bool {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				return url.Parse(proxy)
			},
		},
	}
	req, err := http.NewRequest("GET", "http://ifconfig.me", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func getCountry(proxy string) string {
	ip := extractHost(proxy)
	if ip == "" {
		return "未知"
	}
	url := fmt.Sprintf("https://ipapi.co/%s/json", ip)
	resp, err := http.Get(url)
	if err != nil {
		return "未知"
	}
	defer resp.Body.Close()

	data, _ := ioutil.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	if country, ok := result["country_name"]; ok {
		return country.(string)
	}
	return "未知"
}

func extractHost(proxy string) string {
	u, err := url.Parse(proxy)
	if err != nil {
		return ""
	}
	host, _, _ := net.SplitHostPort(u.Host)
	return host
}

func saveResults(filename string, results chan ProxyResult) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("[错误] 无法保存结果:", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	count := 0
	for r := range results {
		if r.Working {
			count++
			fmt.Fprintf(writer, "%s\t%s\n", r.Proxy, r.Country)
		}
	}
	writer.Flush()
	fmt.Printf("\n[信息] 共发现 %d 条可用代理.\n", count)
}

func progressBar() {
	for {
		current := atomic.LoadInt64(&done)
		if current >= total {
			fmt.Printf("\r进度: [%-50s] 100%%", strings.Repeat("█", 50))
			return
		}
		ratio := float64(current) / float64(total)
		width := int(ratio * 50)
		bar := strings.Repeat("█", width) + strings.Repeat(" ", 50-width)
		fmt.Printf("\r进度: [%-50s] %5.1f%%", bar, ratio*100)
		time.Sleep(200 * time.Millisecond)
	}
}
EOF

# 编译 Go 程序
echo "[构建] 初始化 Go 模块并编译..."
go mod init scamnet >/dev/null 2>&1
go mod tidy >/dev/null 2>&1
go build -o scamnet scamnet.go

# 日志轮换
mkdir -p logs
touch logs/latest.log
MAX_LOG=500
tail -n $MAX_LOG logs/latest.log > logs/tmp.log && mv logs/tmp.log logs/latest.log

# 执行并记录
echo "[运行] 开始扫描..."
./scamnet -i proxies.txt -o working.txt -t 200 | tee -a logs/latest.log

echo "[完成] 所有任务执行完毕。"
