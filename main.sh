#!/bin/bash
# scamnet 纯 Bash + netcat 版 - 零依赖、多线程 SOCKS5 连通性扫描
# 功能: 使用 nc (netcat) 测试 SOCKS5 是否通（无认证），延迟<=15000ms
# 输出: socks5_connected.txt (socks5://ip:port)
# 多线程: 10 并发 (bash &)
# 兼容: 所有 Linux (nc/openbsd-nc/gnutls-nc)
# 一键运行: chmod +x main.sh && ./main.sh

set -euo pipefail
IFS=$'\n\t'

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; NC='\033[0m'
log() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $*"; }
succ() { echo -e "${GREEN}[$(date '+%H:%M:%S')] [+] $*${NC}"; }

CONNECTED_FILE="socks5_connected.txt"
LOG_DIR="logs"
mkdir -p "$LOG_DIR"
LATEST_LOG="$LOG_DIR/latest.log"
MAX_PROCS=20  # 并发数
COUNT=0
TOTAL=0

> "$CONNECTED_FILE"
echo "# SOCKS5 Connected (nc bash版)" > "$CONNECTED_FILE"
echo "# Generated: $(date)" >> "$CONNECTED_FILE"

log "纯 Bash + nc 零依赖扫描器启动"

# 交互配置
read -p "起始 IP (默认 47.80.0.0): " START_IP
START_IP=${START_IP:-47.80.0.0}
read -p "结束 IP (默认 47.86.255.255): " END_IP
END_IP=${END_IP:-47.86.255.255}
read -p "端口 (默认 1080,8080,8888,5555): " PORTS_STR
PORTS_STR=${PORTS_STR:-1080,8080,8888,5555}

# 解析端口
IFS=',' read -ra PORTS <<< "$PORTS_STR"
for i in "${!PORTS[@]}"; do
  if [[ ${PORTS[i]} == *-* ]]; then
    unset 'PORTS[i]'
    RANGE=(${PORTS[i]//-/ })
    for ((p=${RANGE[0]}; p<=${RANGE[1]}; p++)); do
      PORTS+=($p)
    done
  fi
done

# IP 转 int
ip2int() {
  local a b c d
  IFS=. read -r a b c d <<< "$1"
  echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

int2ip() {
  local n=$1
  printf "%d.%d.%d.%d\n" $((n>>24&255)) $((n>>16&255)) $((n>>8&255)) $((n&255))
}

START_I=$(ip2int "$START_IP")
END_I=$(ip2int "$END_IP")
[[ $START_I -gt $END_I ]] && { tmp=$START_I; START_I=$END_I; END_I=$tmp; }

IP_COUNT=$((END_I - START_I + 1))
TOTAL=$((IP_COUNT * ${#PORTS[@]}))
log "范围: $START_IP ~ $END_IP ($IP_COUNT IP)"
log "端口: ${PORTS[*]} (${#PORTS[@]} 个)"
log "总任务: $TOTAL | 并发: $MAX_PROCS | 超时: 6s"

# nc 测试函数 (SOCKS5 无认证握手 + GET)
test_proxy() {
  local ip=$1 port=$2
  local timeout=6
  local start_ms=$(date +%s%3N)

  # SOCKS5 无认证握手: 05 01 00 (ver=5, 1 method, no auth)
  # 服务器应答: 05 00
  # 请求: 05 01 00 03 len domain port (connect ifconfig.me:80)
  local payload=$(
    printf '\x05\x01\x00'  # 握手
    printf '\x05\x01\x00\x03\x0cifconfig.me\x00\x50'  # CONNECT ifconfig.me:80 (len=12, \x00\x50=80)
    printf 'GET / HTTP/1.1\r\nHost: ifconfig.me\r\n\r\n'
  )

  # 使用 nc -w 超时
  local output=$(echo -n "$payload" | nc -w "$timeout" -q 0 "$ip" "$port" 2>/dev/null || true)
  local lat=$(( $(date +%s%3N) - start_ms ))

  if [[ $lat -gt 15000 ]]; then return; fi

  # 检查是否有 HTTP 响应 + IP
  if echo "$output" | grep -qE "HTTP/1.1 [0-9]+|([0-9]{1,3}\.){3}[0-9]{1,3}"; then
    local origin=$(echo "$output" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)
    if [[ -n $origin && $origin =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "socks5://$ip:$port" >> "$CONNECTED_FILE"
      succ "通 #$(cat "$CONNECTED_FILE" | grep -v '^#' | wc -l) socks5://$ip:$port ($lat ms) 出站:$origin"
      return
    fi
  fi
}

# 进度条
progress() {
  local done=0
  while [[ $done -lt $TOTAL ]]; do
    done=$(jobs -r | wc -l)
    done=$((TOTAL - done))
    local r=$(awk "BEGIN {printf \"%.2f\", $done/$TOTAL*100}")
    local bar=$(printf "%50s" "" | tr ' ' '░')
    bar=${bar:0:$(($done * 50 / TOTAL))}█${bar:$(($done * 50 / TOTAL))}
    printf "\r进度: [$bar] $r%% ($done/$TOTAL)"
    sleep 0.3
  done
  printf "\r进度: [%50s] 100.00%% ($TOTAL/$TOTAL)\n" $(printf "█%.0s" {1..50})
}

# 主循环
go_progress() { progress; }
go_progress &

i=$START_I
while [[ $i -le $END_I ]]; do
  ip=$(int2ip $i)
  for port in "${PORTS[@]}"; do
    while [[ $(jobs -r | wc -l) -ge $MAX_PROCS ]]; do sleep 0.01; done
    test_proxy "$ip" "$port" &
  done
  ((i++))
done

wait
sort -u "$CONNECTED_FILE" -o "$CONNECTED_FILE"  # 去重

succ "扫描完成！连通: $(grep -v '^#' "$CONNECTED_FILE" | wc -l) 条"
echo "========================================"
echo "结果: cat $CONNECTED_FILE"
echo "日志: cat $LATEST_LOG"
echo "清理: rm -rf $CONNECTED_FILE $LOG_DIR main.sh"
echo "========================================"
