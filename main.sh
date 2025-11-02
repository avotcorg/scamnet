#!/bin/bash
# scamnet 纯 Bash + nc 终极版 - 零依赖、多线程 SOCKS5 连通性扫描
# 新功能:
# 1. 日志只保留成功 ([+] 通 ...)
# 2. 支持后台运行: nohup ./main.sh &
# 3. 支持取消: pkill -f main.sh
# 4. 扫描结束自动退出
# 5. PID 文件记录，便于杀进程
# 输出: socks5_connected.txt + logs/success.log (仅成功)
# 兼容: 所有 Linux nc

set -euo pipefail
IFS=$'\n\t'

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; NC='\033[0m'
succ() { 
  echo -e "${GREEN}[$(date '+%H:%M:%S')] [+] $*${NC}" | tee -a "$SUCCESS_LOG"
}

CONNECTED_FILE="socks5_connected.txt"
LOG_DIR="logs"
mkdir -p "$LOG_DIR"
SUCCESS_LOG="$LOG_DIR/success.log"  # 只存成功
PID_FILE="$LOG_DIR/scamnet.pid"
MAX_PROCS=5
TOTAL=0

> "$CONNECTED_FILE"
> "$SUCCESS_LOG"
echo "# SOCKS5 Connected (nc bash版)" > "$CONNECTED_FILE"
echo "# Generated: $(date)" >> "$CONNECTED_FILE"
echo "# Success Log" > "$SUCCESS_LOG"

# 记录 PID 支持杀进程
echo $$ > "$PID_FILE"

log() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $*"; }

log "纯 Bash + nc 零依赖扫描器启动 (PID: $$)"
log "后台运行: nohup $0 &"
log "取消进程: pkill -f $(basename $0)  或  kill $$"

# 交互配置
read -p "起始 IP (默认 47.80.0.0): " START_IP
START_IP=${START_IP:-47.80.0.0}
read -p "结束 IP (默认 47.86.255.255): " END_IP
END_IP=${END_IP:-47.86.255.255}
read -p "端口 (默认 1080,8080,8888,5555): " PORTS_STR
PORTS_STR=${PORTS_STR:-1080,8080,8888,5555}

# 解析端口
IFS=',' read -ra PORTS <<< "$PORTS_STR"
expanded_ports=()
for p in "${PORTS[@]}"; do
  if [[ $p == *-* ]]; then
    range=(${p//-/ })
    for ((i=${range[0]}; i<=${range[1]}; i++)); do
      expanded_ports+=($i)
    done
  else
    expanded_ports+=($p)
  fi
done
PORTS=("${expanded_ports[@]}")

# IP 转 int
ip2int() {
  local a b c d
  IFS=. read -r a b c d <<< "$1"
  echo $((a * 16777216 + b * 65536 + c * 256 + d))
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

# nc 测试函数
test_proxy() {
  local ip=$1 port=$2
  local timeout=6
  local start_ms=$(date +%s%N 2>/dev/null || date +%s)000
  start_ms=${start_ms%000}

  local handshake='\x05\x01\x00'
  local connect='\x05\x01\x00\x03\x0Cifconfig.me\x00\x50'
  local http='GET / HTTP/1.1\r\nHost: ifconfig.me\r\n\r\n'
  local payload=$(printf "%b%b%b" "$handshake" "$connect" "$http")

  local output=$(printf "%b" "$payload" | nc -w "$timeout" -q 0 "$ip" "$port" 2>/dev/null || true)
  local end_ms=$(date +%s%N 2>/dev/null || date +%s)000
  end_ms=${end_ms%000}
  local lat=$(( (end_ms - start_ms) / 1000000 ))

  [[ $lat -gt 15000 ]] && return

  if echo "$output" | grep -qE "HTTP/1\.1 [0-9]+ OK|([0-9]{1,3}\.){3}[0-9]{1,3}"; then
    local origin=$(echo "$output" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || echo "unknown")
    if [[ $origin =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      {
        flock -x 200
        echo "socks5://$ip:$port" >> "$CONNECTED_FILE"
        local num=$(grep -v '^#' "$CONNECTED_FILE" | wc -l)
        succ "通 #$num socks5://$ip:$port ($lat ms) 出站:$origin"
      } 200<"$CONNECTED_FILE"
    fi
  fi
}

# 进度条
progress() {
  while jobs -r >/dev/null 2>&1; do
    local running=$(jobs -r | wc -l)
    local done=$((TOTAL - running))
    local r=$(awk "BEGIN {printf \"%.2f\", $done*100/$TOTAL}")
    local filled=$((done * 50 / TOTAL))
    local bar=$(printf "█%.0s" $(seq 1 $filled))$(printf "░%.0s" $(seq 1 $((50-filled))))
    printf "\r进度: [$bar] $r%% ($done/$TOTAL) 运行中:$running"
    sleep 0.3
  done
  printf "\r进度: [%50s] 100.00%% ($TOTAL/$TOTAL)          \n" $(printf "█%.0s" {1..50})
}

# 启动进度条
progress &
PROG_PID=$!

# 主循环
i=$START_I
while [[ $i -le $END_I ]]; do
  ip=$(int2ip $i)
  for port in "${PORTS[@]}"; do
    while [[ $(jobs -r | wc -l) -ge $MAX_PROCS ]]; do sleep 0.01; done
    test_proxy "$ip" "$port" &
  done
  ((i++))
done

wait  # 等待所有任务结束
kill $PROG_PID 2>/dev/null || true

# 去重排序
sort -u "$CONNECTED_FILE" -o "$CONNECTED_FILE"

succ "扫描完成！连通: $(grep -v '^#' "$CONNECTED_FILE" | wc -l) 条"
log "日志 (仅成功): cat $SUCCESS_LOG"
log "结果: cat $CONNECTED_FILE"

# 清理 PID
rm -f "$PID_FILE"

echo "========================================"
echo "后台运行: nohup $0 &"
echo "取消进程: pkill -f $(basename $0)  或  kill $$"
echo "实时成功: tail -f $SUCCESS_LOG"
echo "清理文件: rm -rf $CONNECTED_FILE $LOG_DIR $PID_FILE $(basename $0)"
echo "========================================"
