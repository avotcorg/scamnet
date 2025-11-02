#!/bin/bash
# scamnet 纯 Bash + nc 无敌版

set -euo pipefail
IFS=$'\n\t'

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; NC='\033[0m'
succ() { 
  echo -e "${GREEN}[$(date '+%H:%M:%S')] [+] $*${NC}" | tee -a "$SUCCESS_LOG"
}

CONNECTED_FILE="socks5_connected.txt"
LOG_DIR="logs"
mkdir -p "$LOG_DIR"
SUCCESS_LOG="$LOG_DIR/success.log"
PID_FILE="$LOG_DIR/scamnet.pid"
DONE_FILE="$LOG_DIR/done.count"
MAX_PROCS=3
TOTAL=0

> "$CONNECTED_FILE"
> "$SUCCESS_LOG"
echo "0" > "$DONE_FILE"
echo "# SOCKS5 Connected" > "$CONNECTED_FILE"
echo "# Generated: $(date)" >> "$CONNECTED_FILE"
echo "# Success Only" > "$SUCCESS_LOG"

echo $$ > "$PID_FILE"

log() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $*"; }

log "扫描器启动 (PID: $$)"
log "后台运行: nohup $(basename $0) &"
log "取消进程: pkill -f $(basename $0) 或 kill $$"

read -p "起始 IP (默认 47.80.0.0): " START_IP
START_IP=${START_IP:-47.80.0.0}
read -p "结束 IP (默认 47.86.255.255): " END_IP
END_IP=${END_IP:-47.86.255.255}
read -p "端口 (默认 1080,8080,8888,3128): " PORTS_STR
PORTS_STR=${PORTS_STR:-1080,8080,8888,3128}

IFS=',' read -ra PORTS <<< "$PORTS_STR"
expanded=()
for p in "${PORTS[@]}"; do
  if [[ $p == *-* ]]; then
    r=(${p//-/ })
    for ((i=${r[0]}; i<=${r[1]}; i++)); do expanded+=($i); done
  else
    expanded+=($p)
  fi
done
PORTS=("${expanded[@]}")

ip2int() {
  IFS=. read -r a b c d <<< "$1"
  echo $((a * 16777216 + b * 65536 + c * 256 + d))
}

int2ip() {
  printf "%d.%d.%d.%d\n" $((($1>>24)&255)) $((($1>>16)&255)) $((($1>>8)&255)) $(($1&255))
}

START_I=$(ip2int "$START_IP")
END_I=$(ip2int "$END_IP")
if (( START_I > END_I )); then
  t=$START_I; START_I=$END_I; END_I=$t
fi

IP_COUNT=$((END_I - START_I + 1))
TOTAL=$((IP_COUNT * ${#PORTS[@]}))
log "范围: $START_IP ~ $END_IP ($IP_COUNT IP)"
log "端口: ${PORTS[*]} (${#PORTS[@]} 个)"
log "任务: $TOTAL | 并发: $MAX_PROCS | 超时: 6s"

printf -v PAYLOAD '\x05\x01\x00\x05\x01\x00\x03\x0Cifconfig.me\x00\x50GET / HTTP/1.1\r\nHost: ifconfig.me\r\n\r\n'

increment_done() {
  {
    flock 200
    current=$(cat "$DONE_FILE")
    printf "%s\n" "$((current + 1))" > "$DONE_FILE"
  } 200<"$DONE_FILE"
}

test_proxy() {
  local ip=$1 port=$2
  local timeout=6
  local start_ns=$(date +%s%N 2>/dev/null || date +%s)
  local output=$(printf -- "$PAYLOAD" | nc -w "$timeout" -q 0 "$ip" "$port" 2>/dev/null || true)
  local end_ns=$(date +%s%N 2>/dev/null || date +%s)
  local lat
  if [[ $start_ns == *N ]]; then
    lat=$(( (end_ns - start_ns) / 1000000 ))
  else
    lat=$(( (end_ns - start_ns) * 1000 ))
  fi

  if (( lat > 15000 )); then
    increment_done
    return
  fi

  if echo "$output" | grep -qE "HTTP/1\.1 [0-9]+|([0-9]{1,3}\.){3}[0-9]{1,3}"; then
    local origin=$(echo "$output" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || echo "unknown")
    if [[ $origin =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      {
        flock 200
        echo "socks5://$ip:$port" >> "$CONNECTED_FILE"
        num=$(grep -v '^#' "$CONNECTED_FILE" | wc -l)
        succ "通 #$num socks5://$ip:$port ($lat ms) 出站:$origin"
      } 200<"$CONNECTED_FILE"
    fi
  fi
  increment_done
}

progress() {
  local current_done=0 running=0 r=0.00 filled=0 bar=""
  while :; do
    {
      flock 200
      current_done=$(cat "$DONE_FILE" 2>/dev/null || echo 0)
    } 200<"$DONE_FILE"
    running=$(jobs -r | wc -l)
    if (( current_done > TOTAL )); then current_done=$TOTAL; fi
    r=$(awk "BEGIN {printf \"%.2f\", $current_done * 100 / $TOTAL}")
    filled=$(( current_done * 50 / TOTAL ))
    bar=""
    for ((i=1; i<=filled; i++)); do bar+='█'; done
    for ((i=filled+1; i<=50; i++)); do bar+='░'; done
    printf "\r进度: [$bar] $r%% ($current_done/$TOTAL) 运行:$running   "
    if (( current_done >= TOTAL )); then break; fi
    sleep 0.3
  done
  printf "\r进度: [%50s] 100.00%% ($TOTAL/$TOTAL)          \n" "$(printf '█%.0s' {1..50})"
}

progress &
PROG_PID=$!

i=$START_I
while (( i <= END_I )); do
  ip=$(int2ip $i)
  for port in "${PORTS[@]}"; do
    while (( $(jobs -r | wc -l) >= MAX_PROCS )); do sleep 0.01; done
    test_proxy "$ip" "$port" &
  done
  ((i++))
done

wait
kill $PROG_PID 2>/dev/null || true
{
  flock 200
  sort -u "$CONNECTED_FILE" -o "$CONNECTED_FILE"
} 200<"$CONNECTED_FILE"
rm -f "$PID_FILE" "$DONE_FILE"

succ "完成！连通: $(grep -v '^#' "$CONNECTED_FILE" | wc -l) 条"
log "成功日志: tail -f $SUCCESS_LOG"
log "结果: cat $CONNECTED_FILE"
echo "========================================"
echo "后台运行: nohup $(basename $0) &"
echo "取消进程: pkill -f $(basename $0)"
echo "实时成功: tail -f $SUCCESS_LOG"
echo "清理: rm -rf $CONNECTED_FILE $LOG_DIR $(basename $0)"
echo "========================================"
