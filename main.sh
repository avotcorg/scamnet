#!/bin/bash
# main.sh - OTC SOCKS5 扫描器一键启动

set -e

# 颜色
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
NC='\033[0m'

LOG="logs/scanner.log"
mkdir -p logs

echo -e "${GREEN}[OTC] OTC-socks5 插件扫描器启动${NC}"
echo "日志 → $LOG"

# 检查 Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] 未找到 python3，请安装${NC}"
    exit 1
fi

# 安装依赖
if [ ! -f ".installed" ]; then
    echo -e "${YELLOW}[*] 安装依赖...${NC}"
    pip3 install -q requests tqdm pyyaml ipaddress > /dev/null 2>>$LOG
    touch .installed
fi

# 启动
echo -e "${GREEN}[*] 启动扫描任务...${NC}"
python3 scanner.py 2>>$LOG

echo -e "${GREEN}[+] 扫描完成！查看 socks5_valid.txt${NC}"
