#!/bin/bash
# main.sh - Scamnet OTC SOCKS5 扫描器（自包含版）
# 包含 requirements.txt 内容，无需外部文件
# 作者: avotcorg | TG: @soqunla
# 仓库: https://github.com/avotcorg/scamnet

set -e

# ==================== 颜色 & 日志 ====================
RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; NC='\033[0m'
LOG_DIR="logs"; mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/scanner_$(date +%Y%m%d_%H%M%S).log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"; }
echo -e "${GREEN}[OTC] Scamnet 自包含启动器 v1.0${NC}"
echo "日志 → $LOG"

# ==================== 内嵌 requirements.txt ====================
REQUIREMENTS_CONTENT="
requests>=2.28.0
tqdm>=4.64.0
PyYAML>=6.0
ipaddress>=1.0.23
"

# ==================== 检查 & 安装依赖（国内镜像）================
if [ ! -f ".deps_installed" ]; then
    echo -e "${YELLOW}[*] 安装依赖（清华源）...${NC}"
    echo "$REQUIREMENTS_CONTENT" > /tmp/scamnet_reqs.txt
    pip3 install --user -i https://pypi.tuna.tsinghua.edu.cn/simple \
        -r /tmp/scamnet_reqs.txt --no-warn-script-location 2>&1 | tee -a "$LOG"
    rm -f /tmp/scamnet_reqs.txt
    touch .deps_installed
    log "依赖安装完成"
else
    log "依赖已安装，跳过"
fi

# ==================== 下载核心文件 ====================
download() {
    local url="$1" file="$2"
    curl -Ls --fail --retry 3 --create-dirs -o "$file" "$url" || {
        echo -e "${RED}[!] 下载失败: $file${NC}" >&2
        exit 1
    }
}

echo -e "${YELLOW}[*] 下载 scanner.py 和插件...${NC}"
download "https://raw.githubusercontent.com/avotcorg/scamnet/main/scanner.py" "scanner.py"
mkdir -p plugins
download "https://raw.githubusercontent.com/avotcorg/scamnet/main/plugins/__init__.py" "plugins/__init__.py"
download "https://raw.githubusercontent.com/avotcorg/scamnet/main/plugins/auth_weak.py" "plugins/auth_weak.py"
download "https://raw.githubusercontent.com/avotcorg/scamnet/main/plugins/geo_ipapi.py" "plugins/geo_ipapi.py"
download "https://raw.githubusercontent.com/avotcorg/scamnet/main/plugins/output_file.py" "plugins/output_file.py"

# ==================== 创建默认配置 ====================
cat > config.yaml << 'EOF'
# Scamnet 配置
range: "157.254.32.0-157.254.32.255"
ports: [1080, 8080, 3128, 8000, 8081, 5555, 8888, 4890, 20000, 40000, 8081]
timeout: 6.0
workers: 300
EOF
log "config.yaml 创建"

# ==================== 初始化结果文件 ====================
echo "# Scamnet SOCKS5 扫描详细日志 ($(date))" > result_detail.txt
echo "# 可用 SOCKS5 代理 (socks5://user:pass@ip:port#Country)" > socks5_valid.txt
log "结果文件初始化"

# ==================== 启动扫描 ====================
echo -e "${GREEN}[*] 启动扫描任务...${NC}"
python3 scanner.py 2>&1 | tee -a "$LOG"

# ==================== 完成报告 ====================
VALID_COUNT=$(grep -c "^socks5://" socks5_valid.txt 2>/dev/null || echo 0)
echo -e "${GREEN}[+] 扫描完成！发现 ${VALID_COUNT} 个可用代理${NC}"
echo "   详细日志 → result_detail.txt"
echo "   有效代理 → socks5_valid.txt"
log "扫描结束: $VALID_COUNT 个有效代理"

echo -e "${GREEN}[*] 全部完成！再次运行: bash <(curl -Ls $(curl -Ls https://bit.ly/scamnet-sh))${NC}"
