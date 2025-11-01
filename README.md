### 单协议 
```
bash <(curl -Ls https://raw.githubusercontent.com/avotcorg/scamnet/main/main.sh)
```
### 全协议
```
bash <(curl -Ls https://raw.githubusercontent.com/avotcorg/scamnet/main/allmain.sh )
```
### 功能简介
生成弱口令字典
编译 Go 扫描器（scamnet.go）
启动守护进程（scamnet_guard.sh）
实时输出 + Telegram 推送
### 全部功能
核心功能详解
功能说明
1. 交互式配置启动时输入 IP 范围、端口、Telegram
2. 弱口令字典内置 324 条高频弱口令（admin:admin、root:root 等）
3. Go 高并发扫描并发 150，批次 250，超时 6 秒
4. 延迟放宽至 15000ms确保慢速代理也能命中
5. 国家识别自动识别 #US #CN #KR 等
6. 结果去重 + 排序最终输出 socks5_valid.txt
7. Telegram 实时推送每命中一个立即推送8. 守护进程自动重启扫描完一轮自动重启，永不停止

### 输出文件
文件,内容
socks5_valid.txt,最终去重结果（格式：socks5://user:pass@ip:port#CN）
logs/weak.txt,弱口令字典
logs/latest.log,实时日志（含 [DEBUG]、[+]）
logs/scamnet_go,编译后的二进制

### 实时监控命令
# 只看成功结果（推荐）
```
tail -f logs/latest.log | grep '^\[+]'
```

# 彩色高亮
```
tail -f logs/latest.log | grep --color=always '^\[+]'
```

# 后台静默追加
```
nohup tail -f logs/latest.log | grep '^\[+]' >> socks5_valid.txt &
```

### 停止扫描
```
pkill -f scamnet_guard.sh
```

