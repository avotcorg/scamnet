import sys
import os
sys.path.append(os.path.dirname(__file__))

from plugins import load_plugins
from concurrent.futures import ThreadPoolExecutor
import socket
import ipaddress
import threading
import time
import yaml
from tqdm import tqdm

# ==================== 加载配置 ====================
try:
    with open("config.yaml", "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}
except:
    config = {}

INPUT_RANGE = config.get("range", "157.254.32.0-157.254.52.255")
PORTS = config.get("ports", list(range(1080, 65536)))
TIMEOUT = config.get("timeout", 6.0)
MAX_WORKERS = config.get("workers", 300)

# ==================== 全局 ====================
file_lock = threading.Lock()
valid_count = 0
plugins = load_plugins()

# ==================== 核心函数 ====================
def test_proxy(ip: str, port: int):
    global valid_count
    result = {"ip": ip, "port": port, "status": "FAIL", "country": "XX", "latency": "-", "export_ip": "-", "auth": ""}

    # 1. 无认证测试
    ok, latency, export_ip = is_socks5_available(ip, port, None, None)
    if ok:
        country = get_country(export_ip) or get_country(ip)
        result.update({"status": "OK", "country": country, "latency": f"{latency}ms", "export_ip": export_ip})
    else:
        # 2. 弱密码爆破（插件）
        auth = plugins["auth_weak"].brute(ip, port)
        if auth:
            user, pwd = auth
            ok, latency, export_ip = is_socks5_available(ip, port, user, pwd)
            if ok:
                country = get_country(export_ip) or get_country(ip)
                result.update({"status": "OK (Weak)", "country": country, "latency": f"{latency}ms", "export_ip": export_ip, "auth": f"{user}:{pwd}"})

    # 3. 输出（插件）
    plugins["output_file"].save_detail(result)
    if result["status"].startswith("OK"):
        valid_count += 1
        plugins["output_file"].save_valid(result)

def get_country(ip):
    for name in ["geo_ipapi", "geo_ipinfo", "geo_countryis"]:
        if name in plugins:
            country = plugins[name].get(ip)
            if country and country != "XX":
                return country
    return "XX"

def is_socks5_available(ip, port, user, pwd):
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            sock.settimeout(TIMEOUT)
            methods = b"\x05\x02\x00\x02" if user and pwd else b"\x05\x01\x00"
            sock.sendall(methods)
            resp = sock.recv(2)
            if len(resp) != 2 or resp[0] != 5: return False, 0, None
            method = resp[1]
            if method == 0: pass
            elif method == 2 and user and pwd:
                auth = b"\x01" + bytes([len(user)]) + user.encode() + bytes([len(pwd)]) + pwd.encode()
                sock.sendall(auth)
                if sock.recv(2)[1] != 0: return False, 0, None
            else:
                return False, 0, None

            target = socket.inet_aton(socket.gethostbyname("ifconfig.me")) + b"\x00\x50"
            sock.sendall(b"\x05\x01\x00\x01" + target)
            if sock.recv(10)[1] != 0: return False, 0, None

            sock.sendall(f"GET / HTTP/1.1\r\nHost: ifconfig.me\r\n\r\n".encode())
            resp = b""
            start = time.time()
            while time.time() - start < TIMEOUT:
                try:
                    chunk = sock.recv(1024)
                    if not chunk: break
                    resp += chunk
                    if b"\r\n\r\n" in resp: break
                except: break
            export_ip = resp.split(b"\r\n\r\n", 1)[1].decode(errors='ignore').split()[0] if b"\r\n\r\n" in resp else "Unknown"
            return True, round((time.time() - start) * 1000), export_ip
    except:
        return False, 0, None

# ==================== 主函数 ====================
def main():
    print("[OTC] OTC-socks5 插件版扫描器启动")
    os.makedirs("logs", exist_ok=True)

    ips = list(parse_ip_range(INPUT_RANGE))
    ports = PORTS
    total = len(ips) * len(ports)
    print(f"[*] 扫描范围: {INPUT_RANGE} | IP: {len(ips):,} | 端口: {len(ports)} | 总任务: {total:,}")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        pbar = tqdm(total=total, desc="扫描", unit="port", ncols=100)
        for ip in ips:
            for port in ports:
                executor.submit(test_proxy, ip, port)
                pbar.update(1)
        pbar.close()

    print(f"\n[+] 扫描完成！发现 {valid_count} 个可用 SOCKS5")
    print("   详细 → result_detail.txt")
    print("   有效 → socks5_valid.txt")

def parse_ip_range(s):
    if '/' in s:
        return [str(ip) for ip in ipaddress.ip_network(s, strict=False).hosts()]
    else:
        a, b = s.split('-')
        start = int(ipaddress.IPv4Address(a.strip()))
        end = int(ipaddress.IPv4Address(b.strip()))
        return [str(ipaddress.IPv4Address(i)) for i in range(start, end + 1)]

if __name__ == "__main__":
    main()
