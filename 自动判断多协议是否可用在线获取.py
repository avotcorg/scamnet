import os
import sys
import json
import time
import random
import requests
import threading
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

try:
    import geoip2.database
except ImportError:
    print("正在安装依赖...")
    os.system(f"{sys.executable} -m pip install geoip2 beautifulsoup4 tqdm requests -q")
    import geoip2.database

# ========== 配置 ==========
GEO_DB_PATH = "GeoLite2-City.mmdb"
OUT_TXT = "alive_proxies.txt"
OUT_JSON = "alive_proxies.json"
TEST_URL_HTTP = "http://httpbin.org/ip"
TEST_URL_HTTPS = "https://api.ipify.org?format=json"
TIMEOUT = 4
MAX_WORKERS = 100

# 多个免费代理源（自动轮询）
PROXY_SOURCES = [
    "https://www.proxyscan.io/download?type=http",
    "https://www.proxyscan.io/download?type=https",
    "https://www.proxyscan.io/download?type=socks4",
    "https://www.proxyscan.io/download?type=socks5",

    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5",

    "https://openproxy.space/list/http",
    "https://openproxy.space/list/socks4",
    "https://openproxy.space/list/socks5",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
]
# =========================

_lock = threading.Lock()
session = requests.Session()
session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

def ensure_geoip_db():
    if os.path.exists(GEO_DB_PATH): return
    print("正在下载 GeoLite2-City.mmdb...")
    url = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
    try:
        r = session.get(url, stream=True, timeout=30)
        r.raise_for_status()
        with open(GEO_DB_PATH, "wb") as f:
            for c in r.iter_content(8192): f.write(c)
        print("GeoIP 数据库下载完成")
    except: print("GeoIP 下载失败，将使用在线查询")

def geo_lookup(ip: str):
    if os.path.exists(GEO_DB_PATH):
        try:
            with geoip2.database.Reader(GEO_DB_PATH) as r:
                rec = r.city(ip)
                return {"country": rec.country.name or "Unknown", "city": rec.city.name or "Unknown"}
        except: pass
    try:
        j = session.get(f"http://ip-api.com/json/{ip}?fields=country,city", timeout=5).json()
        return {"country": j.get("country") or "Unknown", "city": j.get("city") or "Unknown"}
    except: pass
    return {"country": "Unknown", "city": "Unknown"}

def try_protocol(proxy: str, proto: str) -> bool:
    url = TEST_URL_HTTPS if proto in ("https", "socks5") else TEST_URL_HTTP
    try:
        r = session.get(url, proxies={ "http": f"{proto}://{proxy}", "https": f"{proto}://{proxy}" }, timeout=TIMEOUT, verify=False)
        return r.status_code == 200
    except: return False

def detect_protocols(proxy: str):
    return [p for p in ("http", "https", "socks4", "socks5") if try_protocol(proxy, p)]

def save_txt_line(line: str):
    with _lock:
        with open(OUT_TXT, "a", encoding="utf-8") as f: f.write(line + "\n")

def save_json(results: list):
    with _lock:
        with open(OUT_JSON, "w", encoding="utf-8") as f: json.dump(results, f, ensure_ascii=False, indent=2)

def worker(proxy: str, results: list):
    supported = detect_protocols(proxy)
    if not supported: return
    host = proxy.split("@")[-1].split(":")[0]
    geo = geo_lookup(host)
    country, city = geo["country"], geo["city"]
    lines = [f"{p}://{proxy}#{country} - {city}" for p in supported]
    with _lock:
        print(f"\n成功: {proxy} ({country} - {city}) → {', '.join(supported)}")
        for l in lines: print(" " + l)
    for l in lines: save_txt_line(l)
    results.append({
        "ip": host,
        "port": int(proxy.split(":")[-1]),
        "protocols": [f"{p}://{proxy}" for p in supported],
        "country": country,
        "city": city,
    })
    save_json(results)

def parse_proxy_text(text: str):
    """从纯文本中提取 IP:PORT"""
    import re
    pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}\b'
    return list(set(re.findall(pattern, text)))

def fetch_all_proxies():
    all_proxies = set()
    print("正在从多个免费代理源抓取...")
    for url in tqdm(PROXY_SOURCES, desc="抓取源", unit="源"):
        try:
            r = session.get(url, timeout=15)
            r.raise_for_status()
            content = r.text

            # 1. 纯文本格式
            ips = parse_proxy_text(content)
            all_proxies.update(ips)

            # 2. HTML 格式（openproxy.space）
            if "<" in content:
                soup = BeautifulSoup(content, 'html.parser')
                text = soup.get_text()
                ips = parse_proxy_text(text)
                all_proxies.update(ips)

            time.sleep(random.uniform(0.5, 1.5))
        except Exception as e:
            # print(f"源失效: {url} → {e}")
            continue

    print(f"共收集到 {len(all_proxies)} 个唯一代理")
    return list(all_proxies)

def main():
    os.system("cls" if os.name == "nt" else "clear")
    print("HTTP / HTTPS / SOCKS4 / SOCKS5 多协议代理检测器-OTC TG频道:@soqunla")
    print("自动多源抓取 + GeoIP + 实时保存 + JSON 输出\n")

    ensure_geoip_db()
    proxies = fetch_all_proxies()
    if not proxies:
        print("所有源均失败，程序退出。")
        return

    total = len(proxies)
    print(f"\n开始检测 {total} 个代理...\n")

    for f in (OUT_TXT, OUT_JSON):
        if os.path.exists(f): os.remove(f)

    results = []
    start = time.time()

    with tqdm(total=total, desc="检测中", unit="个") as bar:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = [pool.submit(worker, p, results) for p in proxies]
            for _ in as_completed(futures):
                bar.update(1)
                bar.set_postfix_str(f"成功 {len(results)}/{total} ({len(results)/total*100:.1f}%)")

    elapsed = time.time() - start
    rate = len(results)/total*100
    print(f"\n检测完成！可用: {len(results)}/{total} ({rate:.2f}%) 耗时: {elapsed:.1f}s")
    print(f"结果已保存 → {OUT_TXT} | {OUT_JSON}")

requests.packages.urllib3.disable_warnings()
if __name__ == "__main__":
    main()