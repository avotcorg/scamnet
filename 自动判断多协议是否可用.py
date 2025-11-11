import os
import sys
import json
import time
import requests
import threading
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import geoip2.database
except Exception:
    print("📦 正在安装 geoip2...")
    os.system(f"{sys.executable} -m pip install geoip2 tqdm requests")
    import geoip2.database


# ========== 配置 ==========
GEO_DB_PATH = "GeoLite2-City.mmdb"
OUT_TXT = "alive_proxies.txt"
OUT_JSON = "alive_proxies.json"
TEST_URL_HTTP = "http://httpbin.org/ip"
TEST_URL_HTTPS = "https://api.ipify.org?format=json"
TIMEOUT = 4
MAX_WORKERS = 100
# =========================

_lock = threading.Lock()


def ensure_geoip_db():
    """自动下载 GeoLite2 数据库"""
    if os.path.exists(GEO_DB_PATH):
        return
    print("🌍 未检测到 GeoLite2-City.mmdb，正在下载...")
    url = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
    try:
        r = requests.get(url, stream=True, timeout=30)
        r.raise_for_status()
        with open(GEO_DB_PATH, "wb") as f:
            for chunk in r.iter_content(8192):
                if chunk:
                    f.write(chunk)
        print("✅ GeoLite2-City.mmdb 下载完成！")
    except Exception as e:
        print(f"⚠️ 下载失败：{e}，将使用在线方式查询地理信息。")


def geo_lookup(ip: str):
    """查询地理位置"""
    if os.path.exists(GEO_DB_PATH):
        try:
            with geoip2.database.Reader(GEO_DB_PATH) as reader:
                rec = reader.city(ip)
                return {
                    "country": rec.country.name or "Unknown",
                    "city": rec.city.name or "Unknown",
                }
        except Exception:
            pass
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city", timeout=5)
        if r.status_code == 200:
            j = r.json()
            return {
                "country": j.get("country") or "Unknown",
                "city": j.get("city") or "Unknown",
            }
    except Exception:
        pass
    return {"country": "Unknown", "city": "Unknown"}


def try_protocol(proxy_ipport: str, proto: str) -> bool:
    """检测代理是否可用"""
    proxy_url = f"{proto}://{proxy_ipport}"
    proxies = {"http": proxy_url, "https": proxy_url}

    url = TEST_URL_HTTPS if proto == "https" else TEST_URL_HTTP
    try:
        r = requests.get(url, proxies=proxies, timeout=TIMEOUT)
        return r.status_code == 200
    except Exception:
        return False


def detect_protocols(proxy: str):
    """检测该代理支持的协议"""
    supported = []
    for proto in ("http", "https", "socks4", "socks5"):
        if try_protocol(proxy, proto):
            supported.append(proto)
    return supported


def save_txt_line(line: str):
    with _lock:
        with open(OUT_TXT, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def save_json(results: list):
    with _lock:
        with open(OUT_JSON, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)


def worker(proxy: str, results: list):
    """检测单个代理"""
    supported = detect_protocols(proxy)
    if not supported:
        return

    if "@" in proxy:
        host = proxy.split("@")[-1].split(":")[0]
    else:
        host = proxy.split(":")[0]

    geo = geo_lookup(host)
    country, city = geo["country"], geo["city"]

    lines = [f"{proto}://{proxy}#{country} - {city}" for proto in supported]

    with _lock:
        print()
        print(f"🟢 成功: {proxy} ({country} - {city}) 支持 {', '.join(supported)}")
        for l in lines:
            print("  " + l)

    for l in lines:
        save_txt_line(l)

    entry = {
        "ip": host,
        "port": int(proxy.split(":")[-1]),
        "protocols": [f"{p}://{proxy}" for p in supported],
        "country": country,
        "city": city,
    }
    results.append(entry)
    save_json(results)


def main():
    os.system("cls" if os.name == "nt" else "clear")
    print("🌐 HTTP / HTTPS / SOCKS4 / SOCKS5 多协议代理检测器-OTC TG频道:soqunla")
    print("支持带用户名密码 + GeoIP + 实时保存 + JSON 输出\n")

    file_path = input("请输入代理列表文件路径（例如 proxies.txt）: ").strip()
    if not os.path.exists(file_path):
        print("❌ 文件不存在！")
        return

    ensure_geoip_db()
    with open(file_path, "r", encoding="utf-8") as f:
        proxies = [line.strip() for line in f if line.strip()]

    total = len(proxies)
    print(f"📦 共加载 {total} 个代理\n")

    if os.path.exists(OUT_TXT):
        os.remove(OUT_TXT)
    if os.path.exists(OUT_JSON):
        os.remove(OUT_JSON)

    results = []
    start = time.time()

    with tqdm(total=total, desc="🔍 检测中", unit="代理") as bar:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(worker, proxy, results) for proxy in proxies]
            for _ in as_completed(futures):
                bar.update(1)
                ok = len(results)
                rate = ok / total * 100 if total else 0
                bar.set_postfix_str(f"成功 {ok}/{total} ({rate:.1f}%)")

    elapsed = time.time() - start
    success = len(results)
    rate = success / total * 100 if total else 0

    print("\n📊 检测完成！")
    print(f"🟢 可用代理: {success}/{total} 成功率: {rate:.2f}% 耗时: {elapsed:.1f}s")
    print(f"✅ 结果已保存: {OUT_TXT} 与 {OUT_JSON}")


if __name__ == "__main__":
    main()
