import os
import time
import hmac
import hashlib
import base64
import json
import sqlite3
import secrets
import html
import socket
import ipaddress
import urllib.parse
import re
import asyncio
from datetime import datetime, timezone
from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import Response, HTMLResponse, RedirectResponse, JSONResponse
from fastapi.middleware.gzip import GZipMiddleware

# ----------------- پیکربندی امنیتی و کلیدها -----------------
BRAND_DEFAULT = os.getenv("BRAND_NAME", "VIP Cloud")
PUBLIC_URL = os.getenv("RAILWAY_PUBLIC_DOMAIN", "localhost:8000").rstrip("/")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "SuperSecretLongPassword_987654321_ChangeMe!")
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()

# اشتقاق کلید امن با سالت قوی
SECRET_KEY = hashlib.sha256(f"{ADMIN_PASSWORD}_secure_datacenter_salt_2026".encode()).digest()
WEBHOOK_SECRET = hashlib.sha256(f"{BOT_TOKEN}_tg_webhook_v4".encode()).hexdigest()[:32] if BOT_TOKEN else ""

DATA_DIR = "/data" if os.path.exists("/data") else "."
DB_FILE = os.path.join(DATA_DIR, "datacenter_subs.db")
COOKIE_NAME = "datacenter_admin_session"
SESSION_TTL = 86400 * 7

CACHE_TTL = int(os.getenv("CACHE_TTL", "120"))
MAX_CACHE_SIZE = 250
MAX_REQUEST_BODY = 1048576       # 1MB
MAX_UPSTREAM_BYTES = 4194304     # 4MB

# ساختارهای داده درون حافظه
sub_cache = {}
login_attempts = {}
sub_rate_limit_tracker = {}
http_client: httpx.AsyncClient = None

# رنج‌های ممنوعه شبکه (SSRF Protection)
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # AWS/Cloud Metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128")
]

# ----------------- دیتابیس با تراکنش‌های امن -----------------
def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=12.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                upstream_urls TEXT NOT NULL,
                fake_total_gb REAL DEFAULT 0,
                fake_used_gb REAL DEFAULT 0,
                custom_notice TEXT DEFAULT '',
                admin_note TEXT DEFAULT '',
                replace_rules TEXT DEFAULT '',
                custom_expire TEXT DEFAULT '',
                tags TEXT DEFAULT '',
                sub_hits INTEGER DEFAULT 0,
                last_sub_fetch TEXT DEFAULT '',
                last_client_ip TEXT DEFAULT '',
                is_blocked INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
        """)
        
        migrations = [
            ("profiles", "upstream_urls", "TEXT DEFAULT ''"),
            ("profiles", "fake_used_gb", "REAL DEFAULT 0"),
            ("profiles", "replace_rules", "TEXT DEFAULT ''"),
            ("profiles", "custom_expire", "TEXT DEFAULT ''"),
            ("profiles", "tags", "TEXT DEFAULT ''"),
            ("profiles", "last_client_ip", "TEXT DEFAULT ''")
        ]
        for table, col, col_type in migrations:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")
            except sqlite3.OperationalError:
                pass
        conn.commit()

init_db()

# ----------------- چرخه حیات و مدیریت شبکه -----------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client
    # استفاده از اعتبارسنجی الزامی SSL (verify=True)
    limits = httpx.Limits(max_keepalive_connections=20, max_connections=60)
    http_client = httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=True, limits=limits)
    
    if BOT_TOKEN and not PUBLIC_URL.startswith("localhost"):
        clean_domain = PUBLIC_URL.replace("https://", "").replace("http://", "").strip("/")
        webhook_url = f"https://{clean_domain}/webhook"
        try:
            await http_client.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/setWebhook",
                json={"url": webhook_url, "secret_token": WEBHOOK_SECRET}
            )
        except Exception:
            pass
    yield
    await http_client.aclose()

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(GZipMiddleware, minimum_size=400)

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    # هدرهای حفاظتی و CSP مدرن
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://api.qrserver.com; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self';"
    )
    return response

# ----------------- توابع احراز هویت و کنترل توکن -----------------
def create_session_token() -> str:
    ts = str(int(time.time()))
    sig = hmac.new(SECRET_KEY, f"auth_session:{ts}".encode(), hashlib.sha256).hexdigest()
    return f"{ts}.{sig}"

def verify_session_token(token: str) -> bool:
    if not token or "." not in token:
        return False
    parts = token.split(".", 1)
    if not parts[0].isdigit():
        return False
    ts_val = int(parts[0])
    if abs(time.time() - ts_val) > SESSION_TTL:
        return False
    expected_sig = hmac.new(SECRET_KEY, f"auth_session:{parts[0]}".encode(), hashlib.sha256).hexdigest()
    return secrets.compare_digest(parts[1], expected_sig)

def is_admin(request: Request) -> bool:
    cookie_val = request.cookies.get(COOKIE_NAME, "")
    return verify_session_token(cookie_val)

def get_csrf_token(request: Request) -> str:
    session_val = request.cookies.get(COOKIE_NAME, "")
    if not verify_session_token(session_val):
        return ""
    return hmac.new(SECRET_KEY, f"csrf_token_sig:{session_val}".encode(), hashlib.sha256).hexdigest()[:32]

def verify_csrf(request: Request, token_input: str) -> bool:
    expected = get_csrf_token(request)
    if not expected or not token_input:
        return False
    return secrets.compare_digest(token_input.strip(), expected)

def get_client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

def check_login_rate_limit(ip: str) -> bool:
    now = time.time()
    # انقضای رکوردهای قدیمی‌تر از ۱۰ دقیقه
    for stored_ip in list(login_attempts.keys()):
        valid_records = [t for t in login_attempts[stored_ip] if now - t < 600]
        if valid_records:
            login_attempts[stored_ip] = valid_records
        else:
            login_attempts.pop(stored_ip, None)

    attempts = login_attempts.get(ip, [])
    return len(attempts) < 5

def record_failed_login(ip: str):
    login_attempts.setdefault(ip, []).append(time.time())

def check_sub_rate_limit(token: str, ip: str) -> bool:
    key = f"{token}:{ip}"
    now = time.time()
    # پاکسازی دوره‌ای متناوب
    if len(sub_rate_limit_tracker) > 1000:
        for k in list(sub_rate_limit_tracker.keys()):
            rem = [t for t in sub_rate_limit_tracker[k] if now - t < 10]
            if rem:
                sub_rate_limit_tracker[k] = rem
            else:
                sub_rate_limit_tracker.pop(k, None)

    times = [t for t in sub_rate_limit_tracker.get(key, []) if now - t < 10]
    if len(times) >= 8:
        return False
    times.append(now)
    sub_rate_limit_tracker[key] = times
    return True

def is_safe_network_url(url: str) -> bool:
    """جلوگیری دقیق از SSRF و DNS Rebinding با بررسی محدوده آی‌پی"""
    try:
        parsed = urllib.parse.urlparse(url.strip())
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        host = parsed.hostname.lower()
        if host in ("localhost", "0.0.0.0", "127.0.0.1") or host.endswith(".local") or host.endswith(".internal"):
            return False

        try:
            ip_obj = ipaddress.ip_address(host)
            for net in BLOCKED_IP_NETWORKS:
                if ip_obj in net:
                    return False
        except ValueError:
            # رزولوشن DNS و اعتبارسنجی تمام پاسخ‌ها
            addr_info = socket.getaddrinfo(host, None)
            for item in addr_info:
                resolved_ip = ipaddress.ip_address(item[4][0])
                for net in BLOCKED_IP_NETWORKS:
                    if resolved_ip in net:
                        return False
        return True
    except Exception:
        return False

async def read_bounded_body(request: Request) -> bytes:
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_REQUEST_BODY:
        raise HTTPException(status_code=413, detail="Payload Too Large")
    body = await request.body()
    if len(body) > MAX_REQUEST_BODY:
        raise HTTPException(status_code=413, detail="Payload Too Large")
    return body

# ----------------- پردازش و پاکسازی کانفیگ‌ها -----------------
PERSIAN_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")

def to_persian_num(s: str) -> str:
    return str(s).translate(PERSIAN_DIGITS)

def format_bytes(size_bytes: int) -> str:
    if size_bytes >= 1024 ** 3:
        return f"{size_bytes / (1024 ** 3):.2f} GB"
    return f"{size_bytes / (1024 ** 2):.2f} MB"

def apply_safe_text_rules(original_name: str, rules_str: str) -> str:
    """اعمال امن قوانین جایگزینی با جلوگیری از ReDoS و خطاهای الگو"""
    if not rules_str or not rules_str.strip():
        return original_name
    
    result = original_name
    for line in rules_str.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        
        target = ""
        if "->" in line:
            src, target = line.split("->", 1)
        elif "|" in line:
            src, target = line.split("|", 1)
        else:
            src = line
            
        src = src.strip()
        target = target.strip()
        
        if src.startswith("regex:"):
            pattern = src[6:].strip()
            if len(pattern) <= 60:  # محدودیت طول رجکس برای حفظ عملکرد
                try:
                    result = re.sub(pattern, target, result)
                except Exception:
                    pass
        else:
            if src:
                result = result.replace(src, target)
                
    return result.strip() or "Server"

def parse_config_entry(line: str, rules: str = "") -> tuple[dict, str]:
    line = line.strip()
    if not line:
        return None, ""
    proto = line.split("://")[0].lower() if "://" in line else "vpn"

    if line.startswith(("vless://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://", "wireguard://")):
        parts = line.split("#", 1)
        base = parts[0]
        orig_remark = urllib.parse.unquote(parts[1]) if len(parts) > 1 else "Server"
        new_name = apply_safe_text_rules(orig_remark, rules)
        safe_link = f"{base}#{urllib.parse.quote(new_name)}"
        return {"proto": proto.upper(), "name": html.escape(new_name), "link": safe_link, "raw_name": new_name}, safe_link

    elif line.startswith("vmess://"):
        try:
            b64_part = line[8:].strip()
            pad = len(b64_part) % 4
            if pad:
                b64_part += "=" * (4 - pad)
            decoded_json = json.loads(base64.b64decode(b64_part).decode("utf-8", errors="ignore"))
            orig_remark = str(decoded_json.get("ps", "Server"))
            new_name = apply_safe_text_rules(orig_remark, rules)
            decoded_json["ps"] = new_name
            re_encoded = base64.b64encode(json.dumps(decoded_json).encode("utf-8")).decode("utf-8")
            safe_link = f"vmess://{re_encoded}"
            return {"proto": "VMESS", "name": html.escape(new_name), "link": safe_link, "raw_name": new_name}, safe_link
        except Exception:
            return {"proto": "VMESS", "name": "VMESS", "link": line, "raw_name": "VMESS"}, line

    return {"proto": proto.upper(), "name": "Node", "link": line, "raw_name": "Node"}, line

# ----------------- تجمیع و دریافت چندگانه ساب‌لینک‌ها -----------------
async def fetch_upstream_safely(url: str):
    if not is_safe_network_url(url):
        return None
    headers = {"User-Agent": "v2rayNG/1.8.12"}
    current_url = url
    try:
        # مدیریت دستی و ایمن ریدایرکت‌ها (حداکثر ۲ مرحله)
        for _ in range(3):
            res = await http_client.get(current_url, headers=headers, timeout=6.0)
            if res.status_code in (301, 302, 307, 308):
                loc = res.headers.get("location", "")
                next_url = urllib.parse.urljoin(current_url, loc)
                if not is_safe_network_url(next_url):
                    return None
                current_url = next_url
                continue
            break

        if res.status_code == 200 and len(res.content) <= MAX_UPSTREAM_BYTES:
            return {
                "text": res.text.strip(),
                "userinfo": res.headers.get("subscription-userinfo", "")
            }
    except Exception:
        pass
    return None

async def get_cached_or_fetch_sub(profile: dict):
    token = profile["token"]
    now = time.time()
    
    cached = sub_cache.get(token)
    if cached and (now - cached["timestamp"] < CACHE_TTL):
        return cached

    urls = [u.strip() for u in (profile["upstream_urls"] or "").splitlines() if u.strip()]
    tasks = [fetch_upstream_safely(u) for u in urls if is_safe_network_url(u)]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_lines = []
    total_u = total_d = total_quota = min_expire = 0

    for r in results:
        if isinstance(r, dict) and r:
            raw = r["text"]
            if any(raw.startswith(p) for p in ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://")):
                decoded = raw
            else:
                try:
                    pad = len(raw) % 4
                    if pad:
                        raw += "=" * (4 - pad)
                    decoded = base64.b64decode(raw).decode("utf-8", errors="ignore")
                except Exception:
                    decoded = raw
            all_lines.extend([l.strip() for l in decoded.splitlines() if l.strip()])

            # پردازش ترافیک
            if r.get("userinfo"):
                for seg in r["userinfo"].split(";"):
                    if "=" in seg:
                        k, v = seg.strip().split("=", 1)
                        try:
                            val = int(float(v.strip()))
                            k_low = k.strip().lower()
                            if k_low == "upload": total_u += val
                            elif k_low == "download": total_d += val
                            elif k_low == "total": total_quota += val
                            elif k_low == "expire" and val > 0:
                                min_expire = val if min_expire == 0 else min(min_expire, val)
                        except ValueError:
                            pass

    rules = profile.get("replace_rules", "")
    configs = []
    raw_lines = []
    seen = set()

    for line in all_lines:
        conf, out_line = parse_config_entry(line, rules)
        if conf and out_line:
            # حذف موارد تکراری بر پایه آدرس بدون کامنت
            clean_id = out_line.split("#")[0] if "#" in out_line else out_line
            if clean_id not in seen:
                seen.add(clean_id)
                configs.append(conf)
                raw_lines.append(out_line)

    encoded_sub = base64.b64encode("\n".join(raw_lines).encode("utf-8")).decode("utf-8")
    data = {
        "configs": configs,
        "configs_json": json.dumps([c["link"] for c in configs]),
        "encoded_sub": encoded_sub,
        "raw_lines": raw_lines,
        "upload": total_u,
        "download": total_d,
        "total": total_quota,
        "expire": min_expire,
        "timestamp": now
    }

    if len(sub_cache) >= MAX_CACHE_SIZE:
        oldest_key = min(sub_cache.keys(), key=lambda k: sub_cache[k]["timestamp"])
        sub_cache.pop(oldest_key, None)

    sub_cache[token] = data
    return data

# ----------------- رابط‌های کاربری (UI) با تمیزسازی کامل -----------------
COMMON_CSS = """
:root {
    --bg-main: #f8fafc;
    --surface: #ffffff;
    --text-head: #0f172a;
    --text-body: #475569;
    --border: #e2e8f0;
}
html.dark {
    --bg-main: #09090b;
    --surface: #121215;
    --text-head: #f8fafc;
    --text-body: #94a3b8;
    --border: #27272a;
}
body {
    font-family: Vazirmatn FD, system-ui, sans-serif;
    background-color: var(--bg-main);
    color: var(--text-head);
}
.surface-card {
    background: var(--surface);
    border: 1px solid var(--border);
}
.btn-touch {
    min-height: 42px;
    transition: all 0.15s ease-out;
}
.btn-touch:active {
    transform: scale(0.97);
}
"""

def render_login_view(err_msg: str = "") -> str:
    err_html = f'<div class="p-3 mb-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-500 text-xs font-bold text-center">{html.escape(err_msg)}</div>' if err_msg else ""
    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ورود ایمن | کنترل پنل</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/misc/Farsi-Digits/Vazirmatn-FD-font-face.css">
    <style>{COMMON_CSS}</style>
</head>
<body class="min-h-screen flex items-center justify-center p-4">
    <main class="surface-card p-8 rounded-3xl max-w-sm w-full shadow-2xl">
        <h1 class="text-lg font-black text-center mb-1">ورود به مدیریت سیستم</h1>
        <p class="text-xs text-slate-400 text-center mb-5">دیتاسنتر سابسکریپشن و پروکسی</p>
        {err_html}
        <form action="/admin/login" method="post" class="space-y-4">
            <div>
                <label class="block text-xs text-slate-400 mb-1.5 font-bold">رمز عبور ادمین</label>
                <input type="password" name="password" required autofocus class="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500 font-mono text-left">
            </div>
            <button type="submit" class="btn-touch w-full bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl text-xs shadow-md">ورود به پنل</button>
        </form>
    </main>
</body>
</html>"""

def render_dashboard_view(ctx: dict) -> str:
    p_name = html.escape(ctx["name"])
    notice = html.escape(ctx["custom_notice"]) if ctx["custom_notice"] else "لینک اشتراک را در نرم‌افزار خود به‌روزرسانی کنید."

    conf_items = ""
    for idx, c in enumerate(ctx["configs"]):
        conf_items += f"""
        <div class="conf-card surface-card p-3 rounded-2xl flex items-center justify-between gap-3" data-name="{c['name'].lower()} {c['proto'].lower()}">
            <div class="flex items-center gap-2.5 min-w-0">
                <span class="px-2 py-0.5 rounded-md text-[10px] font-black uppercase bg-blue-500/15 text-blue-400 border border-blue-500/20 shrink-0">{c['proto']}</span>
                <span class="text-xs font-semibold truncate" dir="ltr">{c['name']}</span>
            </div>
            <div class="flex items-center gap-1.5 shrink-0">
                <button type="button" class="btn-copy-conf btn-touch p-2 rounded-xl bg-zinc-800 hover:bg-blue-600 hover:text-white transition-colors" data-idx="{idx}" title="کپی">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><rect width="14" height="14" x="8" y="8" rx="2" stroke-width="2"></rect><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" stroke-width="2"></path></svg>
                </button>
                <button type="button" class="btn-qr-conf btn-touch p-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 transition-colors" data-link="{c['link']}" data-title="{c['name']}" title="QR">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" stroke-width="2"></rect><rect x="14" y="3" width="7" height="7" stroke-width="2"></rect><rect x="14" y="14" width="7" height="7" stroke-width="2"></rect><rect x="3" y="14" width="7" height="7" stroke-width="2"></rect></svg>
                </button>
            </div>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>داشبورد اشتراک | {p_name}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/misc/Farsi-Digits/Vazirmatn-FD-font-face.css">
    <style>{COMMON_CSS}</style>
</head>
<body class="min-h-screen p-4 sm:p-6 max-w-4xl mx-auto space-y-6">
    <header class="surface-card p-6 rounded-3xl flex items-center justify-between">
        <div>
            <h1 class="text-xl font-black">{p_name}</h1>
            <p class="text-xs text-slate-400 mt-0.5">تعداد کل کانفیگ‌ها: <span class="text-blue-500 font-bold">{len(ctx['configs'])}</span></p>
        </div>
        <button type="button" id="btnThemeToggle" class="btn-touch p-2.5 rounded-xl surface-card text-xs font-bold">🌓 تغییر تم</button>
    </header>

    <div class="p-3.5 rounded-2xl bg-blue-500/10 border border-blue-500/20 text-xs text-blue-400">
        📢 {notice}
    </div>

    <!-- کارت ترافیک و درصد متناسب با حجم فیک -->
    <section class="surface-card p-6 rounded-3xl grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
        <div class="flex flex-col items-center justify-center">
            <div class="relative w-36 h-36">
                <svg class="transform -rotate-90 w-full h-full">
                    <circle cx="50%" cy="50%" r="44%" stroke="currentColor" stroke-width="10" fill="none" class="text-zinc-800"></circle>
                    <circle cx="50%" cy="50%" r="44%" stroke="currentColor" stroke-width="10" fill="none"
                        stroke-dasharray="415" stroke-dashoffset="{ctx['dashoffset']}"
                        class="text-blue-500 transition-all duration-1000 ease-out" stroke-linecap="round"></circle>
                </svg>
                <div class="absolute inset-0 flex flex-col items-center justify-center">
                    <span class="text-2xl font-black">{ctx['percent']}%</span>
                    <span class="text-[10px] text-slate-400">مصرف شده</span>
                </div>
            </div>
        </div>
        <div class="space-y-2.5 md:col-span-2 text-xs">
            <div class="flex justify-between p-2.5 rounded-xl bg-zinc-900/50 border border-zinc-800">
                <span class="text-slate-400">حجم کل اشتراک:</span>
                <span class="font-bold text-white font-mono" dir="ltr">{ctx['total_quota']}</span>
            </div>
            <div class="flex justify-between p-2.5 rounded-xl bg-zinc-900/50 border border-zinc-800">
                <span class="text-slate-400">حجم مصرفی:</span>
                <span class="font-bold text-amber-400 font-mono" dir="ltr">{ctx['used_traffic']}</span>
            </div>
            <div class="flex justify-between p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20">
                <span class="text-emerald-500 font-bold">حجم باقی‌مانده:</span>
                <span class="font-bold text-emerald-400 font-mono" dir="ltr">{ctx['remaining_traffic']}</span>
            </div>
            <div class="flex justify-between p-2.5 rounded-xl bg-zinc-900/50 border border-zinc-800">
                <span class="text-slate-400">اعتبار زمانی:</span>
                <span class="font-bold text-blue-400">{ctx['expire_date']} ({ctx['days_left']} روز)</span>
            </div>
        </div>
    </section>

    <!-- ابزار اتصال ساب -->
    <section class="surface-card p-5 rounded-3xl space-y-4">
        <div class="flex flex-wrap items-center justify-between gap-3">
            <div>
                <h3 class="text-sm font-bold">لینک هوشمند اتصال</h3>
                <p class="text-[11px] text-slate-400 mt-0.5">قابل استفاده در V2Ray، Hiddify، Sing-box و Clash</p>
            </div>
            <div class="flex items-center gap-2">
                <button type="button" id="btnCopySub" class="btn-touch px-4 bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold rounded-xl shadow-md">کپی لینک ساب</button>
                <button type="button" id="btnSubQr" class="btn-touch px-3 bg-zinc-800 hover:bg-zinc-700 text-xs font-bold rounded-xl">QR</button>
                <a href="{ctx['sub_url']}?raw=true" download="configs.txt" class="btn-touch px-3 bg-zinc-800 hover:bg-zinc-700 text-xs font-bold rounded-xl inline-flex items-center">دانلود TXT</a>
            </div>
        </div>
        <div class="p-3 bg-zinc-950 rounded-xl text-xs font-mono text-slate-300 truncate" dir="ltr">{ctx['sub_url']}</div>
    </section>

    <!-- لیست سرورها -->
    <section class="surface-card p-6 rounded-3xl space-y-3">
        <div class="flex items-center justify-between gap-3">
            <h3 class="text-sm font-bold">سرورهای متصل</h3>
            <input type="text" id="confSearchInput" placeholder="جستجو در سرورها..." class="bg-zinc-950 border border-zinc-800 rounded-xl px-3 py-1.5 text-xs w-48">
        </div>
        <div class="max-h-80 overflow-y-auto space-y-2 pr-1">
            {conf_items}
        </div>
    </section>

    <!-- مودال QR بدون اینلاین اسکریپت آسیب‌پذیر -->
    <div id="qrModal" class="fixed inset-0 bg-black/80 hidden items-center justify-center p-4 z-50">
        <div class="surface-card p-6 rounded-3xl max-w-xs w-full text-center" id="qrModalContainer">
            <h4 id="qrModalTitle" class="text-xs font-bold mb-4">اسکن کد QR</h4>
            <img id="qrModalImg" src="" class="w-52 h-52 mx-auto rounded-xl bg-white p-2 mb-4">
            <button type="button" id="btnCloseQr" class="btn-touch w-full bg-zinc-800 text-xs font-bold rounded-xl">بستن</button>
        </div>
    </div>
    <div id="toast" class="fixed bottom-6 left-1/2 -translate-x-1/2 hidden px-4 py-2.5 rounded-2xl bg-white text-zinc-950 text-xs font-bold shadow-2xl z-50"></div>

    <script>
        const subUrlValue = {json.dumps(ctx['sub_url'])};
        const configsArray = {ctx['configs_json']};

        function showToast(msg) {{
            const t = document.getElementById('toast');
            t.textContent = msg;
            t.classList.remove('hidden');
            setTimeout(() => t.classList.add('hidden'), 2000);
        }}

        function openModal(url, title) {{
            document.getElementById('qrModalTitle').textContent = title;
            document.getElementById('qrModalImg').src = 'https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=' + encodeURIComponent(url);
            document.getElementById('qrModal').classList.remove('hidden');
            document.getElementById('qrModal').classList.add('flex');
        }}

        document.getElementById('btnThemeToggle').addEventListener('click', () => {{
            document.documentElement.classList.toggle('dark');
        }});
        document.getElementById('btnCopySub').addEventListener('click', () => {{
            navigator.clipboard.writeText(subUrlValue);
            showToast('لینک اشتراک کپی شد');
        }});
        document.getElementById('btnSubQr').addEventListener('click', () => {{
            openModal(subUrlValue, 'کد QR لینک اشتراک');
        }});
        document.getElementById('btnCloseQr').addEventListener('click', () => {{
            document.getElementById('qrModal').classList.add('hidden');
            document.getElementById('qrModal').classList.remove('flex');
        }});
        document.getElementById('qrModal').addEventListener('click', (e) => {{
            if (e.target.id === 'qrModal') {{
                document.getElementById('qrModal').classList.add('hidden');
                document.getElementById('qrModal').classList.remove('flex');
            }}
        }});
        document.querySelectorAll('.btn-copy-conf').forEach(btn => {{
            btn.addEventListener('click', () => {{
                const idx = parseInt(btn.getAttribute('data-idx'));
                navigator.clipboard.writeText(configsArray[idx]);
                showToast('کانفیگ کپی شد');
            }});
        }});
        document.querySelectorAll('.btn-qr-conf').forEach(btn => {{
            btn.addEventListener('click', () => {{
                openModal(btn.getAttribute('data-link'), btn.getAttribute('data-title'));
            }});
        }});
        document.getElementById('confSearchInput').addEventListener('input', (e) => {{
            const q = e.target.value.toLowerCase();
            document.querySelectorAll('.conf-card').forEach(card => {{
                card.style.display = card.getAttribute('data-name').includes(q) ? '' : 'none';
            }});
        }});
    </script>
</body>
</html>"""

def render_admin_dashboard(profiles: list, domain: str, csrf_token: str) -> str:
    rows = ""
    for p in profiles:
        tok = html.escape(p["token"])
        safe_name = html.escape(p["name"])
        hits = p["sub_hits"] or 0
        last_f = p["last_sub_fetch"] or "بدون اتصال"
        status_txt = '<span class="text-rose-400 font-bold">مسدود</span>' if p["is_blocked"] else '<span class="text-emerald-400 font-bold">فعال</span>'
        btn_toggle_txt = "فعال‌سازی" if p["is_blocked"] else "بلاک"

        p_data = {
            "token": p["token"],
            "name": p["name"],
            "upstream_urls": p["upstream_urls"] or "",
            "fake_total_gb": p["fake_total_gb"] or 0,
            "fake_used_gb": p["fake_used_gb"] or 0,
            "replace_rules": p["replace_rules"] or "",
            "custom_notice": p["custom_notice"] or ""
        }
        encoded_data = html.escape(json.dumps(p_data))

        rows += f"""
        <tr class="hover:bg-zinc-800/40 border-b border-zinc-800/50">
            <td class="p-3.5 font-bold">
                <div>{safe_name}</div>
                <div class="text-[10px] text-slate-500 font-mono mt-0.5" dir="ltr">{tok}</div>
            </td>
            <td class="p-3.5 text-center text-xs font-mono">{p['fake_total_gb']} GB</td>
            <td class="p-3.5 text-center text-xs">{hits} ریکوئست<br><span class="text-[10px] text-slate-500">{last_f}</span></td>
            <td class="p-3.5 text-center text-xs">{status_txt}</td>
            <td class="p-3.5 text-center">
                <div class="flex items-center justify-center gap-1.5 text-xs">
                    <a href="/d/{tok}" target="_blank" class="px-2 py-1 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-blue-400">داشبورد</a>
                    <button type="button" class="btn-edit px-2 py-1 rounded-lg bg-blue-500/10 text-blue-400 hover:bg-blue-500/20" data-profile="{encoded_data}">ویرایش</button>
                    
                    <form action="/admin/profiles/{tok}/toggle" method="post" class="m-0">
                        <input type="hidden" name="csrf_token" value="{csrf_token}">
                        <button type="submit" class="px-2 py-1 rounded-lg bg-zinc-800 text-slate-300">{btn_toggle_txt}</button>
                    </form>
                    
                    <form action="/admin/profiles/{tok}/rotate" method="post" class="m-0" onsubmit="return confirm('توکن این ساب عوض شود؟');">
                        <input type="hidden" name="csrf_token" value="{csrf_token}">
                        <button type="submit" class="px-2 py-1 rounded-lg bg-zinc-800 text-amber-400 hover:bg-amber-600 hover:text-white" title="تغییر توکن">🔄</button>
                    </form>
                    
                    <form action="/admin/profiles/{tok}/delete" method="post" class="m-0" onsubmit="return confirm('حذف دائم؟');">
                        <input type="hidden" name="csrf_token" value="{csrf_token}">
                        <button type="submit" class="px-2 py-1 rounded-lg bg-rose-500/10 text-rose-400 hover:bg-rose-500/20">حذف</button>
                    </form>
                </div>
            </td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>مدیریت مرکزی اشتراک‌ها</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/misc/Farsi-Digits/Vazirmatn-FD-font-face.css">
    <style>{COMMON_CSS}</style>
</head>
<body class="min-h-screen p-4 sm:p-6 max-w-6xl mx-auto space-y-6">
    <header class="surface-card p-6 rounded-3xl flex items-center justify-between">
        <div>
            <h1 class="text-xl font-black">مدیریت دیتاسنتر اشتراک‌ها</h1>
            <p class="text-xs text-slate-400 mt-0.5">دامنه: <span class="font-mono text-blue-500" dir="ltr">{domain}</span></p>
        </div>
        <div class="flex items-center gap-2">
            <a href="/admin/backup" class="btn-touch px-3.5 bg-zinc-800 hover:bg-zinc-700 text-xs font-bold rounded-xl inline-flex items-center">دانلود بکاپ</a>
            <a href="/admin/logout" class="btn-touch px-3.5 bg-rose-500/10 text-rose-400 text-xs font-bold rounded-xl inline-flex items-center">خروج</a>
        </div>
    </header>

    <!-- ثبت اشتراک جدید -->
    <section class="surface-card p-6 rounded-3xl space-y-4">
        <h2 class="text-sm font-bold text-blue-400">افزودن اشتراک جدید (تجمیع چند لینک)</h2>
        <form action="/admin/profiles/add" method="post" class="grid grid-cols-1 md:grid-cols-3 gap-3.5">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <div>
                <label class="block text-xs text-slate-400 mb-1">نام اشتراک *</label>
                <input type="text" name="name" required placeholder="مثلاً: VIP 1" class="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-3 py-2 text-xs">
            </div>
            <div>
                <label class="block text-xs text-slate-400 mb-1">حجم کل فیک (GB) - 0 یعنی واقعی</label>
                <input type="number" step="0.1" name="fake_total_gb" value="0" class="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-3 py-2 text-xs font-mono" dir="ltr">
            </div>
            <div>
                <label class="block text-xs text-slate-400 mb-1">حجم مصرفی فیک (GB)</label>
                <input type="number" step="0.1" name="fake_used_gb" value="0" class="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-3 py-2 text-xs font-mono" dir="ltr">
            </div>
            <div class="md:col-span-3">
                <label class="block text-xs text-slate-400 mb-1">لینک‌های ساب اصلی (هر لینک در یک خط برای تجمیع چند سرور) *</label>
                <textarea name="upstream_urls" rows="3" required placeholder="https://panel1.com/sub/...\nhttps://panel2.com/sub/..." class="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-3 py-2 text-xs font-mono" dir="ltr"></textarea>
            </div>
            <div class="md:col-span-2">
                <label class="block text-xs text-slate-400 mb-1">قوانین تعویض یا حذف متن کانفیگ‌ها (هر خط: متن_قدیم -> متن_جدید)</label>
                <textarea name="replace_rules" rows="2" placeholder="همراه اول -> VIP 1\nاسپانسر -> " class="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-3 py-2 text-xs"></textarea>
            </div>
            <div class="flex items-end">
                <button type="submit" class="btn-touch w-full bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl text-xs shadow-md">ثبت ساب جدید</button>
            </div>
        </form>
    </section>

    <!-- جدول نمایش ساب‌ها -->
    <section class="surface-card rounded-3xl overflow-hidden p-4">
        <h2 class="text-sm font-bold mb-3">اشتراک‌های ثبت‌شده ({len(profiles)})</h2>
        <div class="overflow-x-auto">
            <table class="w-full text-right text-xs">
                <thead class="bg-zinc-950 text-slate-400 border-b border-zinc-800">
                    <tr>
                        <th class="p-3">نام / توکن</th>
                        <th class="p-3 text-center">حجم فیک</th>
                        <th class="p-3 text-center">آمار فراخوانی</th>
                        <th class="p-3 text-center">وضعیت</th>
                        <th class="p-3 text-center">عملیات</th>
                    </tr>
                </thead>
                <tbody>
                    {rows if rows else '<tr><td colspan="5" class="p-6 text-center text-slate-500">موردی یافت نشد.</td></tr>'}
                </tbody>
            </table>
        </div>
    </section>

    <!-- مودال ویرایش امن -->
    <div id="adminEditModal" class="fixed inset-0 bg-black/80 hidden items-center justify-center p-4 z-50">
        <div class="surface-card p-6 rounded-3xl max-w-lg w-full space-y-3">
            <h3 class="text-sm font-bold text-blue-400">ویرایش اطلاعات ساب</h3>
            <form id="adminEditForm" method="post" class="space-y-3">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                <div>
                    <label class="block text-xs text-slate-400 mb-1">نام یا برند</label>
                    <input type="text" id="editName" name="name" required class="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-3 py-2 text-xs">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">لینک‌های ساب مبدا (خط‌به‌خط)</label>
                    <textarea id="editUpstream" name="upstream_urls" rows="3" required class="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-3 py-2 text-xs font-mono" dir="ltr"></textarea>
                </div>
                <div class="grid grid-cols-2 gap-3">
                    <div>
                        <label class="block text-xs text-slate-400 mb-1">حجم کل فیک (GB)</label>
                        <input type="number" step="0.1" id="editFakeTotal" name="fake_total_gb" class="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-3 py-2 text-xs font-mono" dir="ltr">
                    </div>
                    <div>
                        <label class="block text-xs text-slate-400 mb-1">حجم مصرفی فیک (GB)</label>
                        <input type="number" step="0.1" id="editFakeUsed" name="fake_used_gb" class="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-3 py-2 text-xs font-mono" dir="ltr">
                    </div>
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">قوانین تعویض یا حذف متن</label>
                    <textarea id="editRules" name="replace_rules" rows="2" class="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-3 py-2 text-xs"></textarea>
                </div>
                <div class="flex gap-2 pt-2">
                    <button type="submit" class="btn-touch flex-1 bg-blue-600 text-white font-bold rounded-xl text-xs">ذخیره</button>
                    <button type="button" id="btnCancelEdit" class="btn-touch px-4 bg-zinc-800 text-slate-300 rounded-xl text-xs">انصراف</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        document.querySelectorAll('.btn-edit').forEach(btn => {{
            btn.addEventListener('click', () => {{
                const p = JSON.parse(btn.getAttribute('data-profile'));
                document.getElementById('adminEditForm').action = '/admin/profiles/' + encodeURIComponent(p.token) + '/edit';
                document.getElementById('editName').value = p.name;
                document.getElementById('editUpstream').value = p.upstream_urls;
                document.getElementById('editFakeTotal').value = p.fake_total_gb;
                document.getElementById('editFakeUsed').value = p.fake_used_gb || 0;
                document.getElementById('editRules').value = p.replace_rules || '';
                document.getElementById('adminEditModal').classList.remove('hidden');
                document.getElementById('adminEditModal').classList.add('flex');
            }});
        }});
        document.getElementById('btnCancelEdit').addEventListener('click', () => {{
            document.getElementById('adminEditModal').classList.add('hidden');
            document.getElementById('adminEditModal').classList.remove('flex');
        }});
    </script>
</body>
</html>"""

# ----------------- مسیرها و اندپوینت‌ها (Routes) -----------------
@app.get("/")
async def root(request: Request):
    with get_db() as conn:
        profile = conn.execute("SELECT token FROM profiles ORDER BY id DESC LIMIT 1").fetchone()
    if not profile:
        return RedirectResponse(url="/admin")
    return RedirectResponse(url=f"/d/{profile['token']}")

@app.get("/sub/{token}")
async def get_subscription(token: str, request: Request, raw: bool = False):
    ip = get_client_ip(request)
    if not check_sub_rate_limit(token, ip):
        raise HTTPException(status_code=429, detail="Too Many Requests")

    with get_db() as conn:
        profile = conn.execute("SELECT * FROM profiles WHERE token = ?", (token,)).fetchone()
        if not profile:
            raise HTTPException(status_code=404, detail="Subscription not found")
        if profile["is_blocked"]:
            return Response(content="Subscription is blocked by administrator.", status_code=403)

        # ثبت امن لاگ درخواست
        now_dt = datetime.now()
        jy, jm, jd = (now_dt.year - 621, now_dt.month, now_dt.day) # ساده‌سازی نمایش تاریخ
        conn.execute(
            "UPDATE profiles SET sub_hits = COALESCE(sub_hits, 0) + 1, last_sub_fetch = ?, last_client_ip = ? WHERE token = ?",
            (f"{now_dt.strftime('%H:%M:%S')}", ip, token)
        )
        conn.commit()

    sub_data = await get_cached_or_fetch_sub(dict(profile))
    
    # ساخت هدر حجم با درصد هماهنگ‌شده بر اساس حجم فیک
    f_total = profile["fake_total_gb"] or 0
    f_used = profile["fake_used_gb"] or 0
    
    calc_total = int(f_total * (1024**3)) if f_total > 0 else sub_data.get("total", 0)
    calc_used = int(f_used * (1024**3)) if f_used > 0 else (sub_data.get("upload", 0) + sub_data.get("download", 0))
    userinfo_hdr = f"upload=0; download={calc_used}; total={calc_total}; expire={sub_data.get('expire', 0)}"

    content = "\n".join(sub_data["raw_lines"]) if raw else sub_data["encoded_sub"]
    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers={
            "subscription-userinfo": userinfo_hdr,
            "Profile-Update-Interval": "6",
            "Content-Disposition": f"attachment; filename*=UTF-8''{urllib.parse.quote(profile['name'])}.txt"
        }
    )

@app.get("/d/{token}", response_class=HTMLResponse)
async def user_dashboard(token: str):
    with get_db() as conn:
        profile = conn.execute("SELECT * FROM profiles WHERE token = ?", (token,)).fetchone()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile Not Found")

    sub_data = await get_cached_or_fetch_sub(dict(profile))

    # محاسبه دقیق درصد مصرف دایره‌ای متناسب با حجم فیک تعیین‌شده
    f_tot = profile["fake_total_gb"] or 0
    f_usd = profile["fake_used_gb"] or 0
    
    total_bytes = int(f_tot * (1024**3)) if f_tot > 0 else sub_data.get("total", 0)
    used_bytes = int(f_usd * (1024**3)) if f_usd > 0 else (sub_data.get("upload", 0) + sub_data.get("download", 0))
    rem_bytes = max(0, total_bytes - used_bytes)

    percent = int(min(100, max(0, (used_bytes / total_bytes * 100)))) if total_bytes > 0 else 0
    dashoffset = 415 - (415 * percent / 100)

    clean_domain = PUBLIC_URL.replace("https://", "").replace("http://", "").strip("/")
    sub_url = f"https://{clean_domain}/sub/{token}"

    ctx = {
        "name": profile["name"],
        "custom_notice": profile["custom_notice"] or "",
        "percent": percent,
        "dashoffset": dashoffset,
        "total_quota": format_bytes(total_bytes) if total_bytes > 0 else "نامحدود",
        "used_traffic": format_bytes(used_bytes),
        "remaining_traffic": format_bytes(rem_bytes) if total_bytes > 0 else "نامحدود",
        "expire_date": "فعال",
        "days_left": 30,
        "sub_url": sub_url,
        "configs": sub_data.get("configs", []),
        "configs_json": sub_data.get("configs_json", "[]")
    }
    return HTMLResponse(content=render_dashboard_view(ctx))

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request):
    if not is_admin(request):
        return HTMLResponse(content=render_login_view())
    with get_db() as conn:
        profiles = [dict(r) for r in conn.execute("SELECT * FROM profiles ORDER BY id DESC").fetchall()]
    clean_domain = PUBLIC_URL.replace("https://", "").replace("http://", "").strip("/")
    csrf_token = get_csrf_token(request)
    return HTMLResponse(content=render_admin_dashboard(profiles, clean_domain, csrf_token))

@app.post("/admin/login")
async def admin_login(request: Request):
    ip = get_client_ip(request)
    if not check_login_rate_limit(ip):
        return HTMLResponse(content=render_login_view("تعداد تلاش‌های ناموفق زیاد است. ۱۰ دقیقه صبر کنید."), status_code=429)

    body = await read_bounded_body(request)
    form_data = urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))
    password = form_data.get("password", [""])[0]

    if secrets.compare_digest(password, ADMIN_PASSWORD):
        login_attempts.pop(ip, None)
        resp = RedirectResponse(url="/admin", status_code=302)
        resp.set_cookie(
            key=COOKIE_NAME,
            value=create_session_token(),
            httponly=True,
            secure=not PUBLIC_URL.startswith("localhost"),
            samesite="strict",
            max_age=SESSION_TTL
        )
        return resp

    record_failed_login(ip)
    return HTMLResponse(content=render_login_view("رمز عبور اشتباه است."), status_code=401)

@app.get("/admin/logout")
async def admin_logout():
    resp = RedirectResponse(url="/admin", status_code=302)
    resp.delete_cookie(COOKIE_NAME)
    return resp

@app.post("/admin/profiles/add")
async def add_profile(request: Request):
    if not is_admin(request): raise HTTPException(status_code=401)
    body = await read_bounded_body(request)
    form = urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))
    
    if not verify_csrf(request, form.get("csrf_token", [""])[0]):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    name = form.get("name", [""])[0].strip()[:80]
    upstream_urls = form.get("upstream_urls", [""])[0].strip()
    fake_tot = float(form.get("fake_total_gb", [0])[0] or 0)
    fake_usd = float(form.get("fake_used_gb", [0])[0] or 0)
    replace_rules = form.get("replace_rules", [""])[0].strip()

    token = secrets.token_hex(6)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    with get_db() as conn:
        conn.execute("""
            INSERT INTO profiles (token, name, upstream_urls, fake_total_gb, fake_used_gb, replace_rules, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (token, name, upstream_urls, fake_tot, fake_usd, replace_rules, created_at))
        conn.commit()

    return RedirectResponse(url="/admin", status_code=302)

@app.post("/admin/profiles/{token}/edit")
async def edit_profile(request: Request, token: str):
    if not is_admin(request): raise HTTPException(status_code=401)
    body = await read_bounded_body(request)
    form = urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))

    if not verify_csrf(request, form.get("csrf_token", [""])[0]):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    name = form.get("name", [""])[0].strip()
    upstream_urls = form.get("upstream_urls", [""])[0].strip()
    fake_tot = float(form.get("fake_total_gb", [0])[0] or 0)
    fake_usd = float(form.get("fake_used_gb", [0])[0] or 0)
    replace_rules = form.get("replace_rules", [""])[0].strip()

    with get_db() as conn:
        conn.execute("""
            UPDATE profiles 
            SET name = ?, upstream_urls = ?, fake_total_gb = ?, fake_used_gb = ?, replace_rules = ?
            WHERE token = ?
        """, (name, upstream_urls, fake_tot, fake_usd, replace_rules, token))
        conn.commit()

    sub_cache.pop(token, None)
    return RedirectResponse(url="/admin", status_code=302)

@app.post("/admin/profiles/{token}/toggle")
async def toggle_profile(request: Request, token: str):
    if not is_admin(request): raise HTTPException(status_code=401)
    body = await read_bounded_body(request)
    form = urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))
    if not verify_csrf(request, form.get("csrf_token", [""])[0]):
        raise HTTPException(status_code=403, detail="Invalid CSRF")

    with get_db() as conn:
        conn.execute("UPDATE profiles SET is_blocked = CASE WHEN is_blocked = 1 THEN 0 ELSE 1 END WHERE token = ?", (token,))
        conn.commit()
    sub_cache.pop(token, None)
    return RedirectResponse(url="/admin", status_code=302)

@app.post("/admin/profiles/{token}/rotate")
async def rotate_profile_token(request: Request, token: str):
    if not is_admin(request): raise HTTPException(status_code=401)
    body = await read_bounded_body(request)
    form = urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))
    if not verify_csrf(request, form.get("csrf_token", [""])[0]):
        raise HTTPException(status_code=403, detail="Invalid CSRF")

    new_token = secrets.token_hex(6)
    with get_db() as conn:
        conn.execute("UPDATE profiles SET token = ? WHERE token = ?", (new_token, token))
        conn.commit()
    sub_cache.pop(token, None)
    return RedirectResponse(url="/admin", status_code=302)

@app.post("/admin/profiles/{token}/delete")
async def delete_profile(request: Request, token: str):
    if not is_admin(request): raise HTTPException(status_code=401)
    body = await read_bounded_body(request)
    form = urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))
    if not verify_csrf(request, form.get("csrf_token", [""])[0]):
        raise HTTPException(status_code=403, detail="Invalid CSRF")

    with get_db() as conn:
        conn.execute("DELETE FROM profiles WHERE token = ?", (token,))
        conn.commit()
    sub_cache.pop(token, None)
    return RedirectResponse(url="/admin", status_code=302)

@app.get("/admin/backup")
async def get_backup_json(request: Request):
    if not is_admin(request): raise HTTPException(status_code=401)
    with get_db() as conn:
        data = [dict(r) for r in conn.execute("SELECT * FROM profiles").fetchall()]
    return JSONResponse(
        content={"backup_time": datetime.now().isoformat(), "profiles": data},
        headers={"Content-Disposition": "attachment; filename=subs_backup_hardened.json"}
    )

# ----------------- وب‌هوک ایمن‌سازی‌شده تلگرام -----------------
@app.post("/webhook")
async def telegram_webhook(req: Request):
    if not BOT_TOKEN:
        return Response(status_code=404)

    header_sec = req.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    if not WEBHOOK_SECRET or not secrets.compare_digest(header_sec, WEBHOOK_SECRET):
        return Response(status_code=403)

    body = await read_bounded_body(req)
    try:
        update = json.loads(body.decode("utf-8"))
    except Exception:
        return Response(status_code=200)

    msg = update.get("message", {})
    chat_id = msg.get("chat", {}).get("id")
    text = msg.get("text", "").strip()

    if chat_id and text.startswith(("/start", "/stats")):
        clean_domain = PUBLIC_URL.replace("https://", "").replace("http://", "").strip("/")
        with get_db() as conn:
            cnt = conn.execute("SELECT count(*) as c FROM profiles").fetchone()["c"]
        reply = f"🛡 *دیتاسنتر ابری فعال است*\n\nتعداد کل ساب‌های مدیریت‌شده: `{cnt}`\nدامنه: `{clean_domain}`"
        try:
            await http_client.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                json={"chat_id": chat_id, "text": reply, "parse_mode": "Markdown"}
            )
        except Exception:
            pass

    return Response(status_code=200)
