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
from datetime import datetime
from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import Response, HTMLResponse, RedirectResponse, JSONResponse
from fastapi.middleware.gzip import GZipMiddleware

BRAND_DEFAULT = os.getenv("BRAND_NAME", "VIP")
PUBLIC_URL = os.getenv("RAILWAY_PUBLIC_DOMAIN", "localhost:8000")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "SuperSecretLongPassword_987654321_ChangeMe!")
BOT_TOKEN = os.getenv("BOT_TOKEN", "")

SECRET_KEY = hashlib.sha256(f"{ADMIN_PASSWORD}_datacenter_v3_salt".encode()).digest()
WEBHOOK_SECRET = hashlib.sha256(f"{BOT_TOKEN}_tg_webhook".encode()).hexdigest()[:32] if BOT_TOKEN else ""

DATA_DIR = "/data" if os.path.exists("/data") else "."
DB_FILE = os.path.join(DATA_DIR, "datacenter_subs.db")
COOKIE_NAME = "admin_session"
SESSION_TTL = 86400 * 7
TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"

CACHE_TTL = int(os.getenv("CACHE_TTL", "300"))
MAX_CACHE_SIZE = 200
MAX_REQUEST_BODY = 65536
MAX_UPSTREAM_BYTES = 2097152

sub_cache = {}
login_attempts = {}
http_client: httpx.AsyncClient = None

# ----------------- دیتابیس -----------------
def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=10.0)
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
                upstream_url TEXT NOT NULL,
                fake_total_gb REAL DEFAULT 0,
                custom_notice TEXT DEFAULT '',
                admin_note TEXT DEFAULT '',
                sub_hits INTEGER DEFAULT 0,
                last_sub_fetch TEXT DEFAULT '',
                is_blocked INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
        """)
        migrations = [
            "ALTER TABLE profiles ADD COLUMN fake_total_gb REAL DEFAULT 0",
            "ALTER TABLE profiles ADD COLUMN custom_notice TEXT DEFAULT ''",
            "ALTER TABLE profiles ADD COLUMN admin_note TEXT DEFAULT ''",
            "ALTER TABLE profiles ADD COLUMN sub_hits INTEGER DEFAULT 0",
            "ALTER TABLE profiles ADD COLUMN last_sub_fetch TEXT DEFAULT ''"
        ]
        for query in migrations:
            try:
                conn.execute(query)
            except sqlite3.OperationalError:
                pass
        conn.commit()

init_db()

# ----------------- چرخه حیات و مدیریت شبکه -----------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client
    limits = httpx.Limits(max_keepalive_connections=15, max_connections=50)
    http_client = httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False, limits=limits)
    
    if BOT_TOKEN and PUBLIC_URL != "localhost:8000":
        clean_domain = PUBLIC_URL.replace("https://", "").replace("http://", "").strip("/")
        webhook_url = f"https://{clean_domain}/webhook"
        try:
            await http_client.post(
                f"{TELEGRAM_API}/setWebhook",
                json={"url": webhook_url, "secret_token": WEBHOOK_SECRET}
            )
        except Exception:
            pass
    yield
    await http_client.aclose()

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(GZipMiddleware, minimum_size=500)

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

# ----------------- توابع امنیتی -----------------
def create_session_token() -> str:
    ts = str(int(time.time()))
    sig = hmac.new(SECRET_KEY, f"session:{ts}".encode(), hashlib.sha256).hexdigest()
    return f"{ts}.{sig}"

def verify_session_token(token: str) -> bool:
    if not token or "." not in token:
        return False
    ts_str, sig = token.split(".", 1)
    if not ts_str.isdigit():
        return False
    ts = int(ts_str)
    if abs(time.time() - ts) > SESSION_TTL:
        return False
    expected_sig = hmac.new(SECRET_KEY, f"session:{ts_str}".encode(), hashlib.sha256).hexdigest()
    return secrets.compare_digest(sig, expected_sig)

def is_admin(request: Request) -> bool:
    return verify_session_token(request.cookies.get(COOKIE_NAME, ""))

def get_csrf_token(request: Request) -> str:
    session_val = request.cookies.get(COOKIE_NAME, "")
    return hmac.new(SECRET_KEY, f"csrf:{session_val}".encode(), hashlib.sha256).hexdigest()[:32]

def verify_csrf(request: Request, token_from_form: str) -> bool:
    expected = get_csrf_token(request)
    return bool(token_from_form) and secrets.compare_digest(token_from_form, expected)

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def check_rate_limit(ip: str) -> bool:
    now = time.time()
    if len(login_attempts) > 500:
        login_attempts.clear()
    attempts = [t for t in login_attempts.get(ip, []) if now - t < 600]
    login_attempts[ip] = attempts
    return len(attempts) < 5

def record_failed_login(ip: str):
    login_attempts.setdefault(ip, []).append(time.time())

def is_safe_upstream_url(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        hostname = parsed.hostname.lower()
        if hostname in ("localhost", "0.0.0.0") or hostname.endswith(".local") or hostname.endswith(".internal"):
            return False
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
                return False
        except ValueError:
            addr_info = socket.getaddrinfo(hostname, None)
            for item in addr_info:
                ip_str = item[4][0]
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
                    return False
        return True
    except Exception:
        return False

async def read_bounded_form(request: Request) -> dict:
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_REQUEST_BODY:
        raise HTTPException(status_code=413, detail="Payload too large")
    body = await request.body()
    if len(body) > MAX_REQUEST_BODY:
        raise HTTPException(status_code=413, detail="Payload too large")
    return urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))

# ----------------- محاسبات تاریخ و ترافیک -----------------
PERSIAN_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")

def to_persian_num(s: str) -> str:
    return str(s).translate(PERSIAN_DIGITS)

def gregorian_to_jalali(gy, gm, gd):
    g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
    jy = 0 if gy <= 1600 else 979
    gy -= 621 if gy <= 1600 else 1600
    gy2 = (gm > 2) and (gy + 1) or gy
    days = (365 * gy) + ((gy2 + 3) // 4) - ((gy2 + 99) // 100) + ((gy2 + 399) // 400) - 80 + gd + g_d_m[gm - 1]
    jy += 33 * (days // 12053)
    days %= 12053
    jy += 4 * (days // 1461)
    days %= 1461
    jy += (days - 1) // 365
    if days > 0:
        days = (days - 1) % 365
    jm = (days < 186) and (1 + days // 31) or (7 + (days - 186) // 30)
    jd = 1 + ((days < 186) and (days % 31) or ((days - 186) % 30))
    return jy, jm, jd

def now_jalali_str() -> str:
    now_dt = datetime.now()
    jy, jm, jd = gregorian_to_jalali(now_dt.year, now_dt.month, now_dt.day)
    return to_persian_num(f"{jy}/{jm:02d}/{jd:02d} {now_dt.strftime('%H:%M')}")

def parse_user_info(header_val: str) -> dict:
    data = {}
    if not header_val:
        return data
    for item in header_val.split(";"):
        if "=" in item:
            k, v = item.strip().split("=", 1)
            try:
                data[k.strip()] = int(float(v.strip()))
            except ValueError:
                pass
    return data

def apply_fake_traffic(upload: int, download: int, total: int, fake_total_gb: float) -> tuple[int, int, int]:
    if not fake_total_gb or fake_total_gb <= 0:
        return upload, download, total
    fake_total_bytes = int(fake_total_gb * (1024 ** 3))
    multiplier = (fake_total_bytes / total) if total > 0 else 1.0
    return int(upload * multiplier), int(download * multiplier), fake_total_bytes

def format_bytes(size_bytes: int) -> str:
    if size_bytes >= 1024 ** 3:
        return f"{size_bytes / (1024 ** 3):.2f} GB"
    return f"{size_bytes / (1024 ** 2):.2f} MB"

def fix_b64_padding(s: str) -> str:
    s = s.strip().replace("\r", "").replace("\n", "").replace(" ", "")
    return s + "=" * ((4 - len(s) % 4) % 4)

def transform_config_name(original_name: str) -> str:
    name = original_name.strip()
    if not name:
        return "Server"
    if "VIP" in name.upper() or "𝗩𝗜𝗣" in name:
        return "VIP"
    if "ویژه" in name:
        name = name.replace("ویژه", "Stable")
    return name

def parse_and_modify_configs(raw_text: str):
    raw_text = raw_text.strip()
    if any(raw_text.startswith(p) for p in ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")):
        decoded = raw_text
    else:
        try:
            decoded = base64.b64decode(fix_b64_padding(raw_text)).decode("utf-8", errors="ignore")
        except Exception:
            decoded = raw_text

    lines = [l.strip() for l in decoded.splitlines() if l.strip()]
    configs = []
    modified_raw_lines = []

    for idx, line in enumerate(lines, start=1):
        proto = line.split("://")[0].lower() if "://" in line else "vpn"

        if line.startswith(("vless://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")):
            parts = line.split("#", 1)
            base_part = parts[0]
            orig_remark = urllib.parse.unquote(parts[1]) if len(parts) > 1 else f"Server {idx}"
            new_name = transform_config_name(orig_remark)
            new_link = f"{base_part}#{urllib.parse.quote(new_name)}"
            configs.append({"proto": proto.upper(), "name": html.escape(new_name), "link": new_link})
            modified_raw_lines.append(new_link)

        elif line.startswith("vmess://"):
            try:
                b64_part = fix_b64_padding(line[8:])
                conf = json.loads(base64.b64decode(b64_part).decode("utf-8", errors="ignore"))
                orig_remark = str(conf.get("ps", f"Server {idx}"))
                new_name = transform_config_name(orig_remark)
                conf["ps"] = new_name
                re_encoded = base64.b64encode(json.dumps(conf).encode("utf-8")).decode("utf-8")
                new_link = f"vmess://{re_encoded}"
                configs.append({"proto": "VMESS", "name": html.escape(new_name), "link": new_link})
                modified_raw_lines.append(new_link)
            except Exception:
                configs.append({"proto": "VMESS", "name": f"Server {idx}", "link": line})
                modified_raw_lines.append(line)
        else:
            configs.append({"proto": proto.upper(), "name": f"Server {idx}", "link": line})
            modified_raw_lines.append(line)

    encoded_sub = base64.b64encode("\n".join(modified_raw_lines).encode("utf-8")).decode("utf-8")
    return configs, encoded_sub

async def get_cached_sub_data(token: str, upstream_url: str):
    now = time.time()
    cached = sub_cache.get(token)
    if cached and (now - cached["timestamp"] < CACHE_TTL):
        return cached

    if not is_safe_upstream_url(upstream_url):
        raise ValueError("Unsafe upstream URL")

    if len(sub_cache) >= MAX_CACHE_SIZE:
        oldest_key = min(sub_cache.keys(), key=lambda k: sub_cache[k]["timestamp"])
        sub_cache.pop(oldest_key, None)

    headers_req = {"User-Agent": "v2rayNG/1.8.12"}
    current_url = upstream_url
    for _ in range(3):
        res = await http_client.get(current_url, headers=headers_req)
        if res.status_code in (301, 302, 303, 307, 308):
            loc = res.headers.get("location", "")
            next_url = urllib.parse.urljoin(current_url, loc)
            if not is_safe_upstream_url(next_url):
                raise ValueError("Unsafe redirect target")
            current_url = next_url
            continue
        break

    if len(res.content) > MAX_UPSTREAM_BYTES:
        raise ValueError("Response exceeded memory bound")

    resp_headers = {k.lower(): v for k, v in res.headers.items()}
    raw_text = res.text.strip()
    
    configs, encoded_sub = parse_and_modify_configs(raw_text)
    info = parse_user_info(resp_headers.get("subscription-userinfo", ""))

    data = {
        "configs": configs,
        "configs_json": json.dumps([c["link"] for c in configs]),
        "encoded_sub": encoded_sub,
        "info": info,
        "raw_userinfo": resp_headers.get("subscription-userinfo", ""),
        "timestamp": now
    }
    sub_cache[token] = data
    return data

def is_v2ray_client(user_agent: str) -> bool:
    ua = user_agent.lower()
    client_signatures = (
        "v2ray", "v2rayng", "v2rayn", "clash", "sing-box", "nekobox", 
        "streisand", "shadowrocket", "stash", "quantumult", "surge", "loon", "happ", "hiddify"
    )
    return any(sig in ua for sig in client_signatures)

# ----------------- سیستم طراحی و انیمیشن -----------------
ANIMATED_DESIGN_SYSTEM_CSS = """
:root {
    --ease-out: cubic-bezier(0.23, 1, 0.32, 1);
    --duration-snappy: 160ms;
    --duration-flow: 240ms;
    --duration-enter: 320ms;

    --p-blue-500: #4b85d1;
    --p-blue-600: #3671bf;
    --p-slate-50: #f4f5f7;
    --p-zinc-900: #18181b;
    --p-zinc-950: #0c0c0e;

    --bg-canvas: var(--p-slate-50);
    --bg-surface: rgba(255, 255, 255, 0.88);
    --text-primary: #0f172a;
    --text-secondary: #64748b;
    --border-subtle: rgba(226, 232, 240, 0.95);
    --btn-primary-bg: linear-gradient(135deg, var(--p-blue-500), var(--p-blue-600));
}

html.dark {
    --bg-canvas: var(--p-zinc-950);
    --bg-surface: rgba(24, 24, 27, 0.85);
    --text-primary: #f1f5f9;
    --text-secondary: #94a3b8;
    --border-subtle: rgba(39, 39, 42, 0.9);
}

body {
    font-family: Vazirmatn FD, system-ui, -apple-system, sans-serif;
    background-color: var(--bg-canvas);
    color: var(--text-primary);
}

* {
    scrollbar-width: thin;
    scrollbar-color: rgba(75, 133, 209, 0.35) transparent;
}
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: transparent !important; }
::-webkit-scrollbar-thumb { background: rgba(75, 133, 209, 0.35); border-radius: 9999px; }
::-webkit-scrollbar-thumb:hover { background: rgba(75, 133, 209, 0.8); }
::-webkit-scrollbar-button { display: none !important; }

@keyframes emilEnter {
    from {
        opacity: 0;
        transform: translateY(12px) scale(0.97);
    }
    to {
        opacity: 1;
        transform: translateY(0) scale(1);
    }
}

.animate-enter {
    animation: emilEnter var(--duration-enter) var(--ease-out) both;
}

.stagger-1 { animation-delay: 40ms; }
.stagger-2 { animation-delay: 80ms; }
.stagger-3 { animation-delay: 120ms; }
.stagger-4 { animation-delay: 160ms; }

.btn-press {
    transition: transform var(--duration-snappy) var(--ease-out), opacity var(--duration-snappy) var(--ease-out);
    will-change: transform;
}
.btn-press:active {
    transform: scale(0.96);
}

@media (hover: hover) and (pointer: fine) {
    .hover-lift {
        transition: transform var(--duration-flow) var(--ease-out), border-color var(--duration-flow) var(--ease-out);
        will-change: transform;
    }
    .hover-lift:hover {
        transform: translateY(-2px);
    }
}

@media (prefers-reduced-motion: reduce) {
    .animate-enter, .btn-press, .hover-lift {
        animation: none !important;
        transition: opacity var(--duration-snappy) ease !important;
        transform: none !important;
    }
}

.surface-card {
    background: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    backdrop-filter: blur(14px);
}

.tab-button {
    min-height: 44px;
    padding: 0 1.25rem;
    border-radius: 0.85rem;
    font-weight: 700;
    transition: transform var(--duration-snappy) var(--ease-out), background var(--duration-snappy) var(--ease-out), color var(--duration-snappy) var(--ease-out);
}
.tab-button.active {
    background: var(--btn-primary-bg);
    color: #ffffff;
    box-shadow: 0 4px 14px rgba(75, 133, 209, 0.3);
}
.tab-button:not(.active) {
    background: var(--bg-surface);
    color: var(--text-secondary);
    border: 1px solid var(--border-subtle);
}

.touch-target {
    min-width: 44px;
    min-height: 44px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
}

.en-digits {
    font-family: system-ui, -apple-system, sans-serif !important;
    font-variant-numeric: normal !important;
    direction: ltr !important;
    display: inline-block;
}
"""

def render_login_html(error: str = None) -> str:
    err_box = f'<div role="alert" class="p-3.5 mb-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs font-bold text-center animate-enter">{html.escape(error)}</div>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ورود به مدیریت دیتاسنتر</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/misc/Farsi-Digits/Vazirmatn-FD-font-face.css">
    <style>{ANIMATED_DESIGN_SYSTEM_CSS}</style>
</head>
<body class="min-h-screen flex flex-col justify-between p-4">
    <div></div>
    <main class="surface-card p-8 rounded-3xl w-full max-w-md mx-auto shadow-2xl animate-enter">
        <div class="w-14 h-14 rounded-2xl bg-[#4b85d1]/10 border border-[#4b85d1]/25 flex items-center justify-center mx-auto mb-5 text-[#4b85d1]">
            <svg class="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
        </div>
        <h1 class="text-xl font-extrabold mb-1 text-center">ورود به پنل مدیریت دیتاسنتر</h1>
        <p class="text-xs text-slate-400 text-center mb-6">کنترل نشست رمزنگاری‌شده و ضد Brute-Force</p>
        {err_box}
        <form action="/admin/login" method="post" class="space-y-4">
            <div>
                <label for="admin_pass" class="block text-xs text-slate-400 mb-2">رمز عبور ادمین</label>
                <input id="admin_pass" type="password" name="password" required autofocus class="w-full bg-zinc-950/90 border border-zinc-800 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-[#4b85d1] text-left font-mono">
            </div>
            <button type="submit" class="btn-press w-full min-h-[44px] bg-[#4b85d1] hover:bg-[#3671bf] text-white font-bold rounded-xl text-sm transition-colors shadow-lg cursor-pointer">ورود به سیستم</button>
        </form>
    </main>
    <div></div>
</body>
</html>"""

def render_admin_html(profiles, domain: str, csrf_token: str) -> str:
    total_count = len(profiles)
    blocked_count = sum(1 for p in profiles if p["is_blocked"])
    active_count = total_count - blocked_count
    total_hits = sum((p["sub_hits"] or 0) for p in profiles)
    cached_items = len(sub_cache)

    rows = ""
    for p in profiles:
        safe_name = html.escape(p["name"])
        safe_token = html.escape(p["token"])
        safe_note = html.escape(p["admin_note"] or "")
        safe_notice = html.escape(p["custom_notice"] or "")
        hits = p["sub_hits"] or 0
        last_fetch = html.escape(p["last_sub_fetch"] or "بدون اتصال")
        fake_val = p["fake_total_gb"] or 0

        cached_data = sub_cache.get(p["token"])
        if cached_data and cached_data.get("info"):
            info = cached_data["info"]
            u, d, tot = apply_fake_traffic(info.get("upload", 0), info.get("download", 0), info.get("total", 0), fake_val)
            traffic_badge = f"<span class='text-xs font-mono text-emerald-400' dir='ltr'>{format_bytes(u+d)} / {format_bytes(tot)}</span>"
        else:
            traffic_badge = "<span class='text-[11px] text-slate-500'>آماده همگام‌سازی</span>"

        status_badge = (
            '<span class="inline-flex items-center gap-1.5 whitespace-nowrap px-2.5 py-1 rounded-full text-[11px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20"><span class="w-1.5 h-1.5 rounded-full bg-rose-500"></span>مسدود</span>'
            if p["is_blocked"] else
            '<span class="inline-flex items-center gap-1.5 whitespace-nowrap px-2.5 py-1 rounded-full text-[11px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"><span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>فعال</span>'
        )
        fake_label = f"<span class='px-2 py-0.5 rounded-md bg-blue-500/10 border border-blue-500/20 text-[#4b85d1] font-mono text-xs font-bold'>{fake_val:g} GB</span>" if fake_val > 0 else "<span class='text-slate-500 text-xs'>واقعی</span>"
        
        btn_class = "bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/20" if p["is_blocked"] else "bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/20"
        btn_text = "رفع بلاک" if p["is_blocked"] else "بلاک"
        
        p_json = html.escape(json.dumps({
            "token": p["token"],
            "name": p["name"],
            "upstream_url": p["upstream_url"],
            "fake_total_gb": fake_val,
            "custom_notice": p["custom_notice"] or "",
            "admin_note": p["admin_note"] or ""
        }))

        dash_url = f"https://{domain}/d/{safe_token}"
        sub_url = f"https://{domain}/sub/{safe_token}"
        note_html = f'<div class="text-[11px] text-amber-400/90 mt-1">📌 {safe_note}</div>' if safe_note else ''
        notice_indicator = '<span class="inline-block mr-1 text-[10px] px-1.5 py-0.5 rounded bg-purple-500/15 text-purple-400 border border-purple-500/20">اعلان فعال</span>' if safe_notice else ''

        rows += f"""
        <tr class="profile-row hover:bg-zinc-800/40 transition-colors" data-name="{safe_name.lower()} {safe_token.lower()} {safe_note.lower()}" data-status="{'blocked' if p['is_blocked'] else 'active'}">
            <td class="p-4 whitespace-nowrap">
                <div class="font-bold text-sm flex items-center">{safe_name} {notice_indicator}</div>
                {note_html}
            </td>
            <td class="p-4 whitespace-nowrap">
                <div class="flex items-center gap-1.5">
                    <button type="button" onclick="copyText('{dash_url}', 'لینک داشبورد کپی شد')" class="btn-press px-2.5 py-1.5 rounded-lg bg-zinc-800 hover:bg-[#4b85d1] hover:text-white text-xs font-semibold transition-colors cursor-pointer">کپی داشبورد</button>
                    <button type="button" onclick="copyText('{sub_url}', 'لینک ساب کپی شد')" class="btn-press px-2.5 py-1.5 rounded-lg bg-zinc-800 hover:bg-[#4b85d1] hover:text-white text-xs font-semibold transition-colors cursor-pointer">کپی ساب</button>
                    <button type="button" onclick="openQR('{sub_url}', '{safe_name}')" class="btn-press p-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-slate-300 transition-colors cursor-pointer" title="QR Code">
                        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
                    </button>
                    <a href="/d/{safe_token}" target="_blank" class="p-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-[#4b85d1] transition-colors" title="مشاهده">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
                    </a>
                </div>
            </td>
            <td class="p-4 whitespace-nowrap text-center">{fake_label}</td>
            <td class="p-4 whitespace-nowrap text-center">{traffic_badge}</td>
            <td class="p-4 whitespace-nowrap">
                <div class="text-xs font-bold text-slate-200">{hits} بار</div>
                <div class="text-[11px] text-slate-500 mt-0.5">{last_fetch}</div>
            </td>
            <td class="p-4 whitespace-nowrap">{status_badge}</td>
            <td class="p-4 whitespace-nowrap">
                <div class="flex justify-center items-center gap-1.5">
                    <button type="button" onclick="openEditModal({p_json})" class="btn-press min-h-[36px] px-3 rounded-xl text-xs font-semibold bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 border border-blue-500/20 transition-colors cursor-pointer">ویرایش</button>
                    <form action="/admin/profiles/{safe_token}/refresh-cache" method="post" class="m-0">
                        <input type="hidden" name="csrf_token" value="{csrf_token}">
                        <button type="submit" class="btn-press min-h-[36px] px-2.5 rounded-xl text-xs font-semibold bg-zinc-800 hover:bg-zinc-700 text-slate-300 transition-colors cursor-pointer" title="بروزرسانی کش">🔄</button>
                    </form>
                    <form action="/admin/profiles/{safe_token}/toggle-block" method="post" class="m-0">
                        <input type="hidden" name="csrf_token" value="{csrf_token}">
                        <button type="submit" class="btn-press min-h-[36px] px-3 rounded-xl text-xs font-semibold transition-colors cursor-pointer {btn_class}">{btn_text}</button>
                    </form>
                    <form action="/admin/profiles/{safe_token}/delete" method="post" class="m-0" onsubmit="return confirm('آیا از حذف کامل این ساب اطمینان داری؟');">
                        <input type="hidden" name="csrf_token" value="{csrf_token}">
                        <button type="submit" class="btn-press min-h-[36px] px-3 rounded-xl text-xs font-semibold bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 transition-colors cursor-pointer">حذف</button>
                    </form>
                </div>
            </td>
        </tr>"""

    if not rows:
        rows = '<tr><td colspan="7" class="p-10 text-center text-slate-500 text-xs">هنوز هیچ سابی ثبت نشده است.</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>مدیریت ساب‌ها</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/misc/Farsi-Digits/Vazirmatn-FD-font-face.css">
    <style>{ANIMATED_DESIGN_SYSTEM_CSS}</style>
</head>
<body class="min-h-screen p-4 sm:p-6 lg:p-8 flex flex-col justify-between">
    <main class="max-w-7xl w-full mx-auto space-y-6 animate-enter">
        <header class="flex flex-wrap justify-between items-center gap-4 surface-card p-6 rounded-3xl">
            <div class="flex items-center gap-3.5">
                <div class="w-12 h-12 rounded-2xl bg-[#4b85d1]/15 border border-[#4b85d1]/30 flex items-center justify-center text-[#4b85d1]">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2"></path></svg>
                </div>
                <div>
                    <h1 class="text-xl sm:text-2xl font-extrabold">کنترل پنل مرکزی دیتاسنتر</h1>
                    <p class="text-xs text-slate-400 mt-0.5">دامنه سرور: <span class="font-mono text-[#4b85d1]" dir="ltr">{domain}</span></p>
                </div>
            </div>
            <div class="flex flex-wrap items-center gap-2.5">
                <form action="/admin/cache/clear" method="post" class="m-0">
                    <input type="hidden" name="csrf_token" value="{csrf_token}">
                    <button type="submit" class="btn-press min-h-[42px] px-4 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-xl text-xs font-bold transition-colors cursor-pointer">پاکسازی کل کش ({cached_items})</button>
                </form>
                <a href="/admin/backup" class="btn-press min-h-[42px] px-4 inline-flex items-center bg-[#4b85d1]/15 hover:bg-[#4b85d1]/25 text-[#4b85d1] border border-[#4b85d1]/30 rounded-xl text-xs font-bold transition-colors">دانلود بکاپ JSON</a>
                <a href="/admin/logout" class="btn-press min-h-[42px] px-4 inline-flex items-center bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 rounded-xl text-xs font-bold transition-colors">خروج</a>
            </div>
        </header>

        <section class="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div class="surface-card hover-lift p-5 rounded-3xl animate-enter stagger-1">
                <div class="text-xs text-slate-400 mb-1">کل اشتراک‌ها</div>
                <div class="text-2xl sm:text-3xl font-black text-white">{total_count}</div>
            </div>
            <div class="surface-card hover-lift p-5 rounded-3xl animate-enter stagger-2">
                <div class="text-xs text-slate-400 mb-1">اشتراک‌های فعال</div>
                <div class="text-2xl sm:text-3xl font-black text-emerald-400">{active_count}</div>
            </div>
            <div class="surface-card hover-lift p-5 rounded-3xl animate-enter stagger-3">
                <div class="text-xs text-slate-400 mb-1">مسدود شده</div>
                <div class="text-2xl sm:text-3xl font-black text-rose-400">{blocked_count}</div>
            </div>
            <div class="surface-card hover-lift p-5 rounded-3xl animate-enter stagger-4">
                <div class="text-xs text-slate-400 mb-1">مجموع آپدیت کلاینت‌ها</div>
                <div class="text-2xl sm:text-3xl font-black text-[#4b85d1]">{total_hits} <span class="text-xs font-normal text-slate-400">بار</span></div>
            </div>
        </section>

        <section class="surface-card p-6 rounded-3xl animate-enter stagger-2">
            <h2 class="text-base font-bold mb-4 flex items-center gap-2">
                <svg class="w-5 h-5 text-[#4b85d1]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg>
                افزودن اشتراک جدید
            </h2>
            <form action="/admin/profiles/add" method="post" class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                <div>
                    <label class="block text-xs text-slate-400 mb-1.5">نام یا برند نمایشی *</label>
                    <input type="text" name="name" placeholder="مثلاً: VIP" required class="w-full bg-zinc-950/90 border border-zinc-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-[#4b85d1]">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1.5">لینک ساب اصلی فروشنده *</label>
                    <input type="url" name="upstream_url" placeholder="https://seller.com/sub/..." required class="w-full bg-zinc-950/90 border border-zinc-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-[#4b85d1] text-left font-mono" dir="ltr">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1.5">حجم فیک کل (GB) - اختیاری</label>
                    <input type="number" step="0.1" min="0" name="fake_total_gb" placeholder="0 = حجم واقعی" class="w-full bg-zinc-950/90 border border-zinc-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-[#4b85d1] text-left font-mono" dir="ltr">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1.5">اعلان اختصاصی کاربر (اختیاری)</label>
                    <input type="text" name="custom_notice" placeholder="مثلاً: سرورهای جدید اضافه شدند" class="w-full bg-zinc-950/90 border border-zinc-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-[#4b85d1]">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1.5">یادداشت محرمانه ادمین (اختیاری)</label>
                    <input type="text" name="admin_note" placeholder="مثلاً: خریدار تلگرام @user" class="w-full bg-zinc-950/90 border border-zinc-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-[#4b85d1]">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1.5">توکن اختصاصی لینک (اختیاری)</label>
                    <div class="flex gap-2">
                        <input type="text" name="custom_token" placeholder="خالی = خودکار" class="w-full bg-zinc-950/90 border border-zinc-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-[#4b85d1] text-left font-mono" dir="ltr">
                        <button type="submit" class="btn-press px-6 min-h-[42px] bg-[#4b85d1] hover:bg-[#3671bf] text-white font-bold rounded-xl text-sm shrink-0 transition-colors cursor-pointer shadow-lg">ثبت ساب</button>
                    </div>
                </div>
            </form>
        </section>

        <section class="surface-card rounded-3xl overflow-hidden animate-enter stagger-3">
            <div class="p-5 sm:p-6 border-b border-zinc-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <h2 class="text-base font-bold">لیست اشتراک‌های دیتاسنتر ({total_count})</h2>
                <div class="flex flex-wrap items-center gap-2">
                    <input type="text" id="searchInput" oninput="filterTable()" placeholder="جستجوی ساب یا یادداشت..." class="bg-zinc-950 border border-zinc-800 rounded-xl px-3.5 py-2 text-xs focus:outline-none focus:border-[#4b85d1] w-56">
                    <select id="statusFilter" onchange="filterTable()" class="bg-zinc-950 border border-zinc-800 rounded-xl px-3 py-2 text-xs focus:outline-none focus:border-[#4b85d1]">
                        <option value="all">همه</option>
                        <option value="active">فعال‌ها</option>
                        <option value="blocked">مسدودها</option>
                    </select>
                </div>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-right text-sm">
                    <thead class="bg-zinc-950/60 text-slate-400 text-xs border-b border-zinc-800">
                        <tr>
                            <th class="p-4 whitespace-nowrap">نام ساب / یادداشت</th>
                            <th class="p-4 whitespace-nowrap">لینک‌ها</th>
                            <th class="p-4 whitespace-nowrap text-center">حجم فیک</th>
                            <th class="p-4 whitespace-nowrap text-center">مصرف کش‌شده</th>
                            <th class="p-4 whitespace-nowrap">آمار کلاینت</th>
                            <th class="p-4 whitespace-nowrap">وضعیت</th>
                            <th class="p-4 text-center whitespace-nowrap">عملیات</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-zinc-800/60">
                        {rows}
                    </tbody>
                </table>
            </div>
        </section>
    </main>

    <div id="editModal" class="fixed inset-0 bg-black/75 backdrop-blur-xs hidden items-center justify-center z-50 p-4" onclick="closeEditModal()">
        <div class="surface-card rounded-3xl p-6 sm:p-8 max-w-lg w-full shadow-2xl animate-enter" onclick="event.stopPropagation()">
            <h3 class="text-lg font-bold mb-4">ویرایش اطلاعات ساب</h3>
            <form id="editForm" method="post" class="space-y-3.5">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                <div>
                    <label class="block text-xs text-slate-400 mb-1">نام یا برند نمایشی</label>
                    <input type="text" id="edit_name" name="name" required class="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-[#4b85d1]">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">لینک اصلی فروشنده</label>
                    <input type="url" id="edit_upstream" name="upstream_url" required class="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-[#4b85d1] font-mono text-left" dir="ltr">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">حجم فیک کل (GB) - 0 یعنی واقعی</label>
                    <input type="number" step="0.1" min="0" id="edit_fake" name="fake_total_gb" required class="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-[#4b85d1] font-mono text-left" dir="ltr">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">اعلان اختصاصی برای این مشتری</label>
                    <input type="text" id="edit_notice" name="custom_notice" class="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-[#4b85d1]">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">یادداشت محرمانه ادمین</label>
                    <input type="text" id="edit_note" name="admin_note" class="w-full bg-zinc-950 border border-zinc-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-[#4b85d1]">
                </div>
                <div class="flex gap-2 pt-3">
                    <button type="submit" class="btn-press flex-1 min-h-[44px] bg-[#4b85d1] hover:bg-[#3671bf] text-white font-bold rounded-xl text-sm transition-colors cursor-pointer">ذخیره تغییرات</button>
                    <button type="button" onclick="closeEditModal()" class="btn-press px-5 min-h-[44px] bg-zinc-800 hover:bg-zinc-700 text-slate-300 font-bold rounded-xl text-sm transition-colors cursor-pointer">انصراف</button>
                </div>
            </form>
        </div>
    </div>

    <div id="adminQrModal" class="fixed inset-0 bg-black/75 backdrop-blur-xs hidden items-center justify-center z-50 p-4" onclick="closeAdminQR()">
        <div class="surface-card p-6 rounded-3xl max-w-xs w-full flex flex-col items-center text-center animate-enter" onclick="event.stopPropagation()">
            <h3 id="adminQrTitle" class="font-bold text-sm mb-4">QR Code</h3>
            <img id="adminQrImg" src="" alt="QR" class="w-52 h-52 rounded-2xl mb-4 p-2.5 bg-white shadow-inner">
            <button type="button" onclick="closeAdminQR()" class="btn-press w-full min-h-[42px] bg-zinc-800 hover:bg-zinc-700 text-xs font-bold rounded-xl cursor-pointer">بستن</button>
        </div>
    </div>

    <div id="adminToast" class="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 hidden px-5 py-3 rounded-2xl bg-white text-slate-900 text-xs font-bold shadow-2xl animate-enter"></div>

    <script>
        function copyText(txt, msg) {{
            navigator.clipboard.writeText(txt);
            const t = document.getElementById('adminToast');
            t.textContent = msg;
            t.classList.remove('hidden');
            setTimeout(() => t.classList.add('hidden'), 2000);
        }}
        function openQR(url, title) {{
            document.getElementById('adminQrTitle').textContent = 'کد QR اشتراک: ' + title;
            document.getElementById('adminQrImg').src = 'https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=' + encodeURIComponent(url);
            document.getElementById('adminQrModal').classList.remove('hidden');
            document.getElementById('adminQrModal').classList.add('flex');
        }}
        function closeAdminQR() {{
            document.getElementById('adminQrModal').classList.add('hidden');
            document.getElementById('adminQrModal').classList.remove('flex');
        }}
        function openEditModal(profile) {{
            document.getElementById('editForm').action = '/admin/profiles/' + encodeURIComponent(profile.token) + '/edit';
            document.getElementById('edit_name').value = profile.name;
            document.getElementById('edit_upstream').value = profile.upstream_url;
            document.getElementById('edit_fake').value = profile.fake_total_gb;
            document.getElementById('edit_notice').value = profile.custom_notice || '';
            document.getElementById('edit_note').value = profile.admin_note || '';
            document.getElementById('editModal').classList.remove('hidden');
            document.getElementById('editModal').classList.add('flex');
        }}
        function closeEditModal() {{
            document.getElementById('editModal').classList.add('hidden');
            document.getElementById('editModal').classList.remove('flex');
        }}
        function filterTable() {{
            const q = document.getElementById('searchInput').value.toLowerCase();
            const st = document.getElementById('statusFilter').value;
            document.querySelectorAll('.profile-row').forEach(row => {{
                const matchName = row.getAttribute('data-name').includes(q);
                const matchStatus = (st === 'all') || (row.getAttribute('data-status') === st);
                row.style.display = (matchName && matchStatus) ? '' : 'none';
            }});
        }}
    </script>
</body>
</html>"""

def render_app_card(name_html: str, url: str, btn_label: str, recommended: bool = False) -> str:
    badge = '<span class="absolute top-2.5 right-2.5 text-[10px] font-extrabold px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-500 border border-emerald-500/25">پیشنهادی</span>' if recommended else ''
    return f"""
    <div class="surface-card hover-lift p-4 sm:p-5 rounded-2xl flex flex-col items-center justify-between text-center relative border border-slate-200/80 dark:border-zinc-800">
        {badge}
        <div class="w-full text-center mt-3 mb-4">
            <h3 class="font-extrabold text-base tracking-wide">{name_html}</h3>
        </div>
        <a href="{url}" target="_blank" rel="noopener noreferrer" class="btn-press w-full min-h-[40px] inline-flex items-center justify-center bg-[#4b85d1] hover:bg-[#3671bf] text-white rounded-xl text-xs font-bold transition-colors shadow-xs">{btn_label}</a>
    </div>"""

def render_dashboard_html(ctx: dict) -> str:
    safe_brand = html.escape(ctx["brand_name"])
    safe_notice = html.escape(ctx["custom_notice"]) if ctx.get("custom_notice") else "لطفاً قبل از اتصال، یک‌بار لینک اشتراک (Update Subscription) را درون نرم‌افزار خود به‌روزرسانی کنید."
    
    if ctx["is_blocked"]:
        main_section = """
        <div role="alert" class="p-8 rounded-3xl border border-rose-500/30 bg-rose-500/5 mb-8 text-center shadow-lg animate-enter">
            <div class="inline-flex items-center whitespace-nowrap gap-2 px-4 py-1.5 rounded-full bg-rose-500/10 text-rose-500 text-sm font-bold mb-3 border border-rose-500/20">
                <span class="w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping"></span> مسدود شده
            </div>
            <div class="text-2xl sm:text-3xl font-bold text-rose-500 mb-2">اشتراک شما مسدود شده است</div>
            <p class="text-sm opacity-75">دسترسی این اشتراک توسط پشتیبانی غیرفعال شده است.</p>
        </div>"""
    else:
        conf_items = ""
        for idx, c in enumerate(ctx["configs"]):
            conf_items += f"""
            <div class="config-item surface-card hover-lift group relative p-3.5 rounded-2xl transition-all duration-200" data-confname="{c['name'].lower()} {c['proto'].lower()}">
                <div class="flex items-center gap-3">
                    <span class="px-2.5 py-1 rounded-lg text-[11px] font-bold uppercase bg-[#4b85d1]/15 text-[#4b85d1] border border-[#4b85d1]/25 shrink-0">{c['proto']}</span>
                    <div dir="ltr" class="text-sm sm:text-base font-semibold flex-1 min-w-0 truncate text-right">{c['name']}</div>
                    <div class="flex gap-1.5 shrink-0">
                        <button type="button" onclick="copyConfig({idx}, this)" aria-label="کپی کانفیگ" class="btn-press touch-target rounded-xl transition-all cursor-pointer bg-slate-200/70 dark:bg-zinc-800/90 hover:bg-[#4b85d1] hover:text-white" title="کپی کانفیگ">
                            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"></rect><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"></path></svg>
                        </button>
                        <button type="button" onclick="showConfigQR({idx})" aria-label="نمایش کد QR" class="btn-press touch-target rounded-xl bg-slate-200/70 dark:bg-zinc-800/90 hover:bg-slate-300 dark:hover:bg-zinc-700 transition-all cursor-pointer" title="کد QR">
                            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 12v4a1 1 0 0 1-1 1h-4"></path><path d="M17 3h2a2 2 0 0 1 2 2v2"></path><path d="M17 8V7"></path><path d="M21 17v2a2 2 0 0 1-2 2h-2"></path><path d="M3 7V5a2 2 0 0 1 2-2h2"></path><path d="M7 17h.01"></path><path d="M7 21H5a2 2 0 0 1-2-2v-2"></path><rect x="7" y="7" width="5" height="5" rx="1"></rect></svg>
                        </button>
                    </div>
                </div>
            </div>"""

        encoded_sub_url = urllib.parse.quote(ctx["sub_url"], safe="")
        hiddify_deep = f"hiddify://import/{ctx['sub_url']}#{urllib.parse.quote(ctx['brand_name'])}"
        v2rayng_deep = f"v2rayng://install-sub?url={encoded_sub_url}&name={urllib.parse.quote(ctx['brand_name'])}"
        singbox_deep = f"sing-box://import-remote-profile?url={encoded_sub_url}#{urllib.parse.quote(ctx['brand_name'])}"
        streisand_deep = f"streisand://import/{ctx['sub_url']}"

        android_apps = "".join([
            render_app_card("<span class='en-digits'>Hiddify</span>", "https://github.com/hiddify/hiddify-next/releases", "دانلود از گیتهاب", True),
            render_app_card("<span class='en-digits'>v2rayNG</span>", "https://github.com/2dust/v2rayNG/releases", "دانلود از گیتهاب", True),
            render_app_card("<span class='en-digits'>Flclash</span>", "https://github.com/chen08209/FlClash/releases", "دانلود از گیتهاب", True),
            render_app_card("<span class='en-digits'>Karing</span>", "https://github.com/KaringX/karing/releases", "دانلود از گیتهاب", False),
            render_app_card("<span class='en-digits'>Sing-box</span>", "https://github.com/SagerNet/sing-box/releases", "دانلود از گیتهاب", False),
            render_app_card("<span class='en-digits'>NekoBox</span>", "https://github.com/MatsuriDayo/NekoBoxForAndroid/releases", "دانلود از گیتهاب", False),
        ])
        ios_apps = "".join([
            render_app_card("<span class='en-digits'>Hiddify</span>", "https://apps.apple.com/us/app/hiddify-proxy-vpn/id6596777532", "دانلود از اپ‌استور", True),
            render_app_card("<span class='en-digits'>Streisand</span>", "https://apps.apple.com/us/app/streisand/id6450534064", "دانلود از اپ‌استور", True),
            render_app_card("<span class='en-digits'>Shadowrocket</span>", "https://apps.apple.com/us/app/shadowrocket/id932747118", "دانلود از اپ‌استور", True),
            render_app_card("<span class='en-digits'>Karing</span>", "https://apps.apple.com/us/app/karing/id6472431552", "دانلود از اپ‌استور", False),
            render_app_card("<span class='en-digits'>Sing-box</span>", "https://apps.apple.com/us/app/sing-box/id6451272673", "دانلود از اپ‌استور", False),
            render_app_card("<span class='en-digits'>FoXray</span>", "https://apps.apple.com/us/app/foxray/id6448898396", "دانلود از اپ‌استور", False),
        ])
        win_apps = "".join([
            render_app_card("<span class='en-digits'>Hiddify</span>", "https://github.com/hiddify/hiddify-next/releases", "دانلود از گیتهاب", True),
            render_app_card("<span class='en-digits'>v2rayN</span>", "https://github.com/2dust/v2rayN/releases", "دانلود از گیتهاب", True),
            render_app_card("<span class='en-digits'>Flclash</span>", "https://github.com/chen08209/FlClash/releases", "دانلود از گیتهاب", True),
            render_app_card("<span class='en-digits'>Clash Verge</span>", "https://github.com/clash-verge-rev/clash-verge-rev/releases", "دانلود از گیتهاب", False),
            render_app_card("<span class='en-digits'>Karing</span>", "https://github.com/KaringX/karing/releases", "دانلود از گیتهاب", False),
            render_app_card("<span class='en-digits'>Nekoray</span>", "https://github.com/MatsuriDayo/nekoray/releases", "دانلود از گیتهاب", False),
        ])
        mac_apps = "".join([
            render_app_card("<span class='en-digits'>Hiddify</span>", "https://github.com/hiddify/hiddify-next/releases", "دانلود از گیتهاب", True),
            render_app_card("<span class='en-digits'>Clash Verge</span>", "https://github.com/clash-verge-rev/clash-verge-rev/releases", "دانلود از گیتهاب", True),
            render_app_card("<span class='en-digits'>Flclash</span>", "https://github.com/chen08209/FlClash/releases", "دانلود از گیتهاب", True),
            render_app_card("<span class='en-digits'>Sing-box</span>", "https://github.com/SagerNet/sing-box/releases", "دانلود از گیتهاب", False),
            render_app_card("<span class='en-digits'>FoXray</span>", "https://apps.apple.com/us/app/foxray/id6448898396", "دانلود از اپ‌استور", False),
            render_app_card("<span class='en-digits'>Nekoray</span>", "https://github.com/MatsuriDayo/nekoray/releases", "دانلود از گیتهاب", False),
        ])

        main_section = f"""
        <div class="mb-6 sm:mb-8 animate-enter">
            <div class="p-4 sm:p-5 rounded-2xl border bg-gradient-to-r from-[#4b85d1]/15 via-[#4b85d1]/10 to-transparent border-[#4b85d1]/30 shadow-xs">
                <div class="flex items-start gap-3.5">
                    <div class="shrink-0 mt-0.5 text-[#4b85d1]">
                        <svg class="w-5 h-5 sm:w-6 sm:h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.268 21a2 2 0 0 0 3.464 0"></path><path d="M3.262 15.326A1 1 0 0 0 4 17h16a1 1 0 0 0 .74-1.673C19.41 13.956 18 12.499 18 8A6 6 0 0 0 6 8c0 4.499-1.411 5.956-2.738 7.326"></path></svg>
                    </div>
                    <div class="flex-1 min-w-0">
                        <div class="text-sm sm:text-base font-bold mb-1">اطلاعیه اشتراک</div>
                        <p class="text-xs sm:text-sm opacity-85 leading-relaxed">{safe_notice}</p>
                    </div>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-4 sm:gap-6 mb-8 animate-enter stagger-1">
            <div class="lg:col-span-2 surface-card p-6 sm:p-8 rounded-3xl shadow-lg flex flex-col justify-between">
                <div class="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4 mb-6">
                    <div class="flex items-center gap-2.5">
                        <span class="text-2xl sm:text-3xl font-extrabold text-emerald-500">فعال</span>
                        <span class="relative flex h-3 w-3">
                            <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                            <span class="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
                        </span>
                    </div>
                    <div class="sm:text-left">
                        <div class="text-xs opacity-70">اعتبار زمانی</div>
                        <p class="text-xl sm:text-2xl font-black mt-0.5">{ctx['days_left']} روز</p>
                    </div>
                </div>

                <div class="flex flex-col sm:flex-row items-center gap-6 sm:gap-8">
                    <div class="relative w-36 h-36 sm:w-40 sm:h-40 shrink-0">
                        <svg class="transform -rotate-90 w-full h-full">
                            <circle cx="50%" cy="50%" r="45%" stroke="currentColor" stroke-width="12" fill="none" class="text-slate-200/70 dark:text-zinc-800"></circle>
                            <circle cx="50%" cy="50%" r="45%" stroke="currentColor" stroke-width="12" fill="none"
                                stroke-dasharray="440" stroke-dashoffset="{ctx['dashoffset']}"
                                class="text-[#4b85d1] transition-all duration-1000 ease-out" stroke-linecap="round"></circle>
                        </svg>
                        <div class="absolute inset-0 flex flex-col items-center justify-center">
                            <span class="text-2xl sm:text-3xl font-black">{ctx['percent']}%</span>
                            <span class="text-xs opacity-70 font-medium">مصرف شده</span>
                        </div>
                    </div>

                    <div class="flex-1 w-full space-y-3">
                        <div class="flex justify-between items-center p-3 rounded-xl bg-slate-200/50 dark:bg-zinc-800/50">
                            <span class="text-xs sm:text-sm opacity-75">کل حجم سرویس</span>
                            <span dir="ltr" class="text-sm sm:text-base font-bold">{ctx['total_quota']}</span>
                        </div>
                        <div class="flex justify-between items-center p-3 rounded-xl bg-slate-200/50 dark:bg-zinc-800/50">
                            <span class="text-xs sm:text-sm opacity-75">حجم مصرفی</span>
                            <span dir="ltr" class="text-sm sm:text-base font-bold text-amber-500">{ctx['used_traffic']}</span>
                        </div>
                        <div class="flex justify-between items-center p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20">
                            <span class="text-xs sm:text-sm font-bold text-emerald-600 dark:text-emerald-400">حجم باقی‌مانده</span>
                            <span dir="ltr" class="text-sm sm:text-base font-bold text-emerald-600 dark:text-emerald-400">{ctx['remaining_traffic']}</span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-1 gap-4">
                <div class="surface-card hover-lift p-5 sm:p-6 rounded-3xl flex flex-col justify-center">
                    <div class="text-xs opacity-70 mb-1">تعداد سرورهای فعال</div>
                    <div class="text-xl sm:text-2xl font-black text-right text-[#4b85d1]">{len(ctx['configs'])} سرور</div>
                </div>
                <div class="surface-card hover-lift p-5 sm:p-6 rounded-3xl flex flex-col justify-center">
                    <div class="text-xs opacity-70 mb-1">تاریخ انقضا</div>
                    <div dir="ltr" class="text-sm sm:text-base font-bold text-right">{ctx['expire_date']}</div>
                </div>
                <div class="surface-card hover-lift p-5 sm:p-6 rounded-3xl flex flex-col justify-center">
                    <div class="text-xs opacity-70 mb-1">آخرین بروزرسانی</div>
                    <div dir="ltr" class="flex items-center justify-end gap-2">
                        <span class="text-xs sm:text-sm font-semibold">{ctx['now_jalali']}</span>
                        <span class="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
                    </div>
                </div>
            </div>
        </div>

        <div class="surface-card p-5 rounded-3xl mb-8 animate-enter stagger-2">
            <div class="text-sm font-bold mb-3 flex items-center gap-2">
                <svg class="w-4 h-4 text-[#4b85d1]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                افزودن خودکار اشتراک به نرم‌افزار
            </div>
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                <a href="{hiddify_deep}" class="btn-press min-h-[42px] px-3 rounded-xl bg-[#4b85d1]/15 hover:bg-[#4b85d1] text-[#4b85d1] hover:text-white border border-[#4b85d1]/30 text-xs font-bold flex items-center justify-center transition-all">افزودن به Hiddify</a>
                <a href="{v2rayng_deep}" class="btn-press min-h-[42px] px-3 rounded-xl bg-[#4b85d1]/15 hover:bg-[#4b85d1] text-[#4b85d1] hover:text-white border border-[#4b85d1]/30 text-xs font-bold flex items-center justify-center transition-all">افزودن به v2rayNG</a>
                <a href="{singbox_deep}" class="btn-press min-h-[42px] px-3 rounded-xl bg-[#4b85d1]/15 hover:bg-[#4b85d1] text-[#4b85d1] hover:text-white border border-[#4b85d1]/30 text-xs font-bold flex items-center justify-center transition-all">افزودن به Sing-box</a>
                <a href="{streisand_deep}" class="btn-press min-h-[42px] px-3 rounded-xl bg-[#4b85d1]/15 hover:bg-[#4b85d1] text-[#4b85d1] hover:text-white border border-[#4b85d1]/30 text-xs font-bold flex items-center justify-center transition-all">افزودن به Streisand</a>
            </div>
        </div>

        <div class="w-full py-2 animate-enter stagger-3">
            <div class="space-y-4">
                <div class="flex flex-wrap items-center justify-between gap-3">
                    <h2 class="text-lg sm:text-xl font-bold flex items-center gap-2">
                        <svg class="w-5 h-5 text-[#4b85d1]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>
                        لینک‌های اتصال و کانفیگ
                    </h2>
                    <div class="flex items-center gap-2">
                        <input type="text" id="confSearch" oninput="filterConfigs()" placeholder="جستجوی سرور..." class="surface-card rounded-xl px-3 py-2 text-xs focus:outline-none focus:border-[#4b85d1] w-36 sm:w-48">
                        <button type="button" onclick="copyAll(this)" class="btn-press min-h-[42px] cursor-pointer flex items-center gap-2 px-4 text-xs sm:text-sm font-bold rounded-xl transition-all duration-200 bg-[#4b85d1] hover:bg-[#3671bf] text-white shadow-md">
                            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"></rect><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"></path></svg>
                            <span>کپی همه</span>
                        </button>
                    </div>
                </div>

                <div class="p-4 rounded-2xl border-2 border-[#4b85d1]/50 bg-[#4b85d1]/10 transition-all duration-200">
                    <div class="flex items-center gap-3">
                        <span class="px-2.5 py-1 rounded-lg text-xs font-black bg-[#4b85d1] text-white shrink-0">SUB</span>
                        <div class="flex-1 min-w-0">
                            <div class="text-sm sm:text-base font-bold">لینک هوشمند اشتراک (پیشنهادی)</div>
                            <div class="text-[11px] opacity-75 truncate font-mono mt-0.5" dir="ltr">{ctx['sub_url']}</div>
                        </div>
                        <div class="flex gap-2 shrink-0">
                            <button type="button" onclick="copySubUrl(this)" aria-label="کپی لینک اشتراک" class="btn-press touch-target rounded-xl transition-all cursor-pointer bg-white dark:bg-zinc-800 hover:bg-[#4b85d1] hover:text-white shadow-xs" title="کپی لینک ساب">
                                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"></rect><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"></path></svg>
                            </button>
                            <button type="button" onclick="showSubQR()" aria-label="نمایش کد QR اشتراک" class="btn-press touch-target rounded-xl bg-white dark:bg-zinc-800 hover:bg-slate-200 dark:hover:bg-zinc-700 transition-all cursor-pointer shadow-xs" title="کد QR">
                                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 12v4a1 1 0 0 1-1 1h-4"></path><path d="M17 3h2a2 2 0 0 1 2 2v2"></path><path d="M17 8V7"></path><path d="M21 17v2a2 2 0 0 1-2 2h-2"></path><path d="M3 7V5a2 2 0 0 1 2-2h2"></path><path d="M7 17h.01"></path><path d="M7 21H5a2 2 0 0 1-2-2v-2"></path><rect x="7" y="7" width="5" height="5" rx="1"></rect></svg>
                            </button>
                        </div>
                    </div>
                </div>

                <div class="max-h-[440px] overflow-y-auto space-y-2.5 pl-1 pr-0.5">
                    {conf_items}
                </div>
            </div>
        </div>

        <div class="my-12 animate-enter stagger-4">
            <div class="flex items-center gap-4 mb-6">
                <div class="flex-1 h-px bg-gradient-to-r from-transparent via-slate-300 dark:via-zinc-800 to-transparent"></div>
                <div class="px-5 py-2 rounded-full bg-[#4b85d1]/15 text-sm font-bold text-[#4b85d1] border border-[#4b85d1]/30">
                    دریافت نرم‌افزارهای اتصال
                </div>
                <div class="flex-1 h-px bg-gradient-to-r from-transparent via-slate-300 dark:via-zinc-800 to-transparent"></div>
            </div>

            <div role="tablist" class="flex justify-center flex-wrap gap-2 mb-6">
                <button type="button" onclick="switchTab('android')" id="tab-btn-android" class="tab-button btn-press active text-xs sm:text-sm cursor-pointer">اندروید</button>
                <button type="button" onclick="switchTab('ios')" id="tab-btn-ios" class="tab-button btn-press text-xs sm:text-sm cursor-pointer">آیفون (iOS)</button>
                <button type="button" onclick="switchTab('windows')" id="tab-btn-windows" class="tab-button btn-press text-xs sm:text-sm cursor-pointer">ویندوز</button>
                <button type="button" onclick="switchTab('mac_linux')" id="tab-btn-mac_linux" class="tab-button btn-press text-xs sm:text-sm cursor-pointer">مک / لینوکس</button>
            </div>

            <div id="tab-android" class="platform-tab-content grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3.5 animate-enter">{android_apps}</div>
            <div id="tab-ios" class="platform-tab-content hidden grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3.5 animate-enter">{ios_apps}</div>
            <div id="tab-windows" class="platform-tab-content hidden grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3.5 animate-enter">{win_apps}</div>
            <div id="tab-mac_linux" class="platform-tab-content hidden grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3.5 animate-enter">{mac_apps}</div>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>داشبورد اشتراک | {safe_brand}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/misc/Farsi-Digits/Vazirmatn-FD-font-face.css">
    <script>tailwind.config = {{ darkMode: 'class' }}</script>
    <style>{ANIMATED_DESIGN_SYSTEM_CSS}</style>
</head>
<body class="min-h-screen flex flex-col justify-between overflow-x-hidden selection:bg-[#4b85d1] selection:text-white">

    <main class="container mx-auto px-4 pt-10 pb-6 max-w-5xl relative z-10 flex-1">
        <header class="flex items-center justify-between gap-4 mb-8 sm:mb-10 animate-enter">
            <div class="flex-1 min-w-0">
                <h1 class="text-2xl sm:text-4xl font-extrabold mb-1.5">داشبورد اشتراک</h1>
                <div class="flex items-center gap-3 text-sm opacity-75">
                    <p dir="ltr" class="font-bold text-[#4b85d1] truncate">{safe_brand}</p>
                    <div class="flex items-center gap-1.5">
                        <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
                        <span class="text-xs">سرور ابری</span>
                    </div>
                </div>
            </div>
            <div class="flex items-center gap-2">
                <button type="button" onclick="location.reload()" aria-label="بروزرسانی اطلاعات" class="btn-press touch-target rounded-xl surface-card hover:border-[#4b85d1] hover:text-[#4b85d1] transition-all cursor-pointer" title="بروزرسانی">
                    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"></path><path d="M3 3v5h5"></path><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"></path><path d="M16 16h5v5"></path></svg>
                </button>
                <button type="button" onclick="document.documentElement.classList.toggle('dark')" aria-label="تغییر تم" class="btn-press touch-target rounded-xl surface-card hover:border-[#4b85d1] hover:text-[#4b85d1] transition-all cursor-pointer" title="تغییر تم">
                    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2"></path><path d="M12 20v2"></path><path d="m4.93 4.93 1.41 1.41"></path><path d="m17.66 17.66 1.41 1.41"></path><path d="M2 12h2"></path><path d="M20 12h2"></path><path d="m6.34 17.66-1.41 1.41"></path><path d="m19.07 4.93-1.41 1.41"></path></svg>
                </button>
            </div>
        </header>

        {main_section}
    </main>

    <footer dir="rtl" class="relative w-full pb-8 pt-4 px-6 z-10">
        <div class="container mx-auto max-w-5xl flex justify-center">
            <div class="flex flex-col items-center gap-2.5">
                <a href="https://t.me/DARK_WIKI20" target="_blank" rel="noopener noreferrer" class="btn-press min-h-[42px] inline-flex items-center gap-2 px-5 rounded-xl bg-[#4b85d1]/10 hover:bg-[#4b85d1]/20 text-[#4b85d1] text-xs font-bold transition-all border border-[#4b85d1]/25">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 5.636l-3.536 3.536m0 5.656l3.536 3.536M9.172 9.172L5.636 5.636m3.536 9.192l-3.536 3.536M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-5 0a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
                    <span>پشتیبانی تلگرام:</span>
                    <span class="en-digits font-bold">@DARK_WIKI20</span>
                </a>
            </div>
        </div>
    </footer>

    <div id="toastBox" role="status" aria-live="polite" class="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 hidden px-5 py-3 rounded-2xl bg-slate-900 dark:bg-white text-white dark:text-slate-900 text-xs font-bold shadow-2xl animate-enter"></div>

    <div id="qrModal" class="fixed inset-0 bg-black/65 backdrop-blur-xs hidden items-center justify-center z-50 p-4" onclick="closeQR()">
        <div class="surface-card p-6 rounded-3xl shadow-2xl max-w-xs w-full flex flex-col items-center text-center animate-enter" onclick="event.stopPropagation()">
            <h3 class="font-bold text-sm mb-4">اسکن کد QR</h3>
            <img id="qrImage" src="" alt="QR Code" width="208" height="208" class="w-52 h-52 rounded-2xl mb-4 p-2.5 bg-white shadow-inner">
            <button type="button" onclick="closeQR()" class="btn-press w-full min-h-[44px] bg-slate-200 dark:bg-zinc-800 hover:opacity-90 text-xs font-bold rounded-xl transition-opacity cursor-pointer">بستن</button>
        </div>
    </div>

    <script>
        const subUrl = {json.dumps(ctx['sub_url'])};
        const allConfigs = {ctx['configs_json']};
        const checkSvg = '<svg class="w-4 h-4 text-emerald-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';

        function switchTab(platform) {{
            document.querySelectorAll('.platform-tab-content').forEach(el => {{
                el.classList.add('hidden');
                el.classList.remove('animate-enter');
            }});
            document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
            
            const target = document.getElementById('tab-' + platform);
            const btn = document.getElementById('tab-btn-' + platform);
            if (target) {{
                target.classList.remove('hidden');
                void target.offsetWidth;
                target.classList.add('animate-enter');
            }}
            if (btn) btn.classList.add('active');
        }}

        function filterConfigs() {{
            const q = document.getElementById('confSearch').value.toLowerCase();
            document.querySelectorAll('.config-item').forEach(el => {{
                el.style.display = el.getAttribute('data-confname').includes(q) ? '' : 'none';
            }});
        }}

        function showToast(msg) {{
            const box = document.getElementById("toastBox");
            box.textContent = msg;
            box.classList.remove("hidden");
            setTimeout(() => box.classList.add("hidden"), 2000);
        }}

        function animateCopyBtn(btn) {{
            if (!btn) return;
            const orig = btn.innerHTML;
            btn.innerHTML = checkSvg;
            setTimeout(() => {{ btn.innerHTML = orig; }}, 1200);
        }}

        function copySubUrl(btn) {{
            navigator.clipboard.writeText(subUrl);
            animateCopyBtn(btn);
            showToast("لینک اشتراک کپی شد!");
        }}
        function copyConfig(idx, btn) {{
            navigator.clipboard.writeText(allConfigs[idx]);
            animateCopyBtn(btn);
            showToast("کانفیگ کپی شد!");
        }}
        function copyAll(btn) {{
            if (allConfigs.length > 0) {{
                navigator.clipboard.writeText(allConfigs.join("\\n"));
                showToast("تمام کانفیگ‌ها کپی شدند!");
            }}
        }}

        function openQRModal(text) {{
            document.getElementById("qrImage").src = "https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=" + encodeURIComponent(text);
            document.getElementById("qrModal").classList.remove("hidden");
            document.getElementById("qrModal").classList.add("flex");
        }}
        function showSubQR() {{ openQRModal(subUrl); }}
        function showConfigQR(idx) {{ openQRModal(allConfigs[idx]); }}
        function closeQR() {{
            document.getElementById("qrModal").classList.add("hidden");
            document.getElementById("qrModal").classList.remove("flex");
        }}
    </script>
</body>
</html>"""

# ----------------- مسیرها (Routes) -----------------
@app.get("/")
async def root(request: Request):
    user_agent = request.headers.get("user-agent", "")
    with get_db() as conn:
        profile = conn.execute("SELECT * FROM profiles ORDER BY id DESC LIMIT 1").fetchone()
    
    if not profile:
        return RedirectResponse(url="/admin")
    
    if is_v2ray_client(user_agent):
        return await get_user_sub(profile["token"])
        
    return RedirectResponse(url=f"/d/{profile['token']}")

@app.get("/sub/{token}")
async def get_user_sub(token: str):
    with get_db() as conn:
        profile = conn.execute("SELECT * FROM profiles WHERE token = ?", (token,)).fetchone()
        if not profile:
            raise HTTPException(status_code=404, detail="Profile not found")
        if profile["is_blocked"] == 1:
            return Response(content="Subscription is blocked by administrator.", status_code=403)
        
        conn.execute(
            "UPDATE profiles SET sub_hits = COALESCE(sub_hits, 0) + 1, last_sub_fetch = ? WHERE token = ?",
            (now_jalali_str(), token)
        )
        conn.commit()

    try:
        sub_data = await get_cached_sub_data(token, profile["upstream_url"])
        info = sub_data["info"]
        fake_gb = profile["fake_total_gb"] or 0
        
        if info and fake_gb > 0:
            up, down, tot = apply_fake_traffic(info.get("upload", 0), info.get("download", 0), info.get("total", 0), fake_gb)
            user_info = f"upload={up}; download={down}; total={tot}; expire={info.get('expire', 0)}"
        else:
            user_info = sub_data["raw_userinfo"]
    except Exception:
        return Response(content="", status_code=502)

    return Response(
        content=sub_data["encoded_sub"],
        media_type="text/plain; charset=utf-8",
        headers={
            "subscription-userinfo": user_info,
            "Profile-Update-Interval": "6"
        }
    )

@app.get("/d/{token}", response_class=HTMLResponse)
async def user_dashboard(request: Request, token: str):
    user_agent = request.headers.get("user-agent", "")
    if is_v2ray_client(user_agent):
        return await get_user_sub(token)

    with get_db() as conn:
        profile = conn.execute("SELECT * FROM profiles WHERE token = ?", (token,)).fetchone()

    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    is_blocked = bool(profile["is_blocked"])
    upload = download = total_quota = expire_ts = 0
    configs = []
    configs_json = "[]"

    if not is_blocked:
        try:
            sub_data = await get_cached_sub_data(token, profile["upstream_url"])
            info = sub_data["info"]
            configs = sub_data["configs"]
            configs_json = sub_data["configs_json"]
            
            raw_up = info.get("upload", 0)
            raw_down = info.get("download", 0)
            raw_total = info.get("total", 0)
            expire_ts = info.get("expire", 0)
            
            fake_gb = profile["fake_total_gb"] or 0
            upload, download, total_quota = apply_fake_traffic(raw_up, raw_down, raw_total, fake_gb)
        except Exception:
            pass

    used_traffic = upload + download
    remaining = max(0, total_quota - used_traffic)
    percent = int((used_traffic / total_quota * 100)) if total_quota > 0 else 0
    percent = min(100, max(0, percent))
    dashoffset = 440 - (440 * percent / 100)

    days_left = max(0, int((expire_ts - time.time()) // 86400)) if expire_ts > 0 else "نامحدود"
    expire_jalali = "نامحدود"
    if expire_ts > 0:
        dt = datetime.fromtimestamp(expire_ts)
        jy, jm, jd = gregorian_to_jalali(dt.year, dt.month, dt.day)
        expire_jalali = to_persian_num(f"{jy}/{jm:02d}/{jd:02d}, {dt.strftime('%H:%M')}")

    clean_domain = PUBLIC_URL.replace("https://", "").replace("http://", "").strip("/")
    sub_url = f"https://{clean_domain}/sub/{token}"

    ctx = {
        "brand_name": profile["name"],
        "custom_notice": profile["custom_notice"] or "",
        "is_blocked": is_blocked,
        "percent": percent,
        "dashoffset": dashoffset,
        "total_quota": format_bytes(total_quota),
        "used_traffic": format_bytes(used_traffic),
        "remaining_traffic": format_bytes(remaining),
        "days_left": days_left,
        "expire_date": expire_jalali,
        "now_jalali": now_jalali_str(),
        "sub_url": sub_url,
        "configs": configs,
        "configs_json": configs_json
    }
    return HTMLResponse(content=render_dashboard_html(ctx))

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request):
    if not is_admin(request):
        return HTMLResponse(content=render_login_html())

    with get_db() as conn:
        profiles = conn.execute("SELECT * FROM profiles ORDER BY id DESC").fetchall()

    clean_domain = PUBLIC_URL.replace("https://", "").replace("http://", "").strip("/")
    csrf_tok = get_csrf_token(request)
    return HTMLResponse(content=render_admin_html(profiles, clean_domain, csrf_tok))

@app.post("/admin/login")
async def admin_login(request: Request):
    client_ip = get_client_ip(request)
    if not check_rate_limit(client_ip):
        return HTMLResponse(
            content=render_login_html("تعداد تلاش‌های ناموفق زیاد است. لطفاً ۱۰ دقیقه بعد امتحان کن."),
            status_code=429
        )

    form_data = await read_bounded_form(request)
    password = form_data.get("password", [""])[0]

    if secrets.compare_digest(password, ADMIN_PASSWORD):
        login_attempts.pop(client_ip, None)
        response = RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
        is_secure = not PUBLIC_URL.startswith("localhost")
        response.set_cookie(
            key=COOKIE_NAME,
            value=create_session_token(),
            httponly=True,
            secure=is_secure,
            samesite="strict",
            max_age=SESSION_TTL
        )
        return response

    record_failed_login(client_ip)
    return HTMLResponse(content=render_login_html("رمز عبور نادرست است."), status_code=401)

@app.get("/admin/logout")
async def admin_logout():
    response = RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(COOKIE_NAME)
    return response

@app.get("/admin/backup")
async def admin_backup(request: Request):
    if not is_admin(request):
        raise HTTPException(status_code=401)
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM profiles ORDER BY id DESC").fetchall()
        data = [dict(r) for r in rows]
    return JSONResponse(
        content={"backup_date": datetime.now().isoformat(), "profiles": data},
        headers={"Content-Disposition": "attachment; filename=datacenter_subs_backup.json"}
    )

@app.post("/admin/cache/clear")
async def clear_all_cache(request: Request):
    if not is_admin(request):
        raise HTTPException(status_code=401)
    form_data = await read_bounded_form(request)
    if not verify_csrf(request, form_data.get("csrf_token", [""])[0]):
        raise HTTPException(status_code=403, detail="CSRF token invalid")
    sub_cache.clear()
    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)

@app.post("/admin/profiles/add")
async def add_profile(request: Request):
    if not is_admin(request):
        raise HTTPException(status_code=401)

    form_data = await read_bounded_form(request)
    if not verify_csrf(request, form_data.get("csrf_token", [""])[0]):
        raise HTTPException(status_code=403, detail="CSRF token invalid")

    name = form_data.get("name", [""])[0].strip()[:80]
    upstream_url = form_data.get("upstream_url", [""])[0].strip()
    custom_token = form_data.get("custom_token", [""])[0].strip()
    custom_notice = form_data.get("custom_notice", [""])[0].strip()[:250]
    admin_note = form_data.get("admin_note", [""])[0].strip()[:150]
    fake_total_raw = form_data.get("fake_total_gb", ["0"])[0].strip()

    try:
        fake_total_gb = max(0.0, float(fake_total_raw)) if fake_total_raw else 0.0
    except ValueError:
        fake_total_gb = 0.0

    safe_custom = "".join(c for c in custom_token if c.isalnum() or c in "-_")[:40]
    token = safe_custom if safe_custom else secrets.token_hex(6)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    if name and is_safe_upstream_url(upstream_url):
        with get_db() as conn:
            try:
                conn.execute(
                    """INSERT INTO profiles 
                       (token, name, upstream_url, fake_total_gb, custom_notice, admin_note, is_blocked, created_at) 
                       VALUES (?, ?, ?, ?, ?, ?, 0, ?)""",
                    (token, name, upstream_url, fake_total_gb, custom_notice, admin_note, created_at)
                )
                conn.commit()
            except sqlite3.IntegrityError:
                pass

    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)

@app.post("/admin/profiles/{token}/edit")
async def edit_profile(request: Request, token: str):
    if not is_admin(request):
        raise HTTPException(status_code=401)

    form_data = await read_bounded_form(request)
    if not verify_csrf(request, form_data.get("csrf_token", [""])[0]):
        raise HTTPException(status_code=403, detail="CSRF token invalid")

    name = form_data.get("name", [""])[0].strip()[:80]
    upstream_url = form_data.get("upstream_url", [""])[0].strip()
    custom_notice = form_data.get("custom_notice", [""])[0].strip()[:250]
    admin_note = form_data.get("admin_note", [""])[0].strip()[:150]
    fake_total_raw = form_data.get("fake_total_gb", ["0"])[0].strip()

    try:
        fake_total_gb = max(0.0, float(fake_total_raw)) if fake_total_raw else 0.0
    except ValueError:
        fake_total_gb = 0.0

    if name and is_safe_upstream_url(upstream_url):
        with get_db() as conn:
            conn.execute(
                """UPDATE profiles 
                   SET name = ?, upstream_url = ?, fake_total_gb = ?, custom_notice = ?, admin_note = ? 
                   WHERE token = ?""",
                (name, upstream_url, fake_total_gb, custom_notice, admin_note, token)
            )
            conn.commit()

    sub_cache.pop(token, None)
    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)

@app.post("/admin/profiles/{token}/refresh-cache")
async def refresh_single_cache(request: Request, token: str):
    if not is_admin(request):
        raise HTTPException(status_code=401)
    form_data = await read_bounded_form(request)
    if not verify_csrf(request, form_data.get("csrf_token", [""])[0]):
        raise HTTPException(status_code=403)
    sub_cache.pop(token, None)
    with get_db() as conn:
        profile = conn.execute("SELECT * FROM profiles WHERE token = ?", (token,)).fetchone()
    if profile:
        try:
            await get_cached_sub_data(token, profile["upstream_url"])
        except Exception:
            pass
    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)

@app.post("/admin/profiles/{token}/toggle-block")
async def toggle_block(request: Request, token: str):
    if not is_admin(request):
        raise HTTPException(status_code=401)
    form_data = await read_bounded_form(request)
    if not verify_csrf(request, form_data.get("csrf_token", [""])[0]):
        raise HTTPException(status_code=403)

    with get_db() as conn:
        conn.execute("UPDATE profiles SET is_blocked = CASE WHEN is_blocked = 1 THEN 0 ELSE 1 END WHERE token = ?", (token,))
        conn.commit()

    sub_cache.pop(token, None)
    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)

@app.post("/admin/profiles/{token}/delete")
async def delete_profile(request: Request, token: str):
    if not is_admin(request):
        raise HTTPException(status_code=401)
    form_data = await read_bounded_form(request)
    if not verify_csrf(request, form_data.get("csrf_token", [""])[0]):
        raise HTTPException(status_code=403)

    with get_db() as conn:
        conn.execute("DELETE FROM profiles WHERE token = ?", (token,))
        conn.commit()

    sub_cache.pop(token, None)
    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)

@app.post("/webhook")
async def telegram_webhook(req: Request):
    if not BOT_TOKEN:
        return Response(status_code=200)

    header_secret = req.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    if WEBHOOK_SECRET and not secrets.compare_digest(header_secret, WEBHOOK_SECRET):
        return Response(status_code=403)

    try:
        body = await req.body()
        if len(body) > MAX_REQUEST_BODY:
            return Response(status_code=413)
        update = json.loads(body.decode("utf-8"))
    except Exception:
        return Response(status_code=200)

    if "message" not in update:
        return Response(status_code=200)

    message = update["message"]
    chat_id = message.get("chat", {}).get("id")
    text = message.get("text", "")

    if text.startswith(("/start", "/stats")):
        with get_db() as conn:
            profile = conn.execute("SELECT * FROM profiles ORDER BY id DESC LIMIT 1").fetchone()

        if not profile:
            caption = "هیچ پروفایلی در دیتاسنتر ثبت نشده است."
        else:
            try:
                sub_data = await get_cached_sub_data(profile["token"], profile["upstream_url"])
                info = sub_data["info"]
                fake_gb = profile["fake_total_gb"] or 0
                u, d, tot = apply_fake_traffic(info.get("upload", 0), info.get("download", 0), info.get("total", 0), fake_gb)
                
                used_gb = (u + d) / (1024**3)
                total_gb = tot / (1024**3)
                remaining_gb = max(0.0, total_gb - used_gb)
            except Exception:
                used_gb = total_gb = remaining_gb = 0.0

            clean_domain = PUBLIC_URL.replace("https://", "").replace("http://", "").strip("/")
            sub_link = f"https://{clean_domain}/sub/{profile['token']}"
            dash_link = f"https://{clean_domain}/d/{profile['token']}"

            caption = (
                f"🏷 Brand: {profile['name']}\n"
                f"📊 Total: `{total_gb:.2f}` GB\n"
                f"📉 Used: `{used_gb:.2f}` GB\n"
                f"📈 Remaining: `{remaining_gb:.2f}` GB\n"
                f"🔄 Client Syncs: `{profile['sub_hits'] or 0}`\n\n"
                f"🌐 داشبورد وب:\n{dash_link}\n\n"
                f"🔗 لینک ساب v2ray:\n`{sub_link}`\n\n"
                f"⚡ Support: @DARK_WIKI20"
            )

        await http_client.post(
            f"{TELEGRAM_API}/sendMessage",
            json={"chat_id": chat_id, "text": caption, "parse_mode": "Markdown"}
        )

    return Response(status_code=200)
