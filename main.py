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
from datetime import datetime, timezone
from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import Response, HTMLResponse, RedirectResponse, JSONResponse
from fastapi.middleware.gzip import GZipMiddleware

BRAND_DEFAULT = os.getenv("BRAND_NAME", "VIP")
PUBLIC_URL = (
    os.getenv("RENDER_EXTERNAL_HOSTNAME")
    or os.getenv("RAILWAY_PUBLIC_DOMAIN")
    or os.getenv("PUBLIC_URL", "localhost:8000")
)
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "SuperSecretLongPassword_987654321_ChangeMe!")
BOT_TOKEN = os.getenv("BOT_TOKEN", "")

# مسیر امنیتی مدیریت (قابل شخصی‌سازی در متغیرهای محیطی)
ADMIN_SECRET_PATH = os.getenv("ADMIN_SECRET_PATH", "manage-panel-x92").strip("/")

SECRET_KEY = hashlib.sha256(f"{ADMIN_PASSWORD}_datacenter_v3_salt".encode()).digest()
WEBHOOK_SECRET = hashlib.sha256(f"{BOT_TOKEN}_tg_webhook".encode()).hexdigest()[:32] if BOT_TOKEN else ""

DATA_DIR = "/data" if os.path.exists("/data") else "."
DB_FILE = os.path.join(DATA_DIR, "datacenter_subs.db")
COOKIE_NAME = "admin_session"
SESSION_TTL = 86400 * 7
TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"

CACHE_TTL = int(os.getenv("CACHE_TTL", "120"))
MAX_CACHE_SIZE = 200
MAX_REQUEST_BODY = 1048576
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

# ----------------- چرخه حیات و شبکه -----------------
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

# ----------------- تاریخ و ترافیک -----------------
PERSIAN_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")

def to_persian_num(s: str) -> str:
    return str(s).translate(PERSIAN_DIGITS)

def parse_datetime_to_timestamp(val) -> float:
    if not val:
        return 0.0
    if isinstance(val, (int, float)):
        return float(val)
    val_str = str(val).strip()
    try:
        return float(val_str)
    except ValueError:
        pass

    try:
        clean_iso = val_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        pass

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M:%S"):
        try:
            dt = datetime.strptime(val_str, fmt).replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            continue
    return 0.0

def format_relative_time(past_timestamp: float) -> str:
    try:
        diff = int(time.time() - past_timestamp)
        if diff < 0:
            return "هم‌اکنون"
        if diff < 60:
            return f"{to_persian_num(str(diff))} ثانیه قبل"
        minutes = diff // 60
        if minutes < 60:
            return f"{to_persian_num(str(minutes))} دقیقه قبل"
        hours = minutes // 60
        if hours < 24:
            return f"{to_persian_num(str(hours))} ساعت قبل"
        days = hours // 24
        if days < 7:
            return f"{to_persian_num(str(days))} روز قبل"
        weeks = days // 7
        if weeks < 4:
            return f"{to_persian_num(str(weeks))} هفته قبل"
        months = days // 30
        return f"{to_persian_num(str(months))} ماه قبل"
    except Exception:
        return "نامشخص"

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

def parse_user_info(header_val: str, all_headers: dict = None) -> dict:
    data = {}
    if header_val:
        for item in header_val.split(";"):
            if "=" in item:
                k, v = item.strip().split("=", 1)
                k_clean = k.strip().lower()
                v_clean = v.strip()
                try:
                    data[k_clean] = int(float(v_clean))
                except ValueError:
                    data[k_clean] = v_clean

    if all_headers:
        for possible_key in ("last-online", "x-last-online", "last-use", "online-status", "status"):
            if possible_key in all_headers and possible_key not in data:
                val = all_headers[possible_key]
                try:
                    data[possible_key] = int(float(val))
                except ValueError:
                    data[possible_key] = val

    return data

async def fetch_upstream_online_status(upstream_url: str) -> tuple[bool, str]:
    try:
        clean_url = upstream_url.rstrip("/")
        try:
            res_info = await http_client.get(
                f"{clean_url}/info",
                headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
                timeout=5.0
            )
            if res_info.status_code == 200:
                data = res_info.json()
                if isinstance(data, dict):
                    online_val = data.get("online_at") or data.get("last_online") or data.get("last_use")
                    if online_val:
                        ts = parse_datetime_to_timestamp(online_val)
                        if ts > 0:
                            diff = time.time() - ts
                            if 0 <= diff <= 180:
                                return True, "متصل"
                            return False, format_relative_time(ts)
                    if data.get("is_online") is True or str(data.get("status", "")).lower() == "online":
                        return True, "متصل"
        except Exception:
            pass

        try:
            res_html = await http_client.get(
                upstream_url,
                headers={"Accept": "text/html", "User-Agent": "Mozilla/5.0"},
                timeout=5.0
            )
            if res_html.status_code == 200:
                html_text = res_html.text
                match_online = re.search(r'"online_at"\s*:\s*"([^"]+)"', html_text)
                if not match_online:
                    match_online = re.search(r'"(?:last_online|last_use|online_at)"\s*:\s*([0-9]+(?:\.[0-9]+)?)', html_text)
                
                if match_online:
                    ts = parse_datetime_to_timestamp(match_online.group(1))
                    if ts > 0:
                        diff = time.time() - ts
                        if 0 <= diff <= 180:
                            return True, "متصل"
                        return False, format_relative_time(ts)
        except Exception:
            pass

    except Exception:
        pass

    return False, "نامشخص"

def extract_online_status(info: dict, configs: list) -> tuple[bool, str]:
    try:
        now = time.time()
        for key in ("last_online", "last-online", "last_use", "last-use", "online_at"):
            if key in info:
                ts = parse_datetime_to_timestamp(info[key])
                if ts > 0:
                    diff = now - ts
                    if 0 <= diff <= 180:
                        return True, "متصل"
                    return False, format_relative_time(ts)

        for c in configs:
            name_lower = str(c.get("name", "")).lower()
            if "online" in name_lower or "متصل" in name_lower:
                return True, "متصل"
            if "آخرین اتصال" in name_lower or "last seen" in name_lower:
                clean_txt = c["name"].replace("آخرین اتصال:", "").replace("آخرین اتصال", "").replace("last seen:", "").strip()
                return False, clean_txt if clean_txt else "نامشخص"

        return False, "نامشخص"
    except Exception:
        return False, "نامشخص"

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
    info = parse_user_info(resp_headers.get("subscription-userinfo", ""), resp_headers)
    
    is_online, last_seen_text = await fetch_upstream_online_status(upstream_url)
    if not is_online and last_seen_text == "نامشخص":
        is_online, last_seen_text = extract_online_status(info, configs)

    data = {
        "configs": configs,
        "configs_json": json.dumps([c["link"] for c in configs]),
        "encoded_sub": encoded_sub,
        "info": info,
        "is_online": is_online,
        "last_seen_text": last_seen_text,
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

# ----------------- دیزاین سیستم اصلاح‌شده (UNSLOP) -----------------
ANIMATED_DESIGN_SYSTEM_CSS = """
:root {
    --bg-base: #090a0f;
    --bg-surface: #11131a;
    --bg-surface-elevated: #161922;
    --bg-input: #0c0e14;
    
    --border-subtle: rgba(255, 255, 255, 0.07);
    --border-hover: rgba(255, 255, 255, 0.16);
    --border-focus: #3b82f6;

    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;

    --accent-primary: #3b82f6;
    --accent-hover: #2563eb;
    --accent-subtle: rgba(59, 130, 246, 0.12);
    --accent-border: rgba(59, 130, 246, 0.28);

    --status-active-bg: rgba(16, 185, 129, 0.1);
    --status-active-text: #34d399;
    --status-active-border: rgba(16, 185, 129, 0.25);

    --status-danger-bg: rgba(244, 63, 94, 0.1);
    --status-danger-text: #fb7185;
    --status-danger-border: rgba(244, 63, 94, 0.25);
}

* {
    box-sizing: border-box;
    scrollbar-width: thin;
    scrollbar-color: rgba(255, 255, 255, 0.18) transparent;
}
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.18); border-radius: 9999px; }
::-webkit-scrollbar-thumb:hover { background: rgba(255, 255, 255, 0.35); }

body {
    font-family: 'Vazirmatn FD', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background-color: var(--bg-base);
    color: var(--text-primary);
    -webkit-font-smoothing: antialiased;
}

.mono-num {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
    font-variant-numeric: tabular-nums;
    direction: ltr !important;
    display: inline-block;
}

.surface-box {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 16px;
}

.surface-card {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 14px;
    transition: border-color 0.15s ease;
}
.surface-card:hover {
    border-color: var(--border-hover);
}

.btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    font-weight: 600;
    line-height: 1;
    border-radius: 10px;
    transition: all 0.14s ease;
    cursor: pointer;
    user-select: none;
    border: 1px solid transparent;
}
.btn:active {
    transform: scale(0.97);
}

.btn-primary {
    background-color: var(--accent-primary);
    color: #ffffff;
}
.btn-primary:hover {
    background-color: var(--accent-hover);
}

.btn-secondary {
    background-color: var(--bg-surface-elevated);
    border: 1px solid var(--border-subtle);
    color: var(--text-primary);
}
.btn-secondary:hover {
    background-color: #1e2230;
    border-color: var(--border-hover);
}

.input-field {
    width: 100%;
    background-color: var(--bg-input);
    border: 1px solid var(--border-subtle);
    border-radius: 10px;
    padding: 0.65rem 0.875rem;
    font-size: 0.8125rem;
    color: var(--text-primary);
    outline: none;
    transition: border-color 0.15s ease;
}
.input-field:focus {
    border-color: var(--border-focus);
}

.tab-btn {
    padding: 0.55rem 1rem;
    border-radius: 10px;
    font-size: 0.8125rem;
    font-weight: 600;
    color: var(--text-secondary);
    background: transparent;
    border: 1px solid transparent;
    cursor: pointer;
    transition: all 0.15s ease;
}
.tab-btn.active {
    color: #ffffff;
    background-color: var(--bg-surface-elevated);
    border-color: var(--border-subtle);
}
.tab-btn:hover:not(.active) {
    color: var(--text-primary);
}
"""

def render_login_html(admin_path: str, error: str = None) -> str:
    err_box = f"""
    <div class="p-3 mb-4 rounded-xl text-xs font-semibold text-center border" style="background-color: var(--status-danger-bg); color: var(--status-danger-text); border-color: var(--status-danger-border);">
        {html.escape(error)}
    </div>""" if error else ""

    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>مدیریت | ورود ادمین</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/misc/Farsi-Digits/Vazirmatn-FD-font-face.css">
    <style>{ANIMATED_DESIGN_SYSTEM_CSS}</style>
</head>
<body class="min-h-screen flex items-center justify-center p-4">
    <div class="surface-box w-full max-w-sm p-6 sm:p-8 shadow-2xl">
        <div class="flex items-center justify-center mb-6">
            <div class="w-12 h-12 rounded-xl flex items-center justify-center bg-blue-500/10 border border-blue-500/25 text-blue-400">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" stroke-width="2"></rect><path d="M7 11V7a5 5 0 0110 0v4" stroke-width="2"></path></svg>
            </div>
        </div>
        <h1 class="text-base font-bold text-center mb-1 text-slate-100">احراز هویت سرور</h1>
        <p class="text-xs text-slate-400 text-center mb-6">دسترسی محدود به مدیر دیتاسنتر</p>
        {err_box}
        <form action="/{admin_path}/login" method="post" class="space-y-4">
            <div>
                <label for="admin_pass" class="block text-xs text-slate-400 mb-1.5 font-medium">رمز عبور امنیتی</label>
                <input id="admin_pass" type="password" name="password" required autofocus class="input-field mono-num text-left">
            </div>
            <button type="submit" class="btn btn-primary w-full py-2.5">ورود به پنل</button>
        </form>
    </div>
</body>
</html>"""

def render_admin_html(profiles, domain: str, csrf_token: str, admin_path: str) -> str:
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
        last_fetch = html.escape(p["last_sub_fetch"] or "اتصال ثبت نشده")
        fake_val = p["fake_total_gb"] or 0

        cached_data = sub_cache.get(p["token"])
        if cached_data and cached_data.get("info"):
            info = cached_data["info"]
            u, d, tot = apply_fake_traffic(info.get("upload", 0), info.get("download", 0), info.get("total", 0), fake_val)
            traffic_badge = f"<span class='text-xs mono-num text-slate-200'>{format_bytes(u+d)} / {format_bytes(tot)}</span>"
            
            if cached_data.get("is_online"):
                online_badge = '<span class="inline-flex items-center gap-1.5 text-xs text-emerald-400 font-semibold"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>متصل</span>'
            else:
                last_s = cached_data.get("last_seen_text", "نامشخص")
                online_badge = f'<span class="text-xs text-slate-400">{last_s}</span>'
        else:
            traffic_badge = "<span class='text-xs text-slate-500'>—</span>"
            online_badge = "<span class='text-xs text-slate-500'>—</span>"

        status_badge = (
            '<span class="px-2 py-0.5 rounded-md text-[11px] font-semibold border" style="background-color: var(--status-danger-bg); color: var(--status-danger-text); border-color: var(--status-danger-border);">مسدود</span>'
            if p["is_blocked"] else
            '<span class="px-2 py-0.5 rounded-md text-[11px] font-semibold border" style="background-color: var(--status-active-bg); color: var(--status-active-text); border-color: var(--status-active-border);">فعال</span>'
        )
        fake_label = f"<span class='mono-num text-xs text-blue-400 font-bold'>{fake_val:g} GB</span>" if fake_val > 0 else "<span class='text-slate-500 text-xs'>واقعی</span>"
        
        btn_class = "btn-secondary text-emerald-400 border-emerald-500/30 hover:border-emerald-500/50" if p["is_blocked"] else "btn-secondary text-amber-400 border-amber-500/30 hover:border-amber-500/50"
        btn_text = "فعال‌سازی" if p["is_blocked"] else "مسدود"
        
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
        note_html = f'<div class="text-[11px] text-amber-400/80 mt-1 font-mono leading-tight">{safe_note}</div>' if safe_note else ''
        notice_indicator = '<span class="inline-block mr-1 text-[10px] px-1.5 py-0.2 rounded border border-blue-500/30 bg-blue-500/10 text-blue-400">اعلان</span>' if safe_notice else ''

        rows += f"""
        <tr class="profile-row border-b border-white/[0.04] hover:bg-white/[0.02] transition-colors" data-name="{safe_name.lower()} {safe_token.lower()} {safe_note.lower()}" data-status="{'blocked' if p['is_blocked'] else 'active'}">
            <td class="p-3.5 whitespace-nowrap">
                <div class="font-bold text-sm text-slate-200">{safe_name} {notice_indicator}</div>
                {note_html}
            </td>
            <td class="p-3.5 whitespace-nowrap">
                <div class="flex items-center gap-1.5">
                    <button type="button" onclick="copyText('{dash_url}', 'لینک داشبورد کپی شد')" class="btn btn-secondary px-2.5 py-1 text-xs">داشبورد</button>
                    <button type="button" onclick="copyText('{sub_url}', 'لینک اشتراک کپی شد')" class="btn btn-secondary px-2.5 py-1 text-xs">ساب</button>
                    <button type="button" onclick="openQR('{sub_url}', '{safe_name}')" class="btn btn-secondary p-1.5" title="QR Code">
                        <svg class="w-3.5 h-3.5 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
                    </button>
                </div>
            </td>
            <td class="p-3.5 whitespace-nowrap text-center">{online_badge}</td>
            <td class="p-3.5 whitespace-nowrap text-center">{fake_label}</td>
            <td class="p-3.5 whitespace-nowrap text-center">{traffic_badge}</td>
            <td class="p-3.5 whitespace-nowrap">
                <div class="text-xs font-semibold mono-num text-slate-300">{hits} بار</div>
                <div class="text-[11px] text-slate-500 mt-0.5">{last_fetch}</div>
            </td>
            <td class="p-3.5 whitespace-nowrap text-center">{status_badge}</td>
            <td class="p-3.5 whitespace-nowrap text-left">
                <div class="flex justify-end items-center gap-1.5">
                    <button type="button" onclick="openEditModal({p_json})" class="btn btn-secondary px-2.5 py-1 text-xs">ویرایش</button>
                    <form action="/{admin_path}/profiles/{safe_token}/refresh-cache" method="post" class="m-0">
                        <input type="hidden" name="csrf_token" value="{csrf_token}">
                        <button type="submit" class="btn btn-secondary p-1.5 text-slate-400" title="تازه‌سازی کش">
                            <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"></path></svg>
                        </button>
                    </form>
                    <form action="/{admin_path}/profiles/{safe_token}/toggle-block" method="post" class="m-0">
                        <input type="hidden" name="csrf_token" value="{csrf_token}">
                        <button type="submit" class="btn px-2.5 py-1 text-xs {btn_class}">{btn_text}</button>
                    </form>
                    <form action="/{admin_path}/profiles/{safe_token}/delete" method="post" class="m-0" onsubmit="return confirm('تایید حذف نهایی ساب؟');">
                        <input type="hidden" name="csrf_token" value="{csrf_token}">
                        <button type="submit" class="btn btn-secondary px-2.5 py-1 text-xs text-rose-400 border-rose-500/30 hover:border-rose-500/50">حذف</button>
                    </form>
                </div>
            </td>
        </tr>"""

    if not rows:
        rows = '<tr><td colspan="8" class="p-8 text-center text-slate-500 text-xs">هنوز هیچ اشتراکی ساخته نشده است.</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>داشبورد مدیریت دیتاسنتر</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/misc/Farsi-Digits/Vazirmatn-FD-font-face.css">
    <style>{ANIMATED_DESIGN_SYSTEM_CSS}</style>
</head>
<body class="min-h-screen p-4 sm:p-6 lg:p-8">
    <div class="max-w-7xl mx-auto space-y-6">
        
        <!-- هدر کنترل پنل -->
        <header class="surface-box p-5 flex flex-wrap justify-between items-center gap-4">
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/25 flex items-center justify-center text-blue-400">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h7"></path></svg>
                </div>
                <div>
                    <h1 class="text-base font-bold text-slate-100">کنترل پنل مرکزی</h1>
                    <div class="text-xs text-slate-500 mono-num mt-0.5">{domain}</div>
                </div>
            </div>
            <div class="flex flex-wrap items-center gap-2">
                <form action="/{admin_path}/cache/clear" method="post" class="m-0">
                    <input type="hidden" name="csrf_token" value="{csrf_token}">
                    <button type="submit" class="btn btn-secondary px-3 py-2 text-xs">پاکسازی کش ({cached_items})</button>
                </form>
                <a href="/{admin_path}/backup" class="btn btn-secondary px-3 py-2 text-xs text-blue-400">دانلود بکاپ JSON</a>
                <a href="/{admin_path}/logout" class="btn btn-secondary px-3 py-2 text-xs text-rose-400">خروج</a>
            </div>
        </header>

        <!-- آمار کلی سیستم (KPI) -->
        <section class="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
            <div class="surface-card p-4">
                <div class="text-xs text-slate-400 mb-1">کل اشتراک‌ها</div>
                <div class="text-2xl font-bold mono-num text-slate-100">{total_count}</div>
            </div>
            <div class="surface-card p-4">
                <div class="text-xs text-slate-400 mb-1">فعال</div>
                <div class="text-2xl font-bold mono-num text-emerald-400">{active_count}</div>
            </div>
            <div class="surface-card p-4">
                <div class="text-xs text-slate-400 mb-1">مسدود شده</div>
                <div class="text-2xl font-bold mono-num text-rose-400">{blocked_count}</div>
            </div>
            <div class="surface-card p-4">
                <div class="text-xs text-slate-400 mb-1">درخواست‌های آپدیت کلاینت</div>
                <div class="text-2xl font-bold mono-num text-blue-400">{total_hits}</div>
            </div>
        </section>

        <!-- ثبت اشتراک و بازیابی بکاپ -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <section class="lg:col-span-2 surface-box p-5">
                <h2 class="text-sm font-bold text-slate-200 mb-4 flex items-center gap-2">
                    <svg class="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg>
                    ثبت اشتراک جدید
                </h2>
                <form action="/{admin_path}/profiles/add" method="post" class="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                    <input type="hidden" name="csrf_token" value="{csrf_token}">
                    <div>
                        <label class="block text-xs text-slate-400 mb-1">نام یا شناسه کاربری *</label>
                        <input type="text" name="name" placeholder="User-VIP" required class="input-field">
                    </div>
                    <div>
                        <label class="block text-xs text-slate-400 mb-1">لینک مستقیم فروشنده (Upstream) *</label>
                        <input type="url" name="upstream_url" placeholder="https://panel.site/sub/..." required class="input-field mono-num text-left">
                    </div>
                    <div>
                        <label class="block text-xs text-slate-400 mb-1">حجم مجازی کل (GB) — اختیاری</label>
                        <input type="number" step="0.1" min="0" name="fake_total_gb" placeholder="0 = حجم واقعی" class="input-field mono-num text-left">
                    </div>
                    <div>
                        <label class="block text-xs text-slate-400 mb-1">توکن اختصاصی لینک (اختیاری)</label>
                        <input type="text" name="custom_token" placeholder="خالی = تصادفی" class="input-field mono-num text-left">
                    </div>
                    <div>
                        <label class="block text-xs text-slate-400 mb-1">اعلان اختصاصی در داشبورد</label>
                        <input type="text" name="custom_notice" placeholder="متن پیام به کاربر..." class="input-field">
                    </div>
                    <div>
                        <label class="block text-xs text-slate-400 mb-1">یادداشت داخلی ادمین</label>
                        <input type="text" name="admin_note" placeholder="آیدی تلگرام، تاریخ و..." class="input-field">
                    </div>
                    <div class="md:col-span-2 pt-2">
                        <button type="submit" class="btn btn-primary px-6 py-2.5">ایجاد و ذخیره اشتراک</button>
                    </div>
                </form>
            </section>

            <section class="surface-box p-5 flex flex-col justify-between">
                <div>
                    <h2 class="text-sm font-bold text-slate-200 mb-2 flex items-center gap-2">
                        <svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"></path></svg>
                        بازگردانی داده‌ها از بکاپ
                    </h2>
                    <p class="text-xs text-slate-400 mb-4 leading-relaxed">فایل JSON بکاپ قبلی خود را برای بازیابی سریع در کادر زیر انتخاب کنید.</p>
                    <input type="file" id="dashboardBackupFile" accept=".json" class="input-field text-xs mb-3">
                    <label class="flex items-center gap-2 text-xs text-slate-300 select-none cursor-pointer">
                        <input type="checkbox" id="overwrite_backup_chk" class="rounded border-zinc-700 bg-zinc-900">
                        <span>به‌روزرسانی رکوردهای تکراری</span>
                    </label>
                </div>
                <button type="button" onclick="uploadAndRestoreBackup()" id="btnUploadBackup" class="btn btn-secondary w-full py-2.5 mt-4 text-emerald-400">آپلود و بازیابی اطلاعات</button>
            </section>
        </div>

        <!-- جدول لیست ساب‌ها -->
        <section class="surface-box overflow-hidden">
            <div class="p-4 border-b border-white/[0.06] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <h2 class="text-sm font-bold text-slate-200">فهرست اشتراک‌ها ({total_count})</h2>
                <div class="flex items-center gap-2">
                    <input type="text" id="searchInput" oninput="filterTable()" placeholder="جستجو نام، توکن، یادداشت..." class="input-field py-1.5 px-3 text-xs w-60">
                    <select id="statusFilter" onchange="filterTable()" class="input-field py-1.5 px-3 text-xs w-28">
                        <option value="all">همه</option>
                        <option value="active">فعال</option>
                        <option value="blocked">مسدود</option>
                    </select>
                </div>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-right text-sm">
                    <thead class="bg-white/[0.02] text-slate-400 text-xs border-b border-white/[0.06]">
                        <tr>
                            <th class="p-3.5 whitespace-nowrap">کاربر</th>
                            <th class="p-3.5 whitespace-nowrap">لینک‌ها</th>
                            <th class="p-3.5 whitespace-nowrap text-center">وضعیت لایو</th>
                            <th class="p-3.5 whitespace-nowrap text-center">حجم مجازی</th>
                            <th class="p-3.5 whitespace-nowrap text-center">مصرف / سقف</th>
                            <th class="p-3.5 whitespace-nowrap">همگام‌سازی</th>
                            <th class="p-3.5 whitespace-nowrap text-center">دسترسی</th>
                            <th class="p-3.5 text-left whitespace-nowrap">مدیریت</th>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </section>
    </div>

    <!-- مدال ویرایش -->
    <div id="editModal" class="fixed inset-0 bg-black/70 backdrop-blur-xs hidden items-center justify-center z-50 p-4" onclick="closeEditModal()">
        <div class="surface-box rounded-2xl p-6 max-w-md w-full shadow-2xl" onclick="event.stopPropagation()">
            <h3 class="text-base font-bold mb-4 text-slate-100">ویرایش اشتراک</h3>
            <form id="editForm" method="post" class="space-y-3">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                <div>
                    <label class="block text-xs text-slate-400 mb-1">نام یا شناسه کاربر</label>
                    <input type="text" id="edit_name" name="name" required class="input-field">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">لینک مستقیم فروشنده</label>
                    <input type="url" id="edit_upstream" name="upstream_url" required class="input-field mono-num text-left">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">حجم مجازی کل (GB) — 0 یعنی واقعی</label>
                    <input type="number" step="0.1" min="0" id="edit_fake" name="fake_total_gb" required class="input-field mono-num text-left">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">اعلان داشبورد</label>
                    <input type="text" id="edit_notice" name="custom_notice" class="input-field">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">یادداشت داخلی ادمین</label>
                    <input type="text" id="edit_note" name="admin_note" class="input-field">
                </div>
                <div class="flex gap-2 pt-3">
                    <button type="submit" class="btn btn-primary flex-1 py-2">ذخیره تغییرات</button>
                    <button type="button" onclick="closeEditModal()" class="btn btn-secondary px-4 py-2">انصراف</button>
                </div>
            </form>
        </div>
    </div>

    <!-- مدال QR -->
    <div id="adminQrModal" class="fixed inset-0 bg-black/70 backdrop-blur-xs hidden items-center justify-center z-50 p-4" onclick="closeAdminQR()">
        <div class="surface-box p-6 rounded-2xl max-w-xs w-full flex flex-col items-center text-center" onclick="event.stopPropagation()">
            <div id="adminQrTitle" class="font-bold text-xs text-slate-300 mb-4 truncate w-full">QR Code</div>
            <img id="adminQrImg" src="" alt="QR" class="w-48 h-48 rounded-lg mb-4 bg-white p-2">
            <button type="button" onclick="closeAdminQR()" class="btn btn-secondary w-full py-2 text-xs">بستن</button>
        </div>
    </div>

    <div id="adminToast" class="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 hidden px-4 py-2 rounded-lg bg-slate-100 text-slate-900 text-xs font-bold shadow-xl"></div>

    <script>
        const adminCsrfToken = "{csrf_token}";
        const adminPath = "{admin_path}";

        function copyText(txt, msg) {{
            navigator.clipboard.writeText(txt);
            const t = document.getElementById('adminToast');
            t.textContent = msg;
            t.classList.remove('hidden');
            setTimeout(() => t.classList.add('hidden'), 2000);
        }}
        function openQR(url, title) {{
            document.getElementById('adminQrTitle').textContent = title;
            document.getElementById('adminQrImg').src = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' + encodeURIComponent(url);
            document.getElementById('adminQrModal').classList.remove('hidden');
            document.getElementById('adminQrModal').classList.add('flex');
        }}
        function closeAdminQR() {{
            document.getElementById('adminQrModal').classList.add('hidden');
            document.getElementById('adminQrModal').classList.remove('flex');
        }}
        function openEditModal(profile) {{
            document.getElementById('editForm').action = '/' + adminPath + '/profiles/' + encodeURIComponent(profile.token) + '/edit';
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
        async function uploadAndRestoreBackup() {{
            const fileInput = document.getElementById('dashboardBackupFile');
            if (!fileInput.files.length) {{
                alert('لطفاً ابتدا فایل JSON بکاپ را انتخاب کنید.');
                return;
            }}
            const file = fileInput.files[0];
            const reader = new FileReader();
            reader.onload = async function(e) {{
                try {{
                    const parsedJson = JSON.parse(e.target.result);
                    const overwrite = document.getElementById('overwrite_backup_chk').checked;
                    const btn = document.getElementById('btnUploadBackup');
                    btn.disabled = true;
                    btn.textContent = 'در حال بازگردانی...';

                    const res = await fetch('/' + adminPath + '/backup/restore', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{
                            csrf_token: adminCsrfToken,
                            overwrite_existing: overwrite,
                            backup: parsedJson
                        }})
                    }});
                    const data = await res.json();
                    if (data.ok) {{
                        alert(data.msg);
                        location.reload();
                    }} else {{
                        alert(data.msg || 'خطا در اعمال بکاپ');
                        btn.disabled = false;
                        btn.textContent = 'آپلود و اعمال بکاپ';
                    }}
                }} catch (err) {{
                    alert('فرمت فایل JSON نامعتبر است.');
                }}
            }};
            reader.readAsText(file);
        }}
    </script>
</body>
</html>"""

def render_app_card(name_html: str, url: str, btn_label: str, recommended: bool = False) -> str:
    rec_badge = '<span class="text-[10px] font-semibold text-emerald-400 bg-emerald-500/10 border border-emerald-500/25 px-2 py-0.5 rounded-full mb-2 inline-block">پیشنهادی</span>' if recommended else '<span class="text-[10px] text-transparent mb-2 inline-block select-none">—</span>'
    return f"""
    <div class="surface-card p-4 flex flex-col items-center justify-between text-center">
        <div>
            {rec_badge}
            <div class="font-bold text-sm text-slate-200 mb-3">{name_html}</div>
        </div>
        <a href="{url}" target="_blank" rel="noopener noreferrer" class="btn btn-secondary w-full py-1.5 text-xs text-blue-400 hover:text-blue-300">{btn_label}</a>
    </div>"""

def render_dashboard_html(ctx: dict) -> str:
    safe_brand = html.escape(ctx["brand_name"])
    safe_notice = html.escape(ctx["custom_notice"]) if ctx.get("custom_notice") else "قبل از اتصال، یک‌بار دکمه Update Subscription را داخل نرم‌افزار خود بزنید."
    
    online_indicator = (
        '<div class="flex items-center gap-1.5 text-xs text-emerald-400 font-semibold">'
        '<span class="w-2 h-2 rounded-full bg-emerald-400"></span>آنلاین و در حال استفاده</div>'
        if ctx.get("is_online") else
        f'<div class="text-xs text-slate-400">آخرین اتصال: <span class="text-slate-200 font-semibold">{ctx.get("last_seen_text", "نامشخص")}</span></div>'
    )

    if ctx["is_blocked"]:
        main_section = """
        <div class="surface-box p-8 text-center border-rose-500/25 my-8">
            <div class="inline-block px-3 py-1 rounded-full text-xs font-bold text-rose-400 bg-rose-500/10 border border-rose-500/25 mb-3">مسدود شده</div>
            <div class="text-xl font-bold text-slate-100 mb-1">دسترسی این سرویس غیرفعال است</div>
            <p class="text-xs text-slate-400">جهت تمدید یا رفع انسداد با بخش پشتیبانی تماس بگیرید.</p>
        </div>"""
    else:
        conf_items = ""
        for idx, c in enumerate(ctx["configs"]):
            conf_items += f"""
            <div class="config-item surface-card p-3 flex items-center justify-between gap-3" data-confname="{c['name'].lower()} {c['proto'].lower()}">
                <div class="flex items-center gap-2.5 min-w-0">
                    <span class="mono-num text-[11px] font-bold px-2 py-0.5 rounded bg-white/[0.05] border border-white/[0.08] text-slate-300 uppercase">{c['proto']}</span>
                    <span dir="ltr" class="text-xs sm:text-sm font-semibold truncate text-slate-200">{c['name']}</span>
                </div>
                <div class="flex items-center gap-1.5 shrink-0">
                    <button type="button" onclick="copyConfig({idx}, this)" class="btn btn-secondary px-2.5 py-1 text-xs" title="کپی کانفیگ">کپی</button>
                    <button type="button" onclick="showConfigQR({idx})" class="btn btn-secondary p-1.5 text-slate-400" title="کد QR">
                        <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
                    </button>
                </div>
            </div>"""

        encoded_sub_url = urllib.parse.quote(ctx["sub_url"], safe="")
        hiddify_deep = f"hiddify://import/{ctx['sub_url']}#{urllib.parse.quote(ctx['brand_name'])}"
        v2rayng_deep = f"v2rayng://install-sub?url={encoded_sub_url}&name={urllib.parse.quote(ctx['brand_name'])}"
        singbox_deep = f"sing-box://import-remote-profile?url={encoded_sub_url}#{urllib.parse.quote(ctx['brand_name'])}"
        streisand_deep = f"streisand://import/{ctx['sub_url']}"

        android_apps = "".join([
            render_app_card("<span class='mono-num'>Hiddify</span>", "https://github.com/hiddify/hiddify-next/releases", "گیت‌هاب", True),
            render_app_card("<span class='mono-num'>v2rayNG</span>", "https://github.com/2dust/v2rayNG/releases", "گیت‌هاب", True),
            render_app_card("<span class='mono-num'>Flclash</span>", "https://github.com/chen08209/FlClash/releases", "گیت‌هاب", False),
            render_app_card("<span class='mono-num'>Sing-box</span>", "https://github.com/SagerNet/sing-box/releases", "گیت‌هاب", False),
        ])
        ios_apps = "".join([
            render_app_card("<span class='mono-num'>Hiddify</span>", "https://apps.apple.com/us/app/hiddify-proxy-vpn/id6596777532", "اپ‌استور", True),
            render_app_card("<span class='mono-num'>Streisand</span>", "https://apps.apple.com/us/app/streisand/id6450534064", "اپ‌استور", True),
            render_app_card("<span class='mono-num'>Shadowrocket</span>", "https://apps.apple.com/us/app/shadowrocket/id932747118", "اپ‌استور", True),
            render_app_card("<span class='mono-num'>Sing-box</span>", "https://apps.apple.com/us/app/sing-box/id6451272673", "اپ‌استور", False),
        ])
        win_apps = "".join([
            render_app_card("<span class='mono-num'>Hiddify</span>", "https://github.com/hiddify/hiddify-next/releases", "گیت‌هاب", True),
            render_app_card("<span class='mono-num'>v2rayN</span>", "https://github.com/2dust/v2rayN/releases", "گیت‌هاب", True),
            render_app_card("<span class='mono-num'>Flclash</span>", "https://github.com/chen08209/FlClash/releases", "گیت‌هاب", False),
            render_app_card("<span class='mono-num'>Clash Verge</span>", "https://github.com/clash-verge-rev/clash-verge-rev/releases", "گیت‌هاب", False),
        ])
        mac_apps = "".join([
            render_app_card("<span class='mono-num'>Hiddify</span>", "https://github.com/hiddify/hiddify-next/releases", "گیت‌هاب", True),
            render_app_card("<span class='mono-num'>Clash Verge</span>", "https://github.com/clash-verge-rev/clash-verge-rev/releases", "گیت‌هاب", True),
            render_app_card("<span class='mono-num'>Flclash</span>", "https://github.com/chen08209/FlClash/releases", "گیت‌هاب", False),
            render_app_card("<span class='mono-num'>Sing-box</span>", "https://github.com/SagerNet/sing-box/releases", "گیت‌هاب", False),
        ])

        main_section = f"""
        <!-- اطلاعیه اشتراک -->
        <div class="surface-box p-4 border-blue-500/20 bg-blue-500/[0.04] mb-6">
            <div class="flex items-start gap-3">
                <div class="text-blue-400 mt-0.5">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                </div>
                <div class="text-xs text-slate-300 leading-relaxed font-medium">{safe_notice}</div>
            </div>
        </div>

        <!-- خلاصه وضعیت و گیج مصرف -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <div class="md:col-span-2 surface-box p-6 flex flex-col justify-between">
                <div class="flex items-center justify-between mb-6 pb-4 border-b border-white/[0.06]">
                    <div class="flex items-center gap-3">
                        <span class="text-xs font-bold px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/25">اشتراک فعال</span>
                        {online_indicator}
                    </div>
                    <div class="text-xs text-slate-400">اعتبار: <span class="mono-num font-bold text-slate-100">{ctx['days_left']}</span> روز</div>
                </div>

                <div class="flex flex-col sm:flex-row items-center gap-6">
                    <!-- گیج دقیق وکتور بدون بلور -->
                    <div class="relative w-28 h-28 shrink-0">
                        <svg class="transform -rotate-90 w-full h-full" viewBox="0 0 120 120">
                            <circle cx="60" cy="60" r="50" stroke="rgba(255,255,255,0.06)" stroke-width="8" fill="none"></circle>
                            <circle cx="60" cy="60" r="50" stroke="#3b82f6" stroke-width="8" fill="none"
                                stroke-dasharray="314.15" stroke-dashoffset="{314.15 - (314.15 * ctx['percent'] / 100)}"
                                stroke-linecap="round" class="transition-all duration-700"></circle>
                        </svg>
                        <div class="absolute inset-0 flex flex-col items-center justify-center">
                            <span class="text-lg font-bold mono-num text-slate-100">{ctx['percent']}%</span>
                            <span class="text-[10px] text-slate-400">مصرف</span>
                        </div>
                    </div>

                    <div class="flex-1 w-full space-y-2.5">
                        <div class="flex justify-between items-center text-xs p-2 rounded-lg bg-white/[0.02]">
                            <span class="text-slate-400">کل سهمیه</span>
                            <span class="mono-num font-bold text-slate-200">{ctx['total_quota']}</span>
                        </div>
                        <div class="flex justify-between items-center text-xs p-2 rounded-lg bg-white/[0.02]">
                            <span class="text-slate-400">ترافیک مصرفی</span>
                            <span class="mono-num font-bold text-amber-400">{ctx['used_traffic']}</span>
                        </div>
                        <div class="flex justify-between items-center text-xs p-2 rounded-lg bg-emerald-500/[0.06] border border-emerald-500/20">
                            <span class="text-emerald-400 font-semibold">باقی‌مانده</span>
                            <span class="mono-num font-bold text-emerald-400">{ctx['remaining_traffic']}</span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="surface-box p-6 flex flex-col justify-between space-y-4">
                <div>
                    <div class="text-xs text-slate-400 mb-1">سرورهای در دسترس</div>
                    <div class="text-xl font-bold mono-num text-blue-400">{len(ctx['configs'])} سرور</div>
                </div>
                <div class="border-t border-white/[0.06] pt-4">
                    <div class="text-xs text-slate-400 mb-1">انقضای زمانی</div>
                    <div class="text-xs font-semibold mono-num text-slate-200">{ctx['expire_date']}</div>
                </div>
                <div class="border-t border-white/[0.06] pt-4">
                    <div class="text-xs text-slate-400 mb-1">بروزرسانی داده‌ها</div>
                    <div class="text-xs mono-num text-slate-400">{ctx['now_jalali']}</div>
                </div>
            </div>
        </div>

        <!-- لینک اختصاصی هوشمند -->
        <div class="surface-box p-4 mb-6">
            <div class="flex flex-col sm:flex-row items-center justify-between gap-3">
                <div class="min-w-0 w-full sm:w-auto">
                    <div class="text-xs font-bold text-slate-300 mb-1">لینک اختصاصی اشتراک (Smart Sub)</div>
                    <div class="text-xs mono-num text-slate-500 truncate">{ctx['sub_url']}</div>
                </div>
                <div class="flex items-center gap-2 w-full sm:w-auto justify-end">
                    <button type="button" onclick="copySubUrl(this)" class="btn btn-primary px-4 py-2 text-xs flex-1 sm:flex-initial">کپی آدرس ساب</button>
                    <button type="button" onclick="showSubQR()" class="btn btn-secondary px-3 py-2 text-xs" title="QR Code">QR</button>
                </div>
            </div>
        </div>

        <!-- اتصال مستقیم نرم‌افزار -->
        <div class="surface-box p-4 mb-6">
            <div class="text-xs font-bold text-slate-300 mb-3">ایمپورت تک‌کلیک به نرم‌افزار</div>
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-2">
                <a href="{hiddify_deep}" class="btn btn-secondary py-2 text-xs">Hiddify</a>
                <a href="{v2rayng_deep}" class="btn btn-secondary py-2 text-xs">v2rayNG</a>
                <a href="{singbox_deep}" class="btn btn-secondary py-2 text-xs">Sing-box</a>
                <a href="{streisand_deep}" class="btn btn-secondary py-2 text-xs">Streisand</a>
            </div>
        </div>

        <!-- لیست کانفیگ‌ها -->
        <div class="surface-box p-5 mb-8">
            <div class="flex flex-wrap items-center justify-between gap-3 mb-4">
                <h2 class="text-sm font-bold text-slate-200">فهرست کانفیگ‌های فعال</h2>
                <div class="flex items-center gap-2">
                    <input type="text" id="confSearch" oninput="filterConfigs()" placeholder="فیلتر سرور..." class="input-field py-1.5 px-3 text-xs w-36 sm:w-48">
                    <button type="button" onclick="copyAll(this)" class="btn btn-secondary px-3 py-1.5 text-xs">کپی یکجای همه</button>
                </div>
            </div>
            <div class="max-h-96 overflow-y-auto space-y-2 pr-1">{conf_items}</div>
        </div>

        <!-- تب دانلود نرم‌افزارها -->
        <div class="mb-10">
            <div class="text-xs font-bold text-slate-400 mb-3 text-center">دانلود کلاینت‌های استاندارد اتصال</div>
            <div class="flex justify-center gap-2 mb-4">
                <button type="button" onclick="switchTab('android')" id="tab-btn-android" class="tab-btn active">اندروید</button>
                <button type="button" onclick="switchTab('ios')" id="tab-btn-ios" class="tab-btn">آیفون (iOS)</button>
                <button type="button" onclick="switchTab('windows')" id="tab-btn-windows" class="tab-btn">ویندوز</button>
                <button type="button" onclick="switchTab('mac_linux')" id="tab-btn-mac_linux" class="tab-btn">مک / لینوکس</button>
            </div>
            <div id="tab-android" class="platform-tab-content grid grid-cols-2 sm:grid-cols-4 gap-3">{android_apps}</div>
            <div id="tab-ios" class="platform-tab-content hidden grid grid-cols-2 sm:grid-cols-4 gap-3">{ios_apps}</div>
            <div id="tab-windows" class="platform-tab-content hidden grid grid-cols-2 sm:grid-cols-4 gap-3">{win_apps}</div>
            <div id="tab-mac_linux" class="platform-tab-content hidden grid grid-cols-2 sm:grid-cols-4 gap-3">{mac_apps}</div>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>اشتراک | {safe_brand}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/misc/Farsi-Digits/Vazirmatn-FD-font-face.css">
    <style>{ANIMATED_DESIGN_SYSTEM_CSS}</style>
</head>
<body class="min-h-screen flex flex-col justify-between">
    <main class="container mx-auto px-4 py-8 max-w-4xl flex-1">
        <header class="flex items-center justify-between mb-8 pb-4 border-b border-white/[0.06]">
            <div>
                <h1 class="text-lg sm:text-xl font-bold text-slate-100">سرویس اشتراک اختصاصی</h1>
                <div class="text-xs text-blue-400 font-bold mono-num mt-0.5">{safe_brand}</div>
            </div>
            <button type="button" onclick="location.reload()" class="btn btn-secondary px-3 py-1.5 text-xs text-slate-300">
                <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"></path></svg>
                بروزرسانی
            </button>
        </header>

        {main_section}
    </main>

    <footer class="border-t border-white/[0.06] py-5 px-4 text-center">
        <a href="https://t.me/DARK_WIKI20" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors">
            <span>پشتیبانی تلگرام:</span>
            <span class="mono-num font-bold text-blue-400">@DARK_WIKI20</span>
        </a>
    </footer>

    <div id="qrModal" class="fixed inset-0 bg-black/75 backdrop-blur-xs hidden items-center justify-center z-50 p-4" onclick="closeQR()">
        <div class="surface-box p-6 rounded-2xl max-w-xs w-full flex flex-col items-center text-center" onclick="event.stopPropagation()">
            <div class="font-bold text-xs text-slate-300 mb-3">اسکن اشتراک</div>
            <img id="qrImage" src="" alt="QR Code" class="w-48 h-48 rounded-lg bg-white p-2 mb-4">
            <button type="button" onclick="closeQR()" class="btn btn-secondary w-full py-2 text-xs">بستن</button>
        </div>
    </div>

    <div id="toastBox" class="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 hidden px-4 py-2 rounded-lg bg-slate-100 text-slate-900 text-xs font-bold shadow-xl"></div>

    <script>
        const subUrl = {json.dumps(ctx['sub_url'])};
        const allConfigs = {ctx['configs_json']};

        function switchTab(platform) {{
            document.querySelectorAll('.platform-tab-content').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            const target = document.getElementById('tab-' + platform);
            const btn = document.getElementById('tab-btn-' + platform);
            if (target) target.classList.remove('hidden');
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

        function copySubUrl(btn) {{
            navigator.clipboard.writeText(subUrl);
            showToast("لینک اشتراک کپی شد");
        }}
        function copyConfig(idx, btn) {{
            navigator.clipboard.writeText(allConfigs[idx]);
            showToast("کانفیگ سرور کپی شد");
        }}
        function copyAll(btn) {{
            if (allConfigs.length > 0) {{
                navigator.clipboard.writeText(allConfigs.join("\\n"));
                showToast("تمام کانفیگ‌ها کپی شدند");
            }}
        }}

        function openQRModal(text) {{
            document.getElementById("qrImage").src = "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=" + encodeURIComponent(text);
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
async def root():
    # جهت امنیت: مسیر اصلی هیچ اطلاعاتی نشان نمی‌دهد
    raise HTTPException(status_code=404, detail="Not Found")

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
    is_online = False
    last_seen_text = "نامشخص"

    if not is_blocked:
        try:
            sub_data = await get_cached_sub_data(token, profile["upstream_url"])
            info = sub_data.get("info", {})
            configs = sub_data.get("configs", [])
            configs_json = sub_data.get("configs_json", "[]")
            is_online = sub_data.get("is_online", False)
            last_seen_text = sub_data.get("last_seen_text", "نامشخص")
            
            raw_up = info.get("upload", 0)
            raw_down = info.get("download", 0)
            raw_total = info.get("total", 0)
            expire_ts = info.get("expire", 0)
            
            fake_gb = profile["fake_total_gb"] or 0
            upload, download, total_quota = apply_fake_traffic(raw_up, raw_down, raw_total, fake_gb)
        except Exception:
            is_online = False
            last_seen_text = "نامشخص"

    used_traffic = upload + download
    remaining = max(0, total_quota - used_traffic)
    percent = int((used_traffic / total_quota * 100)) if total_quota > 0 else 0
    percent = min(100, max(0, percent))

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
        "is_online": is_online,
        "last_seen_text": last_seen_text,
        "percent": percent,
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

# ----------------- مسیرهای مخفی و امن ادمین -----------------
@app.get(f"/{ADMIN_SECRET_PATH}", response_class=HTMLResponse)
async def admin_panel(request: Request):
    if not is_admin(request):
        return HTMLResponse(content=render_login_html(admin_path=ADMIN_SECRET_PATH))

    with get_db() as conn:
        profiles = conn.execute("SELECT * FROM profiles ORDER BY id DESC").fetchall()

    clean_domain = PUBLIC_URL.replace("https://", "").replace("http://", "").strip("/")
    csrf_tok = get_csrf_token(request)
    return HTMLResponse(content=render_admin_html(profiles, clean_domain, csrf_tok, admin_path=ADMIN_SECRET_PATH))

@app.post(f"/{ADMIN_SECRET_PATH}/login")
async def admin_login(request: Request):
    client_ip = get_client_ip(request)
    if not check_rate_limit(client_ip):
        return HTMLResponse(
            content=render_login_html(admin_path=ADMIN_SECRET_PATH, error="تلاش بیش از حد مجاز. لطفاً ۱۰ دقیقه بعد امتحان کنید."),
            status_code=429
        )

    form_data = await read_bounded_form(request)
    password = form_data.get("password", [""])[0]

    if secrets.compare_digest(password, ADMIN_PASSWORD):
        login_attempts.pop(client_ip, None)
        response = RedirectResponse(url=f"/{ADMIN_SECRET_PATH}", status_code=status.HTTP_302_FOUND)
        is_secure = not PUBLIC_URL.startswith("localhost")
        response.set_cookie(
            key=COOKIE_NAME,
            value=create_session_token(),
            httponly=True,
            secure=is_secure,
            samesite="lax",
            max_age=SESSION_TTL
        )
        return response

    record_failed_login(client_ip)
    return HTMLResponse(content=render_login_html(admin_path=ADMIN_SECRET_PATH, error="رمز عبور نادرست است."), status_code=401)

@app.get(f"/{ADMIN_SECRET_PATH}/logout")
async def admin_logout():
    response = RedirectResponse(url=f"/{ADMIN_SECRET_PATH}", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(COOKIE_NAME)
    return response

@app.get(f"/{ADMIN_SECRET_PATH}/backup")
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

@app.post(f"/{ADMIN_SECRET_PATH}/backup/restore")
async def admin_restore_backup(request: Request):
    if not is_admin(request):
        raise HTTPException(status_code=401)
    
    try:
        body = await request.body()
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        return JSONResponse(status_code=400, content={"ok": False, "msg": "فرمت داده ارسال‌شده نامعتبر است."})

    csrf_token = payload.get("csrf_token", "")
    if not verify_csrf(request, csrf_token):
        return JSONResponse(status_code=403, content={"ok": False, "msg": "توکن امنیتی CSRF نامعتبر است."})

    backup_data = payload.get("backup", {})
    profiles = backup_data.get("profiles", [])
    overwrite_existing = payload.get("overwrite_existing", False)

    if not isinstance(profiles, list):
        return JSONResponse(status_code=400, content={"ok": False, "msg": "ساختار فایل بکاپ نامعتبر است."})

    restored_count = 0
    with get_db() as conn:
        for p in profiles:
            token = p.get("token")
            name = p.get("name")
            upstream_url = p.get("upstream_url")
            fake_total_gb = float(p.get("fake_total_gb", 0.0))
            custom_notice = p.get("custom_notice", "")
            admin_note = p.get("admin_note", "")
            sub_hits = int(p.get("sub_hits", 0))
            last_sub_fetch = p.get("last_sub_fetch", "")
            is_blocked = int(p.get("is_blocked", 0))
            created_at = p.get("created_at", datetime.now().strftime("%Y-%m-%d %H:%M"))

            if not token or not name or not upstream_url:
                continue

            if overwrite_existing:
                conn.execute("""
                    INSERT INTO profiles (token, name, upstream_url, fake_total_gb, custom_notice, admin_note, sub_hits, last_sub_fetch, is_blocked, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(token) DO UPDATE SET
                        name=excluded.name,
                        upstream_url=excluded.upstream_url,
                        fake_total_gb=excluded.fake_total_gb,
                        custom_notice=excluded.custom_notice,
                        admin_note=excluded.admin_note,
                        sub_hits=excluded.sub_hits,
                        last_sub_fetch=excluded.last_sub_fetch,
                        is_blocked=excluded.is_blocked
                """, (token, name, upstream_url, fake_total_gb, custom_notice, admin_note, sub_hits, last_sub_fetch, is_blocked, created_at))
            else:
                conn.execute("""
                    INSERT OR IGNORE INTO profiles (token, name, upstream_url, fake_total_gb, custom_notice, admin_note, sub_hits, last_sub_fetch, is_blocked, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (token, name, upstream_url, fake_total_gb, custom_notice, admin_note, sub_hits, last_sub_fetch, is_blocked, created_at))
            restored_count += 1
        conn.commit()

    sub_cache.clear()
    return JSONResponse(content={"ok": True, "msg": f"تعداد {restored_count} اشتراک با موفقیت بازیابی شد."})

@app.post(f"/{ADMIN_SECRET_PATH}/cache/clear")
async def clear_all_cache(request: Request):
    if not is_admin(request):
        raise HTTPException(status_code=401)
    form_data = await read_bounded_form(request)
    if not verify_csrf(request, form_data.get("csrf_token", [""])[0]):
        raise HTTPException(status_code=403, detail="CSRF token invalid")
    sub_cache.clear()
    return RedirectResponse(url=f"/{ADMIN_SECRET_PATH}", status_code=status.HTTP_302_FOUND)

@app.post(f"/{ADMIN_SECRET_PATH}/profiles/add")
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

    return RedirectResponse(url=f"/{ADMIN_SECRET_PATH}", status_code=status.HTTP_302_FOUND)

@app.post(f"/{ADMIN_SECRET_PATH}/profiles/{{token}}/edit")
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
    return RedirectResponse(url=f"/{ADMIN_SECRET_PATH}", status_code=status.HTTP_302_FOUND)

@app.post(f"/{ADMIN_SECRET_PATH}/profiles/{{token}}/refresh-cache")
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
    return RedirectResponse(url=f"/{ADMIN_SECRET_PATH}", status_code=status.HTTP_302_FOUND)

@app.post(f"/{ADMIN_SECRET_PATH}/profiles/{{token}}/toggle-block")
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
    return RedirectResponse(url=f"/{ADMIN_SECRET_PATH}", status_code=status.HTTP_302_FOUND)

@app.post(f"/{ADMIN_SECRET_PATH}/profiles/{{token}}/delete")
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
    return RedirectResponse(url=f"/{ADMIN_SECRET_PATH}", status_code=status.HTTP_302_FOUND)

# ----------------- وبهوک تلگرام -----------------
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
            caption = "هیچ پروفایلی در سیستم ثبت نشده است."
        else:
            try:
                sub_data = await get_cached_sub_data(profile["token"], profile["upstream_url"])
                info = sub_data.get("info", {})
                fake_gb = profile["fake_total_gb"] or 0
                u, d, tot = apply_fake_traffic(info.get("upload", 0), info.get("download", 0), info.get("total", 0), fake_gb)
                
                used_gb = (u + d) / (1024**3)
                total_gb = tot / (1024**3)
                remaining_gb = max(0.0, total_gb - used_gb)
                
                status_txt = "متصل" if sub_data.get("is_online") else f"آخرین استفاده: {sub_data.get('last_seen_text', 'نامشخص')}"
            except Exception:
                used_gb = total_gb = remaining_gb = 0.0
                status_txt = "نامشخص"

            clean_domain = PUBLIC_URL.replace("https://", "").replace("http://", "").strip("/")
            sub_link = f"https://{clean_domain}/sub/{profile['token']}"
            dash_link = f"https://{clean_domain}/d/{profile['token']}"

            caption = (
                f"شناسه: {profile['name']}\n"
                f"وضعیت: {status_txt}\n"
                f"سقف: `{total_gb:.2f}` GB\n"
                f"مصرف: `{used_gb:.2f}` GB\n"
                f"باقی‌مانده: `{remaining_gb:.2f}` GB\n"
                f"سینک‌های کلاینت: `{profile['sub_hits'] or 0}`\n\n"
                f"داشبورد کاربر:\n{dash_link}\n\n"
                f"لینک ساب:\n`{sub_link}`\n\n"
                f"پشتیبانی: @DARK_WIKI20"
            )

        await http_client.post(
            f"{TELEGRAM_API}/sendMessage",
            json={"chat_id": chat_id, "text": caption, "parse_mode": "Markdown"}
        )

    return Response(status_code=200)
