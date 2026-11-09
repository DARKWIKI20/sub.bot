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
import traceback
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

# مسیر امنیتی و مخفی ورود به پنل ادمین
ADMIN_SECRET_PATH = os.getenv("ADMIN_SECRET_PATH", "manage-panel-x92").strip("/")

SECRET_KEY = hashlib.sha256(f"{ADMIN_PASSWORD}_datacenter_v3_salt".encode()).digest()
WEBHOOK_SECRET = hashlib.sha256(f"{BOT_TOKEN}_tg_webhook".encode()).hexdigest()[:32] if BOT_TOKEN else ""

# انتخاب مسیر دیتابیس با بررسی دسترسی نوشتن
def get_safe_db_path():
    if os.path.exists("/data") and os.access("/data", os.W_OK):
        return "/data/datacenter_subs.db"
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "datacenter_subs.db")

DB_FILE = get_safe_db_path()
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
async def get_http_client() -> httpx.AsyncClient:
    global http_client
    if http_client is None or http_client.is_closed:
        limits = httpx.Limits(max_keepalive_connections=15, max_connections=50)
        http_client = httpx.AsyncClient(timeout=10.0, follow_redirects=False, verify=False, limits=limits)
    return http_client

@asynccontextmanager
async def lifespan(app: FastAPI):
    client = await get_http_client()
    if BOT_TOKEN and PUBLIC_URL != "localhost:8000":
        clean_domain = PUBLIC_URL.replace("https://", "").replace("http://", "").strip("/")
        webhook_url = f"https://{clean_domain}/webhook"
        try:
            await client.post(
                f"{TELEGRAM_API}/setWebhook",
                json={"url": webhook_url, "secret_token": WEBHOOK_SECRET}
            )
        except Exception:
            pass
    yield
    if http_client and not http_client.is_closed:
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

# مدیریت خطای سراسری
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    err_str = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    print(f"CRITICAL ERROR on {request.url.path}: {err_str}")
    return HTMLResponse(
        content=f"""
        <div style="font-family: sans-serif; padding: 25px; background: #07090e; color: #f43f5e; min-height: 100vh;">
            <h2 style="margin-top:0;">خطای سرور (۵۰۰)</h2>
            <pre style="background: #11131a; color: #f87171; padding: 15px; border-radius: 12px; font-size: 12px; overflow-x: auto;">{html.escape(err_str)}</pre>
        </div>
        """,
        status_code=500
    )

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

def safe_parse_timestamp(val) -> float:
    if not val:
        return 0.0
    if isinstance(val, (int, float)):
        ts = float(val)
    else:
        val_str = str(val).strip()
        try:
            ts = float(val_str)
        except ValueError:
            ts = 0.0
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(val_str.split(".")[0].replace("Z", ""), fmt)
                    ts = dt.replace(tzinfo=timezone.utc).timestamp()
                    break
                except Exception:
                    continue
    if ts > 1e11:  # میلی‌ثانیه به ثانیه
        ts = ts / 1000.0
    return max(0.0, ts)

def gregorian_to_jalali(gy, gm, gd):
    try:
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
    except Exception:
        return 1405, 1, 1

def now_jalali_str() -> str:
    now_dt = datetime.now()
    jy, jm, jd = gregorian_to_jalali(now_dt.year, now_dt.month, now_dt.day)
    return to_persian_num(f"{jy}/{jm:02d}/{jd:02d}, {now_dt.strftime('%H:%M')}")

def format_timestamp_to_jalali(ts_val) -> str:
    ts = safe_parse_timestamp(ts_val)
    if ts <= 0:
        return "نامحدود"
    try:
        dt = datetime.fromtimestamp(ts)
        jy, jm, jd = gregorian_to_jalali(dt.year, dt.month, dt.day)
        return to_persian_num(f"{jy}/{jm:02d}/{jd:02d}, {dt.strftime('%H:%M')}")
    except Exception:
        return "نامحدود"

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
        client = await get_http_client()
        try:
            res_info = await client.get(
                f"{clean_url}/info",
                headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
                timeout=5.0
            )
            if res_info.status_code == 200:
                data = res_info.json()
                if isinstance(data, dict):
                    online_val = data.get("online_at") or data.get("last_online") or data.get("last_use")
                    if online_val:
                        ts = safe_parse_timestamp(online_val)
                        if ts > 0:
                            formatted_dt = format_timestamp_to_jalali(ts)
                            diff = time.time() - ts
                            return (0 <= diff <= 180), formatted_dt
                    if data.get("is_online") is True or str(data.get("status", "")).lower() == "online":
                        return True, now_jalali_str()
        except Exception:
            pass

        try:
            res_html = await client.get(
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
                    ts = safe_parse_timestamp(match_online.group(1))
                    if ts > 0:
                        formatted_dt = format_timestamp_to_jalali(ts)
                        diff = time.time() - ts
                        return (0 <= diff <= 180), formatted_dt
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
                ts = safe_parse_timestamp(info[key])
                if ts > 0:
                    formatted_dt = format_timestamp_to_jalali(ts)
                    diff = now - ts
                    return (0 <= diff <= 180), formatted_dt

        for c in configs:
            name_lower = str(c.get("name", "")).lower()
            if "online" in name_lower or "متصل" in name_lower:
                return True, now_jalali_str()

        return False, "نامشخص"
    except Exception:
        return False, "نامشخص"

def apply_fake_traffic(upload, download, total, fake_total_gb) -> tuple[int, int, int]:
    try:
        upload = int(float(upload or 0))
        download = int(float(download or 0))
        total = int(float(total or 0))
        fake_total_gb = float(fake_total_gb or 0.0)
    except Exception:
        return 0, 0, 0

    if fake_total_gb <= 0:
        return upload, download, total
    fake_total_bytes = int(fake_total_gb * (1024 ** 3))
    multiplier = (fake_total_bytes / total) if total > 0 else 1.0
    return int(upload * multiplier), int(download * multiplier), fake_total_bytes

def format_bytes(size_bytes) -> str:
    try:
        size_bytes = float(size_bytes or 0)
    except Exception:
        size_bytes = 0.0
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
    client = await get_http_client()
    for _ in range(3):
        res = await client.get(current_url, headers=headers_req)
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

# ----------------- قالب اختصاصی داشبورد کاربران (GLISSE ENGINE) -----------------
DASHBOARD_REACT_GLISSE_TEMPLATE = """<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>داشبورد اشتراک هوشمند</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/misc/Farsi-Digits/Vazirmatn-FD-font-face.css">
    
    <!-- CSS رسمی کتابخانه Glisse -->
    <link rel="stylesheet" href="https://esm.sh/glisse@0.5.0/dist/styles.css">
    
    <style>
        :root {
            --bg-base: #080a10;
        }
        * { box-sizing: border-box; }
        body {
            font-family: 'Vazirmatn FD', sans-serif;
            background-color: var(--bg-base);
            color: #f8fafc;
            min-height: 100vh;
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(59, 130, 246, 0.12) 0%, transparent 45%),
                radial-gradient(circle at 90% 80%, rgba(16, 185, 129, 0.08) 0%, transparent 45%);
            background-attachment: fixed;
        }
        .mono-num {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
            direction: ltr !important;
            display: inline-block;
        }
        .vazir-num {
            font-family: 'Vazirmatn FD', sans-serif !important;
            direction: rtl !important;
            display: inline-block;
        }

        /* کارت‌های شیشه‌ای شفاف (Liquid Glass) بدون پس‌زمینه مات تیره */
        .stats-box {
            background: rgba(255, 255, 255, 0.03);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 1.25rem;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.35);
        }

        /* اسکرول‌بار شیشه‌ای مات و یکپارچه (Liquid Glass Scrollbar) */
        ::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }
        ::-webkit-scrollbar-track {
            background: transparent;
        }
        ::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.16);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border-radius: 9999px;
            border: 1px solid rgba(255, 255, 255, 0.12);
            box-shadow: inset 0 1px 1px rgba(255, 255, 255, 0.35);
        }
        ::-webkit-scrollbar-thumb:hover {
            background: rgba(255, 255, 255, 0.28);
            border-color: rgba(255, 255, 255, 0.25);
        }
        * {
            scrollbar-width: thin;
            scrollbar-color: rgba(255, 255, 255, 0.18) transparent;
        }
    </style>

    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
</head>
<body>
    <div id="root" data-glisse-backdrop></div>

    <script type="text/babel" data-type="module">
        import React, { useState, useMemo } from 'https://esm.sh/react@18.3.1';
        import ReactDOM from 'https://esm.sh/react-dom@18.3.1/client';
        import { Button, TabBar, SegmentedControl, Menu, Input } from 'https://esm.sh/glisse@0.5.0?deps=react@18.3.1,react-dom@18.3.1';

        const DATA = __CTX_DATA__;

        function App() {
            const [filter, setFilter] = useState("all");
            const [tab, setTab] = useState("android");
            const [search, setSearch] = useState("");
            const [toast, setToast] = useState("");
            const [qrUrl, setQrUrl] = useState(null);

            const showToast = (msg) => {
                setToast(msg);
                setTimeout(() => setToast(""), 2200);
            };

            const copyText = (txt, msg) => {
                navigator.clipboard.writeText(txt);
                showToast(msg);
            };

            const filteredConfigs = useMemo(() => {
                return (DATA.configs || []).filter(c => {
                    const matchProto = (filter === "all") || (c.proto.toLowerCase() === filter.toLowerCase());
                    const matchSearch = c.name.toLowerCase().includes(search.toLowerCase());
                    return matchProto && matchSearch;
                });
            }, [filter, search]);

            return (
                <div className="min-h-screen p-4 sm:p-8 flex flex-col justify-between max-w-4xl mx-auto space-y-6">
                    <main className="space-y-6">
                        
                        {/* ۱. هدر شیشه‌ای بدون سنسور اتصال و با دکمه تازه‌سازی */}
                        <header className="p-4 sm:p-5 rounded-3xl border border-white/10 bg-white/[0.03] backdrop-blur-xl flex justify-between items-center shadow-lg">
                            <div>
                                <h1 className="text-lg sm:text-xl font-extrabold tracking-wide">{DATA.brand_name}</h1>
                                <div className="text-xs text-blue-400 font-mono mt-0.5">Liquid Glass Dashboard</div>
                            </div>
                            <div className="flex items-center gap-2">
                                <Button variant="glass" onClick={() => location.reload()} title="بروزرسانی داده‌ها">
                                    تازه‌سازی
                                </Button>
                                <Menu
                                    aria-label="Options"
                                    items={[
                                        { label: "کپی آدرس ساب", onSelect: () => copyText(DATA.sub_url, "لینک ساب کپی شد") },
                                        { label: "کپی تمام سرورها", onSelect: () => copyText((DATA.configs || []).map(c=>c.link).join("\\n"), "تمام کانفیگ‌ها کپی شدند") },
                                        { label: "کد QR اشتراک", onSelect: () => setQrUrl(DATA.sub_url) },
                                        "separator",
                                        { label: "پشتیبانی تلگرام", onSelect: () => window.open("https://t.me/DARK_WIKI20") }
                                    ]}
                                />
                            </div>
                        </header>

                        {/* ۲. کارت‌های اصلی با پس‌زمینه شیشه‌ای شفاف (Liquid Glass) و اصلاح فونت تاریخ انقضا */}
                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                            
                            {/* کارت بزرگ وضعیت، روزشمار، گیج و تفکیک حجم‌ها */}
                            <div className="lg:col-span-2 stats-box p-6 flex flex-col justify-between">
                                <div className="flex justify-between items-start mb-6">
                                    <div className="text-left">
                                        <div className="text-xs text-slate-400 mb-1">منقضی می‌شود در</div>
                                        <div className="text-2xl font-black mono-num text-slate-100">{DATA.days_left} روز</div>
                                    </div>
                                    <div>
                                        {DATA.is_blocked ? (
                                            <div className="text-2xl font-bold text-rose-500 flex items-center gap-2">
                                                مسدود <span className="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
                                            </div>
                                        ) : (
                                            <div className="text-2xl font-bold text-emerald-400 flex items-center gap-2">
                                                فعال <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.8)]"></span>
                                            </div>
                                        )}
                                    </div>
                                </div>

                                <div className="flex items-center justify-between gap-6">
                                    <div className="space-y-3 flex-1">
                                        <div className="flex justify-between items-center text-sm">
                                            <span className="mono-num font-bold text-slate-100 text-base">{DATA.total_quota}</span>
                                            <span className="text-slate-400 text-xs">حجم سرویس</span>
                                        </div>
                                        <div className="flex justify-between items-center text-sm">
                                            <span className="mono-num font-bold text-slate-100 text-base">{DATA.used_traffic}</span>
                                            <span className="text-slate-400 text-xs">حجم مصرفی</span>
                                        </div>
                                        <div className="flex justify-between items-center text-sm">
                                            <span className="mono-num font-bold text-emerald-400 text-base">{DATA.remaining_traffic}</span>
                                            <span className="text-slate-400 text-xs">حجم باقی مانده</span>
                                        </div>
                                    </div>

                                    {/* گیج دایره‌ای */}
                                    <div className="relative w-32 h-32 shrink-0 flex items-center justify-center">
                                        <svg className="transform -rotate-90 w-full h-full" viewBox="0 0 120 120">
                                            <circle cx="60" cy="60" r="48" stroke="rgba(255,255,255,0.06)" strokeWidth="9" fill="none"></circle>
                                            <circle cx="60" cy="60" r="48" stroke="#10b981" strokeWidth="9" fill="none"
                                                strokeDasharray="301.59" strokeDashoffset={301.59 - (301.59 * DATA.percent / 100)}
                                                strokeLinecap="round" className="transition-all duration-700"></circle>
                                        </svg>
                                        <div className="absolute inset-0 flex flex-col items-center justify-center">
                                            <span className="text-2xl font-black mono-num text-slate-100">{DATA.percent}%</span>
                                            <span className="text-[11px] text-slate-400 font-medium mt-0.5">مصرف شده</span>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* ۳ کارت عمودی ستون کناری (با فونت یکسان وزیرمتن برای تاریخ انقضا و پس‌زمینه شفاف) */}
                            <div className="flex flex-col gap-4">
                                <div className="stats-box p-4 flex flex-col justify-between flex-1">
                                    <div className="text-xs text-slate-400 text-right">حجم کل</div>
                                    <div className="text-2xl font-bold mono-num text-slate-100 text-left mt-2">{DATA.total_quota}</div>
                                </div>
                                <div className="stats-box p-4 flex flex-col justify-between flex-1">
                                    <div className="text-xs text-slate-400 text-right">تاریخ انقضا</div>
                                    <div className="text-base font-bold vazir-num text-slate-100 text-right mt-2">{DATA.expire_date}</div>
                                </div>
                                <div className="stats-box p-4 flex flex-col justify-between flex-1">
                                    <div className="text-xs text-slate-400 text-right">آخرین اتصال</div>
                                    <div className="text-sm font-bold vazir-num text-slate-100 text-right mt-2 flex items-center justify-start gap-1.5" dir="rtl">
                                        <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block shadow-[0_0_6px_rgba(52,211,153,0.6)]"></span>
                                        <span>{DATA.last_seen_text || DATA.now_jalali}</span>
                                    </div>
                                </div>
                            </div>

                        </div>

                        {/* ۳. نوار شکیل و شفاف کپی ساب */}
                        <div className="stats-box p-4 sm:p-5 flex flex-col md:flex-row items-center justify-between gap-4">
                            <div className="flex items-center gap-3 w-full md:w-auto min-w-0">
                                <div className="w-10 h-10 rounded-xl bg-blue-500/15 border border-blue-400/25 flex items-center justify-center text-blue-400 shrink-0">
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>
                                </div>
                                <div className="min-w-0 flex-1">
                                    <div className="text-xs text-slate-400 font-medium mb-1">لینک اختصاصی اشتراک هوشمند:</div>
                                    <div className="mono-num text-xs text-slate-200 bg-white/[0.04] px-3 py-1.5 rounded-lg border border-white/5 truncate select-all">
                                        {DATA.sub_url}
                                    </div>
                                </div>
                            </div>
                            <div className="flex items-center gap-2.5 w-full md:w-auto shrink-0 justify-end">
                                <Button variant="filled" onClick={() => copyText(DATA.sub_url, "لینک اشتراک کپی شد")}>
                                    کپی لینک ساب
                                </Button>
                                <Button variant="glass" onClick={() => setQrUrl(DATA.sub_url)}>
                                    اسکن QR
                                </Button>
                            </div>
                        </div>

                        {/* ۴. فیلتر و جستجو با Glisse */}
                        <div className="space-y-3">
                            <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
                                <div dir="ltr" className="w-full sm:w-auto">
                                    <SegmentedControl
                                        aria-label="Protocol Range"
                                        items={[
                                            { value: "all", label: "همه" },
                                            { value: "vless", label: "VLESS" },
                                            { value: "vmess", label: "VMESS" },
                                            { value: "trojan", label: "Trojan" }
                                        ]}
                                        value={filter}
                                        onValueChange={setFilter}
                                    />
                                </div>
                                <div className="w-full sm:w-64" dir="rtl">
                                    <Input
                                        type="search"
                                        aria-label="Search"
                                        placeholder="جستجوی سرور..."
                                        value={search}
                                        onValueChange={setSearch}
                                    />
                                </div>
                            </div>

                            {/* لیست کانفیگ‌ها */}
                            <div className="max-h-80 overflow-y-auto space-y-2 pr-1">
                                {filteredConfigs.length === 0 ? (
                                    <div className="p-6 text-center text-xs text-slate-500 rounded-2xl border border-white/5 bg-white/[0.01]">
                                        سروری با این مشخصات یافت نشد.
                                    </div>
                                ) : (
                                    filteredConfigs.map((c, idx) => (
                                        <div key={idx} className="p-3 rounded-xl border border-white/10 bg-white/[0.02] hover:border-white/20 transition-colors flex items-center justify-between gap-3">
                                            <div className="flex items-center gap-2.5 min-w-0">
                                                <span className="mono-num text-[11px] font-bold px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-400/30 uppercase shrink-0">
                                                    {c.proto}
                                                </span>
                                                <span className="text-xs sm:text-sm font-medium truncate text-slate-200" dir="auto">
                                                    {c.name}
                                                </span>
                                            </div>
                                            <div className="flex items-center gap-1.5 shrink-0">
                                                <Button variant="glass" onClick={() => copyText(c.link, "کانفیگ کپی شد")}>
                                                    کپی
                                                </Button>
                                                <Button variant="tinted" onClick={() => setQrUrl(c.link)}>
                                                    QR
                                                </Button>
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>

                        {/* ۵. تب‌بار کلاینت‌ها (تفکیک مک و لینوکس با ۴ برنامه برای هر کدام) */}
                        <div className="pt-2 space-y-3">
                            <div className="text-xs text-slate-400 text-center font-semibold">دانلود نرم‌افزار اتصال مخصوص سیستم شما</div>
                            <div dir="ltr" className="flex justify-center w-full overflow-x-auto py-1">
                                <TabBar
                                    aria-label="Platforms"
                                    items={[
                                        { value: "android", label: "Android" },
                                        { value: "ios", label: "iOS" },
                                        { value: "windows", label: "Windows" },
                                        { value: "mac", label: "macOS" },
                                        { value: "linux", label: "Linux" }
                                    ]}
                                    value={tab}
                                    onValueChange={setTab}
                                    style={{ "--lg-lens-grow-x": "12px", "--lg-lens-grow-y": "8px" }}
                                />
                            </div>
                            
                            {/* ۴ برنامه برای هر سیستم‌عامل */}
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-1">
                                {tab === "android" && (
                                    <>
                                        <Button variant="tinted filled" onClick={() => window.open("https://github.com/hiddify/hiddify-next/releases")}>
                                            Hiddify
                                        </Button>
                                        <Button variant="glass" onClick={() => window.open("https://github.com/2dust/v2rayNG/releases")}>
                                            v2rayNG
                                        </Button>
                                        <Button variant="glass" onClick={() => window.open("https://github.com/chen08209/FlClash/releases")}>
                                            Flclash
                                        </Button>
                                        <Button variant="glass" onClick={() => window.open("https://github.com/SagerNet/sing-box/releases")}>
                                            Sing-box
                                        </Button>
                                    </>
                                )}
                                {tab === "ios" && (
                                    <>
                                        <Button variant="tinted filled" onClick={() => window.open("https://apps.apple.com/us/app/hiddify-proxy-vpn/id6596777532")}>
                                            Hiddify
                                        </Button>
                                        <Button variant="glass" onClick={() => window.open("https://apps.apple.com/us/app/streisand/id6450534064")}>
                                            Streisand
                                        </Button>
                                        <Button variant="glass" onClick={() => window.open("https://apps.apple.com/us/app/shadowrocket/id932747118")}>
                                            Shadowrocket
                                        </Button>
                                        <Button variant="glass" onClick={() => window.open("https://apps.apple.com/us/app/sing-box/id6451272673")}>
                                            Sing-box
                                        </Button>
                                    </>
                                )}
                                {tab === "windows" && (
                                    <>
                                        <Button variant="tinted filled" onClick={() => window.open("https://github.com/hiddify/hiddify-next/releases")}>
                                            Hiddify
                                        </Button>
                                        <Button variant="glass" onClick={() => window.open("https://github.com/2dust/v2rayN/releases")}>
                                            v2rayN
                                        </Button>
                                        <Button variant="glass" onClick={() => window.open("https://github.com/chen08209/FlClash/releases")}>
                                            Flclash
                                        </Button>
                                        <Button variant="glass" onClick={() => window.open("https://github.com/clash-verge-rev/clash-verge-rev/releases")}>
                                            Clash Verge
                                        </Button>
                                    </>
                                )}
                                {tab === "mac" && (
                                    <>
                                        <Button variant="tinted filled" onClick={() => window.open("https://github.com/hiddify/hiddify-next/releases")}>
                                            Hiddify
                                        </Button>
                                        <Button variant="glass" onClick={() => window.open("https://github.com/clash-verge-rev/clash-verge-rev/releases")}>
                                            Clash Verge
                                        </Button>
                                        <Button variant="glass" onClick={() => window.open("https://github.com/chen08209/FlClash/releases")}>
                                            Flclash
                                        </Button>
                                        <Button variant="glass" onClick={() => window.open("https://github.com/SagerNet/sing-box/releases")}>
                                            Sing-box
                                        </Button>
                                    </>
                                )}
                                {tab === "linux" && (
                                    <>
                                        <Button variant="tinted filled" onClick={() => window.open("https://github.com/hiddify/hiddify-next/releases")}>
                                            Hiddify
                                        </Button>
                                        <Button variant="glass" onClick={() => window.open("https://github.com/clash-verge-rev/clash-verge-rev/releases")}>
                                            Clash Verge
                                        </Button>
                                        <Button variant="glass" onClick={() => window.open("https://github.com/chen08209/FlClash/releases")}>
                                            Flclash
                                        </Button>
                                        <Button variant="glass" onClick={() => window.open("https://github.com/MatsuriDayo/nekoray/releases")}>
                                            NekoRay
                                        </Button>
                                    </>
                                )}
                            </div>
                        </div>
                    </main>

                    {/* فوتر */}
                    <footer className="pt-8 pb-4 text-center">
                        <a href="https://t.me/DARK_WIKI20" target="_blank" rel="noopener noreferrer" className="text-xs text-slate-400 hover:text-slate-200 transition-colors">
                            پشتیبانی تلگرام: <span className="mono-num font-bold text-blue-400">@DARK_WIKI20</span>
                        </a>
                    </footer>

                    {/* مدال نمایش QR Code */}
                    {qrUrl && (
                        <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 z-50" onClick={() => setQrUrl(null)}>
                            <div className="p-6 rounded-3xl border border-white/20 bg-slate-900/90 shadow-2xl flex flex-col items-center max-w-xs w-full" onClick={(e) => e.stopPropagation()}>
                                <div className="text-xs font-bold mb-4 text-slate-300">کد QR اختصاصی</div>
                                <img src={"https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=" + encodeURIComponent(qrUrl)} alt="QR" className="w-52 h-52 rounded-xl bg-white p-2.5 mb-5 shadow-lg" />
                                <Button variant="glass" onClick={() => setQrUrl(null)} style={{ width: "100%" }}>
                                    بستن
                                </Button>
                            </div>
                        </div>
                    )}

                    {/* توست اعلان کپی */}
                    {toast && (
                        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 px-4 py-2 rounded-xl bg-white text-slate-900 font-bold text-xs shadow-2xl z-50">
                            {toast}
                        </div>
                    )}
                </div>
            );
        }

        ReactDOM.createRoot(document.getElementById("root")).render(<App />);
    </script>
</body>
</html>"""

def render_dashboard_html(ctx: dict) -> str:
    ctx_json = json.dumps(ctx, ensure_ascii=False)
    return DASHBOARD_REACT_GLISSE_TEMPLATE.replace("__CTX_DATA__", ctx_json)

# ----------------- قالب اختصاصی پنل ادمین -----------------
ADMIN_PANEL_CSS = """
:root {
    --bg-base: #07090e;
    --glass-bg: rgba(18, 24, 38, 0.65);
    --glass-border: rgba(255, 255, 255, 0.12);
}
* { box-sizing: border-box; }
body {
    font-family: 'Vazirmatn FD', sans-serif;
    background-color: var(--bg-base);
    color: #f1f5f9;
    min-height: 100vh;
}
.mono-num {
    font-family: ui-monospace, SFMono-Regular, monospace !important;
    direction: ltr !important;
    display: inline-block;
}
.glass-container {
    background: var(--glass-bg);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border: 1px solid var(--glass-border);
    border-radius: 18px;
}
.btn-glass {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0.55rem 1rem;
    font-size: 0.8125rem;
    font-weight: 600;
    border-radius: 10px;
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.15);
    color: #ffffff;
    cursor: pointer;
    transition: all 0.15s ease;
}
.btn-glass:hover {
    background: rgba(255, 255, 255, 0.12);
    border-color: rgba(255, 255, 255, 0.3);
}
.btn-primary { background: #2563eb; border-color: #3b82f6; }
.btn-primary:hover { background: #1d4ed8; }
.btn-danger { background: rgba(244, 63, 94, 0.15); border-color: rgba(244, 63, 94, 0.35); color: #fb7185; }
.glass-input {
    width: 100%;
    background: rgba(10, 14, 22, 0.7);
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 10px;
    padding: 0.6rem 0.85rem;
    font-size: 0.8125rem;
    color: #ffffff;
    outline: none;
}
.glass-input:focus { border-color: #3b82f6; }
"""

ADMIN_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>مدیریت سرویس | کنترل پنل مرکزی</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/misc/Farsi-Digits/Vazirmatn-FD-font-face.css">
    <style>__CSS__</style>
</head>
<body class="min-h-screen p-4 sm:p-6 lg:p-8">
    <div class="max-w-7xl mx-auto space-y-6">
        <header class="glass-container p-5 flex flex-wrap justify-between items-center gap-4">
            <div>
                <h1 class="text-base font-bold text-slate-100">کنترل پنل مرکزی دیتاسنتر</h1>
                <div class="text-xs text-slate-400 mono-num mt-0.5">__DOMAIN__</div>
            </div>
            <div class="flex flex-wrap items-center gap-2">
                <form action="/__ADMIN_PATH__/cache/clear" method="post" class="m-0">
                    <input type="hidden" name="csrf_token" value="__CSRF_TOKEN__">
                    <button type="submit" class="btn-glass px-3 py-2 text-xs">پاکسازی کش (__CACHED_ITEMS__)</button>
                </form>
                <a href="/__ADMIN_PATH__/backup" class="btn-glass px-3 py-2 text-xs text-blue-300">دانلود بکاپ JSON</a>
                <a href="/__ADMIN_PATH__/logout" class="btn-glass btn-danger px-3 py-2 text-xs">خروج</a>
            </div>
        </header>

        <section class="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
            <div class="glass-container p-4">
                <div class="text-xs text-slate-400 mb-1">کل اشتراک‌ها</div>
                <div class="text-2xl font-bold mono-num text-slate-100">__TOTAL_COUNT__</div>
            </div>
            <div class="glass-container p-4">
                <div class="text-xs text-slate-400 mb-1">فعال</div>
                <div class="text-2xl font-bold mono-num text-emerald-400">__ACTIVE_COUNT__</div>
            </div>
            <div class="glass-container p-4">
                <div class="text-xs text-slate-400 mb-1">مسدود شده</div>
                <div class="text-2xl font-bold mono-num text-rose-400">__BLOCKED_COUNT__</div>
            </div>
            <div class="glass-container p-4">
                <div class="text-xs text-slate-400 mb-1">سینک‌های کلاینت</div>
                <div class="text-2xl font-bold mono-num text-blue-400">__TOTAL_HITS__</div>
            </div>
        </section>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <section class="lg:col-span-2 glass-container p-5">
                <h2 class="text-sm font-bold text-slate-200 mb-4">ثبت اشتراک جدید</h2>
                <form action="/__ADMIN_PATH__/profiles/add" method="post" class="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                    <input type="hidden" name="csrf_token" value="__CSRF_TOKEN__">
                    <div>
                        <label class="block text-xs text-slate-400 mb-1">نام یا شناسه کاربر *</label>
                        <input type="text" name="name" placeholder="User-VIP" required class="glass-input">
                    </div>
                    <div>
                        <label class="block text-xs text-slate-400 mb-1">لینک مستقیم فروشنده (Upstream) *</label>
                        <input type="url" name="upstream_url" placeholder="https://panel.site/sub/..." required class="glass-input mono-num text-left">
                    </div>
                    <div>
                        <label class="block text-xs text-slate-400 mb-1">حجم مجازی کل (GB) — اختیاری</label>
                        <input type="number" step="0.1" min="0" name="fake_total_gb" placeholder="0 = حجم واقعی" class="glass-input mono-num text-left">
                    </div>
                    <div>
                        <label class="block text-xs text-slate-400 mb-1">توکن اختصاصی لینک (اختیاری)</label>
                        <input type="text" name="custom_token" placeholder="خالی = خودکار" class="glass-input mono-num text-left">
                    </div>
                    <div>
                        <label class="block text-xs text-slate-400 mb-1">اعلان داشبورد</label>
                        <input type="text" name="custom_notice" placeholder="متن پیام به کاربر..." class="glass-input">
                    </div>
                    <div>
                        <label class="block text-xs text-slate-400 mb-1">یادداشت داخلی ادمین</label>
                        <input type="text" name="admin_note" placeholder="آیدی تلگرام، تاریخ و..." class="glass-input">
                    </div>
                    <div class="md:col-span-2 pt-2">
                        <button type="submit" class="btn-glass btn-primary px-6 py-2.5">ایجاد و ذخیره اشتراک</button>
                    </div>
                </form>
            </section>

            <section class="glass-container p-5 flex flex-col justify-between">
                <div>
                    <h2 class="text-sm font-bold text-slate-200 mb-2">بازگردانی داده‌ها از بکاپ</h2>
                    <p class="text-xs text-slate-400 mb-4 leading-relaxed">فایل JSON بکاپ قبلی خود را برای بازیابی سریع انتخاب کنید.</p>
                    <input type="file" id="dashboardBackupFile" accept=".json" class="glass-input text-xs mb-3">
                    <label class="flex items-center gap-2 text-xs text-slate-300 select-none cursor-pointer">
                        <input type="checkbox" id="overwrite_backup_chk" class="rounded border-zinc-700 bg-zinc-900">
                        <span>به‌روزرسانی رکوردهای تکراری</span>
                    </label>
                </div>
                <button type="button" onclick="uploadAndRestoreBackup()" id="btnUploadBackup" class="btn-glass w-full py-2.5 mt-4 text-emerald-400">آپلود و اعمال بکاپ</button>
            </section>
        </div>

        <section class="glass-container overflow-hidden">
            <div class="p-4 border-b border-white/[0.06] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <h2 class="text-sm font-bold text-slate-200">فهرست اشتراک‌ها (__TOTAL_COUNT__)</h2>
                <div class="flex items-center gap-2">
                    <input type="text" id="searchInput" oninput="filterTable()" placeholder="جستجو نام، توکن، یادداشت..." class="glass-input py-1.5 px-3 text-xs w-60">
                    <select id="statusFilter" onchange="filterTable()" class="glass-input py-1.5 px-3 text-xs w-28">
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
                            <th class="p-3.5 whitespace-nowrap text-center">وضعیت</th>
                            <th class="p-3.5 whitespace-nowrap text-center">حجم مجازی</th>
                            <th class="p-3.5 whitespace-nowrap text-center">مصرف / سقف</th>
                            <th class="p-3.5 whitespace-nowrap">همگام‌سازی</th>
                            <th class="p-3.5 whitespace-nowrap text-center">دسترسی</th>
                            <th class="p-3.5 text-left whitespace-nowrap">مدیریت</th>
                        </tr>
                    </thead>
                    <tbody>__ROWS__</tbody>
                </table>
            </div>
        </section>
    </div>

    <div id="editModal" class="fixed inset-0 bg-black/75 backdrop-blur-sm hidden items-center justify-center z-50 p-4" onclick="closeEditModal()">
        <div class="glass-container p-6 max-w-md w-full shadow-2xl" onclick="event.stopPropagation()">
            <h3 class="text-base font-bold mb-4 text-slate-100">ویرایش اطلاعات ساب</h3>
            <form id="editForm" method="post" class="space-y-3">
                <input type="hidden" name="csrf_token" value="__CSRF_TOKEN__">
                <div>
                    <label class="block text-xs text-slate-400 mb-1">نام یا شناسه کاربر</label>
                    <input type="text" id="edit_name" name="name" required class="glass-input">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">لینک مستقیم فروشنده</label>
                    <input type="url" id="edit_upstream" name="upstream_url" required class="glass-input mono-num text-left">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">حجم مجازی کل (GB)</label>
                    <input type="number" step="0.1" min="0" id="edit_fake" name="fake_total_gb" required class="glass-input mono-num text-left">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">اعلان داشبورد</label>
                    <input type="text" id="edit_notice" name="custom_notice" class="glass-input">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">یادداشت داخلی ادمین</label>
                    <input type="text" id="edit_note" name="admin_note" class="glass-input">
                </div>
                <div class="flex gap-2 pt-3">
                    <button type="submit" class="btn-glass btn-primary flex-1 py-2">ذخیره تغییرات</button>
                    <button type="button" onclick="closeEditModal()" class="btn-glass px-4 py-2">انصراف</button>
                </div>
            </form>
        </div>
    </div>

    <div id="adminQrModal" class="fixed inset-0 bg-black/75 backdrop-blur-sm hidden items-center justify-center z-50 p-4" onclick="closeAdminQR()">
        <div class="glass-container p-6 max-w-xs w-full flex flex-col items-center text-center" onclick="event.stopPropagation()">
            <div id="adminQrTitle" class="font-bold text-xs text-slate-300 mb-4 truncate w-full">QR Code</div>
            <img id="adminQrImg" src="" alt="QR" class="w-48 h-48 rounded-xl mb-4 bg-white p-2.5 shadow-md">
            <button type="button" onclick="closeAdminQR()" class="btn-glass w-full py-2 text-xs">بستن</button>
        </div>
    </div>

    <div id="adminToast" class="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 hidden px-4 py-2.5 rounded-xl bg-white/90 text-slate-900 backdrop-blur-md text-xs font-bold shadow-2xl"></div>

    <script>
        const adminCsrfToken = "__CSRF_TOKEN__";
        const adminPath = "__ADMIN_PATH__";

        function copyText(txt, msg) {
            navigator.clipboard.writeText(txt);
            const t = document.getElementById('adminToast');
            t.textContent = msg;
            t.classList.remove('hidden');
            setTimeout(() => t.classList.add('hidden'), 2000);
        }
        function openQR(url, title) {
            document.getElementById('adminQrTitle').textContent = title;
            document.getElementById('adminQrImg').src = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' + encodeURIComponent(url);
            document.getElementById('adminQrModal').classList.remove('hidden');
            document.getElementById('adminQrModal').classList.add('flex');
        }
        function closeAdminQR() {
            document.getElementById('adminQrModal').classList.add('hidden');
            document.getElementById('adminQrModal').classList.remove('flex');
        }
        function openEditModal(profile) {
            document.getElementById('editForm').action = '/' + adminPath + '/profiles/' + encodeURIComponent(profile.token) + '/edit';
            document.getElementById('edit_name').value = profile.name;
            document.getElementById('edit_upstream').value = profile.upstream_url;
            document.getElementById('edit_fake').value = profile.fake_total_gb;
            document.getElementById('edit_notice').value = profile.custom_notice || '';
            document.getElementById('edit_note').value = profile.admin_note || '';
            document.getElementById('editModal').classList.remove('hidden');
            document.getElementById('editModal').classList.add('flex');
        }
        function closeEditModal() {
            document.getElementById('editModal').classList.add('hidden');
            document.getElementById('editModal').classList.remove('flex');
        }
        function filterTable() {
            const q = document.getElementById('searchInput').value.toLowerCase();
            const st = document.getElementById('statusFilter').value;
            document.querySelectorAll('.profile-row').forEach(row => {
                const matchName = row.getAttribute('data-name').includes(q);
                const matchStatus = (st === 'all') || (row.getAttribute('data-status') === st);
                row.style.display = (matchName && matchStatus) ? '' : 'none';
            });
        }
        async function uploadAndRestoreBackup() {
            const fileInput = document.getElementById('dashboardBackupFile');
            if (!fileInput.files.length) {
                alert('لطفاً ابتدا فایل JSON بکاپ را انتخاب کنید.');
                return;
            }
            const file = fileInput.files[0];
            const reader = new FileReader();
            reader.onload = async function(e) {
                try {
                    const parsedJson = JSON.parse(e.target.result);
                    const overwrite = document.getElementById('overwrite_backup_chk').checked;
                    const btn = document.getElementById('btnUploadBackup');
                    btn.disabled = true;
                    btn.textContent = 'در حال بازگردانی...';

                    const res = await fetch('/' + adminPath + '/backup/restore', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            csrf_token: adminCsrfToken,
                            overwrite_existing: overwrite,
                            backup: parsedJson
                        })
                    });
                    const data = await res.json();
                    if (data.ok) {
                        alert(data.msg);
                        location.reload();
                    } else {
                        alert(data.msg || 'خطا در اعمال بکاپ');
                        btn.disabled = false;
                        btn.textContent = 'آپلود و اعمال بکاپ';
                    }
                } catch (err) {
                    alert('فرمت فایل JSON نامعتبر است.');
                }
            };
            reader.readAsText(file);
        }
    </script>
</body>
</html>"""

# ----------------- مسیرهای اصلی سرور (Routes) -----------------
@app.get("/")
async def root():
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
        info = sub_data.get("info", {})
        fake_gb = profile["fake_total_gb"] or 0
        
        if info and fake_gb > 0:
            up, down, tot = apply_fake_traffic(info.get("upload", 0), info.get("download", 0), info.get("total", 0), fake_gb)
            user_info = f"upload={up}; download={down}; total={tot}; expire={int(safe_parse_timestamp(info.get('expire', 0)))}"
        else:
            user_info = str(sub_data.get("raw_userinfo", ""))
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
    is_online = False
    last_seen_text = "نامشخص"

    if not is_blocked:
        try:
            sub_data = await get_cached_sub_data(token, profile["upstream_url"])
            info = sub_data.get("info", {})
            configs = sub_data.get("configs", [])
            is_online = bool(sub_data.get("is_online", False))
            last_seen_text = str(sub_data.get("last_seen_text", "نامشخص"))
            
            raw_up = info.get("upload", 0)
            raw_down = info.get("download", 0)
            raw_total = info.get("total", 0)
            expire_ts = safe_parse_timestamp(info.get("expire", 0))
            
            fake_gb = profile["fake_total_gb"] or 0
            upload, download, total_quota = apply_fake_traffic(raw_up, raw_down, raw_total, fake_gb)
        except Exception:
            is_online = False
            last_seen_text = "نامشخص"

    used_traffic = upload + download
    remaining = max(0, total_quota - used_traffic)
    percent = int((used_traffic / total_quota * 100)) if total_quota > 0 else 0
    percent = min(100, max(0, percent))

    days_left = "نامحدود"
    if expire_ts > 0:
        diff_days = int((expire_ts - time.time()) // 86400)
        days_left = str(max(0, diff_days))

    expire_jalali = format_timestamp_to_jalali(expire_ts)
    clean_domain = PUBLIC_URL.replace("https://", "").replace("http://", "").strip("/")
    sub_url = f"https://{clean_domain}/sub/{token}"

    ctx = {
        "brand_name": str(profile["name"] or ""),
        "custom_notice": str(profile["custom_notice"] or ""),
        "is_blocked": bool(is_blocked),
        "is_online": bool(is_online),
        "last_seen_text": str(last_seen_text),
        "percent": int(percent),
        "total_quota": format_bytes(total_quota),
        "used_traffic": format_bytes(used_traffic),
        "remaining_traffic": format_bytes(remaining),
        "days_left": str(days_left),
        "expire_date": str(expire_jalali),
        "now_jalali": now_jalali_str(),
        "sub_url": str(sub_url),
        "configs": configs
    }
    return HTMLResponse(content=render_dashboard_html(ctx))

# ----------------- مسیرهای مخفی ادمین -----------------
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

# ----------------- وب‌هوک ربات تلگرام -----------------
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

        client = await get_http_client()
        await client.post(
            f"{TELEGRAM_API}/sendMessage",
            json={"chat_id": chat_id, "text": caption, "parse_mode": "Markdown"}
        )

    return Response(status_code=200)
