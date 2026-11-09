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
from html.parser import HTMLParser
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
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), microphone=()"
    return response

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    err_str = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    return HTMLResponse(
        content=f"""
        <div style="font-family: sans-serif; padding: 25px; background: #07090e; color: #f43f5e; min-height: 100vh;">
            <h2 style="margin-top:0;">خطای سرور (۵۰۰)</h2>
            <pre style="background: #11131a; color: #f87171; padding: 15px; border-radius: 12px; font-size: 12px; overflow-x: auto;">{html.escape(err_str)}</pre>
        </div>
        """,
        status_code=500
    )

# ----------------- توابع امنیتی (Security Audit Hardened) -----------------
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
    # پاکسازی امن رکوردهای قدیمی بدون ریسک پاک شدن رکوردهای فعال
    expired_ips = [k for k, v in login_attempts.items() if not v or (now - max(v)) >= 600]
    for exp_ip in expired_ips:
        login_attempts.pop(exp_ip, None)

    attempts = [t for t in login_attempts.get(ip, []) if now - t < 600]
    login_attempts[ip] = attempts
    return len(attempts) < 5

def record_failed_login(ip: str):
    login_attempts.setdefault(ip, []).append(time.time())

def is_safe_upstream_url(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url.strip())
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        hostname = parsed.hostname.lower()
        if hostname in ("localhost", "0.0.0.0", "127.0.0.1") or hostname.endswith(".local") or hostname.endswith(".internal"):
            return False
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
                return False
        except ValueError:
            pass
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
    if ts > 1e11:
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

# ----------------- استخراج آخرین زمان اتصال از ساب اصلی -----------------
def extract_last_online_from_html(html_text: str) -> str:
    if not html_text:
        return ""
    try:
        class TreeBuilder(HTMLParser):
            def __init__(self):
                super().__init__()
                self.root = {'tag': 'root', 'attrs': {}, 'children': [], 'text': ''}
                self.stack = [self.root]

            def handle_starttag(self, tag, attrs):
                node = {'tag': tag, 'attrs': dict(attrs), 'children': [], 'text': ''}
                self.stack[-1]['children'].append(node)
                self.stack.append(node)

            def handle_endtag(self, tag):
                if len(self.stack) > 1:
                    self.stack.pop()

            def handle_data(self, data):
                self.stack[-1]['text'] += data

        parser = TreeBuilder()
        parser.feed(html_text)

        def find_by_id(node, target_id):
            if node.get('attrs', {}).get('id') == target_id:
                return node
            for child in node.get('children', []):
                res = find_by_id(child, target_id)
                if res:
                    return res
            return None

        def get_child(node, tag, idx=0):
            matches = [c for c in node.get('children', []) if c.get('tag') == tag]
            if 0 <= idx < len(matches):
                return matches[idx]
            return None

        root_node = find_by_id(parser.root, 'root')
        if root_node:
            curr = root_node
            path_steps = [
                ('div', 0), ('main', 0), ('div', 0), ('div', 3),
                ('div', 0), ('div', 0), ('div', 0),
                ('div', 0), ('div', 0), ('div', 0), ('div', 0), ('div', 0),
                ('span', 0)
            ]
            for tag, idx in path_steps:
                if not curr:
                    break
                curr = get_child(curr, tag, idx)
            if curr and curr.get('text', '').strip():
                clean_txt = re.sub(r'^[🟢⚪🔴\s]+', '', curr['text']).strip()
                if clean_txt:
                    return clean_txt
    except Exception:
        pass

    patterns = [
        r'آخرین اتصال[\s\S]{0,250}?<span[^>]*>([^<]+)</span>',
        r'آخرین اتصال[\s\S]{0,100}?([۰-۹0-9]{4}[/-][۰-۹0-9]{1,2}[/-][۰-۹0-9]{1,2}[،,\s]+[۰-۹0-9]{1,2}:[۰-۹0-9]{1,2})',
        r'<span[^>]*>[^<]*?([۰-۹0-9]{4}[/-][۰-۹0-9]{1,2}[/-][۰-۹0-9]{1,2}[،,\s]+[۰-۹0-9]{1,2}:[۰-۹0-9]{1,2})[^<]*?</span>',
        r'"online_at"\s*:\s*"([^"]+)"',
        r'"(?:last_online|last_use|online_at)"\s*:\s*([0-9]+(?:\.[0-9]+)?)'
    ]
    for pat in patterns:
        m = re.search(pat, html_text)
        if m:
            val = m.group(1).strip()
            clean_val = re.sub(r'^[🟢⚪🔴\s]+', '', val).strip()
            if clean_val:
                ts = safe_parse_timestamp(clean_val)
                if ts > 0:
                    return format_timestamp_to_jalali(ts)
                return clean_val
    return ""

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
                extracted_date = extract_last_online_from_html(res_html.text)
                if extracted_date:
                    ts = safe_parse_timestamp(extracted_date)
                    is_on = (0 <= (time.time() - ts) <= 180) if ts > 0 else False
                    return is_on, extracted_date
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

# ----------------- آپدیت نام کانفیگ‌ها و اعمال حجم فیک -----------------
def update_config_remark(name: str, fake_total_gb: float) -> str:
    name = name.strip()
    if not name:
        return "Server"
    
    if fake_total_gb and fake_total_gb > 0:
        fake_str = f"{float(fake_total_gb):.1f} GB"
        if "🔋" in name:
            name = re.sub(r'🔋\s*\d+(?:\.\d+)?\s*(?:GB|گیگ)?', f'🔋{fake_str}', name, flags=re.IGNORECASE)
        elif any(k in name.upper() for k in ("DAY", "𝗗𝗔𝗬", "روز", "حجم", "|")) and re.search(r'\d+(?:\.\d+)?\s*GB', name, flags=re.IGNORECASE):
            name = re.sub(r'\d+(?:\.\d+)?\s*GB', fake_str, name, count=1, flags=re.IGNORECASE)

    if "ویژه" in name:
        name = name.replace("ویژه", "Stable")
    return name

def parse_and_modify_configs(raw_text: str, fake_total_gb: float = 0.0):
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
            new_name = update_config_remark(orig_remark, fake_total_gb)
            new_link = f"{base_part}#{urllib.parse.quote(new_name)}"
            configs.append({"proto": proto.upper(), "name": html.escape(new_name), "link": new_link})
            modified_raw_lines.append(new_link)

        elif line.startswith("vmess://"):
            try:
                b64_part = fix_b64_padding(line[8:])
                conf = json.loads(base64.b64decode(b64_part).decode("utf-8", errors="ignore"))
                orig_remark = str(conf.get("ps", f"Server {idx}"))
                new_name = update_config_remark(orig_remark, fake_total_gb)
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
    return upload, download, fake_total_bytes

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
    return data

async def get_cached_sub_data(token: str, upstream_url: str, fake_total_gb: float = 0.0):
    now = time.time()
    cache_key = f"{token}_{fake_total_gb}"
    cached = sub_cache.get(cache_key)
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
    
    configs, encoded_sub = parse_and_modify_configs(raw_text, fake_total_gb)
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
    sub_cache[cache_key] = data
    return data

def is_v2ray_client(user_agent: str) -> bool:
    ua = user_agent.lower()
    client_signatures = (
        "v2ray", "v2rayng", "v2rayn", "clash", "sing-box", "nekobox", 
        "streisand", "shadowrocket", "stash", "quantumult", "surge", "loon", "happ", "hiddify"
    )
    return any(sig in ua for sig in client_signatures)

# ----------------- قالب داشبورد کاربران (UNSLOP & UI/UX PRO) -----------------
DASHBOARD_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>داشبورد اشتراک | __BRAND_NAME__</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/misc/Farsi-Digits/Vazirmatn-FD-font-face.css">
    
    <style>
        :root {
            --bg-base: #08090d;
        }
        * { box-sizing: border-box; }
        body {
            font-family: 'Vazirmatn FD', sans-serif;
            background-color: var(--bg-base);
            color: #f8fafc;
            min-height: 100vh;
            background-image: 
                radial-gradient(circle at 10% 15%, rgba(59, 130, 246, 0.08) 0%, transparent 40%),
                radial-gradient(circle at 90% 85%, rgba(16, 185, 129, 0.06) 0%, transparent 40%);
            background-attachment: fixed;
            -webkit-font-smoothing: antialiased;
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

        .glass-card {
            background: rgba(255, 255, 255, 0.03);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.07);
            border-radius: 1.25rem;
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.25);
        }

        .ui-btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 0.55rem 1rem;
            font-size: 0.8125rem;
            font-weight: 600;
            border-radius: 0.75rem;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.12);
            color: #ffffff;
            cursor: pointer;
            user-select: none;
            transition: all 0.15s ease;
        }
        .ui-btn:hover {
            background: rgba(255, 255, 255, 0.1);
            border-color: rgba(255, 255, 255, 0.22);
        }
        .ui-btn:active {
            transform: scale(0.98);
        }
        .ui-btn-primary {
            background: #2563eb;
            border-color: #3b82f6;
        }
        .ui-btn-primary:hover {
            background: #1d4ed8;
            border-color: #60a5fa;
        }

        /* اسکرول‌بار شیشه‌ای مات و فوق‌باریک */
        ::-webkit-scrollbar {
            width: 5px;
            height: 5px;
        }
        ::-webkit-scrollbar-track {
            background: transparent;
        }
        ::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            border-radius: 9999px;
            border: 1px solid rgba(255, 255, 255, 0.08);
        }
        ::-webkit-scrollbar-thumb:hover {
            background: rgba(255, 255, 255, 0.25);
        }
        * {
            scrollbar-width: thin;
            scrollbar-color: rgba(255, 255, 255, 0.15) transparent;
        }

        .tab-btn {
            padding: 0.5rem 1.1rem;
            border-radius: 0.75rem;
            font-size: 0.8125rem;
            font-weight: 600;
            color: #94a3b8;
            background: transparent;
            border: 1px solid transparent;
            cursor: pointer;
            transition: all 0.15s ease;
        }
        .tab-btn.active {
            color: #ffffff;
            background: rgba(255, 255, 255, 0.08);
            border-color: rgba(255, 255, 255, 0.15);
        }
        .tab-btn:hover:not(.active) {
            color: #e2e8f0;
        }
    </style>
</head>
<body class="min-h-screen p-4 sm:p-8 flex flex-col justify-between max-w-4xl mx-auto space-y-6">
    <main class="space-y-6">
        
        <header class="p-4 sm:p-5 rounded-3xl border border-white/10 bg-white/[0.03] backdrop-blur-xl flex justify-between items-center shadow-lg">
            <div>
                <h1 class="text-lg sm:text-xl font-extrabold tracking-wide">__BRAND_NAME__</h1>
                <div class="text-xs text-blue-400 font-mono mt-0.5">High Speed Dedicated Cloud</div>
            </div>
            <button type="button" onclick="location.reload()" class="ui-btn gap-2" title="تازه‌سازی داده‌ها">
                <svg class="w-3.5 h-3.5 text-slate-300" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"></path></svg>
                <span>تازه‌سازی</span>
            </button>
        </header>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
            
            <div class="lg:col-span-2 glass-card p-6 flex flex-col justify-between">
                <div class="flex flex-wrap justify-between items-center gap-4 mb-6">
                    <div>
                        __STATUS_BADGE__
                    </div>
                    <div class="flex items-center gap-3">
                        __ONLINE_STATUS_BOX__
                        <div class="text-left bg-white/[0.03] border border-white/10 px-3.5 py-1.5 rounded-xl">
                            <div class="text-[11px] text-slate-400">منقضی می‌شود در</div>
                            <div class="text-lg sm:text-xl font-bold vazir-num text-slate-100">__DAYS_LEFT__ روز</div>
                        </div>
                    </div>
                </div>

                <div class="flex items-center justify-between gap-6">
                    <div class="space-y-3 flex-1">
                        <div class="flex justify-between items-center text-sm">
                            <span class="mono-num font-bold text-slate-100 text-base">__TOTAL_QUOTA__</span>
                            <span class="text-slate-400 text-xs">حجم سرویس</span>
                        </div>
                        <div class="flex justify-between items-center text-sm">
                            <span class="mono-num font-bold text-slate-100 text-base">__USED_TRAFFIC__</span>
                            <span class="text-slate-400 text-xs">حجم مصرفی</span>
                        </div>
                        <div class="flex justify-between items-center text-sm">
                            <span class="mono-num font-bold text-emerald-400 text-base">__REMAINING_TRAFFIC__</span>
                            <span class="text-slate-400 text-xs">حجم باقی مانده</span>
                        </div>
                    </div>

                    <div class="relative w-32 h-32 shrink-0 flex items-center justify-center">
                        <svg class="transform -rotate-90 w-full h-full" viewBox="0 0 120 120">
                            <circle cx="60" cy="60" r="48" stroke="rgba(255,255,255,0.06)" strokeWidth="9" fill="none"></circle>
                            <circle cx="60" cy="60" r="48" stroke="#10b981" strokeWidth="9" fill="none"
                                strokeDasharray="301.59" strokeDashoffset="__DASHOFFSET__"
                                strokeLinecap="round" class="transition-all duration-700"></circle>
                        </svg>
                        <div class="absolute inset-0 flex flex-col items-center justify-center">
                            <span class="text-2xl font-black mono-num text-slate-100">__PERCENT__%</span>
                            <span class="text-[11px] text-slate-400 font-medium mt-0.5">مصرف شده</span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="flex flex-col gap-4">
                <div class="glass-card p-5 flex flex-col justify-between flex-1">
                    <div class="text-xs text-slate-400 text-right">حجم کل سرویس</div>
                    <div class="text-2xl font-bold mono-num text-slate-100 text-left mt-2">__TOTAL_QUOTA__</div>
                </div>
                <div class="glass-card p-5 flex flex-col justify-between flex-1">
                    <div class="text-xs text-slate-400 text-right">تاریخ انقضا</div>
                    <div class="text-base font-bold vazir-num text-slate-100 text-right mt-2">__EXPIRE_DATE__</div>
                </div>
            </div>

        </div>

        <div class="glass-card p-4 sm:p-5 flex flex-col md:flex-row items-center justify-between gap-4">
            <div class="flex items-center gap-3 w-full md:w-auto min-w-0">
                <div class="w-10 h-10 rounded-xl bg-blue-500/15 border border-blue-400/25 flex items-center justify-center text-blue-400 shrink-0">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>
                </div>
                <div class="min-w-0 flex-1">
                    <div class="text-xs text-slate-400 font-medium mb-1">لینک هوشمند اشتراک:</div>
                    <div class="mono-num text-xs text-slate-200 bg-black/40 px-3 py-1.5 rounded-lg border border-white/5 truncate select-all">
                        __SUB_URL__
                    </div>
                </div>
            </div>
            <div class="flex items-center gap-2.5 w-full md:w-auto shrink-0 justify-end">
                <button type="button" onclick="copyText('__SUB_URL__', 'لینک اشتراک کپی شد')" class="ui-btn ui-btn-primary">
                    کپی لینک ساب
                </button>
                <button type="button" onclick="openQRModal('__SUB_URL__')" class="ui-btn">
                    اسکن QR
                </button>
            </div>
        </div>

        <div class="space-y-3">
            <div class="flex flex-col sm:flex-row items-center justify-between gap-3">
                <div class="flex items-center gap-1.5 p-1 rounded-xl bg-white/[0.03] border border-white/10 w-full sm:w-auto">
                    <button type="button" onclick="filterProtocol('all', this)" class="proto-btn px-3 py-1 text-xs font-semibold rounded-lg bg-blue-600 text-white transition-all">همه</button>
                    <button type="button" onclick="filterProtocol('VLESS', this)" class="proto-btn px-3 py-1 text-xs font-semibold rounded-lg text-slate-400 hover:text-white transition-all">VLESS</button>
                    <button type="button" onclick="filterProtocol('VMESS', this)" class="proto-btn px-3 py-1 text-xs font-semibold rounded-lg text-slate-400 hover:text-white transition-all">VMESS</button>
                    <button type="button" onclick="filterProtocol('TROJAN', this)" class="proto-btn px-3 py-1 text-xs font-semibold rounded-lg text-slate-400 hover:text-white transition-all">Trojan</button>
                </div>
                <div class="w-full sm:w-64">
                    <input type="text" id="confSearch" oninput="searchConfigs()" placeholder="جستجوی سرور..." class="w-full bg-white/[0.03] border border-white/10 rounded-xl px-3.5 py-1.5 text-xs text-white focus:outline-none focus:border-blue-500">
                </div>
            </div>

            <div class="max-h-80 overflow-y-auto space-y-2 pr-1" id="configListContainer">
                __CONFIG_ROWS__
            </div>
        </div>

        <div class="pt-2 space-y-3">
            <div class="text-xs text-slate-400 text-center font-semibold">دانلود نرم‌افزار اتصال مخصوص سیستم شما</div>
            <div class="flex justify-center flex-wrap gap-1.5 p-1 rounded-xl bg-white/[0.03] border border-white/10 w-fit mx-auto">
                <button type="button" onclick="switchPlatform('android', this)" class="tab-btn active">Android</button>
                <button type="button" onclick="switchPlatform('ios', this)" class="tab-btn">iOS</button>
                <button type="button" onclick="switchPlatform('windows', this)" class="tab-btn">Windows</button>
                <button type="button" onclick="switchPlatform('mac', this)" class="tab-btn">macOS</button>
                <button type="button" onclick="switchPlatform('linux', this)" class="tab-btn">Linux</button>
            </div>
            
            <div id="platform-android" class="platform-tab grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-1">
                <a href="https://github.com/hiddify/hiddify-next/releases" target="_blank" class="ui-btn ui-btn-primary">Hiddify</a>
                <a href="https://github.com/2dust/v2rayNG/releases" target="_blank" class="ui-btn">v2rayNG</a>
                <a href="https://github.com/chen08209/FlClash/releases" target="_blank" class="ui-btn">Flclash</a>
                <a href="https://github.com/SagerNet/sing-box/releases" target="_blank" class="ui-btn">Sing-box</a>
            </div>
            <div id="platform-ios" class="platform-tab hidden grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-1">
                <a href="https://apps.apple.com/us/app/hiddify-proxy-vpn/id6596777532" target="_blank" class="ui-btn ui-btn-primary">Hiddify</a>
                <a href="https://apps.apple.com/us/app/streisand/id6450534064" target="_blank" class="ui-btn">Streisand</a>
                <a href="https://apps.apple.com/us/app/shadowrocket/id932747118" target="_blank" class="ui-btn">Shadowrocket</a>
                <a href="https://apps.apple.com/us/app/sing-box/id6451272673" target="_blank" class="ui-btn">Sing-box</a>
            </div>
            <div id="platform-windows" class="platform-tab hidden grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-1">
                <a href="https://github.com/hiddify/hiddify-next/releases" target="_blank" class="ui-btn ui-btn-primary">Hiddify</a>
                <a href="https://github.com/2dust/v2rayN/releases" target="_blank" class="ui-btn">v2rayN</a>
                <a href="https://github.com/chen08209/FlClash/releases" target="_blank" class="ui-btn">Flclash</a>
                <a href="https://github.com/clash-verge-rev/clash-verge-rev/releases" target="_blank" class="ui-btn">Clash Verge</a>
            </div>
            <div id="platform-mac" class="platform-tab hidden grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-1">
                <a href="https://github.com/hiddify/hiddify-next/releases" target="_blank" class="ui-btn ui-btn-primary">Hiddify</a>
                <a href="https://github.com/clash-verge-rev/clash-verge-rev/releases" target="_blank" class="ui-btn">Clash Verge</a>
                <a href="https://github.com/chen08209/FlClash/releases" target="_blank" class="ui-btn">Flclash</a>
                <a href="https://github.com/SagerNet/sing-box/releases" target="_blank" class="ui-btn">Sing-box</a>
            </div>
            <div id="platform-linux" class="platform-tab hidden grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-1">
                <a href="https://github.com/hiddify/hiddify-next/releases" target="_blank" class="ui-btn ui-btn-primary">Hiddify</a>
                <a href="https://github.com/clash-verge-rev/clash-verge-rev/releases" target="_blank" class="ui-btn">Clash Verge</a>
                <a href="https://github.com/chen08209/FlClash/releases" target="_blank" class="ui-btn">Flclash</a>
                <a href="https://github.com/MatsuriDayo/nekoray/releases" target="_blank" class="ui-btn">NekoRay</a>
            </div>
        </div>
    </main>

    <footer class="pt-8 pb-4 text-center">
        <a href="https://t.me/DARK_WIKI20" target="_blank" rel="noopener noreferrer" class="text-xs text-slate-400 hover:text-slate-200 transition-colors">
            پشتیبانی تلگرام: <span class="mono-num font-bold text-blue-400">@DARK_WIKI20</span>
        </a>
    </footer>

    <div id="qrModal" class="fixed inset-0 bg-black/80 backdrop-blur-md hidden items-center justify-center p-4 z-50" onclick="closeQRModal()">
        <div class="p-6 rounded-3xl border border-white/20 bg-slate-900/90 shadow-2xl flex flex-col items-center max-w-xs w-full" onclick="event.stopPropagation()">
            <div class="text-xs font-bold mb-4 text-slate-300">کد QR اختصاصی</div>
            <img id="qrModalImg" src="" alt="QR" class="w-52 h-52 rounded-xl bg-white p-2.5 mb-5 shadow-lg">
            <button type="button" onclick="closeQRModal()" class="ui-btn w-full">بستن</button>
        </div>
    </div>

    <div id="toastBox" class="fixed bottom-6 left-1/2 -translate-x-1/2 px-4 py-2 rounded-xl bg-white text-slate-900 font-bold text-xs shadow-2xl z-50 hidden"></div>

    <script>
        function copyText(txt, msg) {
            navigator.clipboard.writeText(txt);
            const t = document.getElementById('toastBox');
            t.textContent = msg;
            t.classList.remove('hidden');
            setTimeout(() => t.classList.add('hidden'), 2000);
        }

        function openQRModal(url) {
            document.getElementById('qrModalImg').src = 'https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=' + encodeURIComponent(url);
            document.getElementById('qrModal').classList.remove('hidden');
            document.getElementById('qrModal').classList.add('flex');
        }

        function closeQRModal() {
            document.getElementById('qrModal').classList.add('hidden');
            document.getElementById('qrModal').classList.remove('flex');
        }

        function filterProtocol(proto, btn) {
            document.querySelectorAll('.proto-btn').forEach(b => {
                b.classList.remove('bg-blue-600', 'text-white');
                b.classList.add('text-slate-400');
            });
            btn.classList.add('bg-blue-600', 'text-white');
            btn.classList.remove('text-slate-400');

            document.querySelectorAll('.config-item').forEach(el => {
                const matchProto = (proto === 'all') || (el.getAttribute('data-proto') === proto);
                const q = document.getElementById('confSearch').value.toLowerCase();
                const matchSearch = el.getAttribute('data-name').includes(q);
                el.style.display = (matchProto && matchSearch) ? '' : 'none';
            });
        }

        function searchConfigs() {
            const q = document.getElementById('confSearch').value.toLowerCase();
            const activeProtoBtn = document.querySelector('.proto-btn.bg-blue-600');
            const proto = activeProtoBtn ? activeProtoBtn.textContent.trim() : 'همه';

            document.querySelectorAll('.config-item').forEach(el => {
                const matchProto = (proto === 'همه') || (el.getAttribute('data-proto') === proto);
                const matchSearch = el.getAttribute('data-name').includes(q);
                el.style.display = (matchProto && matchSearch) ? '' : 'none';
            });
        }

        function switchPlatform(p, btn) {
            document.querySelectorAll('.platform-tab').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.getElementById('platform-' + p).classList.remove('hidden');
            btn.classList.add('active');
        }
    </script>
</body>
</html>"""

def render_dashboard_html(ctx: dict) -> str:
    configs = ctx.get("configs", [])
    config_rows = ""
    for c in configs:
        safe_name = html.escape(c["name"])
        safe_proto = html.escape(c["proto"])
        safe_link = html.escape(c["link"])
        config_rows += f"""
        <div class="config-item p-3 rounded-xl border border-white/10 bg-white/[0.02] hover:border-white/20 transition-colors flex items-center justify-between gap-3" data-proto="{safe_proto}" data-name="{safe_name.lower()}">
            <div class="flex items-center gap-2.5 min-w-0">
                <span class="mono-num text-[11px] font-bold px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-400/30 uppercase shrink-0">
                    {safe_proto}
                </span>
                <span class="text-xs sm:text-sm font-medium truncate text-slate-200" dir="auto">
                    {safe_name}
                </span>
            </div>
            <div class="flex items-center gap-1.5 shrink-0">
                <button type="button" onclick="copyText('{safe_link}', 'کانفیگ کپی شد')" class="ui-btn">
                    کپی
                </button>
                <button type="button" onclick="openQRModal('{safe_link}')" class="ui-btn">
                    QR
                </button>
            </div>
        </div>"""

    if not config_rows:
        config_rows = '<div class="p-6 text-center text-xs text-slate-500 rounded-2xl border border-white/5 bg-white/[0.01]">سروری ثبت نشده است.</div>'

    percent = ctx["percent"]
    dashoffset = 301.59 - (301.59 * percent / 100)

    status_badge = (
        '<div class="text-2xl font-bold text-rose-500 flex items-center gap-2">مسدود <span class="w-2.5 h-2.5 rounded-full bg-rose-500"></span></div>'
        if ctx["is_blocked"] else
        '<div class="text-2xl font-bold text-emerald-400 flex items-center gap-2">فعال <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.8)]"></span></div>'
    )

    if ctx["is_online"]:
        online_status_box = '<div class="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 text-xs font-bold"><span class="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)] animate-pulse"></span>در حال استفاده (روشن)</div>'
    else:
        last_s = ctx["last_seen_text"] or ctx["now_jalali"]
        online_status_box = f'<div class="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-white/[0.04] border border-white/10 text-slate-300 text-xs font-medium"><span class="w-2 h-2 rounded-full bg-slate-500"></span>آخرین اتصال: <span class="vazir-num text-slate-200">{last_s}</span></div>'

    return (
        DASHBOARD_HTML_TEMPLATE
        .replace("__BRAND_NAME__", html.escape(ctx["brand_name"]))
        .replace("__DAYS_LEFT__", str(ctx["days_left"]))
        .replace("__STATUS_BADGE__", status_badge)
        .replace("__ONLINE_STATUS_BOX__", online_status_box)
        .replace("__TOTAL_QUOTA__", str(ctx["total_quota"]))
        .replace("__USED_TRAFFIC__", str(ctx["used_traffic"]))
        .replace("__REMAINING_TRAFFIC__", str(ctx["remaining_traffic"]))
        .replace("__EXPIRE_DATE__", str(ctx["expire_date"]))
        .replace("__SUB_URL__", str(ctx["sub_url"]))
        .replace("__PERCENT__", str(percent))
        .replace("__DASHOFFSET__", str(dashoffset))
        .replace("__CONFIG_ROWS__", config_rows)
    )

# ----------------- قالب اختصاصی پنل ادمین (فقط با GLISSE) -----------------
ADMIN_PANEL_GLISSE_TEMPLATE = """<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>مدیریت سرور | کنترل پنل Glisse</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/misc/Farsi-Digits/Vazirmatn-FD-font-face.css">
    
    <!-- کتابخانه رسمی CSS پکیج Glisse -->
    <link rel="stylesheet" href="https://esm.sh/glisse@0.5.0/dist/styles.css">
    
    <style>
        :root {
            --bg-base: #06080e;
        }
        * { box-sizing: border-box; }
        body {
            font-family: 'Vazirmatn FD', sans-serif;
            background-color: var(--bg-base);
            color: #f8fafc;
            min-height: 100vh;
            background-image: 
                radial-gradient(circle at 15% 15%, rgba(59, 130, 246, 0.14) 0%, transparent 45%),
                radial-gradient(circle at 85% 85%, rgba(16, 185, 129, 0.08) 0%, transparent 45%);
            background-attachment: fixed;
            -webkit-font-smoothing: antialiased;
        }
        .mono-num {
            font-family: ui-monospace, SFMono-Regular, monospace !important;
            direction: ltr !important;
            display: inline-block;
        }
        .vazir-num {
            font-family: 'Vazirmatn FD', sans-serif !important;
            direction: rtl !important;
            display: inline-block;
        }

        .liquid-card {
            background: rgba(255, 255, 255, 0.035);
            backdrop-filter: blur(20px) saturate(180%);
            -webkit-backdrop-filter: blur(20px) saturate(180%);
            border: 1px solid rgba(255, 255, 255, 0.09);
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.35), inset 0 1px 1px 0 rgba(255, 255, 255, 0.2);
            border-radius: 1.5rem;
        }

        ::-webkit-scrollbar { width: 5px; height: 5px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(8px);
            border-radius: 9999px;
            border: 1px solid rgba(255, 255, 255, 0.08);
        }
    </style>

    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
</head>
<body>
    <div id="admin-root" data-glisse-backdrop></div>

    <script type="text/babel" data-type="module">
        import React, { useState, useMemo } from 'https://esm.sh/react@18.3.1';
        import ReactDOM from 'https://esm.sh/react-dom@18.3.1/client';
        import { Button, TabBar, SegmentedControl, Menu, Input, Switch } from 'https://esm.sh/glisse@0.5.0?deps=react@18.3.1,react-dom@18.3.1';

        const ADMIN_DATA = __ADMIN_DATA__;

        function AdminApp() {
            const [view, setView] = useState("profiles");
            const [statusFilter, setStatusFilter] = useState("all");
            const [search, setSearch] = useState("");
            const [overwrite, setOverwrite] = useState(false);
            const [editProfile, setEditProfile] = useState(null);
            const [qrUrl, setQrUrl] = useState(null);
            const [toast, setToast] = useState("");

            const showToast = (msg) => {
                setToast(msg);
                setTimeout(() => setToast(""), 2200);
            };

            const copyText = (txt, msg) => {
                navigator.clipboard.writeText(txt);
                showToast(msg);
            };

            const submitPost = (action, fields = {}) => {
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = action;
                fields['csrf_token'] = ADMIN_DATA.csrf_token;
                for (const [k, v] of Object.entries(fields)) {
                    const inp = document.createElement('input');
                    inp.type = 'hidden';
                    inp.name = k;
                    inp.value = v;
                    form.appendChild(inp);
                }
                document.body.appendChild(form);
                form.submit();
            };

            const filteredProfiles = useMemo(() => {
                return (ADMIN_DATA.profiles || []).filter(p => {
                    const matchStatus = (statusFilter === "all") || (statusFilter === "active" && !p.is_blocked) || (statusFilter === "blocked" && p.is_blocked);
                    const q = search.toLowerCase();
                    const matchSearch = p.name.toLowerCase().includes(q) || p.token.toLowerCase().includes(q) || (p.admin_note || "").toLowerCase().includes(q);
                    return matchStatus && matchSearch;
                });
            }, [statusFilter, search]);

            const handleRestore = async () => {
                const fileInput = document.getElementById('backupFileInput');
                if (!fileInput.files.length) {
                    alert('لطفاً ابتدا فایل JSON بکاپ را انتخاب کنید.');
                    return;
                }
                const reader = new FileReader();
                reader.onload = async (e) => {
                    try {
                        const parsed = JSON.parse(e.target.result);
                        const res = await fetch(`/${ADMIN_DATA.admin_path}/backup/restore`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                csrf_token: ADMIN_DATA.csrf_token,
                                overwrite_existing: overwrite,
                                backup: parsed
                            })
                        });
                        const data = await res.json();
                        alert(data.msg);
                        if (data.ok) location.reload();
                    } catch (err) {
                        alert('فرمت فایل JSON نامعتبر است.');
                    }
                };
                reader.readAsText(fileInput.files[0]);
            };

            return (
                <div className="min-h-screen p-4 sm:p-8 max-w-7xl mx-auto space-y-6">
                    
                    {/* ۱. هدر شیشه‌ای با Glisse Button */}
                    <header className="liquid-card p-5 flex flex-wrap justify-between items-center gap-4">
                        <div className="flex items-center gap-3.5">
                            <div className="w-11 h-11 rounded-2xl bg-blue-500/15 border border-blue-400/30 flex items-center justify-center text-blue-400 shadow-inner">
                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
                            </div>
                            <div>
                                <h1 className="text-base font-extrabold text-slate-100">کنترل پنل مرکزی دیتاسنتر</h1>
                                <div className="text-xs text-slate-400 mono-num mt-0.5">{ADMIN_DATA.domain}</div>
                            </div>
                        </div>

                        <div className="flex flex-wrap items-center gap-2.5">
                            <Button variant="glass" onClick={() => submitPost(`/${ADMIN_DATA.admin_path}/cache/clear`)}>
                                پاکسازی کش ({ADMIN_DATA.cached_items})
                            </Button>
                            <Button variant="filled" onClick={() => window.location.href = `/${ADMIN_DATA.admin_path}/backup`}>
                                دانلود بکاپ JSON
                            </Button>
                            <Button variant="destructive" onClick={() => window.location.href = `/${ADMIN_DATA.admin_path}/logout`}>
                                خروج
                            </Button>
                        </div>
                    </header>

                    {/* ۲. کارت‌های KPI آمار کل سیستم */}
                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                        <div className="liquid-card p-5 flex flex-col justify-between">
                            <div className="text-xs text-slate-400 font-medium mb-1">کل اشتراک‌ها</div>
                            <div className="text-3xl font-black mono-num text-slate-100">{ADMIN_DATA.total_count}</div>
                        </div>
                        <div className="liquid-card p-5 flex flex-col justify-between">
                            <div className="text-xs text-slate-400 font-medium mb-1">اشتراک‌های فعال</div>
                            <div className="text-3xl font-black mono-num text-emerald-400">{ADMIN_DATA.active_count}</div>
                        </div>
                        <div className="liquid-card p-5 flex flex-col justify-between">
                            <div className="text-xs text-slate-400 font-medium mb-1">مسدود شده</div>
                            <div className="text-3xl font-black mono-num text-rose-400">{ADMIN_DATA.blocked_count}</div>
                        </div>
                        <div className="liquid-card p-5 flex flex-col justify-between">
                            <div className="text-xs text-slate-400 font-medium mb-1">سینک‌های کلاینت</div>
                            <div className="text-3xl font-black mono-num text-blue-400">{ADMIN_DATA.total_hits}</div>
                        </div>
                    </div>

                    {/* ۳. تب‌بار تعاملی Glisse TabBar برای ناوبری سریع */}
                    <div dir="ltr" className="flex justify-center w-full overflow-x-auto py-1">
                        <TabBar
                            aria-label="Admin Navigation"
                            items={[
                                { value: "profiles", label: "فهرست اشتراک‌ها" },
                                { value: "new_profile", label: "ثبت ساب جدید" },
                                { value: "backup_view", label: "بازیابی بکاپ" }
                            ]}
                            value={view}
                            onValueChange={setView}
                            style={{ "--lg-lens-grow-x": "16px", "--lg-lens-grow-y": "10px" }}
                        />
                    </div>

                    {/* ۴. فهرست اشتراک‌ها با SegmentedControl و Input و دکمه‌های کپی و تغییر */}
                    {view === "profiles" && (
                        <section className="liquid-card overflow-hidden space-y-4 p-5">
                            <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pb-2 border-b border-white/[0.06]">
                                <div dir="ltr">
                                    <SegmentedControl
                                        aria-label="Filter"
                                        items={[
                                            { value: "all", label: "همه ساب‌ها" },
                                            { value: "active", label: "فعال‌ها" },
                                            { value: "blocked", label: "مسدودها" }
                                        ]}
                                        value={statusFilter}
                                        onValueChange={setStatusFilter}
                                    />
                                </div>
                                <div className="w-full sm:w-64" dir="rtl">
                                    <Input
                                        type="search"
                                        aria-label="Search Profiles"
                                        placeholder="جستجو نام، توکن، یادداشت..."
                                        value={search}
                                        onValueChange={setSearch}
                                    />
                                </div>
                            </div>

                            <div className="overflow-x-auto">
                                <table className="w-full text-right text-sm">
                                    <thead className="bg-white/[0.02] text-slate-400 text-xs border-b border-white/[0.06]">
                                        <tr>
                                            <th className="p-4 whitespace-nowrap">کاربر</th>
                                            <th className="p-4 whitespace-nowrap">لینک‌ها</th>
                                            <th className="p-4 whitespace-nowrap text-center">وضعیت</th>
                                            <th className="p-4 whitespace-nowrap text-center">حجم مجازی</th>
                                            <th className="p-4 whitespace-nowrap text-center">مصرف / سقف</th>
                                            <th className="p-4 whitespace-nowrap">همگام‌سازی</th>
                                            <th className="p-4 whitespace-nowrap text-center">دسترسی</th>
                                            <th className="p-4 text-left whitespace-nowrap">مدیریت</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-white/[0.04]">
                                        {filteredProfiles.length === 0 ? (
                                            <tr>
                                                <td colSpan="8" className="p-8 text-center text-slate-500 text-xs">هیچ رکوردی یافت نشد.</td>
                                            </tr>
                                        ) : (
                                            filteredProfiles.map((p, idx) => (
                                                <tr key={idx} className="hover:bg-white/[0.02] transition-colors">
                                                    <td className="p-4 whitespace-nowrap">
                                                        <div className="font-bold text-sm text-slate-200">
                                                            {p.name}
                                                            {p.custom_notice && <span className="mr-2 text-[10px] px-1.5 py-0.5 rounded border border-blue-400/30 bg-blue-500/15 text-blue-300">اعلان</span>}
                                                        </div>
                                                        {p.admin_note && <div className="text-[11px] text-amber-400/80 mt-1 font-mono">{p.admin_note}</div>}
                                                    </td>
                                                    <td className="p-4 whitespace-nowrap">
                                                        <div className="flex items-center gap-1.5">
                                                            <Button variant="glass" onClick={() => copyText(`https://${ADMIN_DATA.domain}/d/${p.token}`, "لینک داشبورد کپی شد")}>داشبورد</Button>
                                                            <Button variant="glass" onClick={() => copyText(`https://${ADMIN_DATA.domain}/sub/${p.token}`, "لینک ساب کپی شد")}>ساب</Button>
                                                            <Button variant="glass" onClick={() => setQrUrl(`https://${ADMIN_DATA.domain}/sub/${p.token}`)}>QR</Button>
                                                        </div>
                                                    </td>
                                                    <td className="p-4 whitespace-nowrap text-center">
                                                        {p.is_online ? (
                                                            <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400 font-semibold"><span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>متصل</span>
                                                        ) : (
                                                            <span className="text-xs text-slate-400">{p.last_seen_text || "نامشخص"}</span>
                                                        )}
                                                    </td>
                                                    <td className="p-4 whitespace-nowrap text-center">
                                                        {p.fake_total_gb > 0 ? (
                                                            <span className="mono-num text-xs text-blue-400 font-bold">{p.fake_total_gb} GB</span>
                                                        ) : (
                                                            <span className="text-slate-500 text-xs">واقعی</span>
                                                        )}
                                                    </td>
                                                    <td className="p-4 whitespace-nowrap text-center mono-num text-xs text-slate-200">
                                                        {p.traffic_badge}
                                                    </td>
                                                    <td className="p-4 whitespace-nowrap">
                                                        <div className="text-xs font-semibold mono-num text-slate-300">{p.sub_hits || 0} بار</div>
                                                        <div className="text-[11px] text-slate-500 mt-0.5">{p.last_sub_fetch || "بدون اتصال"}</div>
                                                    </td>
                                                    <td className="p-4 whitespace-nowrap text-center">
                                                        {p.is_blocked ? (
                                                            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold border border-rose-500/30 bg-rose-500/10 text-rose-400">مسدود</span>
                                                        ) : (
                                                            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">فعال</span>
                                                        )}
                                                    </td>
                                                    <td className="p-4 whitespace-nowrap text-left">
                                                        <div className="flex justify-end items-center gap-1.5">
                                                            <Button variant="tinted" onClick={() => setEditProfile(p)}>ویرایش</Button>
                                                            <Button variant="glass" onClick={() => submitPost(`/${ADMIN_DATA.admin_path}/profiles/${p.token}/refresh-cache`)}>تازه‌سازی</Button>
                                                            <Button variant="glass" onClick={() => submitPost(`/${ADMIN_DATA.admin_path}/profiles/${p.token}/toggle-block`)}>
                                                                {p.is_blocked ? "فعال‌سازی" : "مسدود"}
                                                            </Button>
                                                            <Button variant="destructive" onClick={() => { if(confirm('آیا از حذف کامل این ساب اطمینان دارید؟')) submitPost(`/${ADMIN_DATA.admin_path}/profiles/${p.token}/delete`); }}>
                                                                حذف
                                                            </Button>
                                                        </div>
                                                    </td>
                                                </tr>
                                            ))
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </section>
                    )}

                    {/* ۵. نمای ثبت ساب جدید با هندلر فرم امن */}
                    {view === "new_profile" && (
                        <section className="liquid-card p-6 max-w-2xl mx-auto">
                            <h2 className="text-base font-bold text-slate-100 mb-4">افزودن اشتراک جدید</h2>
                            <form
                                onSubmit={(e) => {
                                    e.preventDefault();
                                    const fd = new FormData(e.target);
                                    const fields = {};
                                    fd.forEach((val, key) => { fields[key] = val; });
                                    submitPost(`/${ADMIN_DATA.admin_path}/profiles/add`, fields);
                                }}
                                className="space-y-4"
                            >
                                <div>
                                    <label className="block text-xs text-slate-400 mb-1 font-medium">نام یا شناسه کاربر *</label>
                                    <input type="text" name="name" placeholder="User-VIP" required className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-blue-500" />
                                </div>
                                <div>
                                    <label className="block text-xs text-slate-400 mb-1 font-medium">لینک مستقیم فروشنده (Upstream) *</label>
                                    <input type="url" name="upstream_url" placeholder="https://panel.site/sub/..." required className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-blue-500 mono-num text-left" />
                                </div>
                                <div>
                                    <label className="block text-xs text-slate-400 mb-1 font-medium">حجم مجازی کل (GB) — اختیاری</label>
                                    <input type="number" step="0.1" min="0" name="fake_total_gb" placeholder="0 = حجم واقعی" className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-blue-500 mono-num text-left" />
                                </div>
                                <div>
                                    <label className="block text-xs text-slate-400 mb-1 font-medium">توکن اختصاصی لینک (اختیاری)</label>
                                    <input type="text" name="custom_token" placeholder="خالی = خودکار" className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-blue-500 mono-num text-left" />
                                </div>
                                <div>
                                    <label className="block text-xs text-slate-400 mb-1 font-medium">اعلان داشبورد</label>
                                    <input type="text" name="custom_notice" placeholder="متن پیام به کاربر..." className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-blue-500" />
                                </div>
                                <div>
                                    <label className="block text-xs text-slate-400 mb-1 font-medium">یادداشت داخلی ادمین</label>
                                    <input type="text" name="admin_note" placeholder="آیدی تلگرام، تاریخ و..." className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-blue-500" />
                                </div>
                                <div className="pt-2">
                                    <Button variant="filled" type="submit" style={{ width: "100%", padding: "0.75rem" }}>
                                        ایجاد و ذخیره اشتراک
                                    </Button>
                                </div>
                            </form>
                        </section>
                    )}

                    {/* ۶. نمای بازیابی بکاپ */}
                    {view === "backup_view" && (
                        <section className="liquid-card p-6 max-w-xl mx-auto space-y-4">
                            <h2 className="text-base font-bold text-slate-100 mb-1">بازیابی اطلاعات از بکاپ</h2>
                            <p className="text-xs text-slate-400 leading-relaxed">فایل JSON بکاپ قبلی خود را بارگذاری کرده تا تمام رکوردهای ساب بازگردانی شوند.</p>
                            
                            <input type="file" id="backupFileInput" accept=".json" className="w-full bg-black/40 border border-white/10 rounded-xl p-3 text-xs text-white" />

                            <div className="flex items-center justify-between p-3 rounded-xl bg-white/[0.02] border border-white/5">
                                <span className="text-xs text-slate-300 font-medium">به‌روزرسانی رکوردهای تکراری:</span>
                                <Switch aria-label="Overwrite Existing" checked={overwrite} onCheckedChange={setOverwrite} />
                            </div>

                            <Button variant="filled" onClick={handleRestore} style={{ width: "100%", padding: "0.75rem" }}>
                                آپلود و اعمال بکاپ
                            </Button>
                        </section>
                    )}

                    {/* مدال ویرایش ساب با تضمین اجرای دقیق تغییرات */}
                    {editProfile && (
                        <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 z-50" onClick={() => setEditProfile(null)}>
                            <div className="liquid-card p-6 max-w-md w-full shadow-2xl space-y-4" onClick={(e) => e.stopPropagation()}>
                                <h3 className="text-base font-bold text-slate-100 mb-2">ویرایش اطلاعات ساب</h3>
                                <form
                                    onSubmit={(e) => {
                                        e.preventDefault();
                                        const fd = new FormData(e.target);
                                        const fields = {};
                                        fd.forEach((val, key) => { fields[key] = val; });
                                        submitPost(`/${ADMIN_DATA.admin_path}/profiles/${encodeURIComponent(editProfile.token)}/edit`, fields);
                                    }}
                                    className="space-y-3.5"
                                >
                                    <div>
                                        <label className="block text-xs text-slate-400 mb-1 font-medium">نام یا شناسه کاربر</label>
                                        <input type="text" name="name" defaultValue={editProfile.name} required className="w-full bg-black/40 border border-white/10 rounded-xl px-3.5 py-2 text-sm text-white" />
                                    </div>
                                    <div>
                                        <label className="block text-xs text-slate-400 mb-1 font-medium">لینک مستقیم فروشنده</label>
                                        <input type="url" name="upstream_url" defaultValue={editProfile.upstream_url} required className="w-full bg-black/40 border border-white/10 rounded-xl px-3.5 py-2 text-sm text-white mono-num text-left" />
                                    </div>
                                    <div>
                                        <label className="block text-xs text-slate-400 mb-1 font-medium">حجم مجازی کل (GB)</label>
                                        <input type="number" step="0.1" min="0" name="fake_total_gb" defaultValue={editProfile.fake_total_gb} required className="w-full bg-black/40 border border-white/10 rounded-xl px-3.5 py-2 text-sm text-white mono-num text-left" />
                                    </div>
                                    <div>
                                        <label className="block text-xs text-slate-400 mb-1 font-medium">اعلان داشبورد</label>
                                        <input type="text" name="custom_notice" defaultValue={editProfile.custom_notice} className="w-full bg-black/40 border border-white/10 rounded-xl px-3.5 py-2 text-sm text-white" />
                                    </div>
                                    <div>
                                        <label className="block text-xs text-slate-400 mb-1 font-medium">یادداشت داخلی ادمین</label>
                                        <input type="text" name="admin_note" defaultValue={editProfile.admin_note} className="w-full bg-black/40 border border-white/10 rounded-xl px-3.5 py-2 text-sm text-white" />
                                    </div>
                                    <div className="flex gap-2 pt-3">
                                        <Button variant="filled" type="submit" style={{ flex: 1 }}>ذخیره تغییرات</Button>
                                        <Button variant="glass" onClick={() => setEditProfile(null)}>انصراف</Button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    )}

                    {/* مدال نمایش QR Code */}
                    {qrUrl && (
                        <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 z-50" onClick={() => setQrUrl(null)}>
                            <div className="liquid-card p-6 rounded-3xl shadow-2xl flex flex-col items-center max-w-xs w-full" onClick={(e) => e.stopPropagation()}>
                                <div className="text-xs font-bold mb-4 text-slate-300">کد QR اختصاصی اشتراک</div>
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

        ReactDOM.createRoot(document.getElementById("admin-root")).render(<AdminApp />);
    </script>
</body>
</html>"""

def render_admin_html(profiles, domain: str, csrf_token: str, admin_path: str) -> str:
    total_count = len(profiles)
    blocked_count = sum(1 for p in profiles if p["is_blocked"])
    active_count = total_count - blocked_count
    total_hits = sum((p["sub_hits"] or 0) for p in profiles)
    cached_items = len(sub_cache)

    profiles_list = []
    for p in profiles:
        fake_val = p["fake_total_gb"] or 0
        cached_data = sub_cache.get(f"{p['token']}_{fake_val}") or sub_cache.get(p["token"])
        
        if cached_data and cached_data.get("info"):
            info = cached_data["info"]
            u, d, tot = apply_fake_traffic(info.get("upload", 0), info.get("download", 0), info.get("total", 0), fake_val)
            traffic_badge = f"{format_bytes(u+d)} / {format_bytes(tot)}"
            is_online = bool(cached_data.get("is_online"))
            last_seen = str(cached_data.get("last_seen_text") or "نامشخص")
        else:
            traffic_badge = "—"
            is_online = False
            last_seen = "نامشخص"

        profiles_list.append({
            "token": str(p["token"]),
            "name": str(p["name"]),
            "upstream_url": str(p["upstream_url"]),
            "fake_total_gb": float(fake_val),
            "custom_notice": str(p["custom_notice"] or ""),
            "admin_note": str(p["admin_note"] or ""),
            "sub_hits": int(p["sub_hits"] or 0),
            "last_sub_fetch": str(p["last_sub_fetch"] or ""),
            "is_blocked": bool(p["is_blocked"]),
            "is_online": is_online,
            "last_seen_text": last_seen,
            "traffic_badge": traffic_badge
        })

    admin_ctx = {
        "domain": str(domain),
        "admin_path": str(admin_path),
        "csrf_token": str(csrf_token),
        "total_count": total_count,
        "active_count": active_count,
        "blocked_count": blocked_count,
        "total_hits": total_hits,
        "cached_items": cached_items,
        "profiles": profiles_list
    }

    # حفاظت ضد XSS در برابر Script Injection
    ctx_json = json.dumps(admin_ctx, ensure_ascii=False).replace("<", "\\u003c")
    return ADMIN_PANEL_GLISSE_TEMPLATE.replace("__ADMIN_DATA__", ctx_json)

def render_login_html(admin_path: str, error: str = None) -> str:
    err_box = f'<div class="p-3 mb-4 rounded-xl text-xs font-semibold text-center border border-rose-500/30 bg-rose-500/15 text-rose-400">{html.escape(error)}</div>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ورود مدیریت دیتاسنتر</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/misc/Farsi-Digits/Vazirmatn-FD-font-face.css">
    <style>
        body {{
            background-color: #06080e;
            color: #f1f5f9;
            font-family: 'Vazirmatn FD', sans-serif;
            background-image: radial-gradient(circle at 12% 18%, rgba(59, 130, 246, 0.12) 0%, transparent 45%);
            background-attachment: fixed;
        }}
        .liquid-card {{
            background: rgba(255, 255, 255, 0.04);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 1.5rem;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.35);
        }}
    </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4">
    <div class="liquid-card w-full max-w-sm p-6 sm:p-8">
        <div class="w-12 h-12 rounded-2xl bg-blue-500/15 border border-blue-400/30 flex items-center justify-center text-blue-400 mx-auto mb-4 shadow-inner">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
        </div>
        <h1 class="text-base font-extrabold text-center mb-1 text-slate-100">احراز هویت سرور</h1>
        <p class="text-xs text-slate-400 text-center mb-6">کنترل پنل مرکزی دیتاسنتر</p>
        {err_box}
        <form action="/{admin_path}/login" method="post" class="space-y-4">
            <div>
                <label for="admin_pass" class="block text-xs text-slate-400 mb-1.5 font-medium">رمز عبور امنیتی</label>
                <input id="admin_pass" type="password" name="password" required autofocus class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-blue-500 mono-num text-left">
            </div>
            <button type="submit" class="w-full py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs transition-colors shadow-lg cursor-pointer">ورود به سیستم</button>
        </form>
    </div>
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

    fake_gb = float(profile["fake_total_gb"] or 0)
    try:
        sub_data = await get_cached_sub_data(token, profile["upstream_url"], fake_gb)
        info = sub_data.get("info", {})
        
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
    fake_gb = float(profile["fake_total_gb"] or 0)

    if not is_blocked:
        try:
            sub_data = await get_cached_sub_data(token, profile["upstream_url"], fake_gb)
            info = sub_data.get("info", {})
            configs = sub_data.get("configs", [])
            is_online = bool(sub_data.get("is_online", False))
            last_seen_text = str(sub_data.get("last_seen_text", "نامشخص"))
            
            raw_up = info.get("upload", 0)
            raw_down = info.get("download", 0)
            raw_total = info.get("total", 0)
            expire_ts = safe_parse_timestamp(info.get("expire", 0))
            
            upload, download, total_quota = apply_fake_traffic(raw_up, raw_down, raw_total, fake_gb)
        except Exception:
            is_online = False
            last_seen_text = "نامشخص"

    used_traffic = upload + download
    remaining = max(0, total_quota - used_traffic)
    
    # محاسبه درصد کاملاً بر مبنای حجم فیک
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

    clean_token = urllib.parse.unquote(token).strip()
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
                (name, upstream_url, fake_total_gb, custom_notice, admin_note, clean_token)
            )
            conn.commit()

    sub_cache.clear()
    return RedirectResponse(url=f"/{ADMIN_SECRET_PATH}", status_code=status.HTTP_302_FOUND)

@app.post(f"/{ADMIN_SECRET_PATH}/profiles/{{token}}/refresh-cache")
async def refresh_single_cache(request: Request, token: str):
    if not is_admin(request):
        raise HTTPException(status_code=401)
    form_data = await read_bounded_form(request)
    if not verify_csrf(request, form_data.get("csrf_token", [""])[0]):
        raise HTTPException(status_code=403)
    
    clean_token = urllib.parse.unquote(token).strip()
    with get_db() as conn:
        profile = conn.execute("SELECT * FROM profiles WHERE token = ?", (clean_token,)).fetchone()
    if profile:
        fake_gb = float(profile["fake_total_gb"] or 0)
        sub_cache.pop(f"{clean_token}_{fake_gb}", None)
        sub_cache.pop(clean_token, None)
        try:
            await get_cached_sub_data(clean_token, profile["upstream_url"], fake_gb)
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

    clean_token = urllib.parse.unquote(token).strip()
    with get_db() as conn:
        conn.execute("UPDATE profiles SET is_blocked = CASE WHEN is_blocked = 1 THEN 0 ELSE 1 END WHERE token = ?", (clean_token,))
        conn.commit()

    sub_cache.clear()
    return RedirectResponse(url=f"/{ADMIN_SECRET_PATH}", status_code=status.HTTP_302_FOUND)

@app.post(f"/{ADMIN_SECRET_PATH}/profiles/{{token}}/delete")
async def delete_profile(request: Request, token: str):
    if not is_admin(request):
        raise HTTPException(status_code=401)
    form_data = await read_bounded_form(request)
    if not verify_csrf(request, form_data.get("csrf_token", [""])[0]):
        raise HTTPException(status_code=403)

    clean_token = urllib.parse.unquote(token).strip()
    with get_db() as conn:
        conn.execute("DELETE FROM profiles WHERE token = ?", (clean_token,))
        conn.commit()

    sub_cache.clear()
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
                fake_gb = float(profile["fake_total_gb"] or 0)
                sub_data = await get_cached_sub_data(profile["token"], profile["upstream_url"], fake_gb)
                info = sub_data.get("info", {})
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
