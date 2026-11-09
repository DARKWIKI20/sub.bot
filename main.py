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
    response.headers["Referrer-Policy"] = "no-referrer"
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

# ----------------- آپدیت ریمارک و اعمال حجم فیک -----------------
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

# ----------------- قالب اختصاصی داشبورد کاربران (UNSLOP & UI/UX PRO MAX) -----------------
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

        /* کارت‌های شیشه‌ای مایع (Liquid Glass) */
        .glass-card {
            background: rgba(255, 255, 255, 0.03);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.07);
            border-radius: 1.25rem;
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.25);
        }

        /* دکمه‌های مینیمال استاندارد */
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
        
        <!-- ۱. هدر مینیمال بدون سنسور اتصال -->
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

        <!-- ۲. کارت‌های اصلی دقیقا طبق ساختار تصویر ارسالی با پس‌زمینه شفاف -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
            
            <!-- کارت بزرگ: وضعیت، روزشمار، گیج و تفکیک حجم‌ها -->
            <div class="lg:col-span-2 glass-card p-6 flex flex-col justify-between">
                <div class="flex justify-between items-start mb-6">
                    <div class="text-left">
                        <div class="text-xs text-slate-400 mb-1">منقضی می‌شود در</div>
                        <div class="text-2xl font-black mono-num text-slate-100">__DAYS_LEFT__ روز</div>
                    </div>
                    <div>
                        __STATUS_BADGE__
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

                    <!-- گیج دایره‌ای استاندارد با درصد اختصاصی حجم فیک -->
                    <div class="relative w-32 h-32 shrink-0 flex items-center justify-center">
                        <svg class="transform -rotate-90 w-full h-full" viewBox="0 0 120 120">
                            <circle cx="60" cy="60" r="48" stroke="rgba(255,255,255,0.06)" stroke-width="9" fill="none"></circle>
                            <circle cx="60" cy="60" r="48" stroke="#10b981" stroke-width="9" fill="none"
                                stroke-dasharray="301.59" stroke-dashoffset="__DASHOFFSET__"
                                stroke-linecap="round" class="transition-all duration-700"></circle>
                        </svg>
                        <div class="absolute inset-0 flex flex-col items-center justify-center">
                            <span class="text-2xl font-black mono-num text-slate-100">__PERCENT__%</span>
                            <span class="text-[11px] text-slate-400 font-medium mt-0.5">مصرف شده</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ۳ کارت عمودی ستون کناری (فونت فارسی هماهنگ Vazirmatn FD) -->
            <div class="flex flex-col gap-4">
                <div class="glass-card p-4 flex flex-col justify-between flex-1">
                    <div class="text-xs text-slate-400 text-right">حجم کل</div>
                    <div class="text-2xl font-bold mono-num text-slate-100 text-left mt-2">__TOTAL_QUOTA__</div>
                </div>
                <div class="glass-card p-4 flex flex-col justify-between flex-1">
                    <div class="text-xs text-slate-400 text-right">تاریخ انقضا</div>
                    <div class="text-base font-bold vazir-num text-slate-100 text-right mt-2">__EXPIRE_DATE__</div>
                </div>
                <div class="glass-card p-4 flex flex-col justify-between flex-1">
                    <div class="text-xs text-slate-400 text-right">آخرین اتصال</div>
                    <div class="text-sm font-bold vazir-num text-slate-100 text-right mt-2 flex items-center justify-start gap-1.5">
                        <span class="w-2 h-2 rounded-full bg-emerald-400 inline-block shadow-[0_0_6px_rgba(52,211,153,0.6)]"></span>
                        <span>__LAST_SEEN_TEXT__</span>
                    </div>
                </div>
            </div>

        </div>

        <!-- ۳. نوار شکیل و شفاف کپی ساب -->
        <div class="glass-card p-4 sm:p-5 flex flex-col md:flex-row items-center justify-between gap-4">
            <div class="flex items-center gap-3 w-full md:w-auto min-w-0">
                <div class="w-10 h-10 rounded-xl bg-blue-500/15 border border-blue-400/25 flex items-center justify-center text-blue-400 shrink-0">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>
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

        <!-- ۴. فیلتر و لیست کانفیگ‌ها -->
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

            <!-- لیست کانفیگ‌ها -->
            <div class="max-h-80 overflow-y-auto space-y-2 pr-1" id="configListContainer">
                __CONFIG_ROWS__
            </div>
        </div>

        <!-- ۵. تب‌بار کلاینت‌ها (تفکیک مک و لینوکس با ۴ برنامه مجزا برای هر کدام) -->
        <div class="pt-2 space-y-3">
            <div class="text-xs text-slate-400 text-center font-semibold">دانلود نرم‌افزار اتصال مخصوص سیستم شما</div>
            <div class="flex justify-center flex-wrap gap-1.5 p-1 rounded-xl bg-white/[0.03] border border-white/10 w-fit mx-auto">
                <button type="button" onclick="switchPlatform('android', this)" class="tab-btn active">Android</button>
                <button type="button" onclick="switchPlatform('ios', this)" class="tab-btn">iOS</button>
                <button type="button" onclick="switchPlatform('windows', this)" class="tab-btn">Windows</button>
                <button type="button" onclick="switchPlatform('mac', this)" class="tab-btn">macOS</button>
                <button type="button" onclick="switchPlatform('linux', this)" class="tab-btn">Linux</button>
            </div>
            
            <!-- ۴ برنامه برای هر سیستم‌عامل -->
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

    <!-- فوتر -->
    <footer class="pt-8 pb-4 text-center">
        <a href="https://t.me/DARK_WIKI20" target="_blank" rel="noopener noreferrer" class="text-xs text-slate-400 hover:text-slate-200 transition-colors">
            پشتیبانی تلگرام: <span class="mono-num font-bold text-blue-400">@DARK_WIKI20</span>
        </a>
    </footer>

    <!-- مدال QR -->
    <div id="qrModal" class="fixed inset-0 bg-black/80 backdrop-blur-md hidden items-center justify-center p-4 z-50" onclick="closeQRModal()">
        <div class="p-6 rounded-3xl border border-white/20 bg-slate-900/90 shadow-2xl flex flex-col items-center max-w-xs w-full" onclick="event.stopPropagation()">
            <div class="text-xs font-bold mb-4 text-slate-300">کد QR اختصاصی</div>
            <img id="qrModalImg" src="" alt="QR" class="w-52 h-52 rounded-xl bg-white p-2.5 mb-5 shadow-lg">
            <button type="button" onclick="closeQRModal()" class="ui-btn w-full">بستن</button>
        </div>
    </div>

    <!-- توست پیام -->
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

    return (
        DASHBOARD_HTML_TEMPLATE
        .replace("__BRAND_NAME__", html.escape(ctx["brand_name"]))
        .replace("__DAYS_LEFT__", str(ctx["days_left"]))
        .replace("__STATUS_BADGE__", status_badge)
        .replace("__TOTAL_QUOTA__", str(ctx["total_quota"]))
        .replace("__USED_TRAFFIC__", str(ctx["used_traffic"]))
        .replace("__REMAINING_TRAFFIC__", str(ctx["remaining_traffic"]))
        .replace("__EXPIRE_DATE__", str(ctx["expire_date"]))
        .replace("__LAST_SEEN_TEXT__", str(ctx["last_seen_text"] or ctx["now_jalali"]))
        .replace("__SUB_URL__", str(ctx["sub_url"]))
        .replace("__PERCENT__", str(percent))
        .replace("__DASHOFFSET__", str(dashoffset))
        .replace("__CONFIG_ROWS__", config_rows)
    )

# ----------------- قالب و توابع پنل ادمین -----------------
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
    <style>{ADMIN_PANEL_CSS}</style>
</head>
<body class="min-h-screen flex items-center justify-center p-4">
    <div class="glass-container w-full max-w-sm p-6 sm:p-8">
        <h1 class="text-base font-bold text-center mb-1">احراز هویت سرور</h1>
        <p class="text-xs text-slate-400 text-center mb-6">کنترل پنل مرکزی دیتاسنتر</p>
        {err_box}
        <form action="/{admin_path}/login" method="post" class="space-y-4">
            <div>
                <label for="admin_pass" class="block text-xs text-slate-400 mb-1.5 font-medium">رمز عبور امنیتی</label>
                <input id="admin_pass" type="password" name="password" required autofocus class="glass-input mono-num text-left">
            </div>
            <button type="submit" class="btn-glass btn-primary w-full py-2.5">ورود به سیستم</button>
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
        safe_name = html.escape(str(p["name"] or ""))
        safe_token = html.escape(str(p["token"] or ""))
        safe_note = html.escape(str(p["admin_note"] or ""))
        safe_notice = html.escape(str(p["custom_notice"] or ""))
        hits = p["sub_hits"] or 0
        last_fetch = html.escape(str(p["last_sub_fetch"] or "بدون اتصال"))
        fake_val = p["fake_total_gb"] or 0

        cached_data = sub_cache.get(f"{p['token']}_{fake_val}")
        if not cached_data:
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
            '<span class="px-2 py-0.5 rounded-md text-[11px] font-semibold border border-rose-500/30 bg-rose-500/10 text-rose-400">مسدود</span>'
            if p["is_blocked"] else
            '<span class="px-2 py-0.5 rounded-md text-[11px] font-semibold border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">فعال</span>'
        )
        fake_label = f"<span class='mono-num text-xs text-blue-400 font-bold'>{fake_val:g} GB</span>" if fake_val > 0 else "<span class='text-slate-500 text-xs'>واقعی</span>"
        
        btn_class = "btn-glass text-emerald-400 border-emerald-500/30" if p["is_blocked"] else "btn-glass text-amber-400 border-amber-500/30"
        btn_text = "فعال‌سازی" if p["is_blocked"] else "مسدود"
        
        p_json = html.escape(json.dumps({
            "token": str(p["token"]),
            "name": str(p["name"]),
            "upstream_url": str(p["upstream_url"]),
            "fake_total_gb": float(fake_val),
            "custom_notice": str(p["custom_notice"] or ""),
            "admin_note": str(p["admin_note"] or "")
        }))

        dash_url = f"https://{domain}/d/{safe_token}"
        sub_url = f"https://{domain}/sub/{safe_token}"
        note_html = f'<div class="text-[11px] text-amber-400/80 mt-1 font-mono leading-tight">{safe_note}</div>' if safe_note else ''
        notice_indicator = '<span class="inline-block mr-1 text-[10px] px-1.5 py-0.2 rounded border border-blue-400/30 bg-blue-500/15 text-blue-300">اعلان</span>' if safe_notice else ''

        rows += f"""
        <tr class="profile-row border-b border-white/[0.04] hover:bg-white/[0.02] transition-colors" data-name="{safe_name.lower()} {safe_token.lower()} {safe_note.lower()}" data-status="{'blocked' if p['is_blocked'] else 'active'}">
            <td class="p-3.5 whitespace-nowrap">
                <div class="font-bold text-sm text-slate-200">{safe_name} {notice_indicator}</div>
                {note_html}
            </td>
            <td class="p-3.5 whitespace-nowrap">
                <div class="flex items-center gap-1.5">
                    <button type="button" onclick="copyText('{dash_url}', 'لینک داشبورد کپی شد')" class="btn-glass px-2.5 py-1 text-xs">داشبورد</button>
                    <button type="button" onclick="copyText('{sub_url}', 'لینک اشتراک کپی شد')" class="btn-glass px-2.5 py-1 text-xs">ساب</button>
                    <button type="button" onclick="openQR('{sub_url}', '{safe_name}')" class="btn-glass p-1.5" title="QR Code">
                        <svg class="w-3.5 h-3.5 text-slate-300" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
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
                    <button type="button" onclick="openEditModal({p_json})" class="btn-glass px-2.5 py-1 text-xs">ویرایش</button>
                    <form action="/{admin_path}/profiles/{safe_token}/refresh-cache" method="post" class="m-0">
                        <input type="hidden" name="csrf_token" value="{csrf_token}">
                        <button type="submit" class="btn-glass p-1.5 text-slate-300" title="تازه‌سازی کش">
                            <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"></path></svg>
                        </button>
                    </form>
                    <form action="/{admin_path}/profiles/{safe_token}/toggle-block" method="post" class="m-0">
                        <input type="hidden" name="csrf_token" value="{csrf_token}">
                        <button type="submit" class="btn-glass px-2.5 py-1 text-xs {btn_class}">{btn_text}</button>
                    </form>
                    <form action="/{admin_path}/profiles/{safe_token}/delete" method="post" class="m-0" onsubmit="return confirm('تایید حذف نهایی ساب؟');">
                        <input type="hidden" name="csrf_token" value="{csrf_token}">
                        <button type="submit" class="btn-glass btn-danger px-2.5 py-1 text-xs">حذف</button>
                    </form>
                </div>
            </td>
        </tr>"""

    if not rows:
        rows = '<tr><td colspan="8" class="p-8 text-center text-slate-500 text-xs">هنوز هیچ اشتراکی ساخته نشده است.</td></tr>'

    return (
        ADMIN_HTML_TEMPLATE
        .replace("__DOMAIN__", domain)
        .replace("__ADMIN_PATH__", admin_path)
        .replace("__CSRF_TOKEN__", csrf_token)
        .replace("__CACHED_ITEMS__", str(cached_items))
        .replace("__TOTAL_COUNT__", str(total_count))
        .replace("__ACTIVE_COUNT__", str(active_count))
        .replace("__BLOCKED_COUNT__", str(blocked_count))
        .replace("__TOTAL_HITS__", str(total_hits))
        .replace("__ROWS__", rows)
        .replace("__CSS__", ADMIN_PANEL_CSS)
    )

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

    sub_cache.clear()
    return RedirectResponse(url=f"/{ADMIN_SECRET_PATH}", status_code=status.HTTP_302_FOUND)

@app.post(f"/{ADMIN_SECRET_PATH}/profiles/{{token}}/refresh-cache")
async def refresh_single_cache(request: Request, token: str):
    if not is_admin(request):
        raise HTTPException(status_code=401)
    form_data = await read_bounded_form(request)
    if not verify_csrf(request, form_data.get("csrf_token", [""])[0]):
        raise HTTPException(status_code=403)
    
    with get_db() as conn:
        profile = conn.execute("SELECT * FROM profiles WHERE token = ?", (token,)).fetchone()
    if profile:
        fake_gb = float(profile["fake_total_gb"] or 0)
        sub_cache.pop(f"{token}_{fake_gb}", None)
        sub_cache.pop(token, None)
        try:
            await get_cached_sub_data(token, profile["upstream_url"], fake_gb)
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

    sub_cache.clear()
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
