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
from datetime import datetime
from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import Response, HTMLResponse, RedirectResponse, JSONResponse
from fastapi.middleware.gzip import GZipMiddleware

# ----------------- متغیرها و تنظیمات ذخیره منابع -----------------
BRAND_DEFAULT = os.getenv("BRAND_NAME", "VIP Cloud")
PUBLIC_URL = os.getenv("RAILWAY_PUBLIC_DOMAIN", "localhost:8000").rstrip("/")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "ChangeMeImmediately_987654321")
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()

SECRET_KEY = hashlib.sha256(f"{ADMIN_PASSWORD}_secure_lowcost_salt".encode()).digest()
WEBHOOK_SECRET = hashlib.sha256(f"{BOT_TOKEN}_tg_webhook".encode()).hexdigest()[:32] if BOT_TOKEN else ""

DATA_DIR = "/data" if os.path.exists("/data") else "."
DB_FILE = os.path.join(DATA_DIR, "datacenter_subs.db")
COOKIE_NAME = "session_token"
SESSION_TTL = 86400 * 7

# کش طولانی‌تر برای به حداقل رساندن ترافیک خارجی و بیدار شدن پردازنده
CACHE_TTL = 900              # ۱۵ دقیقه کش کامل
MAX_CACHE_SIZE = 100         # سقف رم کانتینر
MAX_UPSTREAM_BYTES = 2097152 # ۲ مگابایت سقف دانلود

sub_cache = {}
login_attempts = {}
rate_limiter = {}
pending_hits = {}            # بافر درون حافظه‌ای برای کاهش IO دیسک
http_client: httpx.AsyncClient = None

# رنج‌های ممنوعه برای مهار SSRF
BLOCKED_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16")
]

# ----------------- ساختار بهینه دیتابیس -----------------
def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=OFF") # بالاترین سرعت و کمترین فشار I/O دیسک
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
                replace_rules TEXT DEFAULT '',
                sub_hits INTEGER DEFAULT 0,
                last_sub_fetch TEXT DEFAULT '',
                is_blocked INTEGER DEFAULT 0
            )
        """)
        conn.commit()

init_db()

# ----------------- تسک دوره‌ای ثبت دسته‌ای آمار -----------------
async def flush_hits_periodically():
    """هر ۱۸۰ ثانیه یک‌بار لاگ‌ها را به دیسک می‌زند تا پردازنده و رم آزاد بماند"""
    while True:
        await asyncio.sleep(180)
        if pending_hits:
            try:
                with get_db() as conn:
                    for token, data in list(pending_hits.items()):
                        conn.execute(
                            "UPDATE profiles SET sub_hits = COALESCE(sub_hits, 0) + ?, last_sub_fetch = ? WHERE token = ?",
                            (data["count"], data["last_time"], token)
                        )
                    conn.commit()
                pending_hits.clear()
            except Exception:
                pass

@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client
    # استفاده از اتصالات سبک برای جلوگیری از قفل ماندن سوکت‌ها
    limits = httpx.Limits(max_keepalive_connections=5, max_connections=15)
    http_client = httpx.AsyncClient(timeout=6.0, follow_redirects=False, verify=True, limits=limits)
    
    flush_task = asyncio.create_task(flush_hits_periodically())
    yield
    flush_task.cancel()
    await http_client.aclose()

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(GZipMiddleware, minimum_size=500)

# ----------------- امنیت و کم‌مصرفی رم -----------------
def create_session_token() -> str:
    ts = str(int(time.time()))
    sig = hmac.new(SECRET_KEY, f"auth:{ts}".encode(), hashlib.sha256).hexdigest()
    return f"{ts}.{sig}"

def verify_session_token(token: str) -> bool:
    if not token or "." not in token:
        return False
    parts = token.split(".", 1)
    if not parts[0].isdigit():
        return False
    if abs(time.time() - int(parts[0])) > SESSION_TTL:
        return False
    expected = hmac.new(SECRET_KEY, f"auth:{parts[0]}".encode(), hashlib.sha256).hexdigest()
    return secrets.compare_digest(parts[1], expected)

def is_admin(request: Request) -> bool:
    return verify_session_token(request.cookies.get(COOKIE_NAME, ""))

def get_csrf_token(request: Request) -> str:
    s = request.cookies.get(COOKIE_NAME, "")
    return hmac.new(SECRET_KEY, f"csrf:{s}".encode(), hashlib.sha256).hexdigest()[:24]

def verify_csrf(request: Request, tok: str) -> bool:
    expected = get_csrf_token(request)
    return bool(tok) and secrets.compare_digest(tok.strip(), expected)

def get_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "127.0.0.1")

def check_rate_limit(key: str, max_requests: int = 10, window: int = 60) -> bool:
    """الگوریتم سبک دو-عنصری در رم به جای ذخیره لیست تایم‌استمپ‌ها"""
    now = time.time()
    record = rate_limiter.get(key)
    if not record or (now - record[1] > window):
        rate_limiter[key] = [1, now]
        return True
    if record[0] >= max_requests:
        return False
    record[0] += 1
    return True

def is_safe_url(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url.strip())
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        host = parsed.hostname.lower()
        if host in ("localhost", "0.0.0.0", "127.0.0.1") or host.endswith((".local", ".internal")):
            return False
        ip = ipaddress.ip_address(host) if not any(c.isalpha() for c in host) else ipaddress.ip_address(socket.gethostbyname(host))
        return not any(ip in net for net in BLOCKED_NETS)
    except Exception:
        return False

def format_bytes(b: int) -> str:
    if b >= 1073741824:
        return f"{b / 1073741824:.2f} GB"
    return f"{b / 1048576:.2f} MB"

# ----------------- پردازش ساده و سریع کانفیگ‌ها -----------------
def apply_replacements(name: str, rules_str: str) -> str:
    if not rules_str:
        return name
    res = name
    for line in rules_str.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        src, target = line.split("->", 1) if "->" in line else (line, "")
        res = res.replace(src.strip(), target.strip())
    return res.strip() or "Server"

def parse_config(line: str, rules: str) -> tuple[dict, str]:
    line = line.strip()
    if not line:
        return None, ""
    proto = line.split("://")[0].lower() if "://" in line else "vpn"

    if line.startswith(("vless://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")):
        parts = line.split("#", 1)
        base = parts[0]
        orig_name = urllib.parse.unquote(parts[1]) if len(parts) > 1 else "Server"
        new_name = apply_replacements(orig_name, rules)
        new_link = f"{base}#{urllib.parse.quote(new_name)}"
        return {"proto": proto.upper(), "name": html.escape(new_name), "link": new_link}, new_link

    elif line.startswith("vmess://"):
        try:
            b64_part = line[8:].strip()
            pad = len(b64_part) % 4
            if pad: b64_part += "=" * (4 - pad)
            data = json.loads(base64.b64decode(b64_part).decode("utf-8", errors="ignore"))
            data["ps"] = apply_replacements(str(data.get("ps", "Server")), rules)
            re_b64 = base64.b64encode(json.dumps(data).encode("utf-8")).decode("utf-8")
            new_link = f"vmess://{re_b64}"
            return {"proto": "VMESS", "name": html.escape(data["ps"]), "link": new_link}, new_link
        except Exception:
            return {"proto": "VMESS", "name": "VMESS", "link": line}, line

    return {"proto": proto.upper(), "name": "Node", "link": line}, line

async def fetch_upstream(url: str):
    if not is_safe_url(url):
        return None
    try:
        res = await http_client.get(url, headers={"User-Agent": "v2rayNG/1.8.12"}, timeout=5.0)
        if res.status_code == 200 and len(res.content) <= MAX_UPSTREAM_BYTES:
            return {"text": res.text.strip(), "userinfo": res.headers.get("subscription-userinfo", "")}
    except Exception:
        pass
    return None

async def get_aggregated_data(profile: dict):
    token = profile["token"]
    now = time.time()
    
    cached = sub_cache.get(token)
    if cached and (now - cached["ts"] < CACHE_TTL):
        return cached

    urls = [u.strip() for u in (profile["upstream_urls"] or "").splitlines() if u.strip()]
    tasks = [fetch_upstream(u) for u in urls if is_safe_url(u)]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    lines = []
    tot_u = tot_d = tot_quota = exp = 0

    for r in results:
        if isinstance(r, dict) and r:
            raw = r["text"]
            if not any(raw.startswith(p) for p in ("vless://", "vmess://", "trojan://", "ss://")):
                pad = len(raw) % 4
                if pad: raw += "=" * (4 - pad)
                try:
                    raw = base64.b64decode(raw).decode("utf-8", errors="ignore")
                except Exception:
                    pass
            lines.extend([l.strip() for l in raw.splitlines() if l.strip()])

            if r.get("userinfo"):
                for seg in r["userinfo"].split(";"):
                    if "=" in seg:
                        k, v = seg.strip().split("=", 1)
                        try:
                            val = int(float(v.strip()))
                            k_low = k.strip().lower()
                            if k_low == "upload": tot_u += val
                            elif k_low == "download": tot_d += val
                            elif k_low == "total": tot_quota += val
                            elif k_low == "expire" and val > 0: exp = val if exp == 0 else min(exp, val)
                        except ValueError:
                            pass

    rules = profile.get("replace_rules", "")
    configs, raw_lines, seen = [], [], set()

    for l in lines:
        c, out_link = parse_config(l, rules)
        if c and out_link:
            cid = out_link.split("#")[0] if "#" in out_link else out_link
            if cid not in seen:
                seen.add(cid)
                configs.append(c)
                raw_lines.append(out_link)

    encoded = base64.b64encode("\n".join(raw_lines).encode("utf-8")).decode("utf-8")
    data = {
        "configs": configs,
        "configs_json": json.dumps([c["link"] for c in configs]),
        "encoded": encoded,
        "raw_lines": raw_lines,
        "upload": tot_u,
        "download": tot_d,
        "total": tot_quota,
        "expire": exp,
        "ts": now
    }

    if len(sub_cache) >= MAX_CACHE_SIZE:
        sub_cache.pop(min(sub_cache.keys(), key=lambda k: sub_cache[k]["ts"]), None)

    sub_cache[token] = data
    return data

# ----------------- UI سبک‌شده و بدون اضافه بار -----------------
def render_dash_html(ctx: dict) -> str:
    p_name = html.escape(ctx["name"])
    notice = html.escape(ctx["notice"]) if ctx["notice"] else "لینک اشتراک را در اپلیکیشن خود کپی و بروزرسانی کنید."

    items = "".join([
        f'<div class="flex items-center justify-between p-2.5 rounded-xl bg-zinc-900/60 border border-zinc-800 text-xs">'
        f'<div class="flex items-center gap-2 truncate"><span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-400">{c["proto"]}</span><span class="truncate" dir="ltr">{c["name"]}</span></div>'
        f'<button onclick="navigator.clipboard.writeText(\'{c["link"]}\');alert(\'کپی شد\')" class="px-2.5 py-1 rounded-lg bg-zinc-800 text-slate-300">کپی</button></div>'
        for c in ctx["configs"]
    ])

    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{p_name}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/misc/Farsi-Digits/Vazirmatn-FD-font-face.css">
    <style>body{{font-family:Vazirmatn FD,sans-serif;background-color:#09090b;color:#f8fafc;}}</style>
</head>
<body class="p-4 sm:p-6 max-w-xl mx-auto space-y-4">
    <header class="p-4 rounded-2xl bg-zinc-900 border border-zinc-800 flex justify-between items-center">
        <div><h1 class="text-base font-black">{p_name}</h1><p class="text-[11px] text-slate-400">تعداد سرور: {len(ctx['configs'])}</p></div>
        <span class="text-xs px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 font-bold border border-emerald-500/20">فعال</span>
    </header>

    <div class="p-3 rounded-xl bg-blue-500/10 border border-blue-500/20 text-xs text-blue-400 leading-relaxed">📢 {notice}</div>

    <!-- گیج درصد مصرف فیک -->
    <div class="p-5 rounded-2xl bg-zinc-900 border border-zinc-800 flex items-center justify-around">
        <div class="relative w-28 h-28">
            <svg class="transform -rotate-90 w-full h-full">
                <circle cx="50%" cy="50%" r="42%" stroke="#27272a" stroke-width="8" fill="none"></circle>
                <circle cx="50%" cy="50%" r="42%" stroke="#3b82f6" stroke-width="8" fill="none"
                    stroke-dasharray="264" stroke-dashoffset="{ctx['dashoffset']}" stroke-linecap="round"></circle>
            </svg>
            <div class="absolute inset-0 flex flex-col items-center justify-center">
                <span class="text-xl font-black">{ctx['percent']}%</span>
                <span class="text-[10px] text-slate-400">مصرف</span>
            </div>
        </div>
        <div class="text-xs space-y-1.5 font-mono" dir="ltr">
            <div><span class="text-slate-400">Total:</span> <b>{ctx['total']}</b></div>
            <div><span class="text-slate-400">Used:</span> <b class="text-amber-400">{ctx['used']}</b></div>
            <div><span class="text-slate-400">Left:</span> <b class="text-emerald-400">{ctx['remaining']}</b></div>
        </div>
    </div>

    <!-- دکمه‌های کپی سریع -->
    <div class="p-4 rounded-2xl bg-zinc-900 border border-zinc-800 space-y-2.5">
        <button onclick="navigator.clipboard.writeText('{ctx['sub_url']}');alert('لینک ساب کپی شد')" class="w-full py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-xs font-bold text-white shadow">کپی لینک اشتراک هوشمند</button>
        <div class="grid grid-cols-2 gap-2 text-xs">
            <a href="hiddify://import/{ctx['sub_url']}#{p_name}" class="text-center py-2 bg-zinc-800 rounded-lg">ورود به Hiddify</a>
            <a href="v2rayng://install-sub?url={urllib.parse.quote(ctx['sub_url'])}" class="text-center py-2 bg-zinc-800 rounded-lg">ورود به v2rayNG</a>
        </div>
    </div>

    <div class="space-y-2">
        <h3 class="text-xs font-bold text-slate-400">لیست کانفیگ‌ها</h3>
        <div class="max-h-64 overflow-y-auto space-y-1.5">{items}</div>
    </div>
</body>
</html>"""

def render_admin_html(profiles: list, csrf_tok: str) -> str:
    rows = "".join([
        f'<tr class="border-b border-zinc-800/60 text-xs"><td class="p-3 font-bold">{p["name"]}<br><span class="text-[10px] text-slate-500 font-mono" dir="ltr">{p["token"]}</span></td>'
        f'<td class="p-3 text-center font-mono">{p["fake_total_gb"]} GB</td>'
        f'<td class="p-3 text-center">{p["sub_hits"]} بار</td>'
        f'<td class="p-3 text-center"><form action="/admin/profiles/{p["token"]}/delete" method="post">'
        f'<input type="hidden" name="csrf" value="{csrf_tok}"><button type="submit" class="text-rose-400 px-2 py-1 rounded bg-rose-500/10">حذف</button></form></td></tr>'
        for p in profiles
    ])

    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8"><title>Admin</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/misc/Farsi-Digits/Vazirmatn-FD-font-face.css">
    <style>body{{font-family:Vazirmatn FD,sans-serif;background-color:#09090b;color:#f8fafc;}}</style>
</head>
<body class="p-4 sm:p-6 max-w-4xl mx-auto space-y-4">
    <div class="flex justify-between items-center p-4 rounded-2xl bg-zinc-900 border border-zinc-800">
        <h1 class="text-base font-black">پنل کنترل کم‌مصرف</h1>
        <a href="/admin/logout" class="text-xs text-rose-400 bg-rose-500/10 px-3 py-1.5 rounded-lg">خروج</a>
    </div>

    <!-- فرم افزودن سبک -->
    <form action="/admin/profiles/add" method="post" class="p-4 rounded-2xl bg-zinc-900 border border-zinc-800 grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
        <input type="hidden" name="csrf" value="{csrf_tok}">
        <div><label class="block mb-1 text-slate-400">نام اشتراک</label><input type="text" name="name" required class="w-full bg-zinc-950 border border-zinc-800 rounded-lg p-2"></div>
        <div><label class="block mb-1 text-slate-400">حجم فیک کل (GB)</label><input type="number" step="0.1" name="fake_total" value="0" class="w-full bg-zinc-950 border border-zinc-800 rounded-lg p-2 font-mono" dir="ltr"></div>
        <div><label class="block mb-1 text-slate-400">حجم فیک مصرفی (GB)</label><input type="number" step="0.1" name="fake_used" value="0" class="w-full bg-zinc-950 border border-zinc-800 rounded-lg p-2 font-mono" dir="ltr"></div>
        <div class="md:col-span-3"><label class="block mb-1 text-slate-400">لینک‌های ساب (خط‌به‌خط)</label><textarea name="urls" rows="2" required class="w-full bg-zinc-950 border border-zinc-800 rounded-lg p-2 font-mono" dir="ltr"></textarea></div>
        <div class="md:col-span-2"><label class="block mb-1 text-slate-400">تعویض متن (قدیم -> جدید)</label><input type="text" name="rules" placeholder="همراه اول -> VIP" class="w-full bg-zinc-950 border border-zinc-800 rounded-lg p-2"></div>
        <div class="flex items-end"><button type="submit" class="w-full p-2 bg-blue-600 rounded-lg font-bold text-white">ثبت ساب</button></div>
    </form>

    <div class="rounded-2xl bg-zinc-900 border border-zinc-800 overflow-x-auto">
        <table class="w-full text-right"><thead class="bg-zinc-950 text-slate-400 text-xs"><tr><th class="p-3">نام</th><th class="p-3 text-center">حجم فیک</th><th class="p-3 text-center">مصرف دیتاسنتر</th><th class="p-3 text-center">عملیات</th></tr></thead><tbody>{rows}</tbody></table>
    </div>
</body>
</html>"""

# ----------------- مسیرها و اندپوینت‌های بهینه -----------------
@app.get("/")
async def root():
    with get_db() as conn:
        p = conn.execute("SELECT token FROM profiles ORDER BY id DESC LIMIT 1").fetchone()
    return RedirectResponse(url=f"/d/{p['token']}" if p else "/admin")

@app.get("/sub/{token}")
async def get_sub(token: str, request: Request, raw: bool = False):
    ip = get_ip(request)
    if not check_rate_limit(f"sub:{token}:{ip}", max_requests=12, window=60):
        raise HTTPException(status_code=429, detail="Limit")

    with get_db() as conn:
        profile = conn.execute("SELECT * FROM profiles WHERE token = ?", (token,)).fetchone()
    if not profile or profile["is_blocked"]:
        raise HTTPException(status_code=404)

    # ثبت دسته‌ای در رم به جای درج مستقیم در دیسک
    now_str = datetime.now().strftime("%H:%M:%S")
    if token in pending_hits:
        pending_hits[token]["count"] += 1
        pending_hits[token]["last_time"] = now_str
    else:
        pending_hits[token] = {"count": 1, "last_time": now_str}

    data = await get_aggregated_data(dict(profile))

    # محاسبه دقیق درصد بر پایه حجم فیک
    f_tot = profile["fake_total_gb"] or 0
    f_usd = profile["fake_used_gb"] or 0
    calc_total = int(f_tot * 1073741824) if f_tot > 0 else data.get("total", 0)
    calc_used = int(f_usd * 1073741824) if f_usd > 0 else (data.get("upload", 0) + data.get("download", 0))

    headers = {
        "subscription-userinfo": f"upload=0; download={calc_used}; total={calc_total}; expire={data.get('expire', 0)}",
        "Profile-Update-Interval": "12"
    }
    content = "\n".join(data["raw_lines"]) if raw else data["encoded"]
    return Response(content=content, media_type="text/plain; charset=utf-8", headers=headers)

@app.get("/d/{token}", response_class=HTMLResponse)
async def user_dashboard(token: str):
    with get_db() as conn:
        profile = conn.execute("SELECT * FROM profiles WHERE token = ?", (token,)).fetchone()
    if not profile:
        raise HTTPException(status_code=404)

    data = await get_aggregated_data(dict(profile))

    f_tot = profile["fake_total_gb"] or 0
    f_usd = profile["fake_used_gb"] or 0
    tot_bytes = int(f_tot * 1073741824) if f_tot > 0 else data.get("total", 0)
    usd_bytes = int(f_usd * 1073741824) if f_usd > 0 else (data.get("upload", 0) + data.get("download", 0))

    percent = int(min(100, max(0, (usd_bytes / tot_bytes * 100)))) if tot_bytes > 0 else 0
    dashoffset = 264 - (264 * percent / 100)

    clean_domain = PUBLIC_URL.replace("https://", "").replace("http://", "")
    ctx = {
        "name": profile["name"],
        "notice": profile["custom_notice"],
        "percent": percent,
        "dashoffset": dashoffset,
        "total": format_bytes(tot_bytes) if tot_bytes > 0 else "نامحدود",
        "used": format_bytes(usd_bytes),
        "remaining": format_bytes(max(0, tot_bytes - usd_bytes)) if tot_bytes > 0 else "نامحدود",
        "sub_url": f"https://{clean_domain}/sub/{token}",
        "configs": data.get("configs", [])
    }
    return HTMLResponse(content=render_dash_html(ctx))

@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    if not is_admin(request):
        return HTMLResponse(content="""
        <form action="/admin/login" method="post" style="max-width:300px;margin:50px auto;font-family:sans-serif;">
            <input type="password" name="password" placeholder="Admin Password" required style="width:100%;padding:10px;margin-bottom:10px;">
            <button type="submit" style="width:100%;padding:10px;background:#2563eb;color:#fff;border:none;border-radius:6px;">Login</button>
        </form>
        """)
    with get_db() as conn:
        profiles = [dict(r) for r in conn.execute("SELECT * FROM profiles ORDER BY id DESC").fetchall()]
    return HTMLResponse(content=render_admin_html(profiles, get_csrf_token(request)))

@app.post("/admin/login")
async def admin_login(request: Request):
    ip = get_ip(request)
    if not check_rate_limit(f"login:{ip}", max_requests=5, window=300):
        raise HTTPException(status_code=429, detail="Too many attempts")

    form = urllib.parse.parse_qs((await request.body()).decode("utf-8", errors="ignore"))
    if secrets.compare_digest(form.get("password", [""])[0], ADMIN_PASSWORD):
        resp = RedirectResponse(url="/admin", status_code=302)
        resp.set_cookie(COOKIE_NAME, create_session_token(), httponly=True, samesite="strict", max_age=SESSION_TTL)
        return resp
    return HTMLResponse(content="رمز اشتباه است", status_code=401)

@app.get("/admin/logout")
async def admin_logout():
    resp = RedirectResponse(url="/admin", status_code=302)
    resp.delete_cookie(COOKIE_NAME)
    return resp

@app.post("/admin/profiles/add")
async def add_profile(request: Request):
    if not is_admin(request): raise HTTPException(status_code=401)
    form = urllib.parse.parse_qs((await request.body()).decode("utf-8", errors="ignore"))
    if not verify_csrf(request, form.get("csrf", [""])[0]): raise HTTPException(status_code=403)

    with get_db() as conn:
        conn.execute("""
            INSERT INTO profiles (token, name, upstream_urls, fake_total_gb, fake_used_gb, replace_rules)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            secrets.token_hex(6),
            form.get("name", [""])[0].strip()[:60],
            form.get("urls", [""])[0].strip(),
            float(form.get("fake_total", [0])[0] or 0),
            float(form.get("fake_used", [0])[0] or 0),
            form.get("rules", [""])[0].strip()
        ))
        conn.commit()
    return RedirectResponse(url="/admin", status_code=302)

@app.post("/admin/profiles/{token}/delete")
async def delete_profile(request: Request, token: str):
    if not is_admin(request): raise HTTPException(status_code=401)
    form = urllib.parse.parse_qs((await request.body()).decode("utf-8", errors="ignore"))
    if not verify_csrf(request, form.get("csrf", [""])[0]): raise HTTPException(status_code=403)

    with get_db() as conn:
        conn.execute("DELETE FROM profiles WHERE token = ?", (token,))
        conn.commit()
    sub_cache.pop(token, None)
    return RedirectResponse(url="/admin", status_code=302)
