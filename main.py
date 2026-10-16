import os
import time
import base64
import json
import sqlite3
import secrets
import urllib.parse
from datetime import datetime
import httpx
from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import Response, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

BRAND_DEFAULT = os.getenv("BRAND_NAME", "VIP-NET")
PUBLIC_URL = os.getenv("RAILWAY_PUBLIC_DOMAIN", "localhost:8000")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "SuperSecretLongPassword_987654321_ChangeMe!")
BOT_TOKEN = os.getenv("BOT_TOKEN", "")

DATA_DIR = "/data" if os.path.exists("/data") else "."
DB_FILE = os.path.join(DATA_DIR, "usage_history.db")
COOKIE_NAME = "admin_session"

app = FastAPI()
templates = Jinja2Templates(directory="templates")

CACHE_TTL = 120
sub_cache = {}

# ----------------- پایگاه داده -----------------
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                upstream_url TEXT NOT NULL,
                is_blocked INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS daily_usage (
                token TEXT,
                date TEXT,
                total_used_bytes INTEGER,
                PRIMARY KEY (token, date)
            )
        """)
        conn.commit()

init_db()

# ----------------- توابع کمکی -----------------
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

def parse_user_info(header_val: str) -> dict:
    data = {}
    if not header_val:
        return data
    for item in header_val.split(";"):
        if "=" in item:
            k, v = item.strip().split("=")
            try:
                data[k] = int(v)
            except ValueError:
                pass
    return data

def format_bytes(size_bytes: int) -> str:
    if size_bytes >= 1024 ** 3:
        return f"{size_bytes / (1024 ** 3):.2f} GB"
    return f"{size_bytes / (1024 ** 2):.2f} MB"

def parse_and_modify_configs(raw_b64: str, brand_name: str):
    try:
        decoded = base64.b64decode(raw_b64).decode("utf-8", errors="ignore")
    except Exception:
        return [], ""
    
    lines = [l.strip() for l in decoded.splitlines() if l.strip()]
    configs = []
    modified_raw_lines = []

    for idx, line in enumerate(lines, start=1):
        custom_name = f"{brand_name} - {idx:02d}"
        proto = line.split("://")[0].lower() if "://" in line else "vpn"
        
        if line.startswith(("vless://", "trojan://", "ss://")):
            base_part = line.split("#")[0]
            new_link = f"{base_part}#{urllib.parse.quote(custom_name)}"
            configs.append({"proto": proto, "name": custom_name, "link": new_link})
            modified_raw_lines.append(new_link)
        elif line.startswith("vmess://"):
            try:
                conf = json.loads(base64.b64decode(line[8:]).decode("utf-8"))
                conf["ps"] = custom_name
                re_encoded = base64.b64encode(json.dumps(conf).encode("utf-8")).decode("utf-8")
                new_link = f"vmess://{re_encoded}"
                configs.append({"proto": "vmess", "name": custom_name, "link": new_link})
                modified_raw_lines.append(new_link)
            except Exception:
                configs.append({"proto": "vmess", "name": custom_name, "link": line})
                modified_raw_lines.append(line)
        else:
            configs.append({"proto": proto, "name": custom_name, "link": line})
            modified_raw_lines.append(line)

    encoded_sub = base64.b64encode("\n".join(modified_raw_lines).encode("utf-8")).decode("utf-8")
    return configs, encoded_sub

async def fetch_upstream(token: str, upstream_url: str):
    now = time.time()
    if token in sub_cache and (now - sub_cache[token]["timestamp"] < CACHE_TTL):
        return sub_cache[token]["text"], sub_cache[token]["headers"]

    async with httpx.AsyncClient(timeout=10.0) as client:
        res = await client.get(upstream_url)
        sub_cache[token] = {
            "text": res.text.strip(),
            "headers": dict(res.headers),
            "timestamp": now
        }
        return sub_cache[token]["text"], sub_cache[token]["headers"]

def is_admin(request: Request) -> bool:
    session = request.cookies.get(COOKIE_NAME)
    return session == ADMIN_PASSWORD

# ----------------- مسیرهای ساب و داشبورد کاربر -----------------
@app.get("/sub/{token}")
async def get_user_sub(token: str):
    with get_db() as conn:
        profile = conn.execute("SELECT * FROM profiles WHERE token = ?", (token,)).fetchone()
    
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    if profile["is_blocked"] == 1:
        return Response(content="Subscription is blocked by administrator.", status_code=403)

    raw_text, headers = await fetch_upstream(token, profile["upstream_url"])
    _, encoded_sub = parse_and_modify_configs(raw_text, profile["name"])
    user_info = headers.get("subscription-userinfo", "")
    
    return Response(
        content=encoded_sub,
        media_type="text/plain; charset=utf-8",
        headers={
            "subscription-userinfo": user_info,
            "Profile-Update-Interval": "6"
        }
    )

@app.get("/d/{token}", response_class=HTMLResponse)
async def user_dashboard(request: Request, token: str):
    with get_db() as conn:
        profile = conn.execute("SELECT * FROM profiles WHERE token = ?", (token,)).fetchone()
    
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    is_blocked = bool(profile["is_blocked"])
    
    upload = download = total_quota = expire_ts = 0
    configs = []
    
    if not is_blocked:
        try:
            raw_text, headers = await fetch_upstream(token, profile["upstream_url"])
            info = parse_user_info(headers.get("subscription-userinfo", ""))
            configs, _ = parse_and_modify_configs(raw_text, profile["name"])
            upload = info.get("upload", 0)
            download = info.get("download", 0)
            total_quota = info.get("total", 0)
            expire_ts = info.get("expire", 0)
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
        expire_jalali = f"{jy}/{jm:02d}/{jd:02d}, {dt.strftime('%H:%M')}"

    clean_domain = PUBLIC_URL.replace("https://", "").replace("http://", "")
    sub_url = f"https://{clean_domain}/sub/{token}"

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "brand_name": profile["name"],
        "is_blocked": is_blocked,
        "percent": percent,
        "dashoffset": dashoffset,
        "total_quota": format_bytes(total_quota),
        "used_traffic": format_bytes(used_traffic),
        "remaining_traffic": format_bytes(remaining),
        "days_left": days_left,
        "expire_date": expire_jalali,
        "sub_url": sub_url,
        "configs": configs,
        "configs_json": json.dumps([c["link"] for c in configs])
    })

# ----------------- پنل مدیریت (Admin) -----------------
@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request):
    if not is_admin(request):
        return templates.TemplateResponse("admin_login.html", {"request": request, "error": None})

    with get_db() as conn:
        profiles = conn.execute("SELECT * FROM profiles ORDER BY id DESC").fetchall()
    
    clean_domain = PUBLIC_URL.replace("https://", "").replace("http://", "")
    return templates.TemplateResponse("admin_panel.html", {
        "request": request,
        "profiles": profiles,
        "domain": clean_domain
    })

@app.post("/admin/login")
async def admin_login(password: str = Form(...)):
    if password == ADMIN_PASSWORD:
        response = RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
        response.set_cookie(key=COOKIE_NAME, value=ADMIN_PASSWORD, httponly=True, max_age=86400 * 7)
        return response
    return templates.TemplateResponse("admin_login.html", {"request": Request, "error": "رمز عبور نادرست است."})

@app.get("/admin/logout")
async def admin_logout():
    response = RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(COOKIE_NAME)
    return response

@app.post("/admin/profiles/add")
async def add_profile(
    request: Request,
    name: str = Form(...),
    upstream_url: str = Form(...),
    custom_token: str = Form(None)
):
    if not is_admin(request):
        raise HTTPException(status_code=401)
    
    token = custom_token.strip() if custom_token and custom_token.strip() else secrets.token_hex(6)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO profiles (token, name, upstream_url, is_blocked, created_at) VALUES (?, ?, ?, 0, ?)",
                (token, name.strip(), upstream_url.strip(), created_at)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            pass

    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)

@app.post("/admin/profiles/{token}/toggle-block")
async def toggle_block(request: Request, token: str):
    if not is_admin(request):
        raise HTTPException(status_code=401)
    
    with get_db() as conn:
        conn.execute("UPDATE profiles SET is_blocked = CASE WHEN is_blocked = 1 THEN 0 ELSE 1 END WHERE token = ?", (token,))
        conn.commit()

    if token in sub_cache:
        del sub_cache[token]

    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)

@app.post("/admin/profiles/{token}/delete")
async def delete_profile(request: Request, token: str):
    if not is_admin(request):
        raise HTTPException(status_code=401)

    with get_db() as conn:
        conn.execute("DELETE FROM profiles WHERE token = ?", (token,))
        conn.execute("DELETE FROM daily_usage WHERE token = ?", (token,))
        conn.commit()

    if token in sub_cache:
        del sub_cache[token]

    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
