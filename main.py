import os
import time
import base64
import json
import sqlite3
import urllib.parse
from datetime import datetime
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response, HTMLResponse
from fastapi.templating import Jinja2Templates

UPSTREAM_SUB_URL = os.getenv("UPSTREAM_SUB_URL", "https://your-seller-sub-url.com/sub/token")
BRAND_NAME = os.getenv("BRAND_NAME", "MY-VIP-NET")
PUBLIC_URL = os.getenv("RAILWAY_PUBLIC_DOMAIN", "localhost:8000")

DATA_DIR = "/data" if os.path.exists("/data") else "."
DB_FILE = os.path.join(DATA_DIR, "usage_history.db")

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# کش ساب‌اسکریپشن برای کاهش فشار پردازنده
CACHE_TTL = 180
cached_sub = {"text": "", "headers": {}, "timestamp": 0}

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS daily_usage (
            date TEXT PRIMARY KEY,
            total_used_bytes INTEGER
        )
    """)
    conn.commit()
    conn.close()

init_db()

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

def parse_and_modify_configs(raw_b64: str):
    try:
        decoded = base64.b64decode(raw_b64).decode("utf-8", errors="ignore")
    except Exception:
        return [], ""
    
    lines = [l.strip() for l in decoded.splitlines() if l.strip()]
    configs = []
    modified_raw_lines = []

    for idx, line in enumerate(lines, start=1):
        custom_name = f"{BRAND_NAME} - {idx:02d}"
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

async def fetch_upstream():
    now = time.time()
    if cached_sub["text"] and (now - cached_sub["timestamp"] < CACHE_TTL):
        return cached_sub["text"], cached_sub["headers"]

    async with httpx.AsyncClient(timeout=10.0) as client:
        res = await client.get(UPSTREAM_SUB_URL)
        cached_sub["text"] = res.text.strip()
        cached_sub["headers"] = dict(res.headers)
        cached_sub["timestamp"] = now
        return cached_sub["text"], cached_sub["headers"]

@app.get("/sub")
async def get_sub():
    raw_text, headers = await fetch_upstream()
    _, encoded_sub = parse_and_modify_configs(raw_text)
    user_info = headers.get("subscription-userinfo", "")
    return Response(
        content=encoded_sub,
        media_type="text/plain; charset=utf-8",
        headers={
            "subscription-userinfo": user_info,
            "Profile-Update-Interval": "6"
        }
    )

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    raw_text, headers = await fetch_upstream()
    user_info_str = headers.get("subscription-userinfo", "")
    info = parse_user_info(user_info_str)
    configs, _ = parse_and_modify_configs(raw_text)

    upload = info.get("upload", 0)
    download = info.get("download", 0)
    total_quota = info.get("total", 0)
    used_traffic = upload + download
    remaining = max(0, total_quota - used_traffic)
    expire_ts = info.get("expire", 0)

    # درصد مصرف و افست انیمیشن دایره
    percent = int((used_traffic / total_quota * 100)) if total_quota > 0 else 0
    percent = min(100, max(0, percent))
    dashoffset = 440 - (440 * percent / 100)

    # محاسبه روزهای مانده و تاریخ شمسی انقضا
    days_left = max(0, int((expire_ts - time.time()) // 86400)) if expire_ts > 0 else "نامحدود"
    expire_jalali = "نامحدود"
    if expire_ts > 0:
        dt = datetime.fromtimestamp(expire_ts)
        jy, jm, jd = gregorian_to_jalali(dt.year, dt.month, dt.day)
        expire_jalali = f"{jy}/{jm:02d}/{jd:02d}, {dt.strftime('%H:%M')}"

    clean_domain = PUBLIC_URL.replace("https://", "").replace("http://", "")
    sub_url = f"https://{clean_domain}/sub"

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "brand_name": BRAND_NAME,
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
