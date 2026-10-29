import os
import time
import base64
import json
import sqlite3
import secrets
import urllib.parse
from datetime import datetime
from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import Response, HTMLResponse, RedirectResponse

BRAND_DEFAULT = os.getenv("BRAND_NAME", "VIP")
PUBLIC_URL = os.getenv("RAILWAY_PUBLIC_DOMAIN", "localhost:8000")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "SuperSecretLongPassword_987654321_ChangeMe!")
BOT_TOKEN = os.getenv("BOT_TOKEN", "")

# ذخیره‌سازی ابری روی Persistent Volume در دیتاسنتر
DATA_DIR = "/data" if os.path.exists("/data") else "."
DB_FILE = os.path.join(DATA_DIR, "datacenter_subs.db")
COOKIE_NAME = "admin_session"
TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"

CACHE_TTL = 90
sub_cache = {}

# ----------------- دیتابیس دیتاسنتر -----------------
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
                fake_total_gb REAL DEFAULT 0,
                is_blocked INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
        """)
        # ارتقای خودکار دیتابیس در صورت وجود از قبل
        try:
            conn.execute("ALTER TABLE profiles ADD COLUMN fake_total_gb REAL DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        conn.commit()

init_db()

# ----------------- چرخه حیات و وب‌هوک -----------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    if BOT_TOKEN and PUBLIC_URL != "localhost:8000":
        clean_domain = PUBLIC_URL.replace("https://", "").replace("http://", "").strip("/")
        webhook_url = f"https://{clean_domain}/webhook"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(f"{TELEGRAM_API}/setWebhook", json={"url": webhook_url})
        except Exception:
            pass
    yield

app = FastAPI(lifespan=lifespan)

# ----------------- توابع محاسباتی و تاریخ -----------------
JALALI_MONTHS = [
    "", "فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور",
    "مهر", "آبان", "آذر", "دی", "بهمن", "اسفند"
]

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
    """محاسبه ضریب فیک برای افزایش حجم و مقیاس‌بندی مصرف"""
    if not fake_total_gb or fake_total_gb <= 0:
        return upload, download, total
    
    fake_total_bytes = int(fake_total_gb * (1024 ** 3))
    multiplier = (fake_total_bytes / total) if total > 0 else 1.0
    
    fake_upload = int(upload * multiplier)
    fake_download = int(download * multiplier)
    return fake_upload, fake_download, fake_total_bytes

def format_bytes(size_bytes: int) -> str:
    if size_bytes >= 1024 ** 3:
        return f"{size_bytes / (1024 ** 3):.2f} GB"
    return f"{size_bytes / (1024 ** 2):.2f} MB"

def fix_b64_padding(s: str) -> str:
    s = s.strip().replace("\r", "").replace("\n", "").replace(" ", "")
    return s + "=" * ((4 - len(s) % 4) % 4)

def transform_config_name(original_name: str) -> tuple[str, str]:
    name = original_name.strip()
    if not name:
        return "🌐", "Server"

    if "VIP" in name.upper() or "𝗩𝗜𝗣" in name:
        return "👋", "VIP"

    if "ویژه" in name:
        name = name.replace("ویژه", "Stable")

    icon = "🌐"
    known_icons = ["🇩🇪", "🇵🇱", "🇹🇷", "🇫🇷", "🇳🇱", "🇬🇧", "🇺🇸", "🇫🇮", "🇸🇪", "🇦🇪", "👋", "🔋", "⚠️", "⏰", "✨"]
    for em in known_icons:
        if em in name:
            icon = em
            break

    return icon, name

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
            icon, new_name = transform_config_name(orig_remark)
            new_link = f"{base_part}#{urllib.parse.quote(new_name)}"
            configs.append({"proto": proto, "icon": icon, "name": new_name, "link": new_link})
            modified_raw_lines.append(new_link)

        elif line.startswith("vmess://"):
            try:
                b64_part = fix_b64_padding(line[8:])
                conf = json.loads(base64.b64decode(b64_part).decode("utf-8", errors="ignore"))
                orig_remark = str(conf.get("ps", f"Server {idx}"))
                icon, new_name = transform_config_name(orig_remark)
                conf["ps"] = new_name
                re_encoded = base64.b64encode(json.dumps(conf).encode("utf-8")).decode("utf-8")
                new_link = f"vmess://{re_encoded}"
                configs.append({"proto": "vmess", "icon": icon, "name": new_name, "link": new_link})
                modified_raw_lines.append(new_link)
            except Exception:
                configs.append({"proto": "vmess", "icon": "🌐", "name": f"Server {idx}", "link": line})
                modified_raw_lines.append(line)
        else:
            configs.append({"proto": proto, "icon": "🌐", "name": f"Server {idx}", "link": line})
            modified_raw_lines.append(line)

    encoded_sub = base64.b64encode("\n".join(modified_raw_lines).encode("utf-8")).decode("utf-8")
    return configs, encoded_sub

async def fetch_upstream(token: str, upstream_url: str):
    now = time.time()
    if token in sub_cache and (now - sub_cache[token]["timestamp"] < CACHE_TTL):
        return sub_cache[token]["text"], sub_cache[token]["headers"]

    headers_req = {"User-Agent": "v2rayNG/1.8.12"}
    async with httpx.AsyncClient(timeout=12.0, follow_redirects=True, verify=False) as client:
        res = await client.get(upstream_url, headers=headers_req)
        resp_headers = {k.lower(): v for k, v in res.headers.items()}
        sub_cache[token] = {
            "text": res.text.strip(),
            "headers": resp_headers,
            "timestamp": now
        }
        return sub_cache[token]["text"], sub_cache[token]["headers"]

def is_admin(request: Request) -> bool:
    return request.cookies.get(COOKIE_NAME) == ADMIN_PASSWORD

def is_v2ray_client(user_agent: str) -> bool:
    ua = user_agent.lower()
    client_signatures = [
        "v2ray", "v2rayng", "v2rayn", "clash", "sing-box", "nekobox", 
        "streisand", "shadowrocket", "stash", "quantumult", "surge", "loon", "happ"
    ]
    return any(sig in ua for sig in client_signatures)

# ----------------- قالب‌های HTML -----------------
def render_login_html(error: str = None) -> str:
    err_box = f'<div class="p-3 mb-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs text-center">{error}</div>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ورود به پنل مدیریت</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/misc/Farsi-Digits/Vazirmatn-FD-font-face.css">
    <style>body {{ font-family: Vazirmatn FD, sans-serif; }}</style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col justify-between p-4">
    <div></div>
    <div class="bg-slate-900 p-8 rounded-3xl border border-slate-800 w-full max-w-md mx-auto shadow-2xl">
        <h2 class="text-xl font-bold mb-6 text-center">ورود به پنل مدیریت دیتاسنتر</h2>
        {err_box}
        <form action="/admin/login" method="post" class="space-y-4">
            <div>
                <label class="block text-xs text-slate-400 mb-2">رمز عبور امنیتی پنل</label>
                <input type="password" name="password" required autofocus class="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-blue-500 text-left font-mono">
            </div>
            <button type="submit" class="w-full py-3 bg-blue-600 hover:bg-blue-500 font-bold rounded-xl text-sm transition-colors shadow-lg cursor-pointer">ورود به پنل</button>
        </form>
    </div>
    <div class="text-center text-xs text-slate-500 py-4" dir="ltr">
        Powered by <a href="https://t.me/DARK_WIKI20" target="_blank" class="text-blue-400 hover:underline font-semibold">@DARK_WIKI20</a>
    </div>
</body>
</html>"""

def render_admin_html(profiles, domain: str) -> str:
    rows = ""
    for p in profiles:
        status_badge = (
            '<span class="inline-flex items-center whitespace-nowrap px-3 py-1 rounded-full text-xs font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">مسدود</span>'
            if p["is_blocked"] else
            '<span class="inline-flex items-center whitespace-nowrap px-3 py-1 rounded-full text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">فعال</span>'
        )
        fake_label = f"<span class='text-blue-400 font-mono'>{p['fake_total_gb']} GB</span>" if p.get("fake_total_gb") and p["fake_total_gb"] > 0 else "<span class='text-slate-500'>عادی</span>"
        btn_class = "bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/20" if p["is_blocked"] else "bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/20"
        btn_text = "رفع بلاک" if p["is_blocked"] else "بلاک"
        rows += f"""
        <tr class="hover:bg-slate-800/40 transition-colors">
            <td class="p-4 font-bold whitespace-nowrap">{p['name']}</td>
            <td class="p-4 whitespace-nowrap"><a href="/d/{p['token']}" target="_blank" class="text-blue-400 hover:underline text-xs font-mono" dir="ltr">https://{domain}/d/{p['token']}</a></td>
            <td class="p-4 whitespace-nowrap"><span class="text-slate-300 text-xs font-mono select-all" dir="ltr">https://{domain}/sub/{p['token']}</span></td>
            <td class="p-4 whitespace-nowrap text-center">{fake_label}</td>
            <td class="p-4 whitespace-nowrap">{status_badge}</td>
            <td class="p-4 whitespace-nowrap">
                <div class="flex justify-center items-center gap-2">
                    <form action="/admin/profiles/{p['token']}/toggle-block" method="post" class="m-0">
                        <button type="submit" class="whitespace-nowrap px-3 py-1.5 rounded-xl text-xs font-semibold transition-colors cursor-pointer {btn_class}">{btn_text}</button>
                    </form>
                    <form action="/admin/profiles/{p['token']}/delete" method="post" class="m-0" onsubmit="return confirm('آیا از حذف این پروفایل اطمینان دارید؟');">
                        <button type="submit" class="whitespace-nowrap px-3 py-1.5 rounded-xl text-xs font-semibold bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 transition-colors cursor-pointer">حذف</button>
                    </form>
                </div>
            </td>
        </tr>"""

    if not rows:
        rows = '<tr><td colspan="6" class="p-8 text-center text-slate-500 text-xs">هنوز سابی در دیتاسنتر ذخیره نشده است.</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>مدیریت ساب‌ها</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/misc/Farsi-Digits/Vazirmatn-FD-font-face.css">
    <style>body {{ font-family: Vazirmatn FD, sans-serif; }}</style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen p-4 sm:p-8 flex flex-col justify-between">
    <div class="max-w-6xl w-full mx-auto space-y-8">
        <div class="flex flex-wrap justify-between items-center gap-4 bg-slate-900 p-6 rounded-3xl border border-slate-800 shadow-sm">
            <div>
                <h1 class="text-2xl font-bold">کنترل پنل دیتاسنتر ساب‌اسکریپشن</h1>
                <p class="text-xs text-slate-400 mt-1">دامنه سرور: <span class="font-mono text-blue-400" dir="ltr">{domain}</span></p>
            </div>
            <a href="/admin/logout" class="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-xl text-xs font-semibold transition-colors">خروج</a>
        </div>

        <div class="bg-slate-900 p-6 rounded-3xl border border-slate-800 shadow-sm">
            <h2 class="text-base font-bold mb-4 flex items-center gap-2"><span>➕</span> ذخیره ساب جدید در دیتاسنتر</h2>
            <form action="/admin/profiles/add" method="post" class="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div>
                    <label class="block text-xs text-slate-400 mb-1.5">نام یا برند نمایشی</label>
                    <input type="text" name="name" placeholder="مثلاً: VIP" required class="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1.5">لینک ساب اصلی فروشنده</label>
                    <input type="url" name="upstream_url" placeholder="https://seller.com/sub/..." required class="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500 text-left font-mono" dir="ltr">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1.5">حجم فیک کل (GB) - اختیاری</label>
                    <input type="number" step="0.1" name="fake_total_gb" placeholder="مثلاً: 20 (ضریب مصرف خودکار)" class="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500 text-left font-mono" dir="ltr">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1.5">توکن اختصاصی (اختیاری)</label>
                    <div class="flex gap-2">
                        <input type="text" name="custom_token" placeholder="خالی = رندوم" class="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500 text-left font-mono" dir="ltr">
                        <button type="submit" class="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 font-bold rounded-xl text-sm shrink-0 transition-colors cursor-pointer">ذخیره</button>
                    </div>
                </div>
            </form>
        </div>

        <div class="bg-slate-900 rounded-3xl border border-slate-800 overflow-hidden shadow-sm">
            <div class="p-6 border-b border-slate-800">
                <h2 class="text-base font-bold">ساب‌های ذخیره شده ({len(profiles)})</h2>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-right text-sm">
                    <thead class="bg-slate-950/60 text-slate-400 text-xs border-b border-slate-800">
                        <tr>
                            <th class="p-4 whitespace-nowrap">نام ساب</th>
                            <th class="p-4 whitespace-nowrap">داشبورد وب</th>
                            <th class="p-4 whitespace-nowrap">لینک ساب v2ray</th>
                            <th class="p-4 whitespace-nowrap text-center">حجم فیک</th>
                            <th class="p-4 whitespace-nowrap">وضعیت</th>
                            <th class="p-4 text-center whitespace-nowrap">عملیات</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-800/60">
                        {rows}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="text-center text-xs text-slate-500 pt-10 pb-2" dir="ltr">
        Powered by <a href="https://t.me/DARK_WIKI20" target="_blank" class="text-blue-400 hover:underline font-semibold">@DARK_WIKI20</a>
    </div>
</body>
</html>"""

def render_dashboard_html(ctx: dict) -> str:
    if ctx["is_blocked"]:
        main_section = """
        <div class="p-8 rounded-3xl border border-rose-500/30 bg-rose-500/5 mb-8 text-center shadow-lg animate-fade-in-up">
            <div class="inline-flex items-center whitespace-nowrap gap-2 px-4 py-1.5 rounded-full bg-rose-500/10 text-rose-500 text-sm font-bold mb-3 border border-rose-500/20">
                <span class="w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping"></span> مسدود شده
            </div>
            <div class="text-2xl sm:text-3xl font-bold text-rose-500 mb-2">اشتراک شما مسدود شده است</div>
            <p class="text-sm text-slate-500 dark:text-zinc-400">دسترسی این اشتراک توسط پشتیبانی غیرفعال شده است.</p>
        </div>"""
    else:
        conf_items = ""
        for idx, c in enumerate(ctx["configs"]):
            conf_items += f"""
            <div class="config-card group relative p-3 sm:p-3.5 rounded-xl border border-slate-200/80 dark:border-zinc-800/90 bg-white/70 dark:bg-zinc-900/80 backdrop-blur-sm hover:border-[#4b85d1] hover:shadow-md hover:-translate-y-0.5 transition-all duration-300">
                <div class="flex items-center gap-2.5">
                    <div class="px-2 py-0.5 rounded-md text-[11px] font-semibold uppercase bg-gradient-to-r from-[#4b85d1] to-[#3a6fb5] text-white shrink-0 shadow-xs">{c['proto']}</div>
                    <span class="text-base select-none">{c['icon']}</span>
                    <div dir="ltr" class="text-sm sm:text-base font-medium flex-1 min-w-0 truncate text-right text-slate-800 dark:text-slate-100">{c['name']}</div>
                    <div class="flex gap-1.5 shrink-0">
                        <button onclick="copyConfig({idx})" class="p-2 rounded-lg transition-all duration-200 cursor-pointer bg-slate-100 dark:bg-zinc-800 hover:bg-[#4b85d1] hover:text-white active:scale-90" title="کپی کانفیگ">
                            <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"></rect><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"></path></svg>
                        </button>
                        <button onclick="showConfigQR({idx})" class="p-2 rounded-lg bg-slate-100 dark:bg-zinc-800 hover:bg-slate-200 dark:hover:bg-zinc-700 transition-all duration-200 cursor-pointer active:scale-90" title="کد QR">
                            <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 12v4a1 1 0 0 1-1 1h-4"></path><path d="M17 3h2a2 2 0 0 1 2 2v2"></path><path d="M17 8V7"></path><path d="M21 17v2a2 2 0 0 1-2 2h-2"></path><path d="M3 7V5a2 2 0 0 1 2-2h2"></path><path d="M7 17h.01"></path><path d="M7 21H5a2 2 0 0 1-2-2v-2"></path><rect x="7" y="7" width="5" height="5" rx="1"></rect></svg>
                        </button>
                    </div>
                </div>
            </div>"""

        main_section = f"""
        <!-- اعلان هوشمند -->
        <div class="mb-6 sm:mb-8 animate-fade-in-up">
            <div class="p-4 sm:p-5 rounded-2xl border bg-gradient-to-r from-[#4b85d1]/15 via-[#4b85d1]/10 to-transparent border-[#4b85d1]/30 hover:border-[#4b85d1]/50 shadow-sm hover:shadow-lg transition-all duration-300">
                <div class="flex items-start gap-3.5">
                    <div class="shrink-0 mt-0.5 text-[#4b85d1] animate-pulse">
                        <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 sm:w-6 sm:h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.268 21a2 2 0 0 0 3.464 0"></path><path d="M3.262 15.326A1 1 0 0 0 4 17h16a1 1 0 0 0 .74-1.673C19.41 13.956 18 12.499 18 8A6 6 0 0 0 6 8c0 4.499-1.411 5.956-2.738 7.326"></path></svg>
                    </div>
                    <div class="flex-1 min-w-0">
                        <div class="text-sm sm:text-base font-bold mb-1">اطلاعیه اتصال سریع</div>
                        <p class="text-xs sm:text-sm text-slate-600 dark:text-zinc-400 leading-relaxed">لطفاً قبل از اتصال یا در صورت بروز اختلال، یک‌بار لینک اشتراک (Update Subscription) را درون برنامه خود به‌روزرسانی فرمایید.</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- کارت وضعیت و اطلاعات مصرف -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-4 sm:gap-6 mb-8 animate-fade-in-up" style="animation-delay: 100ms;">
            <div class="lg:col-span-2 relative p-6 sm:p-8 rounded-3xl border border-slate-200/80 dark:border-zinc-800 bg-white/80 dark:bg-zinc-900/80 backdrop-blur-md shadow-xl flex flex-col justify-between hover:shadow-2xl transition-all duration-300">
                <div class="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4 mb-6">
                    <div class="flex-1">
                        <div class="flex items-center gap-2.5 sm:gap-3">
                            <span class="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-emerald-500">فعال</span>
                            <span class="relative flex h-3 w-3">
                                <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                <span class="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
                            </span>
                        </div>
                    </div>
                    <div class="sm:text-left">
                        <div class="text-xs sm:text-sm text-slate-500 dark:text-zinc-400">اعتبار باقی‌مانده</div>
                        <p class="text-xl sm:text-2xl font-black mt-0.5 text-slate-800 dark:text-slate-100">{ctx['days_left']} روز</p>
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
                            <span class="text-xs text-slate-500 dark:text-zinc-400 font-medium">مصرف شده</span>
                        </div>
                    </div>

                    <div class="flex-1 w-full space-y-3.5 sm:space-y-4">
                        <div class="flex justify-between items-center p-2.5 rounded-xl bg-slate-100/60 dark:bg-zinc-800/40">
                            <span class="text-xs sm:text-sm text-slate-500 dark:text-zinc-400">کل حجم سرویس</span>
                            <span dir="ltr" class="text-sm sm:text-base font-bold text-slate-800 dark:text-slate-200">{ctx['total_quota']}</span>
                        </div>
                        <div class="flex justify-between items-center p-2.5 rounded-xl bg-slate-100/60 dark:bg-zinc-800/40">
                            <span class="text-xs sm:text-sm text-slate-500 dark:text-zinc-400">حجم مصرفی</span>
                            <span dir="ltr" class="text-sm sm:text-base font-bold text-amber-500">{ctx['used_traffic']}</span>
                        </div>
                        <div class="flex justify-between items-center p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20">
                            <span class="text-xs sm:text-sm font-medium text-emerald-600 dark:text-emerald-400">حجم باقی‌مانده</span>
                            <span dir="ltr" class="text-sm sm:text-base font-bold text-emerald-600 dark:text-emerald-400">{ctx['remaining_traffic']}</span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-1 gap-4">
                <div class="p-5 sm:p-6 rounded-3xl border border-slate-200/80 dark:border-zinc-800 bg-white/80 dark:bg-zinc-900/80 backdrop-blur-md shadow-sm flex flex-col justify-center hover:-translate-y-1 transition-all duration-300">
                    <div class="text-xs sm:text-sm text-slate-500 dark:text-zinc-400 mb-1">مصرف شده تابحال</div>
                    <div dir="ltr" class="text-xl sm:text-2xl font-black text-right text-[#4b85d1]">{ctx['used_traffic']}</div>
                </div>
                <div class="p-5 sm:p-6 rounded-3xl border border-slate-200/80 dark:border-zinc-800 bg-white/80 dark:bg-zinc-900/80 backdrop-blur-md shadow-sm flex flex-col justify-center hover:-translate-y-1 transition-all duration-300">
                    <div class="text-xs sm:text-sm text-slate-500 dark:text-zinc-400 mb-1">تاریخ انقضای اشتراک</div>
                    <div dir="ltr" class="text-sm sm:text-base font-bold text-right text-slate-800 dark:text-slate-100">{ctx['expire_date']}</div>
                </div>
                <div class="p-5 sm:p-6 rounded-3xl border border-slate-200/80 dark:border-zinc-800 bg-white/80 dark:bg-zinc-900/80 backdrop-blur-md shadow-sm flex flex-col justify-center hover:-translate-y-1 transition-all duration-300">
                    <div class="text-xs sm:text-sm text-slate-500 dark:text-zinc-400 mb-1">آخرین بررسی دیتاسنتر</div>
                    <div dir="ltr" class="flex items-center justify-end gap-2">
                        <span class="text-xs sm:text-sm font-semibold text-slate-700 dark:text-slate-300">{ctx['now_jalali']}</span>
                        <span class="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
                    </div>
                </div>
            </div>
        </div>

        <!-- لیست کانفیگ‌ها و دکمه کپی کل -->
        <div class="w-full py-2 animate-fade-in-up" style="animation-delay: 200ms;">
            <div class="space-y-4">
                <div class="flex items-center justify-between">
                    <h2 class="text-lg sm:text-xl font-bold flex items-center gap-2">
                        <span class="text-xl animate-bounce">🔗</span>لینک‌های اتصال و کانفیگ
                    </h2>
                    <button onclick="copyAll()" class="cursor-pointer flex items-center gap-2 px-4 py-2.5 text-xs sm:text-sm font-bold rounded-xl transition-all duration-300 hover:scale-105 active:scale-95 bg-gradient-to-r from-[#4b85d1] to-[#3671bf] text-white shadow-lg hover:shadow-[#4b85d1]/30">
                        <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 2a2 2 0 0 1 1.414.586l4 4A2 2 0 0 1 21 8v7a2 2 0 0 1-2 2h-8a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2z"></path><path d="M15 2v4a2 2 0 0 0 2 2h4"></path><path d="M5 7a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h8a2 2 0 0 0 1.732-1"></path></svg>
                        <span>کپی همه کانفیگ‌ها</span>
                    </button>
                </div>

                <!-- لینک اشتراک اصلی -->
                <div class="group relative p-4 rounded-2xl border-2 border-[#4b85d1]/50 bg-gradient-to-r from-[#4b85d1]/15 to-[#4b85d1]/5 hover:border-[#4b85d1] transition-all duration-300 shadow-sm">
                    <div class="flex items-center gap-3">
                        <div class="px-2.5 py-1 rounded-lg text-xs font-black bg-[#4b85d1] text-white shrink-0 shadow-md">SUB LINK</div>
                        <span class="text-lg">⚡</span>
                        <div class="flex-1 min-w-0">
                            <div class="text-sm sm:text-base font-bold text-slate-800 dark:text-slate-100">لینک هوشمند اشتراک (آپدیت خودکار)</div>
                            <div class="text-[11px] text-slate-500 dark:text-zinc-400 truncate font-mono mt-0.5" dir="ltr">{ctx['sub_url']}</div>
                        </div>
                        <div class="flex gap-2 shrink-0">
                            <button onclick="copySubUrl()" class="p-2.5 rounded-xl transition-all duration-200 cursor-pointer bg-white dark:bg-zinc-800 hover:bg-[#4b85d1] hover:text-white shadow-xs active:scale-90" title="کپی لینک ساب">
                                <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"></rect><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"></path></svg>
                            </button>
                            <button onclick="showSubQR()" class="p-2.5 rounded-xl bg-white dark:bg-zinc-800 hover:bg-slate-200 dark:hover:bg-zinc-700 transition-all duration-200 cursor-pointer shadow-xs active:scale-90" title="کد QR">
                                <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 12v4a1 1 0 0 1-1 1h-4"></path><path d="M17 3h2a2 2 0 0 1 2 2v2"></path><path d="M17 8V7"></path><path d="M21 17v2a2 2 0 0 1-2 2h-2"></path><path d="M3 7V5a2 2 0 0 1 2-2h2"></path><path d="M7 17h.01"></path><path d="M7 21H5a2 2 0 0 1-2-2v-2"></path><rect x="7" y="7" width="5" height="5" rx="1"></rect></svg>
                            </button>
                        </div>
                    </div>
                </div>

                <!-- لیست تک‌تک کانفیگ‌ها با اسکرول‌بار کاملاً شفاف و بدون پس‌زمینه سفید -->
                <div class="custom-scrollbar max-h-[460px] overflow-y-auto space-y-2.5 pl-1.5 pr-0.5">
                    {conf_items}
                </div>
            </div>
        </div>

        <!-- بخش اپلیکیشن‌های پیشنهادی برای تمام پلتفرم‌ها -->
        <div class="my-10 animate-fade-in-up" style="animation-delay: 300ms;">
            <div class="flex items-center gap-4 mb-6">
                <div class="flex-1 h-px bg-gradient-to-r from-transparent via-slate-300 dark:via-zinc-800 to-transparent"></div>
                <div class="px-5 py-2 rounded-full bg-gradient-to-r from-[#4b85d1]/20 to-[#4b85d1]/5 text-sm font-bold text-[#4b85d1] border border-[#4b85d1]/30 shadow-xs">
                    📱 راهنمای نرم‌افزارهای اتصال
                </div>
                <div class="flex-1 h-px bg-gradient-to-r from-transparent via-slate-300 dark:via-zinc-800 to-transparent"></div>
            </div>

            <!-- تب‌های پلتفرم‌ها -->
            <div class="flex justify-center flex-wrap gap-2 mb-6">
                <button onclick="switchTab('android')" id="tab-btn-android" class="tab-button active px-4 py-2 rounded-xl text-xs sm:text-sm font-bold transition-all duration-200">اندروید</button>
                <button onclick="switchTab('ios')" id="tab-btn-ios" class="tab-button px-4 py-2 rounded-xl text-xs sm:text-sm font-bold transition-all duration-200">iOS (آیفون / آیپد)</button>
                <button onclick="switchTab('windows')" id="tab-btn-windows" class="tab-button px-4 py-2 rounded-xl text-xs sm:text-sm font-bold transition-all duration-200">ویندوز</button>
                <button onclick="switchTab('mac_linux')" id="tab-btn-mac_linux" class="tab-button px-4 py-2 rounded-xl text-xs sm:text-sm font-bold transition-all duration-200">مک / لینوکس</button>
            </div>

            <!-- محتوای تب اندروید -->
            <div id="tab-android" class="platform-tab-content grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div class="app-card p-5 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white/70 dark:bg-zinc-900/70 backdrop-blur-sm flex flex-col justify-between">
                    <div>
                        <div class="flex items-center justify-between mb-3">
                            <span class="text-2xl">🤖</span>
                            <span class="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-500">پیشنهادی</span>
                        </div>
                        <h3 class="font-bold text-sm mb-1">v2rayNG</h3>
                        <p class="text-xs text-slate-500 dark:text-zinc-400 mb-4">محبوب‌ترین و پایدارترین کلاینت اندروید</p>
                    </div>
                    <div class="flex gap-2">
                        <a href="https://github.com/2dust/v2rayNG/releases" target="_blank" class="flex-1 text-center py-2 rounded-xl bg-[#4b85d1] text-white text-xs font-semibold hover:opacity-90">دانلود گیت‌هاب</a>
                        <a href="https://play.google.com/store/apps/details?id=com.v2ray.ang" target="_blank" class="px-3 py-2 rounded-xl bg-slate-100 dark:bg-zinc-800 text-xs font-semibold hover:bg-slate-200 dark:hover:bg-zinc-700">گوگل‌پلی</a>
                    </div>
                </div>

                <div class="app-card p-5 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white/70 dark:bg-zinc-900/70 backdrop-blur-sm flex flex-col justify-between">
                    <div>
                        <div class="flex items-center justify-between mb-3">
                            <span class="text-2xl">📦</span>
                            <span class="text-[10px] font-bold px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-500">مدرن</span>
                        </div>
                        <h3 class="font-bold text-sm mb-1">Sing-box</h3>
                        <p class="text-xs text-slate-500 dark:text-zinc-400 mb-4">هسته فوق‌العاده سریع با مصرف رم ناچیز</p>
                    </div>
                    <div class="flex gap-2">
                        <a href="https://github.com/SagerNet/sing-box/releases" target="_blank" class="flex-1 text-center py-2 rounded-xl bg-[#4b85d1] text-white text-xs font-semibold hover:opacity-90">دانلود مستقیم</a>
                        <a href="https://play.google.com/store/apps/details?id=io.nekohasekai.sfa" target="_blank" class="px-3 py-2 rounded-xl bg-slate-100 dark:bg-zinc-800 text-xs font-semibold hover:bg-slate-200 dark:hover:bg-zinc-700">گوگل‌پلی</a>
                    </div>
                </div>

                <div class="app-card p-5 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white/70 dark:bg-zinc-900/70 backdrop-blur-sm flex flex-col justify-between">
                    <div>
                        <div class="flex items-center justify-between mb-3">
                            <span class="text-2xl">⚡</span>
                            <span class="text-[10px] font-bold px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-500">حرفه‌ای</span>
                        </div>
                        <h3 class="font-bold text-sm mb-1">NekoBox / Happ</h3>
                        <p class="text-xs text-slate-500 dark:text-zinc-400 mb-4">امکانات فوق‌العاده جهت تست پینگ و روتینگ</p>
                    </div>
                    <div class="flex gap-2">
                        <a href="https://github.com/MatsuriDayo/NekoBoxForAndroid/releases" target="_blank" class="flex-1 text-center py-2 rounded-xl bg-[#4b85d1] text-white text-xs font-semibold hover:opacity-90">دانلود گیت‌هاب</a>
                    </div>
                </div>
            </div>

            <!-- محتوای تب iOS -->
            <div id="tab-ios" class="platform-tab-content hidden grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div class="app-card p-5 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white/70 dark:bg-zinc-900/70 backdrop-blur-sm flex flex-col justify-between">
                    <div>
                        <div class="flex items-center justify-between mb-3">
                            <span class="text-2xl">🍏</span>
                            <span class="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-500">رایگان و عالی</span>
                        </div>
                        <h3 class="font-bold text-sm mb-1">Streisand</h3>
                        <p class="text-xs text-slate-500 dark:text-zinc-400 mb-4">ساده‌ترین و سریع‌ترین اپلیکیشن رایگان در اپ‌استور</p>
                    </div>
                    <a href="https://apps.apple.com/us/app/streisand/id6450534064" target="_blank" class="w-full text-center py-2 rounded-xl bg-[#4b85d1] text-white text-xs font-semibold hover:opacity-90">دریافت از App Store</a>
                </div>

                <div class="app-card p-5 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white/70 dark:bg-zinc-900/70 backdrop-blur-sm flex flex-col justify-between">
                    <div>
                        <div class="flex items-center justify-between mb-3">
                            <span class="text-2xl">📦</span>
                            <span class="text-[10px] font-bold px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-500">مدرن</span>
                        </div>
                        <h3 class="font-bold text-sm mb-1">Sing-box (iOS)</h3>
                        <p class="text-xs text-slate-500 dark:text-zinc-400 mb-4">پشتیبانی از پروتکل‌های جدید و کمترین مصرف باتری</p>
                    </div>
                    <a href="https://apps.apple.com/us/app/sing-box/id6451272673" target="_blank" class="w-full text-center py-2 rounded-xl bg-[#4b85d1] text-white text-xs font-semibold hover:opacity-90">دریافت از App Store</a>
                </div>

                <div class="app-card p-5 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white/70 dark:bg-zinc-900/70 backdrop-blur-sm flex flex-col justify-between">
                    <div>
                        <div class="flex items-center justify-between mb-3">
                            <span class="text-2xl">🚀</span>
                            <span class="text-[10px] font-bold px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-500">قدرتمند</span>
                        </div>
                        <h3 class="font-bold text-sm mb-1">V2Box / FoXray</h3>
                        <p class="text-xs text-slate-500 dark:text-zinc-400 mb-4">پشتیبانی کامل از ساب‌اسکریپشن و QR Code</p>
                    </div>
                    <a href="https://apps.apple.com/us/app/v2box-v2ray-client/id6446814043" target="_blank" class="w-full text-center py-2 rounded-xl bg-[#4b85d1] text-white text-xs font-semibold hover:opacity-90">دریافت از App Store</a>
                </div>
            </div>

            <!-- محتوای تب ویندوز -->
            <div id="tab-windows" class="platform-tab-content hidden grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div class="app-card p-5 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white/70 dark:bg-zinc-900/70 backdrop-blur-sm flex flex-col justify-between">
                    <div>
                        <div class="flex items-center justify-between mb-3">
                            <span class="text-2xl">🪟</span>
                            <span class="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-500">پیشنهادی</span>
                        </div>
                        <h3 class="font-bold text-sm mb-1">v2rayN</h3>
                        <p class="text-xs text-slate-500 dark:text-zinc-400 mb-4">استانداردترین کلاینت برای سیستم‌های ویندوزی</p>
                    </div>
                    <a href="https://github.com/2dust/v2rayN/releases" target="_blank" class="w-full text-center py-2 rounded-xl bg-[#4b85d1] text-white text-xs font-semibold hover:opacity-90">دانلود از گیت‌هاب</a>
                </div>

                <div class="app-card p-5 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white/70 dark:bg-zinc-900/70 backdrop-blur-sm flex flex-col justify-between">
                    <div>
                        <div class="flex items-center justify-between mb-3">
                            <span class="text-2xl">⚡</span>
                            <span class="text-[10px] font-bold px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-500">زیبا و سریع</span>
                        </div>
                        <h3 class="font-bold text-sm mb-1">Clash Verge Rev</h3>
                        <p class="text-xs text-slate-500 dark:text-zinc-400 mb-4">محیط کاربری بسیار شیک با قابلیت TUN Mode</p>
                    </div>
                    <a href="https://github.com/clash-verge-rev/clash-verge-rev/releases" target="_blank" class="w-full text-center py-2 rounded-xl bg-[#4b85d1] text-white text-xs font-semibold hover:opacity-90">دانلود از گیت‌هاب</a>
                </div>

                <div class="app-card p-5 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white/70 dark:bg-zinc-900/70 backdrop-blur-sm flex flex-col justify-between">
                    <div>
                        <div class="flex items-center justify-between mb-3">
                            <span class="text-2xl">🛡</span>
                            <span class="text-[10px] font-bold px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-500">همه‌کاره</span>
                        </div>
                        <h3 class="font-bold text-sm mb-1">Hiddify Next</h3>
                        <p class="text-xs text-slate-500 dark:text-zinc-400 mb-4">اتصال یک‌کلیکه و سازگاری هوشمند با تمام کانفیگ‌ها</p>
                    </div>
                    <a href="https://github.com/hiddify/hiddify-next/releases" target="_blank" class="w-full text-center py-2 rounded-xl bg-[#4b85d1] text-white text-xs font-semibold hover:opacity-90">دانلود از گیت‌هاب</a>
                </div>
            </div>

            <!-- محتوای تب مک / لینوکس -->
            <div id="tab-mac_linux" class="platform-tab-content hidden grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div class="app-card p-5 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white/70 dark:bg-zinc-900/70 backdrop-blur-sm flex flex-col justify-between">
                    <div>
                        <div class="flex items-center justify-between mb-3">
                            <span class="text-2xl">🍎</span>
                            <span class="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-500">پیشنهادی مک</span>
                        </div>
                        <h3 class="font-bold text-sm mb-1">Clash Verge Rev</h3>
                        <p class="text-xs text-slate-500 dark:text-zinc-400 mb-4">سازگار با چیپست‌های اینتل و اپل سیلیکون (M1/M2/M3)</p>
                    </div>
                    <a href="https://github.com/clash-verge-rev/clash-verge-rev/releases" target="_blank" class="w-full text-center py-2 rounded-xl bg-[#4b85d1] text-white text-xs font-semibold hover:opacity-90">دانلود نسخه Mac</a>
                </div>

                <div class="app-card p-5 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white/70 dark:bg-zinc-900/70 backdrop-blur-sm flex flex-col justify-between">
                    <div>
                        <div class="flex items-center justify-between mb-3">
                            <span class="text-2xl">🦊</span>
                            <span class="text-[10px] font-bold px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-500">اپ‌استور مک</span>
                        </div>
                        <h3 class="font-bold text-sm mb-1">FoXray</h3>
                        <p class="text-xs text-slate-500 dark:text-zinc-400 mb-4">قابل نصب مستقیم روی مک‌بوک از طریق Mac App Store</p>
                    </div>
                    <a href="https://apps.apple.com/us/app/foxray/id6448898396" target="_blank" class="w-full text-center py-2 rounded-xl bg-[#4b85d1] text-white text-xs font-semibold hover:opacity-90">دریافت از Mac App Store</a>
                </div>

                <div class="app-card p-5 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white/70 dark:bg-zinc-900/70 backdrop-blur-sm flex flex-col justify-between">
                    <div>
                        <div class="flex items-center justify-between mb-3">
                            <span class="text-2xl">🐧</span>
                            <span class="text-[10px] font-bold px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-500">لینوکس</span>
                        </div>
                        <h3 class="font-bold text-sm mb-1">Sing-box / Nekoray</h3>
                        <p class="text-xs text-slate-500 dark:text-zinc-400 mb-4">کلاینت‌های قدرتمند برای توزیع‌های مختلف لینوکس</p>
                    </div>
                    <a href="https://github.com/MatsuriDayo/nekoray/releases" target="_blank" class="w-full text-center py-2 rounded-xl bg-[#4b85d1] text-white text-xs font-semibold hover:opacity-90">دانلود از گیت‌هاب</a>
                </div>
            </div>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>داشبورد کاربری | {ctx['brand_name']}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/misc/Farsi-Digits/Vazirmatn-FD-font-face.css">
    <script>tailwind.config = {{ darkMode: 'class' }}</script>
    <style>
        body {{ font-family: Vazirmatn FD, system-ui, sans-serif; }}
        
        /* استایل اسکرول‌بار کاملاً شفاف و شیشه‌ای (حذف پس‌زمینه سفید تصویر) */
        * {{
            scrollbar-width: thin;
            scrollbar-color: rgba(75, 133, 209, 0.4) transparent;
        }}
        ::-webkit-scrollbar {{
            width: 5px;
            height: 5px;
        }}
        ::-webkit-scrollbar-track {{
            background: transparent !important;
        }}
        ::-webkit-scrollbar-thumb {{
            background: rgba(75, 133, 209, 0.35);
            border-radius: 9999px;
            transition: all 0.3s ease;
        }}
        ::-webkit-scrollbar-thumb:hover {{
            background: rgba(75, 133, 209, 0.75);
        }}
        ::-webkit-scrollbar-button {{
            display: none !important;
            width: 0;
            height: 0;
        }}

        /* انیمیشن‌های اختصاصی */
        @keyframes fadeInUp {{
            from {{ opacity: 0; transform: translateY(18px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        .animate-fade-in-up {{
            animation: fadeInUp 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }}
        
        .tab-button.active {{
            background-color: #4b85d1;
            color: #ffffff;
            box-shadow: 0 4px 14px rgba(75, 133, 209, 0.35);
        }}
        .tab-button:not(.active) {{
            background-color: rgba(255, 255, 255, 0.6);
            color: #64748b;
        }}
        .dark .tab-button:not(.active) {{
            background-color: rgba(39, 39, 42, 0.6);
            color: #a1a1aa;
        }}
        
        .glow-orb {{
            position: fixed;
            width: 320px;
            height: 320px;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(75, 133, 209, 0.12) 0%, rgba(75, 133, 209, 0) 70%);
            pointer-events: none;
            z-index: 0;
            filter: blur(40px);
        }}
    </style>
</head>
<body class="bg-[#f4f5f7] dark:bg-[#111113] text-slate-800 dark:text-slate-100 min-h-screen flex flex-col justify-between overflow-x-hidden relative selection:bg-[#4b85d1] selection:text-white">
    <div class="glow-orb top-[-100px] right-[-100px]"></div>
    <div class="glow-orb bottom-[-100px] left-[-100px]"></div>

    <div class="container mx-auto px-4 pt-10 pb-6 max-w-5xl relative z-10 flex-1">
        <!-- هدر داشبورد با افکت شیشه‌ای -->
        <div class="flex sm:items-center sm:justify-between gap-4 mb-8 sm:mb-10 animate-fade-in-up">
            <div class="flex-1 min-w-0">
                <h1 class="text-3xl sm:text-4xl font-extrabold mb-1.5 bg-gradient-to-l from-slate-900 to-slate-600 dark:from-white dark:to-zinc-400 bg-clip-text text-transparent">داشبورد اشتراک</h1>
                <div class="flex items-center gap-3 text-sm text-slate-500 dark:text-zinc-400">
                    <p dir="ltr" class="font-bold text-[#4b85d1] truncate">{ctx['brand_name']}</p>
                    <div class="flex items-center gap-1.5">
                        <div class="w-2 h-2 rounded-full bg-emerald-500 animate-ping"></div>
                        <span class="text-xs">سرور ابری دیتاسنتر</span>
                    </div>
                </div>
            </div>
            <div class="flex items-center gap-2">
                <button onclick="location.reload()" class="size-10 rounded-xl border border-slate-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-sm hover:border-[#4b85d1] hover:text-[#4b85d1] flex items-center justify-center transition-all duration-200 cursor-pointer active:scale-95" title="بروزرسانی اطلاعات">
                    <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"></path><path d="M3 3v5h5"></path><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"></path><path d="M16 16h5v5"></path></svg>
                </button>
                <button onclick="document.documentElement.classList.toggle('dark')" class="size-10 rounded-xl border border-slate-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-sm hover:border-[#4b85d1] hover:text-[#4b85d1] flex items-center justify-center transition-all duration-200 cursor-pointer active:scale-95" title="تغییر تم">
                    <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2"></path><path d="M12 20v2"></path><path d="m4.93 4.93 1.41 1.41"></path><path d="m17.66 17.66 1.41 1.41"></path><path d="M2 12h2"></path><path d="M20 12h2"></path><path d="m6.34 17.66-1.41 1.41"></path><path d="m19.07 4.93-1.41 1.41"></path></svg>
                </button>
            </div>
        </div>

        {main_section}
    </div>

    <!-- فوتر با آیدی پشتیبانی @DARK_WIKI20 -->
    <div dir="ltr" class="relative w-full pb-8 pt-4 px-6 z-10">
        <div class="container mx-auto max-w-5xl flex justify-center">
            <div class="flex flex-col items-center gap-2.5">
                <a href="https://t.me/DARK_WIKI20" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-blue-500/10 hover:bg-blue-500/20 text-[#4b85d1] text-xs font-bold transition-all duration-200 border border-blue-500/20 shadow-xs">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 5.636l-3.536 3.536m0 5.656l3.536 3.536M9.172 9.172L5.636 5.636m3.536 9.192l-3.536 3.536M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-5 0a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
                    پشتیبانی تلگرام: @DARK_WIKI20
                </a>
                <p class="inline-block text-center text-xs text-slate-500 dark:text-zinc-500">
                    Powered by <a class="text-[#4b85d1] font-bold hover:underline" href="https://t.me/DARK_WIKI20" target="_blank" rel="noopener noreferrer">@DARK_WIKI20</a>
                </p>
            </div>
        </div>
    </div>

    <!-- اعلان توست کپی -->
    <div id="toastBox" class="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 hidden px-5 py-2.5 rounded-2xl bg-slate-900/90 dark:bg-white/95 text-white dark:text-slate-900 text-xs font-bold shadow-2xl backdrop-blur-md transition-all duration-300"></div>

    <!-- مودال کد QR -->
    <div id="qrModal" class="fixed inset-0 bg-black/60 backdrop-blur-xs hidden items-center justify-center z-50 p-4 transition-all duration-300" onclick="closeQR()">
        <div class="bg-white dark:bg-zinc-900 p-6 rounded-3xl shadow-2xl max-w-xs w-full flex flex-col items-center text-center border border-slate-100 dark:border-zinc-800 animate-fade-in-up" onclick="event.stopPropagation()">
            <h3 class="font-bold text-sm mb-4">اسکن و اتصال با QR Code</h3>
            <img id="qrImage" src="" alt="QR Code" class="w-52 h-52 rounded-2xl mb-4 border border-slate-100 dark:border-zinc-800 p-2.5 bg-white shadow-inner">
            <button onclick="closeQR()" class="w-full py-2.5 bg-slate-100 dark:bg-zinc-800 hover:bg-slate-200 dark:hover:bg-zinc-700 text-xs font-bold rounded-xl transition-colors cursor-pointer">بستن</button>
        </div>
    </div>

    <script>
        const subUrl = {json.dumps(ctx['sub_url'])};
        const allConfigs = {ctx['configs_json']};

        function switchTab(platform) {{
            document.querySelectorAll('.platform-tab-content').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
            
            const target = document.getElementById('tab-' + platform);
            const btn = document.getElementById('tab-btn-' + platform);
            if (target) target.classList.remove('hidden');
            if (btn) btn.classList.add('active');
        }}

        function showToast(msg) {{
            const box = document.getElementById("toastBox");
            box.textContent = msg;
            box.classList.remove("hidden");
            setTimeout(() => box.classList.add("hidden"), 2000);
        }}

        function copySubUrl() {{
            navigator.clipboard.writeText(subUrl);
            showToast("لینک اشتراک کپی شد!");
        }}
        function copyConfig(idx) {{
            navigator.clipboard.writeText(allConfigs[idx]);
            showToast("کانفیگ کپی شد!");
        }}
        function copyAll() {{
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

# آدرس استاندارد ساب‌اسکریپشن برای کلاینت‌ها (با اعمال حجم فیک روی هدر)
@app.get("/sub/{token}")
async def get_user_sub(token: str):
    with get_db() as conn:
        profile = conn.execute("SELECT * FROM profiles WHERE token = ?", (token,)).fetchone()

    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    if profile["is_blocked"] == 1:
        return Response(content="Subscription is blocked by administrator.", status_code=403)

    try:
        raw_text, headers = await fetch_upstream(token, profile["upstream_url"])
        _, encoded_sub = parse_and_modify_configs(raw_text)
        
        # دستکاری هدر با حجم و ضریب فیک
        user_info_raw = headers.get("subscription-userinfo", "")
        info = parse_user_info(user_info_raw)
        fake_gb = profile["fake_total_gb"] if "fake_total_gb" in profile.keys() else 0
        
        if info and fake_gb and fake_gb > 0:
            up, down, tot = apply_fake_traffic(info.get("upload", 0), info.get("download", 0), info.get("total", 0), fake_gb)
            user_info = f"upload={up}; download={down}; total={tot}; expire={info.get('expire', 0)}"
        else:
            user_info = user_info_raw

    except Exception:
        return Response(content="", status_code=502)

    return Response(
        content=encoded_sub,
        media_type="text/plain; charset=utf-8",
        headers={
            "subscription-userinfo": user_info,
            "Profile-Update-Interval": "6"
        }
    )

# داشبورد وب
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

    if not is_blocked:
        try:
            raw_text, headers = await fetch_upstream(token, profile["upstream_url"])
            info = parse_user_info(headers.get("subscription-userinfo", ""))
            configs, _ = parse_and_modify_configs(raw_text)
            
            raw_up = info.get("upload", 0)
            raw_down = info.get("download", 0)
            raw_total = info.get("total", 0)
            expire_ts = info.get("expire", 0)
            
            fake_gb = profile["fake_total_gb"] if "fake_total_gb" in profile.keys() else 0
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

    now_dt = datetime.now()
    njy, njm, njd = gregorian_to_jalali(now_dt.year, now_dt.month, now_dt.day)
    now_jalali = to_persian_num(f"{njy}/{njm:02d}/{njd:02d}, {now_dt.strftime('%H:%M')}")

    clean_domain = PUBLIC_URL.replace("https://", "").replace("http://", "").strip("/")
    sub_url = f"https://{clean_domain}/sub/{token}"

    ctx = {
        "brand_name": profile["name"],
        "is_blocked": is_blocked,
        "percent": percent,
        "dashoffset": dashoffset,
        "total_quota": format_bytes(total_quota),
        "used_traffic": format_bytes(used_traffic),
        "remaining_traffic": format_bytes(remaining),
        "days_left": days_left,
        "expire_date": expire_jalali,
        "now_jalali": now_jalali,
        "sub_url": sub_url,
        "configs": configs,
        "configs_json": json.dumps([c["link"] for c in configs])
    }
    return HTMLResponse(content=render_dashboard_html(ctx))

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request):
    if not is_admin(request):
        return HTMLResponse(content=render_login_html())

    with get_db() as conn:
        profiles = conn.execute("SELECT * FROM profiles ORDER BY id DESC").fetchall()

    clean_domain = PUBLIC_URL.replace("https://", "").replace("http://", "").strip("/")
    return HTMLResponse(content=render_admin_html(profiles, clean_domain))

@app.post("/admin/login")
async def admin_login(request: Request):
    body = await request.body()
    form_data = urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))
    password = form_data.get("password", [""])[0]

    if password == ADMIN_PASSWORD:
        response = RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
        response.set_cookie(key=COOKIE_NAME, value=ADMIN_PASSWORD, httponly=True, max_age=86400 * 7)
        return response
    return HTMLResponse(content=render_login_html("رمز عبور نادرست است."))

@app.get("/admin/logout")
async def admin_logout():
    response = RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(COOKIE_NAME)
    return response

@app.post("/admin/profiles/add")
async def add_profile(request: Request):
    if not is_admin(request):
        raise HTTPException(status_code=401)

    body = await request.body()
    form_data = urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))
    name = form_data.get("name", [""])[0].strip()
    upstream_url = form_data.get("upstream_url", [""])[0].strip()
    custom_token = form_data.get("custom_token", [""])[0].strip()
    fake_total_raw = form_data.get("fake_total_gb", ["0"])[0].strip()

    try:
        fake_total_gb = float(fake_total_raw) if fake_total_raw else 0.0
    except ValueError:
        fake_total_gb = 0.0

    token = custom_token if custom_token else secrets.token_hex(6)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    if name and upstream_url:
        with get_db() as conn:
            try:
                conn.execute(
                    "INSERT INTO profiles (token, name, upstream_url, fake_total_gb, is_blocked, created_at) VALUES (?, ?, ?, ?, 0, ?)",
                    (token, name, upstream_url, fake_total_gb, created_at)
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

    sub_cache.pop(token, None)
    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)

@app.post("/admin/profiles/{token}/delete")
async def delete_profile(request: Request, token: str):
    if not is_admin(request):
        raise HTTPException(status_code=401)

    with get_db() as conn:
        conn.execute("DELETE FROM profiles WHERE token = ?", (token,))
        conn.commit()

    sub_cache.pop(token, None)
    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)

@app.post("/webhook")
async def telegram_webhook(req: Request):
    if not BOT_TOKEN:
        return Response(status_code=200)

    try:
        update = await req.json()
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
            caption = "هیچ پروفایلی در دیتاسنتر ثبت نشده است.\n\nPowered by @DARK_WIKI20"
        else:
            try:
                raw_text, headers = await fetch_upstream(profile["token"], profile["upstream_url"])
                info = parse_user_info(headers.get("subscription-userinfo", ""))
                fake_gb = profile["fake_total_gb"] if "fake_total_gb" in profile.keys() else 0
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
                f"📈 Remaining: `{remaining_gb:.2f}` GB\n\n"
                f"🌐 داشبورد وب:\n{dash_link}\n\n"
                f"🔗 لینک ساب v2ray:\n`{sub_link}`\n\n"
                f"⚡ Support: @DARK_WIKI20"
            )

        async with httpx.AsyncClient() as client:
            await client.post(
                f"{TELEGRAM_API}/sendMessage",
                json={"chat_id": chat_id, "text": caption, "parse_mode": "Markdown"}
            )

    return Response(status_code=200)
