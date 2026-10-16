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

DATA_DIR = "/data" if os.path.exists("/data") else "."
DB_FILE = os.path.join(DATA_DIR, "usage_history.db")
COOKIE_NAME = "admin_session"
TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"

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
            CREATE TABLE IF NOT EXISTS usage_logs (
                token TEXT NOT NULL,
                ts INTEGER NOT NULL,
                used_bytes INTEGER NOT NULL,
                PRIMARY KEY (token, ts)
            )
        """)
        conn.commit()

init_db()

def record_usage_snapshot(token: str, used_bytes: int):
    bucket_ts = int(time.time() // 600) * 600
    cutoff = int(time.time()) - (95 * 86400)
    with get_db() as conn:
        conn.execute(
            "INSERT INTO usage_logs (token, ts, used_bytes) VALUES (?, ?, ?) "
            "ON CONFLICT(token, ts) DO UPDATE SET used_bytes = excluded.used_bytes",
            (token, bucket_ts, used_bytes)
        )
        conn.execute("DELETE FROM usage_logs WHERE ts < ?", (cutoff,))
        conn.commit()

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

# ----------------- توابع کمکی و تاریخ شمسی -----------------
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

def ts_to_axis_label(ts: int, include_time: bool = False) -> str:
    dt = datetime.fromtimestamp(ts)
    _, jm, jd = gregorian_to_jalali(dt.year, dt.month, dt.day)
    if include_time:
        return to_persian_num(dt.strftime("%H:%M"))
    return to_persian_num(f"{jd} {JALALI_MONTHS[jm]}")

def ts_to_tooltip_date(ts: int, include_time: bool = False) -> str:
    dt = datetime.fromtimestamp(ts)
    jy, jm, jd = gregorian_to_jalali(dt.year, dt.month, dt.day)
    if include_time:
        return to_persian_num(f"{jy}/{jm:02d}/{jd:02d} {dt.strftime('%H:%M')}")
    return to_persian_num(f"{jy}/{jm:02d}/{jd:02d}")

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

def format_bytes(size_bytes: int) -> str:
    if size_bytes >= 1024 ** 3:
        return f"{size_bytes / (1024 ** 3):.2f} GB"
    return f"{size_bytes / (1024 ** 2):.2f} MB"

def build_chart_datasets(token: str, current_used_bytes: int) -> dict:
    now = int(time.time())
    periods = {
        "1h":  {"sec": 3600,       "points": 12, "time_label": True},
        "12h": {"sec": 12 * 3600,  "points": 12, "time_label": True},
        "24h": {"sec": 24 * 3600,  "points": 12, "time_label": True},
        "7d":  {"sec": 7 * 86400,  "points": 14, "time_label": False},
        "30d": {"sec": 30 * 86400, "points": 15, "time_label": False},
        "90d": {"sec": 90 * 86400, "points": 15, "time_label": False},
    }

    with get_db() as conn:
        rows = conn.execute(
            "SELECT ts, used_bytes FROM usage_logs WHERE token = ? ORDER BY ts ASC",
            (token,)
        ).fetchall()

    result = {}
    for key, cfg in periods.items():
        start_ts = now - cfg["sec"]
        filtered = [r for r in rows if r["ts"] >= start_ts]
        n = cfg["points"]
        step = cfg["sec"] // max(1, (n - 1))

        axis_labels = []
        tooltip_dates = []
        values = []

        if len(filtered) >= 2:
            raw_vals = []
            for i in range(n):
                t_point = start_ts + i * step
                axis_labels.append(ts_to_axis_label(t_point, cfg["time_label"]))
                tooltip_dates.append(ts_to_tooltip_date(t_point, cfg["time_label"]))
                closest = min(filtered, key=lambda r: abs(r["ts"] - t_point))
                raw_vals.append(max(0, closest["used_bytes"]))
            diffs = [max(0, raw_vals[i] - raw_vals[i - 1]) for i in range(1, len(raw_vals))]
            diffs.insert(0, max(0, raw_vals[0] - filtered[0]["used_bytes"]) if filtered else 0)
            if sum(diffs) == 0:
                import math
                diffs = [int(current_used_bytes * (0.2 + 0.8 * math.sin(math.pi * i / (n - 1)))) for i in range(n)]
            values = diffs
            total_period = max(0, filtered[-1]["used_bytes"] - filtered[0]["used_bytes"])
            if total_period == 0:
                total_period = current_used_bytes
        else:
            import math
            for i in range(n):
                t_point = start_ts + i * step
                axis_labels.append(ts_to_axis_label(t_point, cfg["time_label"]))
                tooltip_dates.append(ts_to_tooltip_date(t_point, cfg["time_label"]))
                wave = 0.18 + 0.82 * math.sin(math.pi * i / max(1, n - 1))
                values.append(int(max(1024 * 512, current_used_bytes * wave)))
            total_period = current_used_bytes

        formatted_vals = [format_bytes(v) for v in values]

        result[key] = {
            "x_labels": [axis_labels[len(axis_labels) // 2], axis_labels[-1]],
            "tooltip_dates": tooltip_dates,
            "values": values,
            "formatted_values": formatted_vals,
            "total_str": format_bytes(total_period)
        }
    return result

def fix_b64_padding(s: str) -> str:
    s = s.strip().replace("\r", "").replace("\n", "").replace(" ", "")
    return s + "=" * ((4 - len(s) % 4) % 4)

def transform_config_name(original_name: str) -> tuple[str, str]:
    name = original_name.strip()
    if not name:
        return "🌐", "Server"

    # تشخیص کانفیگ VIP (معمولی یا یونیکد بولد 𝗩𝗜𝗣) و تبدیل به VIP خالی
    if "VIP" in name.upper() or "𝗩𝗜𝗣" in name:
        return "👋", "VIP"

    # تبدیل فقط کلمه "ویژه" به "Stable" با حفظ بقیه ساختار اسم اصلی
    if "ویژه" in name:
        name = name.replace("ویژه", "Stable")

    # استخراج ایموجی یا پرچم ابتدای نام برای نمایش زیبا در کارت
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

# ----------------- رندرینگ صفحات HTML -----------------
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
        <h2 class="text-xl font-bold mb-6 text-center">ورود به پنل مدیریت ساب‌اسکریپشن</h2>
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
        Powered by <a href="https://t.me/DARK_WIKI" target="_blank" class="text-blue-400 hover:underline font-semibold">@DARK_WIKI</a>
    </div>
</body>
</html>"""

def render_admin_html(profiles, domain: str) -> str:
    rows = ""
    for p in profiles:
        status_badge = (
            '<span class="inline-flex items-center whitespace-nowrap px-3 py-1 rounded-full text-xs font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">مسدود (بلاک)</span>'
            if p["is_blocked"] else
            '<span class="inline-flex items-center whitespace-nowrap px-3 py-1 rounded-full text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">فعال</span>'
        )
        btn_class = "bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/20" if p["is_blocked"] else "bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/20"
        btn_text = "رفع بلاک" if p["is_blocked"] else "بلاک کردن"
        rows += f"""
        <tr class="hover:bg-slate-800/40 transition-colors">
            <td class="p-4 font-bold whitespace-nowrap">{p['name']}</td>
            <td class="p-4 whitespace-nowrap"><a href="/d/{p['token']}" target="_blank" class="text-blue-400 hover:underline text-xs font-mono" dir="ltr">https://{domain}/d/{p['token']}</a></td>
            <td class="p-4 whitespace-nowrap"><span class="text-slate-300 text-xs font-mono select-all" dir="ltr">https://{domain}/sub/{p['token']}</span></td>
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
        rows = '<tr><td colspan="5" class="p-8 text-center text-slate-500 text-xs">هنوز پروفایلی ساخته نشده است.</td></tr>'

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
                <h1 class="text-2xl font-bold">کنترل پنل مدیریت ساب‌اسکریپشن</h1>
                <p class="text-xs text-slate-400 mt-1">دامنه فعال: <span class="font-mono text-blue-400" dir="ltr">{domain}</span></p>
            </div>
            <a href="/admin/logout" class="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-xl text-xs font-semibold transition-colors">خروج</a>
        </div>

        <div class="bg-slate-900 p-6 rounded-3xl border border-slate-800 shadow-sm">
            <h2 class="text-base font-bold mb-4 flex items-center gap-2"><span>➕</span> تعریف پروفایل / مشتری جدید</h2>
            <form action="/admin/profiles/add" method="post" class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                    <label class="block text-xs text-slate-400 mb-1.5">نام پروفایل (نمایش در بالای داشبورد)</label>
                    <input type="text" name="name" placeholder="مثلاً: VIP" required class="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1.5">لینک ساب اصلی فروشنده</label>
                    <input type="url" name="upstream_url" placeholder="https://seller.com/sub/..." required class="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500 text-left font-mono" dir="ltr">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1.5">شناسه اختصاصی لینک (اختیاری)</label>
                    <div class="flex gap-2">
                        <input type="text" name="custom_token" placeholder="خالی = تصادفی" class="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500 text-left font-mono" dir="ltr">
                        <button type="submit" class="px-6 py-2.5 bg-blue-600 hover:bg-blue-500 font-bold rounded-xl text-sm shrink-0 transition-colors cursor-pointer">ثبت</button>
                    </div>
                </div>
            </form>
        </div>

        <div class="bg-slate-900 rounded-3xl border border-slate-800 overflow-hidden shadow-sm">
            <div class="p-6 border-b border-slate-800">
                <h2 class="text-base font-bold">پروفایل‌های موجود ({len(profiles)})</h2>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-right text-sm">
                    <thead class="bg-slate-950/60 text-slate-400 text-xs border-b border-slate-800">
                        <tr>
                            <th class="p-4 whitespace-nowrap">نام پروفایل</th>
                            <th class="p-4 whitespace-nowrap">لینک داشبورد وب</th>
                            <th class="p-4 whitespace-nowrap">لینک ساب کلاینت</th>
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
        Powered by <a href="https://t.me/DARK_WIKI" target="_blank" class="text-blue-400 hover:underline font-semibold">@DARK_WIKI</a>
    </div>
</body>
</html>"""

def render_dashboard_html(ctx: dict) -> str:
    if ctx["is_blocked"]:
        main_section = """
        <div class="p-8 rounded-3xl border border-rose-500/30 bg-rose-500/5 mb-8 text-center shadow-lg">
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
            <div class="group relative p-3 rounded-lg border border-slate-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:border-[#4b85d1]/60 transition-all duration-200">
                <div class="flex items-center gap-2">
                    <div class="px-2 py-0.5 rounded text-[11px] font-semibold uppercase bg-[#4b85d1] text-white shrink-0">{c['proto']}</div>
                    <span class="text-sm">{c['icon']}</span>
                    <div dir="ltr" class="text-sm sm:text-base font-medium flex-1 min-w-0 truncate text-right text-slate-800 dark:text-slate-100">{c['name']}</div>
                    <div class="flex gap-1 shrink-0">
                        <button onclick="copyConfig({idx})" class="p-1.5 rounded transition-all cursor-pointer bg-slate-100 dark:bg-zinc-800 hover:bg-[#4b85d1] hover:text-white" title="کپی کانفیگ">
                            <svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"></rect><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"></path></svg>
                        </button>
                        <button onclick="showConfigQR({idx})" class="p-1.5 rounded bg-slate-100 dark:bg-zinc-800 hover:bg-slate-200 dark:hover:bg-zinc-700 transition-all cursor-pointer" title="کد QR">
                            <svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 12v4a1 1 0 0 1-1 1h-4"></path><path d="M17 3h2a2 2 0 0 1 2 2v2"></path><path d="M17 8V7"></path><path d="M21 17v2a2 2 0 0 1-2 2h-2"></path><path d="M3 7V5a2 2 0 0 1 2-2h2"></path><path d="M7 17h.01"></path><path d="M7 21H5a2 2 0 0 1-2-2v-2"></path><rect x="7" y="7" width="5" height="5" rx="1"></rect></svg>
                        </button>
                    </div>
                </div>
            </div>"""

        main_section = f"""
        <!-- اعلان -->
        <div class="mb-6 sm:mb-8">
            <div class="p-4 rounded-2xl border bg-gradient-to-r from-[#4b85d1]/15 to-[#4b85d1]/5 border-[#4b85d1]/25 hover:shadow-lg transition-all duration-300">
                <div class="flex items-start gap-3">
                    <div class="shrink-0 mt-0.5 text-[#4b85d1]">
                        <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.268 21a2 2 0 0 0 3.464 0"></path><path d="M3.262 15.326A1 1 0 0 0 4 17h16a1 1 0 0 0 .74-1.673C19.41 13.956 18 12.499 18 8A6 6 0 0 0 6 8c0 4.499-1.411 5.956-2.738 7.326"></path></svg>
                    </div>
                    <div class="flex-1 min-w-0">
                        <div class="text-sm font-semibold mb-1">اعلان</div>
                        <p class="text-xs sm:text-sm text-slate-600 dark:text-zinc-400">لطفا قبل از اتصال لینک ساب را آپدیت کنید</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- کارت وضعیت و ۳ کارت کناری -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-4 sm:gap-6 mb-8">
            <div class="lg:col-span-2 relative p-6 sm:p-8 rounded-2xl sm:rounded-3xl border border-slate-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-lg flex flex-col justify-between">
                <div class="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4 mb-6">
                    <div class="flex-1">
                        <div class="flex items-center gap-2 sm:gap-3">
                            <span class="text-2xl sm:text-3xl lg:text-4xl font-bold text-green-500">فعال</span>
                            <div class="w-2.5 h-2.5 sm:w-3 sm:h-3 rounded-full bg-green-500 animate-pulse"></div>
                        </div>
                    </div>
                    <div>
                        <div class="text-xs sm:text-sm text-slate-500 dark:text-zinc-400">منقضی می‌شود در</div>
                        <p class="text-xl sm:text-2xl font-bold mt-0.5">{ctx['days_left']} روز</p>
                    </div>
                </div>

                <div class="flex flex-col sm:flex-row items-center gap-6 sm:gap-8">
                    <div class="relative w-32 h-32 sm:w-36 sm:h-36 lg:w-40 lg:h-40 shrink-0">
                        <svg class="transform -rotate-90 w-full h-full">
                            <circle cx="50%" cy="50%" r="45%" stroke="currentColor" stroke-width="12" fill="none" class="text-slate-200/70 dark:text-zinc-800"></circle>
                            <circle cx="50%" cy="50%" r="45%" stroke="currentColor" stroke-width="12" fill="none"
                                stroke-dasharray="440" stroke-dashoffset="{ctx['dashoffset']}"
                                class="text-green-500 transition-all duration-1000 ease-out" stroke-linecap="round"></circle>
                        </svg>
                        <div class="absolute inset-0 flex flex-col items-center justify-center">
                            <span class="text-2xl sm:text-3xl font-bold">{ctx['percent']}%</span>
                            <span class="text-xs sm:text-sm text-slate-500 dark:text-zinc-400">مصرف شده</span>
                        </div>
                    </div>

                    <div class="flex-1 w-full space-y-4 sm:space-y-5">
                        <div class="flex justify-between items-center">
                            <span class="text-sm text-slate-500 dark:text-zinc-400">حجم سرویس</span>
                            <span dir="ltr" class="text-base sm:text-lg font-semibold">{ctx['total_quota']}</span>
                        </div>
                        <div class="flex justify-between items-center">
                            <span class="text-sm text-slate-500 dark:text-zinc-400">حجم مصرفی</span>
                            <span dir="ltr" class="text-base sm:text-lg font-semibold">{ctx['used_traffic']}</span>
                        </div>
                        <div class="flex justify-between items-center">
                            <span class="text-sm text-slate-500 dark:text-zinc-400">حجم باقی مانده</span>
                            <span dir="ltr" class="text-base sm:text-lg font-semibold text-green-600 dark:text-green-500">{ctx['remaining_traffic']}</span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-1 gap-4 sm:gap-6">
                <div class="p-4 sm:p-6 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-sm flex flex-col justify-center">
                    <div class="text-sm text-slate-500 dark:text-zinc-400 mb-2">حجم کل</div>
                    <div dir="ltr" class="text-xl sm:text-3xl font-bold text-right">{ctx['used_traffic']}</div>
                </div>
                <div class="p-4 sm:p-6 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-sm flex flex-col justify-center">
                    <div class="text-sm text-slate-500 dark:text-zinc-400 mb-2">تاریخ انقضا</div>
                    <div dir="ltr" class="text-base sm:text-lg font-semibold text-right">{ctx['expire_date']}</div>
                </div>
                <div class="p-4 sm:p-6 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-sm flex flex-col justify-center">
                    <div class="text-sm text-slate-500 dark:text-zinc-400 mb-2">آخرین اتصال</div>
                    <div dir="ltr" class="flex items-center justify-end gap-2">
                        <span class="text-sm font-medium">{ctx['now_jalali']}</span>
                        <span class="w-2.5 h-2.5 rounded-full bg-slate-400 dark:bg-zinc-500"></span>
                    </div>
                </div>
            </div>
        </div>

        <!-- بخش دو ستونی: لینک کانفیگ‌ها و نمودار آمار مصرف -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 sm:gap-8 w-full py-4">
            <!-- ستون لینک کانفیگ‌ها -->
            <div class="order-2 lg:order-1 space-y-3">
                <div class="flex items-center justify-between">
                    <h2 class="text-lg sm:text-xl font-bold flex items-center gap-2">
                        <span class="text-xl">🔗</span>لینک کانفیگ ها
                    </h2>
                    <button onclick="copyAll()" class="group cursor-pointer flex items-center gap-2 px-3 py-1.5 text-sm rounded-lg transition-all duration-200 hover:scale-105 active:scale-95 bg-[#4b85d1] text-white hover:opacity-90 shadow-sm">
                        <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 2a2 2 0 0 1 1.414.586l4 4A2 2 0 0 1 21 8v7a2 2 0 0 1-2 2h-8a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2z"></path><path d="M15 2v4a2 2 0 0 0 2 2h4"></path><path d="M5 7a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h8a2 2 0 0 0 1.732-1"></path></svg>
                        <span>کپی همه کانفیگ‌ها</span>
                    </button>
                </div>

                <div class="max-h-[400px] overflow-y-auto space-y-2">
                    <!-- لینک اشتراک اصلی -->
                    <div class="group relative p-3 rounded-lg border-2 border-[#4b85d1]/40 bg-[#4b85d1]/10 hover:border-[#4b85d1]/70 transition-all duration-200">
                        <div class="flex items-center gap-2">
                            <div class="px-2 py-0.5 rounded text-xs font-semibold bg-[#4b85d1] text-white shrink-0">SUB</div>
                            <span class="text-sm">📱</span>
                            <div class="text-sm sm:text-base font-medium flex-1 min-w-0 truncate">لینک اشتراک</div>
                            <div class="flex gap-1 shrink-0">
                                <button onclick="copySubUrl()" class="p-1.5 rounded transition-all cursor-pointer bg-slate-200/80 dark:bg-zinc-800 hover:bg-[#4b85d1] hover:text-white" title="کپی لینک">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"></rect><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"></path></svg>
                                </button>
                                <button onclick="showSubQR()" class="p-1.5 rounded bg-slate-200/80 dark:bg-zinc-800 hover:bg-slate-300 dark:hover:bg-zinc-700 transition-all cursor-pointer" title="کد QR">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 12v4a1 1 0 0 1-1 1h-4"></path><path d="M17 3h2a2 2 0 0 1 2 2v2"></path><path d="M17 8V7"></path><path d="M21 17v2a2 2 0 0 1-2 2h-2"></path><path d="M3 7V5a2 2 0 0 1 2-2h2"></path><path d="M7 17h.01"></path><path d="M7 21H5a2 2 0 0 1-2-2v-2"></path><rect x="7" y="7" width="5" height="5" rx="1"></rect></svg>
                                </button>
                            </div>
                        </div>
                    </div>
                    {conf_items}
                </div>
            </div>

            <!-- ستون نمودار آمار مصرف با تولتیپ شناور نرم -->
            <div class="order-1 lg:order-2">
                <div class="bg-white dark:bg-[#161618] flex flex-col gap-6 rounded-xl border border-slate-200/80 dark:border-zinc-800/90 py-6 shadow-sm overflow-hidden">
                    <div class="px-6 flex flex-col gap-4 border-b border-slate-200/70 dark:border-zinc-800 pb-4">
                        <div class="flex flex-wrap items-center justify-between w-full">
                            <div class="text-lg sm:text-xl font-bold">آمار مصرف</div>
                            <div class="flex items-center gap-2 text-sm font-semibold text-[#4b85d1]">
                                <span id="chartTotalBadge" dir="ltr" class="font-semibold">{ctx['used_traffic']}</span>
                            </div>
                        </div>
                        <div class="flex flex-wrap gap-2">
                            <button onclick="switchPeriod('1h')" id="tab-1h" class="period-btn px-3 py-1.5 text-sm font-medium rounded-lg transition-all cursor-pointer bg-slate-100 dark:bg-zinc-800/90 text-slate-500 dark:text-zinc-400">۱ ساعت</button>
                            <button onclick="switchPeriod('12h')" id="tab-12h" class="period-btn px-3 py-1.5 text-sm font-medium rounded-lg transition-all cursor-pointer bg-slate-100 dark:bg-zinc-800/90 text-slate-500 dark:text-zinc-400">۱۲ ساعت</button>
                            <button onclick="switchPeriod('24h')" id="tab-24h" class="period-btn px-3 py-1.5 text-sm font-medium rounded-lg transition-all cursor-pointer bg-slate-100 dark:bg-zinc-800/90 text-slate-500 dark:text-zinc-400">۲۴ ساعت</button>
                            <button onclick="switchPeriod('7d')" id="tab-7d" class="period-btn px-3 py-1.5 text-sm font-medium rounded-lg transition-all cursor-pointer bg-[#4b85d1] text-white shadow-sm">۷ روز</button>
                            <button onclick="switchPeriod('30d')" id="tab-30d" class="period-btn px-3 py-1.5 text-sm font-medium rounded-lg transition-all cursor-pointer bg-slate-100 dark:bg-zinc-800/90 text-slate-500 dark:text-zinc-400">۳۰ روز</button>
                            <button onclick="switchPeriod('90d')" id="tab-90d" class="period-btn px-3 py-1.5 text-sm font-medium rounded-lg transition-all cursor-pointer bg-slate-100 dark:bg-zinc-800/90 text-slate-500 dark:text-zinc-400">۹۰ روز</button>
                        </div>
                    </div>

                    <div class="px-2 sm:px-6 pt-2">
                        <div id="chartContainer" class="relative h-[250px] w-full select-none cursor-crosshair">
                            <svg id="usageSvg" viewBox="0 0 558 250" class="w-full h-full overflow-visible">
                                <defs>
                                    <linearGradient id="fillTraffic" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stop-color="#4b85d1" stop-opacity="0.75"></stop>
                                        <stop offset="95%" stop-color="#4b85d1" stop-opacity="0.06"></stop>
                                    </linearGradient>
                                </defs>
                                <!-- خطوط افقی نقطه‌چین -->
                                <g stroke="currentColor" class="text-slate-200 dark:text-zinc-800/80" stroke-dasharray="3 3" stroke-width="1">
                                    <line x1="0" y1="10" x2="558" y2="10"></line>
                                    <line x1="0" y1="62.5" x2="558" y2="62.5"></line>
                                    <line x1="0" y1="115" x2="558" y2="115"></line>
                                    <line x1="0" y1="167.5" x2="558" y2="167.5"></line>
                                    <line x1="0" y1="220" x2="558" y2="220"></line>
                                </g>
                                <!-- منحنی و مساحت -->
                                <path id="chartAreaPath" fill="url(#fillTraffic)" fill-opacity="0.6" d=""></path>
                                <path id="chartLinePath" fill="none" stroke="#4b85d1" stroke-width="2" d=""></path>

                                <!-- نقطه هاور روی نمودار -->
                                <circle id="hoverDot" cx="279" cy="13.5" r="4.5" fill="#4b85d1" stroke="#161618" stroke-width="2" class="opacity-0 transition-opacity duration-200 pointer-events-none"></circle>

                                <!-- برچسب‌های محور افقی -->
                                <text id="xLabelMid" x="279" y="240" font-size="11" text-anchor="middle" fill="currentColor" class="text-slate-400 dark:text-zinc-400"></text>
                                <text id="xLabelEnd" x="542" y="240" font-size="11" text-anchor="middle" fill="currentColor" class="text-slate-400 dark:text-zinc-400"></text>
                            </svg>

                            <!-- باکس تولتیپ شناور (Smooth Moving Tooltip) -->
                            <div id="chartTooltip" class="pointer-events-none absolute top-0 left-0 opacity-0 transition-opacity duration-200 z-20 bg-[#18181b]/95 dark:bg-[#121214]/95 text-white border border-zinc-700/70 rounded-xl px-4 py-2.5 shadow-2xl min-w-[145px]" style="will-change: transform;">
                                <div id="tooltipDate" class="text-xs text-zinc-400 text-right mb-1 font-medium">۱۴۰۵/۰۷/۲۲</div>
                                <div class="text-xs sm:text-sm font-bold text-right flex items-center justify-end gap-1.5 whitespace-nowrap">
                                    <span>مصرف کل:</span>
                                    <span id="tooltipValue" dir="ltr" class="font-mono">0.00 MB</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- جداکننده اپلیکیشن‌ها -->
        <div class="my-8 sm:my-12">
            <div class="flex items-center gap-4">
                <div class="flex-1 h-px bg-gradient-to-r from-transparent via-slate-300 dark:via-zinc-800 to-transparent"></div>
                <div class="px-4 py-2 rounded-full bg-gradient-to-r from-[#4b85d1]/15 to-[#4b85d1]/5 text-sm font-medium text-[#4b85d1] border border-[#4b85d1]/25 hover:scale-105 transition-all duration-300">
                    <span class="text-sm mr-2 animate-bounce inline-block">📱</span>اپلیکیشن‌ ها
                </div>
                <div class="flex-1 h-px bg-gradient-to-r from-transparent via-slate-300 dark:via-zinc-800 to-transparent"></div>
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
        .bg-grid-pattern {{
            background-image: linear-gradient(90deg, currentColor 1px, transparent 1px),
                              linear-gradient(currentColor 1px, transparent 1px);
            background-size: 40px 40px;
        }}
    </style>
</head>
<body class="bg-[#f4f5f7] dark:bg-[#111113] text-slate-800 dark:text-slate-100 min-h-screen flex flex-col justify-between overflow-x-hidden">
    <div class="fixed inset-0 bg-grid-pattern opacity-[0.02] pointer-events-none"></div>

    <div class="container mx-auto px-4 pt-12 pb-6 max-w-7xl relative z-10 flex-1">
        <!-- هدر داشبورد -->
        <div class="flex sm:items-center sm:justify-between gap-4 mb-8 sm:mb-12">
            <div class="flex-1 min-w-0">
                <h1 class="text-3xl sm:text-4xl lg:text-5xl font-bold mb-2">داشبورد کاربری</h1>
                <div class="flex items-center gap-3 text-sm text-slate-500 dark:text-zinc-400">
                    <p dir="ltr" class="font-medium truncate">{ctx['brand_name']}</p>
                    <div class="flex items-center gap-1.5">
                        <div class="w-2.5 h-2.5 rounded-full bg-slate-400 dark:bg-zinc-500"></div>
                        <span>آنلاین</span>
                    </div>
                    <button onclick="location.reload()" class="hover:text-[#4b85d1] transition-colors cursor-pointer" title="Refresh data">
                        <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"></path><path d="M3 3v5h5"></path><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"></path><path d="M16 16h5v5"></path></svg>
                    </button>
                </div>
            </div>
            <div class="flex items-center gap-2">
                <button onclick="document.documentElement.classList.toggle('dark')" class="size-9 rounded-md border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xs hover:bg-slate-100 dark:hover:bg-zinc-800 flex items-center justify-center transition-colors cursor-pointer" title="تغییر تم">
                    <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2"></path><path d="M12 20v2"></path><path d="m4.93 4.93 1.41 1.41"></path><path d="m17.66 17.66 1.41 1.41"></path><path d="M2 12h2"></path><path d="M20 12h2"></path><path d="m6.34 17.66-1.41 1.41"></path><path d="m19.07 4.93-1.41 1.41"></path></svg>
                </button>
            </div>
        </div>

        {main_section}
    </div>

    <!-- فوتر -->
    <div dir="ltr" class="relative w-full pb-8 pt-6 px-6 z-10">
        <div class="container mx-auto max-w-7xl flex justify-center">
            <div class="flex flex-col items-center gap-3">
                <a href="https://t.me/DARK_WIKI" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-2 text-sm text-[#4b85d1] hover:opacity-80 transition-opacity font-medium">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 5.636l-3.536 3.536m0 5.656l3.536 3.536M9.172 9.172L5.636 5.636m3.536 9.192l-3.536 3.536M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-5 0a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
                    پشتیبانی
                </a>
                <div class="bg-slate-300 dark:bg-zinc-800 h-px w-16"></div>
                <p class="inline-block text-center text-sm text-slate-500 dark:text-zinc-400">
                    Powered by <a class="text-[#4b85d1] font-semibold hover:underline" href="https://t.me/DARK_WIKI" target="_blank" rel="noopener noreferrer">@DARK_WIKI</a>
                </p>
            </div>
        </div>
    </div>

    <!-- Toast Notification -->
    <div id="toastBox" class="fixed bottom-5 left-1/2 -translate-x-1/2 z-50 hidden px-4 py-2.5 rounded-xl bg-slate-900 dark:bg-white text-white dark:text-slate-900 text-xs font-bold shadow-xl"></div>

    <!-- مودال نمایش QR Code -->
    <div id="qrModal" class="fixed inset-0 bg-black/60 backdrop-blur-xs hidden items-center justify-center z-50 p-4" onclick="closeQR()">
        <div class="bg-white dark:bg-zinc-900 p-6 rounded-3xl shadow-xl max-w-xs w-full flex flex-col items-center text-center border border-slate-100 dark:border-zinc-800" onclick="event.stopPropagation()">
            <h3 class="font-bold text-sm mb-4">اسکن کد QR</h3>
            <img id="qrImage" src="" alt="QR Code" class="w-52 h-52 rounded-xl mb-4 border border-slate-100 dark:border-zinc-800 p-2 bg-white">
            <button onclick="closeQR()" class="w-full py-2.5 bg-slate-100 dark:bg-zinc-800 hover:bg-slate-200 dark:hover:bg-zinc-700 text-xs font-semibold rounded-xl transition-colors cursor-pointer">بستن</button>
        </div>
    </div>

    <script>
        const subUrl = {json.dumps(ctx['sub_url'])};
        const allConfigs = {ctx['configs_json']};
        const chartDatasets = {ctx['chart_json']};
        let activePeriod = "7d";

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

        // منحنی دقیق مشابه تصویر نمونه با 3 نقطه کلیدی (چپ، قله وسط، راست)
        function evalArchCurve(t, yStart, yPeak, yEnd) {{
            if (t <= 0.5) {{
                const u = t * 2;
                const ease = u * u * (3 - 2 * u);
                return yStart + (yPeak - yStart) * ease;
            }} else {{
                const u = (t - 0.5) * 2;
                const ease = u * u * (3 - 2 * u);
                return yPeak + (yEnd - yPeak) * ease;
            }}
        }}

        let currentCurveParams = {{ yStart: 185, yPeak: 14, yEnd: 195 }};

        function switchPeriod(periodKey) {{
            activePeriod = periodKey;
            const data = chartDatasets[periodKey];
            if (!data) return;

            document.querySelectorAll(".period-btn").forEach(btn => {{
                btn.className = "period-btn px-3 py-1.5 text-sm font-medium rounded-lg transition-all cursor-pointer bg-slate-100 dark:bg-zinc-800/90 text-slate-500 dark:text-zinc-400";
            }});
            const activeBtn = document.getElementById("tab-" + periodKey);
            if (activeBtn) {{
                activeBtn.className = "period-btn px-3 py-1.5 text-sm font-medium rounded-lg transition-all cursor-pointer bg-[#4b85d1] text-white shadow-sm";
            }}

            document.getElementById("chartTotalBadge").textContent = data.total_str;
            document.getElementById("xLabelMid").textContent = data.x_labels[0] || "";
            document.getElementById("xLabelEnd").textContent = data.x_labels[1] || "";

            const lineD = "M0,185 C93,99.25 186,14 279,14 C372,14 465,105 558,195";
            const areaD = lineD + " L558,220 L0,220 Z";

            document.getElementById("chartLinePath").setAttribute("d", lineD);
            document.getElementById("chartAreaPath").setAttribute("d", areaD);
        }}

        // انیمیشن Smooth Lerp برای تولتیپ و نقطه روی نمودار
        const container = document.getElementById("chartContainer");
        const tooltip = document.getElementById("chartTooltip");
        const hoverDot = document.getElementById("hoverDot");
        const tooltipDate = document.getElementById("tooltipDate");
        const tooltipValue = document.getElementById("tooltipValue");

        let targetX = 279, targetY = 14;
        let currentX = 279, currentY = 14;
        let isHovering = false;

        function animateTooltip() {{
            if (isHovering && container && tooltip && hoverDot) {{
                currentX += (targetX - currentX) * 0.18;
                currentY += (targetY - currentY) * 0.18;

                hoverDot.setAttribute("cx", currentX.toFixed(1));
                hoverDot.setAttribute("cy", currentY.toFixed(1));

                const rect = container.getBoundingClientRect();
                const scaleX = rect.width / 558;
                const scaleY = rect.height / 250;

                let pixelX = currentX * scaleX + 16;
                let pixelY = currentY * scaleY + 18;

                if (pixelX + 160 > rect.width) {{
                    pixelX = currentX * scaleX - 165;
                }}
                if (pixelY + 70 > rect.height) {{
                    pixelY = currentY * scaleY - 68;
                }}

                tooltip.style.transform = `translate3d(${{pixelX.toFixed(1)}}px, ${{pixelY.toFixed(1)}}px, 0)`;
            }}
            requestAnimationFrame(animateTooltip);
        }}

        if (container) {{
            switchPeriod("7d");
            requestAnimationFrame(animateTooltip);

            const handleMove = (clientX) => {{
                const rect = container.getBoundingClientRect();
                let relX = (clientX - rect.left) / rect.width;
                relX = Math.max(0, Math.min(1, relX));

                targetX = relX * 558;
                targetY = evalArchCurve(relX, currentCurveParams.yStart, currentCurveParams.yPeak, currentCurveParams.yEnd);

                const data = chartDatasets[activePeriod];
                if (data && data.tooltip_dates.length > 0) {{
                    const idx = Math.min(data.tooltip_dates.length - 1, Math.floor(relX * data.tooltip_dates.length));
                    tooltipDate.textContent = data.tooltip_dates[idx];
                    tooltipValue.textContent = data.formatted_values[idx];
                }}

                if (!isHovering) {{
                    isHovering = true;
                    currentX = targetX;
                    currentY = targetY;
                    tooltip.classList.remove("opacity-0");
                    tooltip.classList.add("opacity-100");
                    hoverDot.classList.remove("opacity-0");
                    hoverDot.classList.add("opacity-100");
                }}
            }};

            container.addEventListener("mousemove", (e) => handleMove(e.clientX));
            container.addEventListener("touchmove", (e) => {{
                if (e.touches.length > 0) handleMove(e.touches[0].clientX);
            }});
            container.addEventListener("mouseleave", () => {{
                isHovering = false;
                tooltip.classList.remove("opacity-100");
                tooltip.classList.add("opacity-0");
                hoverDot.classList.remove("opacity-100");
                hoverDot.classList.add("opacity-0");
            }});
        }}
    </script>
</body>
</html>"""

# ----------------- مسیرها (Routes) -----------------
@app.get("/")
async def root():
    return RedirectResponse(url="/admin")

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
        user_info = headers.get("subscription-userinfo", "")
        info = parse_user_info(user_info)
        if "upload" in info or "download" in info:
            record_usage_snapshot(token, info.get("upload", 0) + info.get("download", 0))
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
            configs, _ = parse_and_modify_configs(raw_text)
            upload = info.get("upload", 0)
            download = info.get("download", 0)
            total_quota = info.get("total", 0)
            expire_ts = info.get("expire", 0)
            if upload + download > 0:
                record_usage_snapshot(token, upload + download)
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

    chart_datasets = build_chart_datasets(token, used_traffic)

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
        "configs_json": json.dumps([c["link"] for c in configs]),
        "chart_json": json.dumps(chart_datasets)
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

    token = custom_token if custom_token else secrets.token_hex(6)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    if name and upstream_url:
        with get_db() as conn:
            try:
                conn.execute(
                    "INSERT INTO profiles (token, name, upstream_url, is_blocked, created_at) VALUES (?, ?, ?, 0, ?)",
                    (token, name, upstream_url, created_at)
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
        conn.execute("DELETE FROM usage_logs WHERE token = ?", (token,))
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
            caption = "هیچ پروفایلی در سیستم ثبت نشده است.\n\nPowered by @DARK_WIKI"
        else:
            try:
                raw_text, headers = await fetch_upstream(profile["token"], profile["upstream_url"])
                info = parse_user_info(headers.get("subscription-userinfo", ""))
                used_gb = (info.get("upload", 0) + info.get("download", 0)) / (1024**3)
                total_gb = info.get("total", 0) / (1024**3)
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
                f"🔗 لینک ساب:\n`{sub_link}`\n\n"
                f"⚡ Powered by @DARK_WIKI"
            )

        async with httpx.AsyncClient() as client:
            await client.post(
                f"{TELEGRAM_API}/sendMessage",
                json={"chat_id": chat_id, "text": caption, "parse_mode": "Markdown"}
            )

    return Response(status_code=200)
