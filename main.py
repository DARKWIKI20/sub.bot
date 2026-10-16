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

BRAND_DEFAULT = os.getenv("BRAND_NAME", "VIP-NET")
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

def ts_to_jalali_label(ts: int, include_time: bool = False) -> str:
    dt = datetime.fromtimestamp(ts)
    _, jm, jd = gregorian_to_jalali(dt.year, dt.month, dt.day)
    if include_time:
        return f"{dt.strftime('%H:%M')}"
    return f"{jd} {JALALI_MONTHS[jm]}"

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
        "1h":  {"sec": 3600,       "points": 6, "time_label": True},
        "12h": {"sec": 12 * 3600,  "points": 6, "time_label": True},
        "24h": {"sec": 24 * 3600,  "points": 6, "time_label": True},
        "7d":  {"sec": 7 * 86400,  "points": 7, "time_label": False},
        "30d": {"sec": 30 * 86400, "points": 6, "time_label": False},
        "90d": {"sec": 90 * 86400, "points": 6, "time_label": False},
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

        labels = []
        values = []

        if len(filtered) >= 2:
            for i in range(n):
                t_point = start_ts + i * step
                labels.append(ts_to_jalali_label(t_point, cfg["time_label"]))
                closest = min(filtered, key=lambda r: abs(r["ts"] - t_point))
                values.append(max(0, closest["used_bytes"]))
            diffs = [max(0, values[i] - values[i - 1]) for i in range(1, len(values))]
            diffs.insert(0, max(0, values[0] - filtered[0]["used_bytes"]) if filtered else 0)
            if sum(diffs) == 0:
                diffs = [int(current_used_bytes * r) for r in (0.15, 0.45, 0.85, 1.0, 0.65, 0.35, 0.5)[:n]]
            total_period = max(0, filtered[-1]["used_bytes"] - filtered[0]["used_bytes"])
            if total_period == 0:
                total_period = current_used_bytes
        else:
            curve_ratios = [0.2, 0.55, 0.95, 0.85, 0.5, 0.3, 0.45]
            diffs = []
            for i in range(n):
                t_point = start_ts + i * step
                labels.append(ts_to_jalali_label(t_point, cfg["time_label"]))
                ratio = curve_ratios[i % len(curve_ratios)]
                diffs.append(int(max(1024 * 1024, current_used_bytes * ratio)))
            total_period = current_used_bytes

        result[key] = {
            "labels": [labels[0], labels[len(labels) // 2], labels[-1]],
            "values": diffs,
            "total_str": format_bytes(total_period)
        }
    return result

def fix_b64_padding(s: str) -> str:
    s = s.strip().replace("\r", "").replace("\n", "").replace(" ", "")
    return s + "=" * ((4 - len(s) % 4) % 4)

def parse_and_modify_configs(raw_text: str, brand_name: str):
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
        custom_name = f"{brand_name} | سرور {idx:02d}"
        proto = line.split("://")[0].lower() if "://" in line else "vpn"

        if line.startswith(("vless://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")):
            base_part = line.split("#")[0]
            new_link = f"{base_part}#{urllib.parse.quote(custom_name)}"
            configs.append({"proto": proto, "name": custom_name, "link": new_link})
            modified_raw_lines.append(new_link)
        elif line.startswith("vmess://"):
            try:
                b64_part = fix_b64_padding(line[8:])
                conf = json.loads(base64.b64decode(b64_part).decode("utf-8", errors="ignore"))
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
            <button type="submit" class="w-full py-3 bg-blue-600 hover:bg-blue-500 font-bold rounded-xl text-sm transition-colors shadow-lg">ورود به پنل</button>
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
                        <button type="submit" class="whitespace-nowrap px-3 py-1.5 rounded-xl text-xs font-semibold transition-colors {btn_class}">{btn_text}</button>
                    </form>
                    <form action="/admin/profiles/{p['token']}/delete" method="post" class="m-0" onsubmit="return confirm('آیا از حذف این پروفایل اطمینان دارید؟');">
                        <button type="submit" class="whitespace-nowrap px-3 py-1.5 rounded-xl text-xs font-semibold bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 transition-colors">حذف</button>
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
                    <label class="block text-xs text-slate-400 mb-1.5">نام یا برند اختصاصی</label>
                    <input type="text" name="name" placeholder="مثلاً: DARK_WIKI VIP" required class="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1.5">لینک ساب اصلی فروشنده</label>
                    <input type="url" name="upstream_url" placeholder="https://seller.com/sub/..." required class="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500 text-left font-mono" dir="ltr">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1.5">شناسه اختصاصی (اختیاری)</label>
                    <div class="flex gap-2">
                        <input type="text" name="custom_token" placeholder="خالی = تصادفی" class="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500 text-left font-mono" dir="ltr">
                        <button type="submit" class="px-6 py-2.5 bg-blue-600 hover:bg-blue-500 font-bold rounded-xl text-sm shrink-0 transition-colors">ثبت</button>
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
            <div class="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-rose-500/10 text-rose-500 text-sm font-bold mb-3 border border-rose-500/20">
                <span class="w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping"></span> مسدود شده
            </div>
            <div class="text-2xl sm:text-3xl font-bold text-rose-500 mb-2">اشتراک شما مسدود شده است</div>
            <p class="text-sm text-slate-500 dark:text-zinc-400">دسترسی این اشتراک توسط پشتیبانی غیرفعال شده است.</p>
        </div>"""
    else:
        conf_items = ""
        for idx, c in enumerate(ctx["configs"]):
            conf_items += f"""
            <div class="group relative p-3 rounded-xl border border-slate-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:border-blue-500/50 transition-all duration-200">
                <div class="flex items-center gap-2.5">
                    <div class="px-2 py-0.5 rounded text-[11px] font-bold uppercase bg-blue-600 text-white shrink-0">{c['proto']}</div>
                    <span class="text-sm">🌐</span>
                    <div dir="ltr" class="text-sm font-medium flex-1 min-w-0 truncate text-right text-slate-700 dark:text-slate-200">{c['name']}</div>
                    <div class="flex gap-1.5 shrink-0">
                        <button onclick="copyConfig({idx})" class="p-1.5 rounded-lg transition-all cursor-pointer bg-slate-100 dark:bg-zinc-800 hover:bg-blue-600 hover:text-white" title="کپی کانفیگ">
                            <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"></rect><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"></path></svg>
                        </button>
                        <button onclick="showConfigQR({idx})" class="p-1.5 rounded-lg bg-slate-100 dark:bg-zinc-800 hover:bg-slate-200 dark:hover:bg-zinc-700 transition-all cursor-pointer" title="کد QR">
                            <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 12v4a1 1 0 0 1-1 1h-4"></path><path d="M17 3h2a2 2 0 0 1 2 2v2"></path><path d="M17 8V7"></path><path d="M21 17v2a2 2 0 0 1-2 2h-2"></path><path d="M3 7V5a2 2 0 0 1 2-2h2"></path><path d="M7 17h.01"></path><path d="M7 21H5a2 2 0 0 1-2-2v-2"></path><rect x="7" y="7" width="5" height="5" rx="1"></rect></svg>
                        </button>
                    </div>
                </div>
            </div>"""

        main_section = f"""
        <!-- اعلان -->
        <div class="mb-6 sm:mb-8">
            <div class="p-4 rounded-2xl border bg-gradient-to-r from-blue-600/10 to-blue-600/5 border-blue-600/20 hover:shadow-md transition-all duration-300">
                <div class="flex items-start gap-3">
                    <div class="shrink-0 mt-0.5 text-blue-600 dark:text-blue-400">
                        <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.268 21a2 2 0 0 0 3.464 0"></path><path d="M3.262 15.326A1 1 0 0 0 4 17h16a1 1 0 0 0 .74-1.673C19.41 13.956 18 12.499 18 8A6 6 0 0 0 6 8c0 4.499-1.411 5.956-2.738 7.326"></path></svg>
                    </div>
                    <div class="flex-1 min-w-0">
                        <div class="text-sm font-bold mb-1">اعلان</div>
                        <p class="text-xs sm:text-sm text-slate-600 dark:text-zinc-400">لطفاً قبل از اتصال لینک ساب را در کلاینت خود آپدیت کنید.</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- کارت وضعیت و ۳ کارت کناری -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-4 sm:gap-6 mb-8">
            <div class="lg:col-span-2 relative p-6 sm:p-8 rounded-3xl border border-slate-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-lg flex flex-col justify-between">
                <div class="flex flex-row items-start justify-between gap-4 mb-6">
                    <div class="flex items-center gap-2.5">
                        <span class="text-2xl sm:text-3xl lg:text-4xl font-bold text-emerald-500">فعال</span>
                        <span class="w-3 h-3 rounded-full bg-emerald-500 animate-pulse"></span>
                    </div>
                    <div class="text-left">
                        <div class="text-xs sm:text-sm text-slate-500 dark:text-zinc-400">منقضی می‌شود در</div>
                        <p class="text-xl sm:text-2xl font-bold mt-0.5">{ctx['days_left']} روز</p>
                    </div>
                </div>

                <div class="flex flex-col sm:flex-row items-center gap-6 sm:gap-8">
                    <div class="relative w-32 h-32 sm:w-36 sm:h-36 lg:w-40 lg:h-40 shrink-0">
                        <svg class="transform -rotate-90 w-full h-full">
                            <circle cx="50%" cy="50%" r="45%" stroke="currentColor" stroke-width="12" fill="none" class="text-slate-100 dark:text-zinc-800"></circle>
                            <circle cx="50%" cy="50%" r="45%" stroke="currentColor" stroke-width="12" fill="none"
                                stroke-dasharray="440" stroke-dashoffset="{ctx['dashoffset']}"
                                class="text-emerald-500 transition-all duration-1000 ease-out" stroke-linecap="round"></circle>
                        </svg>
                        <div class="absolute inset-0 flex flex-col items-center justify-center">
                            <span class="text-2xl sm:text-3xl font-bold">{ctx['percent']}%</span>
                            <span class="text-xs text-slate-500 dark:text-zinc-400">مصرف شده</span>
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
                            <span dir="ltr" class="text-base sm:text-lg font-semibold text-emerald-600 dark:text-emerald-500">{ctx['remaining_traffic']}</span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-1 gap-4 sm:gap-6">
                <div class="p-5 sm:p-6 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-sm flex flex-col justify-center">
                    <div class="text-xs sm:text-sm text-slate-500 dark:text-zinc-400 mb-2">حجم کل مصرفی</div>
                    <div dir="ltr" class="text-xl sm:text-2xl font-bold text-right">{ctx['used_traffic']}</div>
                </div>
                <div class="p-5 sm:p-6 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-sm flex flex-col justify-center">
                    <div class="text-xs sm:text-sm text-slate-500 dark:text-zinc-400 mb-2">تاریخ انقضا</div>
                    <div dir="ltr" class="text-base sm:text-lg font-semibold text-right">{ctx['expire_date']}</div>
                </div>
                <div class="p-5 sm:p-6 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-sm flex flex-col justify-center">
                    <div class="text-xs sm:text-sm text-slate-500 dark:text-zinc-400 mb-2">آخرین بروزرسانی</div>
                    <div dir="ltr" class="flex items-center justify-end gap-2">
                        <span class="text-sm font-medium">{ctx['now_jalali']}</span>
                        <span class="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
                    </div>
                </div>
            </div>
        </div>

        <!-- بخش دو ستونی: لینک کانفیگ‌ها و نمودار آمار مصرف -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 sm:gap-8 w-full">
            <!-- ستون لینک کانفیگ‌ها -->
            <div class="order-2 lg:order-1 space-y-3">
                <div class="flex items-center justify-between">
                    <h2 class="text-lg sm:text-xl font-bold flex items-center gap-2">
                        <span>🔗</span> لینک کانفیگ ها
                    </h2>
                    <button onclick="copyAll()" class="cursor-pointer flex items-center gap-2 px-3 py-1.5 text-xs sm:text-sm font-medium rounded-xl transition-all duration-200 hover:scale-105 bg-blue-600 text-white hover:bg-blue-500 shadow-sm">
                        <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 2a2 2 0 0 1 1.414.586l4 4A2 2 0 0 1 21 8v7a2 2 0 0 1-2 2h-8a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2z"></path><path d="M15 2v4a2 2 0 0 0 2 2h4"></path><path d="M5 7a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h8a2 2 0 0 0 1.732-1"></path></svg>
                        <span>کپی همه کانفیگ‌ها</span>
                    </button>
                </div>

                <div class="max-h-[400px] overflow-y-auto space-y-2 pr-1">
                    <!-- لینک اشتراک اصلی -->
                    <div class="p-3 rounded-xl border-2 border-blue-600/30 bg-blue-600/5 hover:border-blue-600/60 transition-all duration-200">
                        <div class="flex items-center gap-2.5">
                            <div class="px-2 py-0.5 rounded text-[11px] font-bold bg-blue-600 text-white shrink-0">SUB</div>
                            <span class="text-sm">📱</span>
                            <div class="text-sm font-semibold flex-1 min-w-0 truncate">لینک اشتراک</div>
                            <div class="flex gap-1.5 shrink-0">
                                <button onclick="copySubUrl()" class="p-1.5 rounded-lg transition-all cursor-pointer bg-slate-200/70 dark:bg-zinc-800 hover:bg-blue-600 hover:text-white" title="کپی لینک">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"></rect><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"></path></svg>
                                </button>
                                <button onclick="showSubQR()" class="p-1.5 rounded-lg bg-slate-200/70 dark:bg-zinc-800 hover:bg-slate-300 dark:hover:bg-zinc-700 transition-all cursor-pointer" title="کد QR">
                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 12v4a1 1 0 0 1-1 1h-4"></path><path d="M17 3h2a2 2 0 0 1 2 2v2"></path><path d="M17 8V7"></path><path d="M21 17v2a2 2 0 0 1-2 2h-2"></path><path d="M3 7V5a2 2 0 0 1 2-2h2"></path><path d="M7 17h.01"></path><path d="M7 21H5a2 2 0 0 1-2-2v-2"></path><rect x="7" y="7" width="5" height="5" rx="1"></rect></svg>
                                </button>
                            </div>
                        </div>
                    </div>
                    {conf_items}
                </div>
            </div>

            <!-- ستون نمودار آمار مصرف (۶ تب زمانی) -->
            <div class="order-1 lg:order-2">
                <div class="bg-white dark:bg-zinc-900 flex flex-col gap-5 rounded-2xl border border-slate-200/80 dark:border-zinc-800 py-6 shadow-sm overflow-hidden">
                    <div class="px-6 flex flex-col gap-4 border-b border-slate-100 dark:border-zinc-800 pb-4">
                        <div class="flex flex-wrap items-center justify-between w-full">
                            <div class="text-lg font-bold">آمار مصرف</div>
                            <div class="text-sm font-bold text-blue-600 dark:text-blue-400">
                                <span id="chartTotalBadge" dir="ltr">{ctx['used_traffic']}</span>
                            </div>
                        </div>
                        <div class="flex flex-wrap gap-1.5 sm:gap-2">
                            <button onclick="switchPeriod('1h')" id="tab-1h" class="period-btn px-3 py-1.5 text-xs sm:text-sm font-medium rounded-lg transition-all cursor-pointer bg-slate-100 dark:bg-zinc-800 text-slate-600 dark:text-zinc-400">۱ ساعت</button>
                            <button onclick="switchPeriod('12h')" id="tab-12h" class="period-btn px-3 py-1.5 text-xs sm:text-sm font-medium rounded-lg transition-all cursor-pointer bg-slate-100 dark:bg-zinc-800 text-slate-600 dark:text-zinc-400">۱۲ ساعت</button>
                            <button onclick="switchPeriod('24h')" id="tab-24h" class="period-btn px-3 py-1.5 text-xs sm:text-sm font-medium rounded-lg transition-all cursor-pointer bg-slate-100 dark:bg-zinc-800 text-slate-600 dark:text-zinc-400">۲۴ ساعت</button>
                            <button onclick="switchPeriod('7d')" id="tab-7d" class="period-btn px-3 py-1.5 text-xs sm:text-sm font-medium rounded-lg transition-all cursor-pointer bg-blue-600 text-white shadow-sm">۷ روز</button>
                            <button onclick="switchPeriod('30d')" id="tab-30d" class="period-btn px-3 py-1.5 text-xs sm:text-sm font-medium rounded-lg transition-all cursor-pointer bg-slate-100 dark:bg-zinc-800 text-slate-600 dark:text-zinc-400">۳۰ روز</button>
                            <button onclick="switchPeriod('90d')" id="tab-90d" class="period-btn px-3 py-1.5 text-xs sm:text-sm font-medium rounded-lg transition-all cursor-pointer bg-slate-100 dark:bg-zinc-800 text-slate-600 dark:text-zinc-400">۹۰ روز</button>
                        </div>
                    </div>

                    <div class="px-4 sm:px-6 pt-2">
                        <div class="relative h-[240px] w-full">
                            <svg id="usageSvg" viewBox="0 0 560 240" class="w-full h-full overflow-visible">
                                <defs>
                                    <linearGradient id="fillTraffic" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stop-color="#2563eb" stop-opacity="0.65"></stop>
                                        <stop offset="95%" stop-color="#2563eb" stop-opacity="0.05"></stop>
                                    </linearGradient>
                                </defs>
                                <g stroke="currentColor" class="text-slate-200 dark:text-zinc-800" stroke-dasharray="3 3" stroke-width="1">
                                    <line x1="0" y1="20" x2="560" y2="20"></line>
                                    <line x1="0" y1="67" x2="560" y2="67"></line>
                                    <line x1="0" y1="115" x2="560" y2="115"></line>
                                    <line x1="0" y1="162" x2="560" y2="162"></line>
                                    <line x1="0" y1="210" x2="560" y2="210"></line>
                                </g>
                                <path id="chartAreaPath" fill="url(#fillTraffic)" d=""></path>
                                <path id="chartLinePath" fill="none" stroke="#2563eb" stroke-width="2.5" stroke-linecap="round" d=""></path>
                                <text id="xLabelStart" x="35" y="232" font-size="11" text-anchor="middle" fill="currentColor" class="text-slate-400 dark:text-zinc-500"></text>
                                <text id="xLabelMid" x="280" y="232" font-size="11" text-anchor="middle" fill="currentColor" class="text-slate-400 dark:text-zinc-500"></text>
                                <text id="xLabelEnd" x="525" y="232" font-size="11" text-anchor="middle" fill="currentColor" class="text-slate-400 dark:text-zinc-500"></text>
                            </svg>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- جداکننده اپلیکیشن‌ها -->
        <div class="my-10 sm:my-12">
            <div class="flex items-center gap-4">
                <div class="flex-1 h-px bg-gradient-to-r from-transparent via-slate-300 dark:via-zinc-800 to-transparent"></div>
                <div class="px-4 py-2 rounded-full bg-gradient-to-r from-blue-600/10 to-blue-600/5 text-sm font-medium text-blue-600 dark:text-blue-400 border border-blue-600/20 flex items-center gap-2">
                    <span class="text-sm animate-bounce">📱</span> اپلیکیشن‌ ها
                </div>
                <div class="flex-1 h-px bg-gradient-to-r from-transparent via-slate-300 dark:via-zinc-800 to-transparent"></div>
            </div>
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6 max-w-3xl mx-auto text-center">
                <a href="https://github.com/2dust/v2rayNG/releases" target="_blank" class="p-3 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:border-blue-500/50 text-xs font-semibold transition-all">🤖 v2rayNG (اندروید)</a>
                <a href="https://apps.apple.com/app/streisand/id6450534064" target="_blank" class="p-3 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:border-blue-500/50 text-xs font-semibold transition-all">🍎 Streisand (آیفون)</a>
                <a href="https://github.com/2dust/v2rayN/releases" target="_blank" class="p-3 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:border-blue-500/50 text-xs font-semibold transition-all">💻 v2rayN (ویندوز)</a>
                <a href="https://github.com/hiddify/hiddify-next/releases" target="_blank" class="p-3 rounded-2xl border border-slate-200/80 dark:border-zinc-800 bg-white dark:bg-zinc-900 hover:border-blue-500/50 text-xs font-semibold transition-all">⚡ Hiddify Next</a>
            </div>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
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
<body class="bg-slate-100/70 dark:bg-zinc-950 text-slate-800 dark:text-slate-100 min-h-screen flex flex-col justify-between overflow-x-hidden">
    <div class="fixed inset-0 bg-grid-pattern opacity-[0.02] pointer-events-none"></div>

    <div class="container mx-auto px-4 pt-10 pb-6 max-w-7xl relative z-10 flex-1">
        <!-- هدر داشبورد -->
        <div class="flex items-center justify-between gap-4 mb-8 sm:mb-10">
            <div class="flex-1 min-w-0">
                <h1 class="text-3xl sm:text-4xl lg:text-5xl font-bold mb-2">داشبورد کاربری</h1>
                <div class="flex items-center gap-3 text-sm text-slate-500 dark:text-zinc-400">
                    <span dir="ltr" class="font-mono font-medium truncate">{ctx['brand_name']}</span>
                    <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
                    <button onclick="location.reload()" class="hover:text-blue-600 transition-colors cursor-pointer" title="بروزرسانی">🔄</button>
                </div>
            </div>
            <div class="flex items-center gap-2">
                <button onclick="document.documentElement.classList.toggle('dark')" class="size-9 rounded-lg border border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xs hover:bg-slate-50 dark:hover:bg-zinc-800 flex items-center justify-center transition-colors cursor-pointer" title="تغییر تم">
                    🌙
                </button>
            </div>
        </div>

        {main_section}
    </div>

    <!-- فوتر -->
    <footer dir="ltr" class="relative w-full pb-8 pt-4 px-6 z-10">
        <div class="container mx-auto max-w-7xl flex justify-center">
            <div class="flex flex-col items-center gap-2.5">
                <a href="https://t.me/DARK_WIKI" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-2 text-sm text-blue-600 dark:text-blue-400 hover:opacity-80 transition-opacity font-medium">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 5.636l-3.536 3.536m0 5.656l3.536 3.536M9.172 9.172L5.636 5.636m3.536 9.192l-3.536 3.536M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-5 0a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
                    پشتیبانی تلگرام
                </a>
                <div class="bg-slate-300 dark:bg-zinc-800 h-px w-20"></div>
                <p class="text-center text-sm text-slate-500 dark:text-zinc-400">
                    Powered by <a class="text-blue-600 dark:text-blue-400 font-bold hover:underline" href="https://t.me/DARK_WIKI" target="_blank" rel="noopener noreferrer">@DARK_WIKI</a>
                </p>
            </div>
        </div>
    </footer>

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

        function showToast(msg) {{
            const box = document.getElementById("toastBox");
            box.textContent = msg;
            box.classList.remove("hidden");
            setTimeout(() => box.classList.add("hidden"), 2200);
        }}

        function copySubUrl() {{
            navigator.clipboard.writeText(subUrl);
            showToast("✅ لینک اشتراک کپی شد!");
        }}
        function copyConfig(idx) {{
            navigator.clipboard.writeText(allConfigs[idx]);
            showToast("✅ کانفیگ کپی شد!");
        }}
        function copyAll() {{
            if (allConfigs.length > 0) {{
                navigator.clipboard.writeText(allConfigs.join("\\n"));
                showToast("✅ تمام کانفیگ‌ها کپی شدند!");
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

        function buildSmoothPath(pts) {{
            if (pts.length === 0) return "";
            if (pts.length === 1) return `M ${{pts[0][0]}},${{pts[0][1]}}`;
            let d = `M ${{pts[0][0]}},${{pts[0][1]}}`;
            for (let i = 0; i < pts.length - 1; i++) {{
                const xMid = (pts[i][0] + pts[i+1][0]) / 2;
                d += ` C ${{xMid}},${{pts[i][1]}} ${{xMid}},${{pts[i+1][1]}} ${{pts[i+1][0]}},${{pts[i+1][1]}}`;
            }}
            return d;
        }}

        function switchPeriod(periodKey) {{
            const data = chartDatasets[periodKey];
            if (!data) return;

            document.querySelectorAll(".period-btn").forEach(btn => {{
                btn.className = "period-btn px-3 py-1.5 text-xs sm:text-sm font-medium rounded-lg transition-all cursor-pointer bg-slate-100 dark:bg-zinc-800 text-slate-600 dark:text-zinc-400";
            }});
            const activeBtn = document.getElementById("tab-" + periodKey);
            if (activeBtn) {{
                activeBtn.className = "period-btn px-3 py-1.5 text-xs sm:text-sm font-medium rounded-lg transition-all cursor-pointer bg-blue-600 text-white shadow-sm";
            }}

            document.getElementById("chartTotalBadge").textContent = data.total_str;
            document.getElementById("xLabelStart").textContent = data.labels[0] || "";
            document.getElementById("xLabelMid").textContent = data.labels[1] || "";
            document.getElementById("xLabelEnd").textContent = data.labels[2] || "";

            const vals = data.values;
            const maxVal = Math.max(...vals, 1);
            const width = 560;
            const topY = 25;
            const bottomY = 210;
            const usableH = bottomY - topY;

            const pts = vals.map((v, idx) => {{
                const x = (idx / Math.max(1, vals.length - 1)) * width;
                const y = bottomY - (v / maxVal) * usableH;
                return [Math.round(x), Math.round(y)];
            }});

            const lineD = buildSmoothPath(pts);
            const areaD = lineD + ` L ${{width}},${{bottomY}} L 0,${{bottomY}} Z`;

            document.getElementById("chartLinePath").setAttribute("d", lineD);
            document.getElementById("chartAreaPath").setAttribute("d", areaD);
        }}

        if (document.getElementById("usageSvg")) {{
            switchPeriod("7d");
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
        _, encoded_sub = parse_and_modify_configs(raw_text, profile["name"])
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
            configs, _ = parse_and_modify_configs(raw_text, profile["name"])
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
        expire_jalali = f"{jy}/{jm:02d}/{jd:02d}, {dt.strftime('%H:%M')}"

    now_dt = datetime.now()
    njy, njm, njd = gregorian_to_jalali(now_dt.year, now_dt.month, now_dt.day)
    now_jalali = f"{njy}/{njm:02d}/{njd:02d}, {now_dt.strftime('%H:%M')}"

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
