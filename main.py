import os
import base64
import json
import sqlite3
import urllib.parse
from datetime import datetime
from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI, Response
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pyrogram import Client, filters

# تنظیمات متغیرهای محیطی
UPSTREAM_SUB_URL = os.getenv("UPSTREAM_SUB_URL", "")
BRAND_NAME = os.getenv("BRAND_NAME", "MY-CUSTOM-SUB")
API_ID = int(os.getenv("TELEGRAM_API_ID", "0"))
API_HASH = os.getenv("TELEGRAM_API_HASH", "")
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
PUBLIC_URL = os.getenv("RAILWAY_PUBLIC_DOMAIN", "localhost:8000")

# ذخیره‌سازی روی Persistent Volume در ریل‌وی
DATA_DIR = "/data" if os.path.exists("/data") else "."
DB_FILE = os.path.join(DATA_DIR, "usage_history.db")

tg_client = Client(
    "sub_bot",
    api_id=API_ID,
    api_hash=API_HASH,
    bot_token=BOT_TOKEN,
    workdir=DATA_DIR
)

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS daily_usage (
            date TEXT PRIMARY KEY,
            total_used_bytes INTEGER
        )
    """)
    conn.commit()
    conn.close()

init_db()

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

def record_usage(total_bytes: int):
    today = datetime.now().strftime("%Y-%m-%d")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO daily_usage (date, total_used_bytes)
        VALUES (?, ?)
        ON CONFLICT(date) DO UPDATE SET total_used_bytes = excluded.total_used_bytes
    """, (today, total_bytes))
    conn.commit()
    conn.close()

def generate_weekly_chart() -> str:
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT date, total_used_bytes FROM daily_usage ORDER BY date DESC LIMIT 8")
    rows = cursor.fetchall()
    conn.close()

    if len(rows) < 2:
        return ""

    rows.reverse()
    dates = []
    deltas_gb = []

    for i in range(1, len(rows)):
        delta = rows[i][1] - rows[i-1][1]
        if delta < 0:
            delta = rows[i][1]
        dates.append(rows[i][0][5:])
        deltas_gb.append(delta / (1024 ** 3))

    chart_path = os.path.join(DATA_DIR, "consumption_chart.png")
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.bar(dates, deltas_gb, color="#2ecc71")
    ax.set_title("Weekly Consumption (GB)")
    ax.set_xlabel("Date")
    ax.set_ylabel("GB")
    plt.tight_layout()
    plt.savefig(chart_path)
    plt.close(fig)
    return chart_path

def modify_configs(raw_b64: str) -> str:
    decoded = base64.b64decode(raw_b64).decode("utf-8", errors="ignore")
    lines = [line.strip() for line in decoded.splitlines() if line.strip()]
    modified = []

    for idx, line in enumerate(lines, start=1):
        custom_remark = f"{BRAND_NAME} - {idx:02d}"
        if line.startswith(("vless://", "trojan://", "ss://")):
            base_url = line.split("#")[0]
            modified.append(f"{base_url}#{urllib.parse.quote(custom_remark)}")
        elif line.startswith("vmess://"):
            try:
                b64_json = line[8:]
                conf = json.loads(base64.b64decode(b64_json).decode("utf-8"))
                conf["ps"] = custom_remark
                re_encoded = base64.b64encode(json.dumps(conf).encode("utf-8")).decode("utf-8")
                modified.append(f"vmess://{re_encoded}")
            except Exception:
                modified.append(line)
        else:
            modified.append(line)

    payload = "\n".join(modified)
    return base64.b64encode(payload.encode("utf-8")).decode("utf-8")

@asynccontextmanager
async def lifespan(app: FastAPI):
    if BOT_TOKEN and API_ID and API_HASH:
        await tg_client.start()
    yield
    if BOT_TOKEN and API_ID and API_HASH:
        await tg_client.stop()

app = FastAPI(lifespan=lifespan)

@app.get("/sub")
async def get_modified_sub():
    async with httpx.AsyncClient(timeout=15.0) as client:
        res = await client.get(UPSTREAM_SUB_URL)
        
    user_info = res.headers.get("subscription-userinfo", "")
    parsed_info = parse_user_info(user_info)
    
    if "upload" in parsed_info and "download" in parsed_info:
        total_used = parsed_info["upload"] + parsed_info["download"]
        record_usage(total_used)

    new_payload = modify_configs(res.text.strip())

    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "subscription-userinfo": user_info,
        "Profile-Update-Interval": "6"
    }
    return Response(content=new_payload, headers=headers)

@tg_client.on_message(filters.command("start") | filters.command("stats"))
async def handle_stats(client, message):
    async with httpx.AsyncClient(timeout=15.0) as http_cli:
        res = await http_cli.get(UPSTREAM_SUB_URL)
        
    info_str = res.headers.get("subscription-userinfo", "")
    info = parse_user_info(info_str)
    
    upload_gb = info.get("upload", 0) / (1024**3)
    download_gb = info.get("download", 0) / (1024**3)
    total_gb = info.get("total", 0) / (1024**3)
    used_gb = upload_gb + download_gb
    remaining_gb = max(0.0, total_gb - used_gb)

    sub_link = f"https://{PUBLIC_URL}/sub" if not PUBLIC_URL.startswith("http") else f"{PUBLIC_URL}/sub"

    caption = (
        f"🏷 Brand: {BRAND_NAME}\n"
        f"📊 Total: {total_gb:.2f} GB\n"
        f"📉 Used: {used_gb:.2f} GB\n"
        f"📈 Remaining: {remaining_gb:.2f} GB\n\n"
        f"🔗 Sub Link:\n`{sub_link}`"
    )

    chart_file = generate_weekly_chart()
    if chart_file and os.path.exists(chart_file):
        await message.reply_photo(photo=chart_file, caption=caption)
    else:
        await message.reply_text(caption)
