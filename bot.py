"""FiribTekshir — Telegram firibgarlik ovchisi. Asosiy bot (skelet)."""
import asyncio
import logging

from aiogram import Bot, Dispatcher, F
from aiogram.filters import CommandStart, Command
from aiogram.types import (
    Message, InlineKeyboardMarkup, InlineKeyboardButton,
)

import config
import db
import analyzers

logging.basicConfig(level=logging.INFO)
bot = Bot(config.BOT_TOKEN)
dp = Dispatcher()

EMOJI = {"green": config.GREEN, "yellow": config.YELLOW, "red": config.RED}
LABEL = {"green": "XAVF TOPILMADI", "yellow": "SHUBHALI", "red": "XAVFLI"}


def verdict_text(kind, verdict, score, detail):
    bars = "🟥" * (score // 20) + "⬜" * (5 - score // 20)
    return (
        f"{EMOJI[verdict]} <b>{LABEL[verdict]}</b> — {score}/100\n"
        f"{bars}\n\n"
        f"📋 {detail}\n\n"
        f"{_advice(verdict)}"
    )


def _advice(verdict):
    if verdict == "red":
        return ("✅ <b>Nima qilish kerak:</b>\n"
                "1. Ochmang / o'rnatmang\n"
                "2. Yuboruvchini bloklang\n"
                "3. Tanishlaringizni ogohlantiring")
    if verdict == "yellow":
        return "⚠️ Ishonchingiz komil bo'lmasa, ochmang."
    return "ℹ️ Baribir ehtiyot bo'ling — bot 100% kafolat bermaydi."


def again_kb():
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="🔍 Yana tekshir", callback_data="again"),
        InlineKeyboardButton(text="📤 Do'stga ulash", switch_inline_query=""),
    ]])


@dp.message(CommandStart())
async def start(m: Message):
    await m.answer(
        "👋 Salom! Men <b>FiribTekshir</b> botman.\n\n"
        "Menga quyidagilardan birini yuboring:\n"
        "• 📝 Shubhali <b>xabar</b> matnini\n"
        "• 🔗 Shubhali <b>havola</b>ni\n"
        "• 📎 Shubhali <b>fayl</b> (.apk yoki .zip)\n\n"
        "Men xavfli yoki xavfsizligini o'zbek tilida tushuntiraman.\n\n"
        "<i>Masalan: \"Kartangiz bloklandi, kodni yuboring\" deb yozib ko'ring.</i>",
        parse_mode="HTML",
    )


@dp.message(Command("id"))
async def my_id(m: Message):
    """O'z Telegram ID'ingizni ko'rsatadi (admin ID'ni bilish uchun)."""
    is_admin = m.from_user.id in config.ADMIN_IDS
    await m.answer(
        f"🆔 Sizning ID: <code>{m.from_user.id}</code>\n"
        f"{'✅ Siz adminsiz' if is_admin else '❌ Siz admin emassiz'}",
        parse_mode="HTML",
    )


@dp.message(Command("admin"))
async def admin_panel(m: Message):
    """Faqat adminlar uchun — umumiy statistika."""
    if m.from_user.id not in config.ADMIN_IDS:
        await m.answer("❌ Bu bo'lim faqat adminlar uchun.")
        return
    try:
        s = await db.stats()
    except Exception as e:
        await m.answer(f"⚠️ Bazadan o'qishda xato: {e}")
        return
    await m.answer(
        "🛠 <b>Admin panel</b>\n\n"
        f"📊 Jami tekshiruvlar: <b>{s['total']}</b>\n"
        f"👥 Foydalanuvchilar: <b>{s['users']}</b>\n\n"
        f"{config.RED} Xavfli: {s['red']}\n"
        f"{config.YELLOW} Shubhali: {s['yellow']}\n"
        f"{config.GREEN} Xavfsiz: {s['green']}",
        parse_mode="HTML",
    )


@dp.message(F.text.regexp(r"https?://"))
async def on_link(m: Message):
    verdict, score, detail = analyzers.check_link(m.text)
    await db.log_check(m.from_user.id, "link", verdict, score, detail)
    await m.answer(verdict_text("link", verdict, score, detail),
                   parse_mode="HTML", reply_markup=again_kb())


@dp.message(F.document)
async def on_file(m: Message):
    name = (m.document.file_name or "").lower()
    size_mb = (m.document.file_size or 0) / 1024 / 1024
    if size_mb > config.MAX_FILE_MB:
        await m.answer(f"⚠️ Fayl juda katta ({size_mb:.0f} MB). "
                       f"Men {config.MAX_FILE_MB} MB gacha tekshira olaman.")
        return
    if name.endswith(".apk"):
        await m.answer("⏳ APK tahlil qilyapman... (ruxsatlar, kod, tokenlar)")
        # TODO: faylni yuklab olish + analyzers.check_apk(path)
        await m.answer("🧩 APK moduli keyingi bosqichda ulanadi.")
    elif name.endswith((".zip", ".rar", ".7z")):
        await m.answer("🔐 Arxiv parolli bo'lsa, 2 daqiqa parol sinab ko'raman.")
        # TODO: analyzers.check_archive(...)
        await m.answer("🧩 Arxiv moduli keyingi bosqichda ulanadi.")
    else:
        await m.answer("Men hozircha .apk va .zip fayllarni tekshiraman.")


@dp.message(F.text)
async def on_text(m: Message):
    verdict, score, detail = analyzers.check_text(m.text)
    await db.log_check(m.from_user.id, "text", verdict, score, detail)
    await m.answer(verdict_text("text", verdict, score, detail),
                   parse_mode="HTML", reply_markup=again_kb())


async def main():
    await db.init()
    logging.info("Bot ishga tushdi")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
