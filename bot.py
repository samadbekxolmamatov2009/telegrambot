"""FiribTekshir — Telegram firibgarlik ovchisi. Asosiy bot."""
import asyncio
import logging
import os
import shutil
import tempfile

from aiogram import Bot, Dispatcher, F
from aiogram.filters import CommandStart, Command
from aiogram.types import (
    Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton,
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


# Oxirgi APK hisoboti (foydalanuvchi bo'yicha) — "to'liq ruxsatlar" tugmasi uchun
LAST_APK = {}

# Verdict'ga qarab bir qatorlik izoh
VERDICT_SUMMARY = {
    "red": "Bu ilova xavfli. Uni o'rnatmang va ishonchli odamdan kelgan bo'lsa ham tekshiring.",
    "yellow": "Bu ilova shubhali. Kelib chiqishiga ishonchingiz komil bo'lmasa, o'rnatmang.",
    "green": "Ochiq xavf topilmadi. Lekin bu 100% xavfsiz degani emas — ehtiyot bo'ling.",
}


def format_apk(verdict, score, info):
    full = score // 10
    bars = "🟥" * full + "⬜" * (10 - full)
    lines = [
        f"{EMOJI[verdict]} <b>{LABEL[verdict]}</b>",
        f"Xavf darajasi: <b>{score}/100</b>",
        bars,
        "",
        f"<i>{VERDICT_SUMMARY[verdict]}</i>",
        "",
        "📦 <b>Ilova haqida</b>",
        f"• Nomi: <b>{info['name']}</b>",
        f"• Paket: <code>{info['package']}</code>",
        f"• Versiya: {info['version']}",
        f"• Hajmi: {info.get('size_kb', '?')} KB",
    ]

    if info["dangerous"]:
        lines.append("\n⚠️ <b>Bu ilova nima qila oladi</b>")
        for _p, desc in info["dangerous"]:
            lines.append(f"• {desc}")

    if info["behaviors"]:
        lines.append("\n🔎 <b>Kodni tekshirganda topildi</b>")
        for b in info["behaviors"]:
            lines.append(f"• {b}")

    if info["tokens"]:
        lines.append("\n📡 <b>Yashirin Telegram tokeni topildi</b>")
        for t in info["tokens"]:
            lines.append(f"• <code>{t}</code>")
        lines.append("<i>O'g'irlangan ma'lumot shu bot orqali begonaga yuborilishi mumkin.</i>")

    if info["urls"]:
        lines.append("\n🌐 <b>Bog'lanadigan manzillar</b>")
        for u in info["urls"][:5]:
            lines.append(f"• <code>{u}</code>")

    nperm = len(info.get("permissions", []))
    lines.append(f"\n📋 Jami <b>{nperm} ta</b> ruxsat so'raydi "
                 f"(to'liq ro'yxat uchun pastdagi tugma)")
    lines.append(f"🔑 SHA-256:\n<code>{info['sha256']}</code>")
    lines.append("\n" + _advice(verdict))
    return "\n".join(lines)


def apk_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📋 To'liq ruxsatlar ro'yxati",
                              callback_data="apk_perms")],
        [InlineKeyboardButton(text="🔍 Yana tekshir", callback_data="again"),
         InlineKeyboardButton(text="📤 Do'stga ulash", switch_inline_query="")],
    ])


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


def admin_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📊 Umumiy", callback_data="adm_stats"),
         InlineKeyboardButton(text="🕐 Oxirgilari", callback_data="adm_recent")],
        [InlineKeyboardButton(text="🔴 Top xavflar", callback_data="adm_threats"),
         InlineKeyboardButton(text="📡 Tokenlar", callback_data="adm_tokens")],
    ])


async def admin_stats_text():
    s = await db.stats()
    bk = s["by_kind"]
    return (
        "🛠 <b>Admin panel — umumiy</b>\n\n"
        f"📊 Jami tekshiruvlar: <b>{s['total']}</b>\n"
        f"📅 Oxirgi 24 soatda: <b>{s['today']}</b>\n"
        f"👥 Foydalanuvchilar: <b>{s['users']}</b>\n\n"
        f"{config.RED} Xavfli: {s['red']}\n"
        f"{config.YELLOW} Shubhali: {s['yellow']}\n"
        f"{config.GREEN} Xavfsiz: {s['green']}\n\n"
        f"📝 Matn: {bk.get('text', 0)} · 🔗 Havola: {bk.get('link', 0)} · "
        f"📎 APK: {bk.get('apk', 0)}\n"
        f"📡 Topilgan tokenlar: {s['tokens']}"
    )


@dp.message(Command("admin"))
async def admin_panel(m: Message):
    """Faqat adminlar uchun — statistika paneli."""
    if m.from_user.id not in config.ADMIN_IDS:
        await m.answer("❌ Bu bo'lim faqat adminlar uchun.")
        return
    try:
        await m.answer(await admin_stats_text(), parse_mode="HTML",
                       reply_markup=admin_kb())
    except Exception as e:
        await m.answer(f"⚠️ Bazadan o'qishda xato: {e}")


KIND_EMOJI = {"text": "📝", "link": "🔗", "apk": "📎", "archive": "🔐"}


@dp.callback_query(F.data.startswith("adm_"))
async def admin_cb(c: CallbackQuery):
    if c.from_user.id not in config.ADMIN_IDS:
        await c.answer("Faqat adminlar uchun", show_alert=True)
        return
    what = c.data
    try:
        if what == "adm_stats":
            text = await admin_stats_text()
        elif what == "adm_recent":
            rows = await db.recent(10)
            text = "🕐 <b>Oxirgi 10 tekshiruv</b>\n\n" + ("\n".join(
                f"{EMOJI.get(r[1], '')}{KIND_EMOJI.get(r[0], '')} "
                f"{r[2]}/100 — {(r[3] or '')[:40]}" for r in rows) or "Hali yo'q")
        elif what == "adm_threats":
            rows = await db.top_threats(8)
            text = "🔴 <b>Eng ko'p uchragan xavflar</b>\n\n" + ("\n".join(
                f"• {(r[0] or 'nomalum')[:45]} — <b>{r[1]}x</b>" for r in rows)
                or "Hali xavfli fayl yo'q")
        elif what == "adm_tokens":
            rows = await db.list_tokens(12)
            text = "📡 <b>Topilgan firibgar tokenlari</b>\n\n" + ("\n".join(
                f"• <code>{r[0]}</code> ({(r[1] or '?')[:25]})" for r in rows)
                or "Hali token topilmagan")
        else:
            text = "?"
        await c.message.edit_text(text, parse_mode="HTML", reply_markup=admin_kb())
    except Exception as e:
        await c.answer(f"Xato: {e}", show_alert=True)
    await c.answer()


@dp.callback_query(F.data == "apk_perms")
async def apk_perms_cb(c: CallbackQuery):
    info = LAST_APK.get(c.from_user.id)
    if not info:
        await c.answer("Ma'lumot eskirgan. APK'ni qayta yuboring.", show_alert=True)
        return
    perms = info.get("permissions", [])
    text = (f"📋 <b>{info['name']} — barcha ruxsatlar ({len(perms)})</b>\n\n"
            + "\n".join(f"• <code>{p.split('.')[-1]}</code>" for p in perms))
    await c.message.answer(text[:4000], parse_mode="HTML")
    await c.answer()


@dp.callback_query(F.data == "again")
async def again_cb(c: CallbackQuery):
    await c.message.answer("🔍 Tekshirish uchun shubhali xabar, havola yoki "
                           "fayl (.apk / .zip) yuboring.")
    await c.answer()


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
        status = await m.answer("⏳ APK tahlil qilyapman... (ruxsatlar, kod, tokenlar)")
        tmp = tempfile.mkdtemp()
        apk_path = os.path.join(tmp, "app.apk")
        try:
            await bot.download(m.document, destination=apk_path)
            verdict, score, info = await asyncio.to_thread(
                analyzers.check_apk, apk_path)
            await db.log_check(m.from_user.id, "apk", verdict, score,
                               f"{info['name']} ({info['package']})")
            for t in info["tokens"]:
                try:
                    await db.save_token(t, info["package"])
                except Exception:
                    pass
            LAST_APK[m.from_user.id] = info
            await m.answer(format_apk(verdict, score, info),
                           parse_mode="HTML", reply_markup=apk_kb())
        except Exception as e:
            logging.exception("APK tahlil xatosi")
            await m.answer(f"⚠️ Bu faylni tahlil qila olmadim.\n"
                           f"Sabab: <code>{e}</code>\n\n"
                           f"Fayl buzilgan yoki haqiqiy APK bo'lmasligi mumkin — "
                           f"baribir ehtiyot bo'ling.", parse_mode="HTML")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
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
