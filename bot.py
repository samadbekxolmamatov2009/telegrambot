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

# Android ruxsatlari -> sodda o'zbekcha tushuntirish (ilova shu bilan nima qiladi)
PERM_INFO = {
    # Tarmoq
    "INTERNET": "Internetga ulanadi (serverga ma'lumot yuborishi mumkin)",
    "ACCESS_WIFI_STATE": "Wi-Fi holatini ko'radi",
    "ACCESS_NETWORK_STATE": "Internet ulanishini tekshiradi",
    "CHANGE_WIFI_MULTICAST_STATE": "Mahalliy tarmoqdagi qurilmalarni qidiradi",
    "CHANGE_WIFI_STATE": "Wi-Fi'ni yoqadi/o'chiradi",
    "NFC": "NFC orqali aloqa qiladi (to'lov/teg o'qish)",
    "BLUETOOTH": "Bluetooth bilan ishlaydi",
    # Xavfli
    "READ_SMS": "🔴 SMS'laringizni o'qiydi (bank kodlari ham)",
    "RECEIVE_SMS": "🔴 Kelgan SMS'larni ushlaydi",
    "SEND_SMS": "🔴 Sizning nomingizdan SMS yuboradi (pul yechilishi mumkin)",
    "READ_CONTACTS": "🔴 Kontaktlaringizni o'qiydi",
    "WRITE_CONTACTS": "Kontaktlarni o'zgartiradi",
    "RECORD_AUDIO": "🔴 Mikrofondan ovoz yozadi",
    "CAMERA": "🔴 Kamerangizdan foydalanadi",
    "READ_CALL_LOG": "🔴 Qo'ng'iroqlar tarixini o'qiydi",
    "CALL_PHONE": "O'zi qo'ng'iroq qiladi",
    "READ_PHONE_STATE": "Telefon raqami va holatini o'qiydi",
    "ACCESS_FINE_LOCATION": "Aniq joylashuvingizni biladi",
    "ACCESS_COARSE_LOCATION": "Taxminiy joylashuvingizni biladi",
    "SYSTEM_ALERT_WINDOW": "🔴 Boshqa ilovalar ustiga oyna chizadi (soxta oyna)",
    "REQUEST_INSTALL_PACKAGES": "🔴 Telefoningizga boshqa ilova o'rnatadi",
    "PACKAGE_USAGE_STATS": "Qaysi ilovadan foydalanishingizni kuzatadi",
    "WRITE_EXTERNAL_STORAGE": "Xotiradagi fayllarni o'zgartiradi",
    "READ_EXTERNAL_STORAGE": "Xotiradagi fayllarni o'qiydi",
    "BIND_ACCESSIBILITY_SERVICE": "🔴 Ekraningizni o'qiydi va o'zi tugma bosadi",
    # Fon / tizim
    "FOREGROUND_SERVICE": "Fonda doimiy ishlaydi",
    "FOREGROUND_SERVICE_SPECIAL_USE": "Fonda maxsus xizmat yuritadi",
    "RECEIVE_BOOT_COMPLETED": "Telefon yonganda o'zi ishga tushadi",
    "WAKE_LOCK": "Ekran/protsessorni uxlatmaydi",
    "REORDER_TASKS": "Ilovalarni old planga chiqaradi",
    "WRITE_SYNC_SETTINGS": "Sinxronlash sozlamalarini o'zgartiradi",
    "READ_GSERVICES": "Google xizmatlari sozlamalarini o'qiydi",
    "CHANGE_CONFIGURATION": "Tizim sozlamalarini o'zgartiradi (til/ekran)",
    "GET_PACKAGE_SIZE": "Ilovalar qancha joy egallashini ko'radi",
    "BROADCAST_STICKY": "Tizimga doimiy bildirishnoma yuboradi",
    # Apparat
    "VIBRATE": "Telefonni tebratadi",
    "SET_WALLPAPER": "Ekran fonini o'zgartiradi",
    "TRANSMIT_IR": "Infraqizil port orqali signal yuboradi (pult kabi)",
}

# Verdict'ga qarab bir qatorlik izoh
VERDICT_SUMMARY = {
    "red": "Bu ilova xavfli. Uni o'rnatmang va ishonchli odamdan kelgan bo'lsa ham tekshiring.",
    "yellow": "Bu ilova shubhali. Kelib chiqishiga ishonchingiz komil bo'lmasa, o'rnatmang.",
    "green": "Ochiq xavf topilmadi. Lekin bu 100% xavfsiz degani emas — ehtiyot bo'ling.",
}


# Texnik ichki belgi -> foydalanuvchi tilidagi sodda tushuntirish.
# "nima qila oladi" = ilovaning haqiqiy qobiliyati; "nimasi shubhali" = aldov belgisi.
# Bir xil ma'noli belgilar bitta sodda qatorga yig'iladi (takror bo'lmasin).
WHAT_IT_DOES = {
    "SMS yuboradi": "Sizning nomingizdan SMS yuborishi mumkin (pulingiz yechilishi mumkin)",
    "Ma'lumotni Telegram bot orqali yuboradi":
        "Ma'lumotlaringizni Telegram orqali begona odamga yuboradi",
    "Qo'shimcha yashirin kod yuklaydi (DexClassLoader)":
        "Internetdan qo'shimcha yashirin dastur yuklab ishga tushiradi",
    "Accessibility (ekranni boshqarish) ishlatadi":
        "Ekraningizni o'qiydi va o'zi tugmalarni bosa oladi",
    "Qurilma administratori huquqini so'raydi":
        "Telefoningiz ustidan to'liq nazorat so'raydi",
    "Native kod yuklaydi (.so kutubxona)":
        "Yashirin qo'shimcha dastur ishga tushiradi",
}
# "Nimasi shubhali" — aldov/yashirish belgilari (hammasi bitta ma'noga yig'iladi)
WHY_SUSPICIOUS = {
    "Fayllar yashirilgan (anti-analiz: ZIP shifr bayrog'i)":
        "Ichki fayllarini tekshiruvdan yashirgan — halol ilovalar bunday qilmaydi",
    "Kodni shifrlab yashiradi (packer: AES/Cipher + yuklash)":
        "Haqiqiy dasturini ichida shifrlab yashirgan",
    "Shubhali yashirin fayl (shifrlangan payload bo'lishi mumkin)":
        "Haqiqiy dasturini ichida shifrlab yashirgan",
    "Ikonkasini yashirishi mumkin":
        "O'rnatilgach ekrandan yo'qoladi — topib o'chirish qiyin bo'ladi",
    "Niqoblangan: oddiy ilova ko'rinadi, lekin kodi yashirilgan":
        "O'zini oddiy ilova qilib ko'rsatgan (aldov)",
    "Paket nomida 'hidden' (yashirin) so'zi bor":
        "Dasturchi uni ataylab 'yashirin' qilib yaratgan",
}


def _plain(info):
    """behaviors ni ikki guruhga ajratadi: qila oladi / nimasi shubhali."""
    does, why = [], []
    for b in info.get("behaviors", []):
        if b in WHAT_IT_DOES:
            does.append(WHAT_IT_DOES[b])
        elif b in WHY_SUSPICIOUS:
            why.append(WHY_SUSPICIOUS[b])
        elif b.startswith("Niqoblangan: nomi fayldek"):
            why.append("O'zini oddiy rasm/fayl qilib ko'rsatgan (aldov)")
    # ruxsatlardan kelib chiqadigan qobiliyatlar
    for _p, desc in info.get("dangerous", []):
        does.append(desc)
    # takrorlarni olib tashlash, tartibni saqlash
    def uniq(xs):
        seen, out = set(), []
        for x in xs:
            if x not in seen:
                seen.add(x); out.append(x)
        return out
    return uniq(does), uniq(why)


def format_apk(verdict, score, info):
    full = score // 10
    bars = "🟥" * full + "⬜" * (10 - full)
    does, why = _plain(info)

    lines = [
        f"{EMOJI[verdict]} <b>{LABEL[verdict]}</b> — {score}/100",
        bars,
        "",
        f"<i>{VERDICT_SUMMARY[verdict]}</i>",
        "",
        f"📱 <b>Ilova nomi:</b> {info['name']}",
    ]
    # Nomi bilan haqiqiy nomi mos kelmasa — sodda ogohlantirish
    if any("aldov" in w or "yashirin" in w for w in why):
        lines.append("<i>⚠️ Ko'rinishi aldamchi — oddiy ilovaga o'xshaydi, "
                     "lekin aslida unday emas.</i>")

    if does:
        lines.append("\n🚨 <b>Bu ilova sizga nima qila oladi:</b>")
        for d in does:
            lines.append(f"• {d}")

    if why:
        lines.append("\n🕵️ <b>Nega biz buni xavfli deb topdik:</b>")
        for w in why:
            lines.append(f"• {w}")

    if info.get("tokens"):
        lines.append("\n📡 <b>Diqqat:</b> bu ilova ma'lumotni begona "
                     "Telegram botiga yuboradi.")

    if not does and not why and verdict == "green":
        lines.append("\n✅ Ochiq xavfli belgi topilmadi.")

    lines.append("\n" + _advice(verdict))
    return "\n".join(lines)


def apk_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📋 To'liq ruxsatlar", callback_data="apk_perms"),
         InlineKeyboardButton(text="🔎 Texnik ma'lumot", callback_data="apk_tech")],
        [InlineKeyboardButton(text="🔍 Yana tekshir", callback_data="again"),
         InlineKeyboardButton(text="📤 Do'stga ulash", switch_inline_query="")],
    ])


def again_kb():
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="🔍 Yana tekshir", callback_data="again"),
        InlineKeyboardButton(text="📤 Do'stga ulash", switch_inline_query=""),
    ]])


def _uname(u):
    return (u.full_name or "") + (f" @{u.username}" if u.username else "")


async def remember(m, is_check=False):
    """Foydalanuvchini bazaga yozadi (xato bo'lsa, ishni to'xtatmaydi)."""
    try:
        await db.touch_user(m.from_user.id, _uname(m.from_user), is_check)
    except Exception:
        pass


@dp.message(CommandStart())
async def start(m: Message):
    await remember(m)
    kb = None
    if m.from_user.id in config.ADMIN_IDS:
        kb = InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(text="🛠 Admin panel", callback_data="adm_open")]])
    await m.answer(
        "👋 Salom! Men <b>FiribTekshir</b> botman.\n\n"
        "Menga quyidagilardan birini yuboring:\n"
        "• 📝 Shubhali <b>xabar</b> matnini\n"
        "• 🔗 Shubhali <b>havola</b>ni\n"
        "• 📎 Shubhali <b>fayl</b> (.apk yoki .zip)\n\n"
        "Men xavfli yoki xavfsizligini o'zbek tilida tushuntiraman.\n\n"
        "<i>Masalan: \"Kartangiz bloklandi, kodni yuboring\" deb yozib ko'ring.</i>",
        parse_mode="HTML", reply_markup=kb,
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
        [InlineKeyboardButton(text="👥 Foydalanuvchilar", callback_data="adm_users"),
         InlineKeyboardButton(text="🔴 Top xavflar", callback_data="adm_threats")],
        [InlineKeyboardButton(text="📡 Tokenlar", callback_data="adm_tokens")],
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
        if what in ("adm_stats", "adm_open"):
            text = await admin_stats_text()
        elif what == "adm_users":
            rows = await db.users_list(15)
            total = await db.users_count()
            head = f"👥 <b>Foydalanuvchilar: {total} ta</b>\n\n"
            body = "\n".join(
                f"• {(r[1] or 'Ismsiz')[:28]} — <code>{r[0]}</code> "
                f"({r[2]} tekshiruv)" for r in rows) or "Hali yo'q"
            text = head + "Oxirgi faol 15 tasi:\n" + body
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
    lines = [f"📋 <b>{info['name']} — barcha ruxsatlar ({len(perms)})</b>",
             "<i>Har biri yonida ilova shu bilan nima qila olishi yozilgan.</i>", ""]
    for p in perms:
        short = p.split(".")[-1]
        desc = PERM_INFO.get(short, "tizim ruxsati")
        mark = "🔴 " if short in analyzers.DANGEROUS_PERMS else ""
        lines.append(f"{mark}<b>{short}</b>\n   — {desc}")
    text = "\n".join(lines)
    # Telegram xabari 4096 belgidan oshmasligi uchun bo'laklab yuborish
    for i in range(0, len(text), 3800):
        await c.message.answer(text[i:i + 3800], parse_mode="HTML")
    await c.answer()


@dp.callback_query(F.data == "apk_tech")
async def apk_tech_cb(c: CallbackQuery):
    info = LAST_APK.get(c.from_user.id)
    if not info:
        await c.answer("Ma'lumot eskirgan. APK'ni qayta yuboring.", show_alert=True)
        return
    text = (
        "🔎 <b>Texnik ma'lumot</b> (mutaxassislar uchun)\n\n"
        f"• Ko'rinadigan nomi: <b>{info['name']}</b>\n"
        f"• Haqiqiy ichki nomi: <code>{info['package']}</code>\n"
        "  <i>(ko'rinadigan nom bilan mos kelmasligi — niqoblash belgisi)</i>\n"
        f"• Versiya: {info['version']}\n"
        f"• Hajmi: {info.get('size_kb', '?')} KB\n"
        f"• Ruxsatlar soni: {len(info.get('permissions', []))}\n\n"
        f"🔑 <b>Fayl barmoq izi (SHA-256):</b>\n<code>{info['sha256']}</code>\n"
        "<i>Bu — faylning noyob raqami. Uni VirusTotal kabi saytlarga "
        "qidirib, bu fayl ilgari virus deb topilganini tekshirsa bo'ladi.</i>"
    )
    await c.message.answer(text, parse_mode="HTML")
    await c.answer()


@dp.callback_query(F.data == "again")
async def again_cb(c: CallbackQuery):
    await c.message.answer("🔍 Tekshirish uchun shubhali xabar, havola yoki "
                           "fayl (.apk / .zip) yuboring.")
    await c.answer()


@dp.message(F.text.regexp(r"https?://"))
async def on_link(m: Message):
    await remember(m, is_check=True)
    verdict, score, detail = analyzers.check_link(m.text)
    await db.log_check(m.from_user.id, "link", verdict, score, detail)
    await m.answer(verdict_text("link", verdict, score, detail),
                   parse_mode="HTML", reply_markup=again_kb())


@dp.message(F.document)
async def on_file(m: Message):
    await remember(m, is_check=True)
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
    await remember(m, is_check=True)
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
