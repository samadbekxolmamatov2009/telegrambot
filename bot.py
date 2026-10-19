"""Apk aniqlovchi — Telegram firibgarlik ovchisi. Asosiy bot."""
import asyncio
import logging
import os
import shutil
import tempfile

from aiogram import Bot, Dispatcher, F
from aiogram.filters import CommandStart, Command
from aiogram.types import (
    Message, CallbackQuery, ChatMemberUpdated,
    InlineKeyboardMarkup, InlineKeyboardButton,
    ReplyKeyboardMarkup, KeyboardButton, ReplyKeyboardRemove,
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
    "Soxta imzo: o'zini Google/Android deb ko'rsatgan":
        "Soxta imzo bilan o'zini Google/Android rasmiy dasturi qilib ko'rsatgan",
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


def _share_url(info, verdict, score):
    """Do'stga ulash: natija + bot havolasini birga yuboradi."""
    import urllib.parse
    name = info.get("name", "ilova")
    txt = (f"⚠️ «Apk aniqlovchi» natijasi:\n"
           f"«{name}» — {EMOJI[verdict]} {LABEL[verdict]} ({score}/100)\n\n"
           f"Shubhali ilovalarни o'zing ham tekshir 👇")
    bot_link = f"https://t.me/{BOT_USERNAME}" if BOT_USERNAME else "https://t.me"
    return ("https://t.me/share/url?url=" + urllib.parse.quote(bot_link)
            + "&text=" + urllib.parse.quote(txt))


def apk_kb(info=None, verdict="red", score=0):
    share = _share_url(info or {}, verdict, score)
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📋 To'liq ruxsatlar", callback_data="apk_perms"),
         InlineKeyboardButton(text="🔎 Texnik ma'lumot", callback_data="apk_tech")],
        [InlineKeyboardButton(text="📤 Do'stga ulash (natija bilan)", url=share)],
        [InlineKeyboardButton(text="🔍 Yana tekshir", callback_data="again")],
    ])


def again_kb():
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="🔍 Yana tekshir", callback_data="again"),
    ]])


def _uname(u):
    return (u.full_name or "") + (f" @{u.username}" if u.username else "")


async def remember(m, is_check=False):
    """Foydalanuvchini bazaga yozadi (xato bo'lsa, ishni to'xtatmaydi)."""
    try:
        await db.touch_user(m.from_user.id, _uname(m.from_user), is_check)
    except Exception:
        pass


def is_group(m):
    return m.chat.type in ("group", "supergroup")


def _sender_line(m):
    """Faylni kim yuborgani (guruhда ko'rsatish uchun)."""
    u = getattr(m, "from_user", None)
    if not u:
        return "📢 <b>Kanalga joylangan</b>"
    who = u.full_name or "Ismsiz"
    tail = f" @{u.username}" if u.username else ""
    return f"📤 <b>Yuboruvchi:</b> {who}{tail} (<code>{u.id}</code>)"


async def group_report(m, verdict, score, info):
    """Guruh/kanalда: kim tashlagani + to'liq tahlil. Xavflini o'chiradi.
    (Tugmasiz — chatда tugma bezovta qiladi.)"""
    note = ""
    if verdict == "red":
        try:
            await m.delete()
            note = "\n\n🗑 <b>Bu xavfli fayl o'chirildi. Hech kim ochmasin!</b>"
        except Exception:
            note = ("\n\n⚠️ <b>Men o'chira olmadim</b> — meni guruhда admin qiling. "
                    "Hozircha hech kim ochmasin!")
    text = _sender_line(m) + "\n\n" + format_apk(verdict, score, info) + note
    for i in range(0, len(text), 3800):
        await m.answer(text[i:i + 3800], parse_mode="HTML",
                       reply_markup=ReplyKeyboardRemove() if i == 0 else None)


async def short_scan(m):
    """Guruh/kanal uchun: .apk/.zip ni tahlil qiladi, kim tashlaganini aytadi,
    to'liq ma'lumotni ko'rsatadi; xavflini o'chiradi."""
    doc = m.document
    name = (doc.file_name or "").lower()
    if (doc.file_size or 0) / 1024 / 1024 > config.MAX_FILE_MB:
        return
    uid = m.from_user.id if m.from_user else m.chat.id
    tmp = tempfile.mkdtemp()
    p = os.path.join(tmp, "f")
    try:
        await bot.download(doc, destination=p)
        if name.endswith(".apk"):
            verdict, score, info = await asyncio.to_thread(analyzers.check_apk, p)
            try:
                await db.log_check(uid, "apk", verdict, score,
                                   f"{info['name']} ({info['package']})")
                for t in info.get("tokens", []):
                    await db.save_token(t, info["package"])
            except Exception:
                pass
            await group_report(m, verdict, score, info)
        elif name.endswith(".zip"):
            res = await asyncio.to_thread(analyzers.check_archive, p, [])
            if res.get("status") == "apk":
                info = res["info"]
                try:
                    await db.log_check(uid, "archive", res["verdict"],
                                       res["score"], f"{info['name']} (arxivда)")
                except Exception:
                    pass
                await group_report(m, res["verdict"], res["score"], info)
            elif res.get("status") == "locked":
                await m.answer(_sender_line(m) + "\n\n🔒 <b>Parolli arxiv</b> — "
                               "ichida ilova bor, lekin oddiy parol bilan "
                               "ocholmadim. Ehtiyot bo'ling, ochmang.",
                               parse_mode="HTML")
    except Exception:
        logging.exception("short_scan xatosi")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        import gc
        gc.collect()  # androguard obyektlarini bo'shatish (xotira)


@dp.channel_post(F.document)
async def on_channel_file(post: Message):
    """Kanalда tarqatilgan .apk/.zip — jimgina tekshiradi, xavflini o'chiradi."""
    await short_scan(post)


@dp.message(CommandStart())
async def start(m: Message):
    # Guruhда bot hech qanday so'rovga javob bermaydi — faqat fayllarni tekshiradi
    if is_group(m):
        return
    await remember(m)
    await m.answer(
        "👋 Salom! Men <b>Apk aniqlovchi</b> botman.\n\n"
        "Menga shubhali <b>ilova faylini</b> (.apk) yoki <b>arxivni</b> "
        "(.zip) yuboring — men uni ochib, ichini tekshirib, xavfli yoki "
        "xavfsizligini o'zbek tilida tushuntiraman.\n\n"
        "Meni <b>guruhingizга</b> ham qo'shsangiz, u yerda tarqatilgan "
        "xavfli ilovalarni o'zim ushlab, ogohlantiraman.",
        parse_mode="HTML",
        reply_markup=main_menu_kb(m.from_user.id in config.ADMIN_IDS),
    )


# Bot guruh/kanalга qo'shilganда hech qanday xabar yoki tugma yubormaydi.
# Shunchaki turadi va faqat xavfli APK topilganда o'sha haqda xabar beradi.


@dp.message(Command("id"))
async def my_id(m: Message):
    """O'z Telegram ID'ingizni ko'rsatadi (admin ID'ni bilish uchun)."""
    if is_group(m):
        return  # guruhда javob bermaydi
    is_admin = m.from_user.id in config.ADMIN_IDS
    await m.answer(
        f"🆔 Sizning ID: <code>{m.from_user.id}</code>\n"
        f"{'✅ Siz adminsiz' if is_admin else '❌ Siz admin emassiz'}",
        parse_mode="HTML",
    )


BOT_USERNAME = ""  # main()da to'ldiriladi


def group_add_kb():
    """'Guruhga qo'shish' inline tugmasi (startgroup)."""
    url = f"https://t.me/{BOT_USERNAME}?startgroup=true" if BOT_USERNAME else "https://t.me"
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="➕ Meni guruhga qo'shish", url=url)]])


# Asosiy menyu (hamma uchun) va admin menyu — katta, doimiy tugmalar
BTN_HISTORY = "🗂 Tekshirilgan APKlar"
BTN_GROUP = "➕ Guruhga qo'shish"
BTN_ADMIN = "🛠 Admin panel"

BTN_STATS = "📊 Statistika"
BTN_USERS = "👥 Foydalanuvchilar"
BTN_RECENT = "🕐 Oxirgi tekshiruvlar"
BTN_THREATS = "🔴 Top xavflar"
BTN_TOKENS = "📡 Topilgan tokenlar"
BTN_CLOSE = "❌ Panelni yopish"


def main_menu_kb(is_admin=False):
    rows = [[KeyboardButton(text=BTN_HISTORY)],
            [KeyboardButton(text=BTN_GROUP)]]
    if is_admin:
        rows.append([KeyboardButton(text=BTN_ADMIN)])
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True,
                               input_field_placeholder="Fayl yuboring yoki tugmani tanlang")


def admin_menu_kb():
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text=BTN_STATS)],
            [KeyboardButton(text=BTN_USERS), KeyboardButton(text=BTN_RECENT)],
            [KeyboardButton(text=BTN_THREATS), KeyboardButton(text=BTN_TOKENS)],
            [KeyboardButton(text=BTN_GROUP), KeyboardButton(text=BTN_CLOSE)],
        ],
        resize_keyboard=True,
        input_field_placeholder="Admin panel — tugmani tanlang",
    )


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


KIND_EMOJI = {"text": "📝", "link": "🔗", "apk": "📎", "archive": "🔐"}


async def open_admin_panel(m):
    """Admin panelni ochadi — katta tugmali menyu + umumiy statistika."""
    try:
        await m.answer(await admin_stats_text(), parse_mode="HTML",
                       reply_markup=admin_menu_kb())
    except Exception as e:
        await m.answer(f"⚠️ Bazadan o'qishda xato: {e}",
                       reply_markup=admin_menu_kb())


@dp.message(Command("admin"))
async def admin_panel(m: Message):
    # Guruhда admin panel umuman ochilmaydi va javob berilmaydi
    if is_group(m):
        return
    if m.from_user.id not in config.ADMIN_IDS:
        await m.answer("❌ Bu bo'lim faqat adminlar uchun.")
        return
    await open_admin_panel(m)


@dp.callback_query(F.data == "adm_open")
async def adm_open_cb(c: CallbackQuery):
    if c.from_user.id not in config.ADMIN_IDS:
        await c.answer("Faqat adminlar uchun", show_alert=True)
        return
    if c.message.chat.type != "private":
        await c.answer("Admin panel faqat shaxsiy chatда ochiladi", show_alert=True)
        return
    await open_admin_panel(c.message)
    await c.answer()


# ── Admin tugmalari (reply keyboard matnlari) ────────────────────
def _admin_only(m):
    return m.from_user.id in config.ADMIN_IDS


@dp.message(F.text == BTN_STATS, F.chat.type == "private")
async def adm_stats(m: Message):
    if not _admin_only(m):
        return
    await m.answer(await admin_stats_text(), parse_mode="HTML")


@dp.message(F.text == BTN_USERS, F.chat.type == "private")
async def adm_users(m: Message):
    if not _admin_only(m):
        return
    rows = await db.users_list(20)
    total = await db.users_count()
    body = "\n".join(
        f"• {(r[1] or 'Ismsiz')[:50]} — <code>{r[0]}</code> ({r[2]} tekshiruv)"
        for r in rows) or "Hali yo'q"
    await m.answer(f"👥 <b>Foydalanuvchilar: {total} ta</b>\n\n"
                   f"Oxirgi faol 20 tasi:\n{body}", parse_mode="HTML")


@dp.message(F.text == BTN_RECENT, F.chat.type == "private")
async def adm_recent(m: Message):
    if not _admin_only(m):
        return
    rows = await db.recent(12)
    body = "\n".join(
        f"{EMOJI.get(r[1], '')}{KIND_EMOJI.get(r[0], '')} {r[2]}/100 — "
        f"{(r[3] or '')[:40]}" for r in rows) or "Hali yo'q"
    await m.answer(f"🕐 <b>Oxirgi 12 tekshiruv</b>\n\n{body}", parse_mode="HTML")


@dp.message(F.text == BTN_THREATS, F.chat.type == "private")
async def adm_threats(m: Message):
    if not _admin_only(m):
        return
    rows = await db.top_threats(10)
    body = "\n".join(f"• {(r[0] or 'nomalum')[:45]} — <b>{r[1]}x</b>"
                     for r in rows) or "Hali xavfli fayl yo'q"
    await m.answer(f"🔴 <b>Eng ko'p uchragan xavflar</b>\n\n{body}",
                   parse_mode="HTML")


@dp.message(F.text == BTN_TOKENS, F.chat.type == "private")
async def adm_tokens(m: Message):
    if not _admin_only(m):
        return
    rows = await db.list_tokens(15)
    body = "\n".join(f"• <code>{r[0]}</code> ({(r[1] or '?')[:25]})"
                     for r in rows) or "Hali token topilmagan"
    await m.answer(f"📡 <b>Topilgan firibgar tokenlari</b>\n\n{body}",
                   parse_mode="HTML")


@dp.message(F.text == BTN_CLOSE, F.chat.type == "private")
async def adm_close(m: Message):
    if not _admin_only(m):
        return
    await m.answer("Admin panel yopildi.", reply_markup=main_menu_kb(True))


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
    lines = [
        "🔎 <b>Texnik / forensik ma'lumot</b>",
        "<i>(davlat organlari va mutaxassislar uchun)</i>\n",
        f"• Ko'rinadigan nomi: <b>{info['name']}</b>",
        f"• Haqiqiy ichki nomi: <code>{info['package']}</code>",
        f"• Versiya: {info['version']} · Hajmi: {info.get('size_kb', '?')} KB",
        f"• Android SDK: min {info.get('min_sdk', '?')} / target {info.get('target_sdk', '?')}",
        f"• Ruxsatlar soni: {len(info.get('permissions', []))}",
    ]
    # Komponentlar (tuzilma)
    comp = (f"• Komponentlar: {len(info.get('activities', []))} ekran, "
            f"{len(info.get('services', []))} xizmat, "
            f"{len(info.get('receivers', []))} tinglovchi")
    lines.append(comp)
    if info.get("main_activity"):
        lines.append(f"• Asosiy ekran: <code>{info['main_activity']}</code>")
    if info.get("lib_archs"):
        lines.append(f"• Native kutubxonalar: {', '.join(info['lib_archs'])}"
                     + (f" ({', '.join(info['libs'][:4])})" if info.get("libs") else ""))
    # Fonda ishlaydigan xizmatlar / tinglovchilar nomlari (forensik)
    if info.get("services"):
        lines.append("\n⚙️ <b>Fon xizmatlari</b>")
        for s0 in info["services"][:6]:
            lines.append(f"• <code>{s0.split('.')[-1]}</code>")
    if info.get("receivers"):
        lines.append("\n📡 <b>Hodisa tinglovchilari</b>")
        for r0 in info["receivers"][:6]:
            lines.append(f"• <code>{r0.split('.')[-1]}</code>")
    # Imzo (kim yasagan/imzolagan)
    s = info.get("signer")
    if s:
        lines.append("\n🪪 <b>Imzo (kim yaratgan)</b>")
        if s.get("common_name"):
            lines.append(f"• Nomi: {s['common_name']}")
        if s.get("org"):
            lines.append(f"• Tashkilot: {s['org']}")
        if s.get("email"):
            lines.append(f"• Email: <code>{s['email']}</code>")
        if s.get("country"):
            lines.append(f"• Davlat: {s['country']}")
        lines.append(f"• Amal qilish: {s.get('not_before')} → {s.get('not_after')}")
        lines.append(f"• Imzo izi: <code>{s.get('sha256','')[:32]}…</code>")
        if s.get("impersonation"):
            lines.append("⚠️ <b>Soxta imzo</b> — o'zini Google/Android deb "
                         "ko'rsatgan (aslida rasmiy emas)")
    # Topilgan aloqa ma'lumotlari
    if info.get("emails"):
        lines.append("\n📧 <b>Kodda topilgan email'lar</b>")
        for em in info["emails"]:
            lines.append(f"• <code>{em}</code>")
    if info.get("tokens"):
        lines.append("\n📡 <b>Topilgan Telegram tokenlari</b>")
        for t in info["tokens"]:
            lines.append(f"• <code>{t}</code>")
    if info.get("urls"):
        lines.append("\n🌐 <b>Bog'lanadigan manzillar</b>")
        for u in info["urls"]:
            lines.append(f"• <code>{u}</code>")
    if info.get("ips"):
        lines.append("\n📍 <b>Topilgan IP manzillar</b>")
        for ip in info["ips"]:
            lines.append(f"• <code>{ip}</code>")
    if info.get("phones"):
        lines.append("\n📞 <b>Topilgan telefon raqamlari</b>")
        for ph in info["phones"]:
            lines.append(f"• <code>{ph}</code>")
    lines.append(f"\n🔑 <b>Fayl barmoq izi (SHA-256)</b>\n<code>{info['sha256']}</code>")
    lines.append("<i>VirusTotal kabi saytlarда shu raqamni qidirib, fayl "
                 "ilgari virus deb topilganini tekshirsa bo'ladi.</i>")
    text = "\n".join(lines)
    for i in range(0, len(text), 3800):
        await c.message.answer(text[i:i + 3800], parse_mode="HTML")
    await c.answer()


async def history_text(user_id):
    import datetime
    rows = await db.user_checks(user_id, 15)
    if not rows:
        return ("🗂 Siz hali birorta APK tekshirmagansiz.\n"
                "Menga .apk yoki .zip fayl yuboring.")
    lines = ["🗂 <b>Siz tekshirgan oxirgi APKlar</b>\n"]
    for verdict, score, detail, created in rows:
        dt = datetime.datetime.fromtimestamp(created).strftime("%d.%m %H:%M")
        lines.append(f"{EMOJI.get(verdict, '')} <b>{score}/100</b> · "
                     f"{(detail or '')[:35]} <i>({dt})</i>")
    return "\n".join(lines)


@dp.message(F.text == BTN_HISTORY, F.chat.type == "private")
async def my_apks_btn(m: Message):
    await m.answer(await history_text(m.from_user.id), parse_mode="HTML")


@dp.message(F.text == BTN_GROUP, F.chat.type == "private")
async def group_btn(m: Message):
    await m.answer("Meni guruhga qo'shish uchun pastdagi tugmani bosing 👇\n"
                   "Guruhда <b>admin</b> qilsangiz, xavfli fayllarni o'zim "
                   "o'chiraman.", parse_mode="HTML", reply_markup=group_add_kb())


@dp.message(F.text == BTN_ADMIN, F.chat.type == "private")
async def admin_btn(m: Message):
    if m.from_user.id not in config.ADMIN_IDS:
        return
    await open_admin_panel(m)


@dp.callback_query(F.data == "my_apks")
async def my_apks_cb(c: CallbackQuery):
    await c.message.answer(await history_text(c.from_user.id), parse_mode="HTML")
    await c.answer()


@dp.callback_query(F.data == "again")
async def again_cb(c: CallbackQuery):
    await c.message.answer("🔍 Tekshirish uchun shubhali fayl (.apk / .zip) "
                           "yuboring.")
    await c.answer()


# Eslatma: bot faqat fayllarni (.apk/.zip) tahlil qiladi.
# Matn va havolalar tahlil qilinmaydi (guruhда ham, shaxsiy chatда ham).


@dp.message(F.document)
async def on_file(m: Message):
    # Guruhда: jimgina tekshiradi, faqat xavfli APK haqida xabar beradi
    if is_group(m):
        await short_scan(m)
        return
    await remember(m, is_check=True)
    name = (m.document.file_name or "").lower()
    size_mb = (m.document.file_size or 0) / 1024 / 1024
    if size_mb > config.MAX_FILE_MB:
        await m.answer(f"⚠️ Fayl juda katta ({size_mb:.0f} MB). "
                       f"Men {config.MAX_FILE_MB} MB gacha tekshira olaman.")
        return
    grp = False
    if name.endswith(".apk"):
        if not grp:
            await m.answer("⏳ APK tahlil qilyapman... (ruxsatlar, kod, tokenlar)")
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
            if grp:
                await group_result(m, verdict, info["name"])
            else:
                LAST_APK[m.from_user.id] = info
                await m.answer(format_apk(verdict, score, info),
                               parse_mode="HTML",
                               reply_markup=apk_kb(info, verdict, score))
        except Exception as e:
            logging.exception("APK tahlil xatosi")
            if not grp:
                await m.answer(f"⚠️ Bu faylni tahlil qila olmadim.\n"
                               f"Sabab: <code>{e}</code>\n\n"
                               f"Fayl buzilgan yoki haqiqiy APK bo'lmasligi mumkin — "
                               f"baribir ehtiyot bo'ling.", parse_mode="HTML")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
            import gc; gc.collect()
    elif name.endswith(".zip"):
        if not grp:
            await m.answer("🔐 Arxivni ochyapman va ichidagini tekshiryapman...")
        tmp = tempfile.mkdtemp()
        zip_path = os.path.join(tmp, "a.zip")
        try:
            await bot.download(m.document, destination=zip_path)
            pw = (m.caption or "").split() if m.caption else []
            res = await asyncio.to_thread(analyzers.check_archive, zip_path, pw)
            st = res.get("status")
            if st == "apk":
                info = res["info"]
                await db.log_check(m.from_user.id, "archive", res["verdict"],
                                   res["score"], f"{info['name']} (arxivда)")
                for t in info.get("tokens", []):
                    try:
                        await db.save_token(t, info["package"])
                    except Exception:
                        pass
                if grp:
                    await group_result(m, res["verdict"], info["name"])
                else:
                    LAST_APK[m.from_user.id] = info
                    pwnote = (f"\n🔓 Parol topildi: <code>{res['password']}</code>"
                              if res.get("password") else "")
                    await m.answer("📦 Arxiv ichida ilova (.apk) topildi va "
                                   "tekshirildi:" + pwnote, parse_mode="HTML")
                    await m.answer(format_apk(res["verdict"], res["score"], info),
                                   parse_mode="HTML",
                                   reply_markup=apk_kb(info, res["verdict"], res["score"]))
            elif grp:
                return  # guruhда faqat xavfli APK haqida xabar beramiz
            elif st == "locked":
                await m.answer(
                    "🔒 <b>Arxiv parol bilan yopilgan.</b>\n\n"
                    "Ichida ilova bor, lekin oddiy parollar bilan ocholmadim.\n"
                    "Agar yuboruvchi parol yozgan bo'lsa — faylni <b>izoh "
                    "(caption)</b> sifatida parol bilan qayta yuboring.\n\n"
                    "⚠️ Rasm/video o'rniga parolli arxivda ilova kelishi — "
                    "bu allaqachon shubhali.", parse_mode="HTML")
            elif st == "no_apk":
                await m.answer("ℹ️ Arxiv ichida ilova (.apk) topilmadi.\n"
                               "Ichidagilar: " +
                               ", ".join(res.get("names", [])[:10]))
            else:
                await m.answer(f"⚠️ Arxivni ocholmadim: "
                               f"<code>{res.get('error', 'nomalum')}</code>",
                               parse_mode="HTML")
        except Exception as e:
            logging.exception("Arxiv tahlil xatosi")
            if not grp:
                await m.answer(f"⚠️ Arxivni tahlil qila olmadim: <code>{e}</code>",
                               parse_mode="HTML")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
            import gc; gc.collect()
    elif name.endswith((".rar", ".7z")):
        if not grp:
            await m.answer("ℹ️ Hozircha faqat .zip arxivlarni ocha olaman. "
                           "RAR/7z keyingi versiyada.")
    elif not grp:
        await m.answer("Men hozircha .apk va .zip fayllarni tekshiraman.")


@dp.message(F.text, F.chat.type == "private")
async def on_text(m: Message):
    """Bot matnni tahlil qilmaydi — faqat .apk/.zip fayllarni tekshiradi."""
    await remember(m)
    await m.answer(
        "📎 Menga shubhali <b>ilova faylini</b> (.apk) yoki <b>arxivni</b> "
        "(.zip) yuboring — men uni ochib, xavfli yoki xavfsizligini "
        "tushuntiraman.\n\n<i>Matn va havolalarni tekshirmayman.</i>",
        parse_mode="HTML")


async def main():
    global BOT_USERNAME
    await db.init()
    try:
        me = await bot.get_me()
        BOT_USERNAME = me.username or ""
    except Exception:
        pass
    logging.info("Bot ishga tushdi (@%s)", BOT_USERNAME)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
