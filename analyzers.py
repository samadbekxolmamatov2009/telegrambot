"""Tahlil modullari. Hozircha matn va havola — asosiy mantiq bilan,
APK va arxiv — keyingi bosqichda to'liq ulanadi (androguard)."""
import re

# ── Matn tahlili (firibgarlik iboralarini qidiradi) ──────────────
SCAM_WORDS = [
    "kodni yuboring", "parolni yuboring", "karta raqam", "sms kod",
    "pul yutdingiz", "bonus", "bloklandi", "tasdiqlang", "shoshiling",
    "faqat bugun", "sovg'a", "yutuq", "kodni ayting",
]


def check_text(text: str):
    t = text.lower()
    hits = [w for w in SCAM_WORDS if w in t]
    if len(hits) >= 2:
        return ("red", 80, f"Firibgarlik belgilari: {', '.join(hits[:3])}")
    if len(hits) == 1:
        return ("yellow", 45, f"Shubhali ibora: {hits[0]}")
    return ("green", 10, "Aniq firibgarlik belgisi topilmadi")


# ── Havola tahlili ────────────────────────────────────────────────
BAD_TLD = (".top", ".xyz", ".click", ".online", ".site", ".click")
LOOKALIKE = ["ciick", "c1ick", "paymee", "0zbek", "clik", "payme-", "uzcard-"]


def check_link(url: str):
    u = url.lower()
    reasons = []
    if any(u.endswith(t) or t + "/" in u for t in BAD_TLD):
        reasons.append("shubhali domen zonasi")
    if any(w in u for w in LOOKALIKE):
        reasons.append("mashhur saytga o'xshatilgan nom")
    if re.search(r"https?://\d+\.\d+\.\d+\.\d+", u):
        reasons.append("domen o'rniga IP manzil")
    # TODO: VirusTotal va Safe Browsing shu yerga ulanadi
    if len(reasons) >= 2:
        return ("red", 75, "; ".join(reasons))
    if reasons:
        return ("yellow", 40, "; ".join(reasons))
    return ("green", 15, "Ochiq xavf topilmadi (lekin ehtiyot bo'ling)")


# ── APK tahlili (androguard) ──────────────────────────────────────
import hashlib

# Xavfli ruxsatlar: (ruxsat qismi, odam tiliga tarjima)
DANGEROUS_PERMS = {
    "READ_SMS": "SMS'laringizni o'qiydi (bank kodlari ham)",
    "RECEIVE_SMS": "Kelgan SMS'larni ushlaydi",
    "SEND_SMS": "Sizning nomingizdan SMS yuboradi",
    "READ_CONTACTS": "Kontaktlaringizni o'qiydi",
    "RECORD_AUDIO": "Mikrofondan ovoz yozadi",
    "CAMERA": "Kamerangizdan foydalanadi",
    "READ_CALL_LOG": "Qo'ng'iroqlar tarixini o'qiydi",
    "SYSTEM_ALERT_WINDOW": "Boshqa ilovalar ustiga oyna chizadi (soxta oyna)",
    "REQUEST_INSTALL_PACKAGES": "Boshqa ilova o'rnatadi",
    "RECEIVE_BOOT_COMPLETED": "Telefon yonganda o'zi ishga tushadi",
    "READ_PHONE_STATE": "Telefon raqami/holatini o'qiydi",
    "PACKAGE_USAGE_STATS": "Qaysi ilovalardan foydalanishingizni kuzatadi",
}

TG_TOKEN_RE = re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}")
URL_RE = re.compile(r"https?://[^\s\"'<>)]+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _redact(token: str) -> str:
    return token[:6] + "…" + token[-4:] if len(token) > 12 else token


def check_apk(path: str) -> tuple:
    """APK'ni ishga tushirmasdan ichini o'qiydi (statik tahlil).
    Qaytaradi: (verdict, score, info_dict)."""
    from androguard.misc import AnalyzeAPK
    a, _d, dx = AnalyzeAPK(path)

    perms = a.get_permissions() or []
    info = {
        "name": a.get_app_name() or "noma'lum",
        "package": a.get_package() or "noma'lum",
        "version": a.get_androidversion_name() or "?",
        "permissions": perms,
        "dangerous": [],      # [(ruxsat, tarjima)]
        "behaviors": [],      # xatti-harakatlar
        "tokens": [],         # topilgan Telegram tokenlari (qisqartirilgan)
        "urls": [],           # topilgan manzillar
    }

    with open(path, "rb") as f:
        info["sha256"] = hashlib.sha256(f.read()).hexdigest()

    # Xavfli ruxsatlar
    for p in perms:
        short = p.split(".")[-1]
        if short in DANGEROUS_PERMS:
            info["dangerous"].append((short, DANGEROUS_PERMS[short]))

    # Kod ichidagi xatti-harakatlar (API chaqiruvlar)
    def has(classname, methodname):
        try:
            return bool(list(dx.find_methods(classname=classname,
                                             methodname=methodname)))
        except Exception:
            return False

    if has(r"Landroid/telephony/SmsManager;", r"sendTextMessage") or \
       has(r"Landroid/telephony/SmsManager;", r"sendMultipartTextMessage"):
        info["behaviors"].append("SMS yuboradi")
    if has(r"Ldalvik/system/DexClassLoader;", r"<init>") or \
       has(r"Ldalvik/system/PathClassLoader;", r"<init>"):
        info["behaviors"].append("Yashirin kodni keyin yuklaydi (dropper belgisi)")
    if has(r"Landroid/app/admin/DevicePolicyManager;", r".*"):
        info["behaviors"].append("Qurilma administratori huquqini so'raydi")

    # Kod ichidagi satrlar: tokenlar, manzillar
    seen_url = set()
    try:
        for s in dx.get_strings():
            val = s.get_value() if hasattr(s, "get_value") else str(s)
            if not val:
                continue
            for tok in TG_TOKEN_RE.findall(val):
                r = _redact(tok)
                if r not in info["tokens"]:
                    info["tokens"].append(r)
            if "api.telegram.org" in val and "telegram" not in info["behaviors"]:
                info["behaviors"].append("Ma'lumotni Telegram bot orqali yuboradi")
            for u in URL_RE.findall(val):
                host = u[:60]
                if host not in seen_url and "schemas.android" not in u \
                        and "w3.org" not in u and "google.com/apk" not in u:
                    seen_url.add(host)
                    if len(info["urls"]) < 8:
                        info["urls"].append(host)
    except Exception:
        pass

    # Xavf bali
    score = 10
    perm_shorts = {p.split(".")[-1] for p in perms}
    if "READ_SMS" in perm_shorts or "RECEIVE_SMS" in perm_shorts:
        score += 25
    if "SEND_SMS" in perm_shorts:
        score += 20
    if "SYSTEM_ALERT_WINDOW" in perm_shorts:
        score += 15
    if "RECEIVE_BOOT_COMPLETED" in perm_shorts:
        score += 10
    if "REQUEST_INSTALL_PACKAGES" in perm_shorts:
        score += 10
    if any("Telegram" in b for b in info["behaviors"]):
        score += 25
    if info["tokens"]:
        score += 20
    if any("dropper" in b for b in info["behaviors"]):
        score += 15
    if any("administratori" in b for b in info["behaviors"]):
        score += 15
    score = min(score, 100)

    verdict = "red" if score >= 70 else "yellow" if score >= 35 else "green"
    return verdict, score, info


# ── Parolli arxiv (keyingi bosqich — pyzipper) ────────────────────
def check_archive(path: str, passwords: list[str]):
    """Keyingi milestone: 2 daqiqa parol sinash, ochilsa APK tahlili."""
    raise NotImplementedError("Arxiv moduli keyingi bosqichda to'ldiriladi")
