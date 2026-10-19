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
    "QUERY_ALL_PACKAGES": "Telefondagi barcha ilovalar ro'yxatini oladi "
                          "(bank ilovalarini aniqlash uchun)",
    "BIND_ACCESSIBILITY_SERVICE": "Ekraningizni o'qiydi va o'zi tugma bosadi",
}

TG_TOKEN_RE = re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}")
URL_RE = re.compile(r"https?://[^\s\"'<>)]+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# Telefon raqamlar — faqat xalqaro '+' bilan (yolg'on natijani kamaytiradi)
PHONE_RE = re.compile(r"\+\d{1,3}[\s-]?\(?\d{2,3}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}")

# OID prefikslari (sertifikatdagi 2.5.4.x kabi — IP emas)
_OID_PREFIX = ("2.5.", "1.2.", "1.3.", "2.16.", "0.")


def _valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octs = [int(p) for p in parts]
    except ValueError:
        return False
    if any(o < 0 or o > 255 for o in octs):
        return False
    if ip.startswith(_OID_PREFIX):
        return False
    # Haqiqiy IP'da odatda kamida bitta oktet > 20 bo'ladi (OID shovqinini kesadi)
    if all(o <= 20 for o in octs):
        return False
    return True


def _cert_info(a):
    """APK imzosi (kim yasagan/imzolagan) — forensik ma'lumot."""
    import hashlib
    try:
        certs = a.get_certificates()
        if not certs:
            return None
        c = certs[0]
        def field(dn, key):
            try:
                return dn.native.get(key)
            except Exception:
                return None
        subj = c.subject
        info = {
            "common_name": field(subj, "common_name"),
            "org": field(subj, "organization_name"),
            "email": field(subj, "email_address"),
            "country": field(subj, "country_name"),
            "not_before": str(c["tbs_certificate"]["validity"]["not_before"].native)[:10],
            "not_after": str(c["tbs_certificate"]["validity"]["not_after"].native)[:10],
            "sha256": hashlib.sha256(c.dump()).hexdigest(),
        }
        # Soxta imzo: o'zini Google/Android deb ko'rsatgan
        blob = " ".join(str(v) for v in info.values() if v).lower()
        info["impersonation"] = any(
            w in blob for w in ("android.com", "google", "com.android"))
        return info
    except Exception:
        return None


def _redact(token: str) -> str:
    return token[:6] + "…" + token[-4:] if len(token) > 12 else token


def _zinfo_size(z, name: str) -> int:
    try:
        return z.getinfo(name).file_size
    except Exception:
        return 0


def _entropy_of(z, name: str, sample: int = 262144) -> float:
    """Fayl boshidan namuna olib entropiyani hisoblaydi (0..8).
    8 ga yaqin = shifrlangan/siqilgan. Tez bo'lishi uchun faqat namuna."""
    import math
    from collections import Counter
    try:
        with z.open(name) as f:
            data = f.read(sample)
    except Exception:
        return 0.0
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


# androguard juda ko'p DEBUG log chiqaradi (loguru orqali) — o'chiramiz,
# aks holda loglar toshadi va sekinlashadi.
try:
    from loguru import logger as _loguru
    _loguru.remove()
except Exception:
    pass

# Kodda qidiriladigan xavfli imzolar (DEX satrlar orasidan)
CODE_SIGNS = {
    "Landroid/telephony/SmsManager;": None,       # SMS bilan ishlash
    "sendTextMessage": "SMS yuboradi",
    "Ldalvik/system/DexClassLoader;": "Qo'shimcha yashirin kod yuklaydi (DexClassLoader)",
    "Ldalvik/system/InMemoryDexClassLoader;": "Qo'shimcha yashirin kod yuklaydi (DexClassLoader)",
    "Landroid/app/admin/DevicePolicyManager;": "Qurilma administratori huquqini so'raydi",
    "android/accessibilityservice": "Accessibility (ekranni boshqarish) ishlatadi",
}

# Packer/dropper kripto va yuklash imzolari (DEX satrlarida)
CRYPTO_SIGNS = ["Ljavax/crypto/Cipher;", "AES/", "javax.crypto", "Ljavax/crypto/spec/SecretKeySpec;"]
LOADLIB_SIGNS = ["loadLibrary", "System/loadLibrary", "Ljava/lang/System;->loadLibrary"]


def check_apk(path: str) -> tuple:
    """APK'ni ishga tushirmasdan ichini o'qiydi (yengil statik tahlil:
    manifest + DEX satrlari, kod grafini qurmasdan — 512 MB uchun mos).
    Qaytaradi: (verdict, score, info_dict)."""
    from androguard.core.apk import APK
    from androguard.core.dex import DEX

    a = APK(path)
    perms = a.get_permissions() or []
    info = {
        "name": a.get_app_name() or "noma'lum",
        "package": a.get_package() or "noma'lum",
        "version": a.get_androidversion_name() or "?",
        "permissions": perms,
        "dangerous": [],
        "behaviors": [],
        "tokens": [],
        "urls": [],
    }

    import os
    with open(path, "rb") as f:
        info["sha256"] = hashlib.sha256(f.read()).hexdigest()
    info["size_kb"] = round(os.path.getsize(path) / 1024)
    info["signer"] = _cert_info(a)
    info["emails"] = []
    info["ips"] = []
    info["phones"] = []

    # Qo'shimcha metama'lumot (maksimal ma'lumot)
    def _safe(fn, default=None):
        try:
            return fn()
        except Exception:
            return default
    info["min_sdk"] = _safe(a.get_min_sdk_version)
    info["target_sdk"] = _safe(a.get_target_sdk_version)
    info["main_activity"] = _safe(a.get_main_activity)
    info["activities"] = _safe(a.get_activities, []) or []
    info["services"] = _safe(a.get_services, []) or []
    info["receivers"] = _safe(a.get_receivers, []) or []
    info["providers"] = _safe(a.get_providers, []) or []
    info["features"] = list(_safe(lambda: a.get_features(), []) or [])

    # Xavfli ruxsatlar
    for p in perms:
        short = p.split(".")[-1]
        if short in DANGEROUS_PERMS:
            info["dangerous"].append((short, DANGEROUS_PERMS[short]))

    # DEX satrlarini o'qish (kod grafini qurmasdan — yengil va tez)
    seen_url = set()
    found_signs = set()
    has_crypto = False
    has_loadlib = False
    try:
        for dex_bytes in a.get_all_dex():
            try:
                d = DEX(dex_bytes)
                strings = d.get_strings()
            except Exception:
                continue
            for s in strings:
                val = s.decode("utf-8", "ignore") if isinstance(s, bytes) else str(s)
                if not val:
                    continue
                for sign, desc in CODE_SIGNS.items():
                    if sign in val and desc:
                        found_signs.add(desc)
                if any(c in val for c in CRYPTO_SIGNS):
                    has_crypto = True
                if any(l in val for l in LOADLIB_SIGNS):
                    has_loadlib = True
                for tok in TG_TOKEN_RE.findall(val):
                    r = _redact(tok)
                    if r not in info["tokens"]:
                        info["tokens"].append(r)
                if "api.telegram.org" in val:
                    found_signs.add("Ma'lumotni Telegram bot orqali yuboradi")
                for em in EMAIL_RE.findall(val):
                    if em not in info["emails"] and len(info["emails"]) < 8 \
                            and "@android.com" not in em and "@example" not in em:
                        info["emails"].append(em)
                for ip in IP_RE.findall(val):
                    if ip not in info["ips"] and len(info["ips"]) < 8 \
                            and _valid_ip(ip) and not ip.startswith(("127.", "255.")):
                        info["ips"].append(ip)
                for ph in PHONE_RE.findall(val):
                    if ph not in info["phones"] and len(info["phones"]) < 8:
                        info["phones"].append(ph)
                for u in URL_RE.findall(val):
                    host = u[:60]
                    if host not in seen_url and "schemas.android" not in u \
                            and "w3.org" not in u and "googleapis" not in u \
                            and "google.com/apk" not in u:
                        seen_url.add(host)
                        if len(info["urls"]) < 8:
                            info["urls"].append(host)
    except Exception:
        pass

    # ── Packer/dropper tahlili (ZIP darajasida) ──────────────────
    packer = []   # xavf bali uchun kalitlar
    try:
        import zipfile
        z = zipfile.ZipFile(path)
        names = z.namelist()
        # 1. Fayllar "shifrlangan" bayrog'i bilan belgilangan (anti-analiz)
        enc = [i.filename for i in z.infolist() if (i.flag_bits & 0x1)]
        if enc:
            found_signs.add("Fayllar yashirilgan (anti-analiz: ZIP shifr bayrog'i)")
            packer.append("enc_zip")
        # 2. Native kod (.so)
        libs = sorted({n.split("/")[2] for n in names
                       if n.startswith("lib/") and n.endswith(".so")
                       and len(n.split("/")) > 2})
        info["libs"] = libs
        archs = sorted({n.split("/")[1] for n in names
                        if n.startswith("lib/") and len(n.split("/")) > 1})
        info["lib_archs"] = archs
        if any(n.startswith("lib/") and n.endswith(".so") for n in names):
            found_signs.add("Native kod yuklaydi (.so kutubxona)")
            packer.append("native")
        # 3. Yashirin shifrlangan payload:
        #    (a) media/dat kengaytmali yirik asset, yoki
        #    (b) matndek atalgan (.json/.txt/.xml...) fayl, lekin ENTROPIYASI yuqori
        #        (haqiqiy JSON ~5, 7.4+ = shifrlangan/siqilgan => soxta)
        TEXTLIKE = (".json", ".txt", ".xml", ".csv", ".cfg", ".properties",
                    ".html", ".js", ".db", ".conf", ".ini", ".yml", ".yaml")
        MEDIA = (".wma", ".mp3", ".mp4", ".dat", ".png", ".jpg", ".bin", ".3gp")
        hidden = []
        for n in names:
            if not n.startswith("assets/"):
                continue
            sz = _zinfo_size(z, n)
            low = n.lower()
            if low.endswith(MEDIA) and sz > 50_000:
                hidden.append(n)
            elif low.endswith(TEXTLIKE) and sz > 30_000:
                # matndek atalgan faylning entropiyasini tekshiramiz
                if _entropy_of(z, n) > 7.2:
                    hidden.append(n)
            elif ("." not in low.rsplit("/", 1)[-1]) and sz > 100_000:
                # kengaytmasiz yirik asset — entropiya yuqori bo'lsa shubhali
                if _entropy_of(z, n) > 7.4:
                    hidden.append(n)
        if hidden:
            found_signs.add("Shifrlangan yashirin fayl topildi (payload) — "
                            "haqiqiy ish shu yerda yashirilgan")
            packer.append("hidden_payload")
        # 4. Ikonka yashirish belgisi
        if any("hidden" in n.lower() and "logo" in n.lower() for n in names) or \
           any("hidden_app" in n.lower() for n in names):
            found_signs.add("Ikonkasini yashirishi mumkin")
            packer.append("hide_icon")
    except Exception:
        pass

    # Kripto + yuklash birgalikda = packer
    if has_crypto and (has_loadlib or "native" in packer):
        found_signs.add("Kodni shifrlab yashiradi (packer: AES/Cipher + yuklash)")
        packer.append("crypto_pack")

    # 5. Niqoblash
    disguise_words = ("rasm", "photo", "video", "galereya", "gallery", "foto",
                      "player", "music", "pdf", "hujjat", "surat", "arxiv",
                      "arxivi", "to'y", "toy", "album", "surat")
    nm = (info["name"] or "").lower()
    # Nomi fayldek ko'rsatilgan (.jpeg/.pdf/.mp4...) — ilova hech qachon bunday atalmaydi
    ext_m = re.search(r"\.(jpe?g|png|gif|bmp|pdf|docx?|xlsx?|pptx?|mp4|mp3|wav|zip|rar|apk|txt|heic)\b", nm)
    if ext_m:
        found_signs.add(f"Niqoblangan: nomi fayldek ko'rsatilgan ('{ext_m.group(0)}')")
        packer.append("disguise")
    elif any(w in nm for w in disguise_words) and packer:
        found_signs.add("Niqoblangan: oddiy ilova ko'rinadi, lekin kodi yashirilgan")
        packer.append("disguise")
    # Paket nomida "hidden" kabi so'z
    if "hidden" in (info["package"] or "").lower():
        found_signs.add("Paket nomida 'hidden' (yashirin) so'zi bor")
        packer.append("sus_pkg")

    # Soxta imzo (o'zini Google/Android deb ko'rsatgan)
    if info.get("signer") and info["signer"].get("impersonation"):
        found_signs.add("Soxta imzo: o'zini Google/Android deb ko'rsatgan")
        packer.append("fake_cert")

    # Dropper kombinatsiyasi: boshqa ilova o'rnatish + barcha ilovalarni ko'rish
    _ps = {p.split(".")[-1] for p in perms}
    if "REQUEST_INSTALL_PACKAGES" in _ps and "QUERY_ALL_PACKAGES" in _ps:
        found_signs.add("Boshqa ilova o'rnatadi + barcha ilovalarni kuzatadi "
                        "(dropper kombinatsiyasi)")
        packer.append("dropper_combo")

    info["behaviors"] = sorted(found_signs)
    info["_packer"] = packer

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
    if "QUERY_ALL_PACKAGES" in perm_shorts:
        score += 10
    if any("Telegram" in b for b in info["behaviors"]):
        score += 25
    if info["tokens"]:
        score += 20
    if any("DexClassLoader" in b for b in info["behaviors"]):
        score += 20
    if any("administratori" in b for b in info["behaviors"]):
        score += 15

    # Packer/dropper indikatorlari
    pk = info.get("_packer", [])
    if "crypto_pack" in pk:
        score += 30
    if "hidden_payload" in pk:
        score += 20
    if "enc_zip" in pk:
        score += 20
    if "native" in pk:
        score += 10
    if "hide_icon" in pk:
        score += 15
    if "disguise" in pk:
        score += 20
    if "sus_pkg" in pk:
        score += 15
    if "fake_cert" in pk:
        score += 25
    if "dropper_combo" in pk:
        score += 20
    # Ikki yoki undan ortiq KUCHLI belgi birga bo'lsa — aniq xavfli
    # (native o'zi oddiy ilovalarda ham bo'ladi, shuning uchun kuchli emas)
    STRONG = ("crypto_pack", "hidden_payload", "enc_zip", "hide_icon",
              "disguise", "sus_pkg", "fake_cert", "dropper_combo")
    if len([x for x in pk if x in STRONG]) >= 2:
        score = max(score, 75)
    # Yashirin shifrlangan payload o'zi ham juda kuchli dalil
    if "hidden_payload" in pk and ("REQUEST_INSTALL_PACKAGES" in perm_shorts
                                   or "disguise" in pk or "dropper_combo" in pk):
        score = max(score, 75)

    score = min(score, 100)
    info.pop("_packer", None)

    verdict = "red" if score >= 70 else "yellow" if score >= 35 else "green"
    return verdict, score, info


# ── Parolli arxiv (.zip) ──────────────────────────────────────────
COMMON_PW = ["1234", "12345", "123456", "0000", "1111", "123123",
             "password", "parol", "qwerty", "admin", "infected", "virus",
             "12345678", "000000", "111111", "123", "apk"]


def check_archive(path: str, passwords=None):
    """ZIP ichidan APK topib tahlil qiladi. Parolli bo'lsa, berilgan va
    oddiy parollarni sinaydi. Qaytaradi: dict (status + ma'lumot)."""
    import os
    import tempfile
    import pyzipper

    try:
        z = pyzipper.AESZipFile(path)
    except Exception as e:
        return {"status": "error", "error": str(e)}

    with z:
        infos = z.infolist()
        names = [i.filename for i in infos]
        encrypted = any(i.flag_bits & 0x1 for i in infos)
        # ZIP-bomba himoyasi
        total = sum(i.file_size for i in infos)
        if total > 300 * 1024 * 1024:
            return {"status": "error", "error": "arxiv juda katta (ZIP-bomba?)"}

        # .zip aslida APK'ning o'zimi? (APK ham zip; ichida AndroidManifest bor)
        is_apk_itself = any(n.endswith("AndroidManifest.xml") for n in names) and \
            any(n.endswith("classes.dex") for n in names)
        apk_names = [n for n in names if n.lower().endswith(".apk")]

    # Fayl aslida APK bo'lsa — to'g'ridan-to'g'ri tahlil qilamiz.
    # (APK'da soxta "shifr" bayrog'i bo'lishi mumkin — androguard baribir o'qiydi.)
    if is_apk_itself:
        try:
            verdict, score, info = check_apk(path)
        except Exception as e:
            return {"status": "error", "error": str(e)}
        info.setdefault("behaviors", [])
        info["behaviors"].insert(0, "Fayl .zip deb atalgan, lekin aslida APK (ilova)")
        if score < 50:
            score = max(score, 50)
            verdict = "red" if score >= 70 else "yellow"
        return {"status": "apk", "verdict": verdict, "score": score,
                "info": info, "password": None, "apk_name": "(fayl o'zi APK)"}

    if not apk_names:
        return {"status": "no_apk", "names": names[:20], "encrypted": encrypted}

    target = apk_names[0]
    pw_used = None
    data = None
    pw_list = list(passwords or []) + COMMON_PW
    with pyzipper.AESZipFile(path) as z2:
        if encrypted:
            for pw in pw_list:
                try:
                    z2.setpassword(pw.encode())
                    data = z2.read(target)
                    pw_used = pw
                    break
                except Exception:
                    continue
            if data is None:
                return {"status": "locked", "apk_name": target,
                        "names": names[:20]}
        else:
            try:
                data = z2.read(target)
            except Exception as e:
                return {"status": "error", "error": str(e)}

    # Topilgan APK'ni vaqtincha yozib tahlil qilamiz
    tmp = tempfile.mkdtemp()
    apk_path = os.path.join(tmp, "inner.apk")
    try:
        with open(apk_path, "wb") as f:
            f.write(data)
        verdict, score, info = check_apk(apk_path)
    except Exception as e:
        return {"status": "error", "error": str(e), "password": pw_used}
    finally:
        try:
            os.remove(apk_path)
            os.rmdir(tmp)
        except Exception:
            pass

    # Arxiv ichida yashiringanning o'zi — qo'shimcha shubha
    info.setdefault("behaviors", [])
    if "Arxiv ichiga yashiringan" not in info["behaviors"]:
        info["behaviors"].insert(0, "Arxiv ichiga yashiringan")
    if score < 35:
        score = 35  # arxivda yashirilgan ilova hech bo'lmasa shubhali
        verdict = "yellow"
    return {"status": "apk", "verdict": verdict, "score": score,
            "info": info, "password": pw_used, "apk_name": target}
