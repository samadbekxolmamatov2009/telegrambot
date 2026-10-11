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


# ── APK tahlili (keyingi bosqich — androguard) ────────────────────
def check_apk(path: str):
    """Keyingi milestone: ruxsatlar, API chaqiruvlar, token/ID topish."""
    raise NotImplementedError("APK moduli keyingi bosqichda to'ldiriladi")


# ── Parolli arxiv (keyingi bosqich — pyzipper) ────────────────────
def check_archive(path: str, passwords: list[str]):
    """Keyingi milestone: 2 daqiqa parol sinash, ochilsa APK tahlili."""
    raise NotImplementedError("Arxiv moduli keyingi bosqichda to'ldiriladi")
