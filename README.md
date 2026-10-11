# HaloskorTekshir — Telegram firibgarlik ovchisi

Shubhali xabar, havola yoki fayl (.apk / .zip) ni tekshirib, xavf darajasini
o'zbek tilida tushuntiradigan bot.

## Hozir tayyor (1-bosqich skelet)
- Bot 4 turdagi xabarni qabul qiladi: matn, havola, .apk, .zip
- Matn va havola tahlili ishlaydi (asosiy qoidalar)
- Turso bazasiga har tekshiruv yoziladi
- Tugmalar, xavf darajasi (🟢/🟡/🔴), maslahat

## Keyingi bosqichlar
- [ ] APK tahlili (androguard): ruxsatlar, API chaqiruvlar, token/ID topish
- [ ] Parolli arxiv: 2 daqiqa parol sinash
- [ ] VirusTotal + Safe Browsing ulanishi
- [ ] Admin panel (statistika)

## Ishga tushirish
```bash
pip install -r requirements.txt
cp .env.example .env     # va .env ni to'ldiring
python bot.py
```

## Render'ga joylash
- Yangi "Background Worker" oching (Web Service emas — polling uchun)
- Build: `pip install -r requirements.txt`
- Start: `python bot.py`
- Environment'ga .env dagi kalitlarni qo'shing

## Turso baza
```bash
turso db create firibtekshir
turso db show firibtekshir --url      # TURSO_URL
turso db tokens create firibtekshir   # TURSO_TOKEN
```
