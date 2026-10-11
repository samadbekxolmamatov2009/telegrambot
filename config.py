"""Sozlamalar — hammasi .env faylidan o'qiladi."""
import os
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN", "")
TURSO_URL = os.getenv("TURSO_URL", "")
TURSO_TOKEN = os.getenv("TURSO_TOKEN", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY", "")

ADMIN_IDS = {int(x) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip()}

MAX_FILE_MB = int(os.getenv("MAX_FILE_MB", "50"))
PASSWORD_TIMEOUT_SEC = int(os.getenv("PASSWORD_TIMEOUT_SEC", "120"))

# Xavf darajalari
GREEN, YELLOW, RED = "🟢", "🟡", "🔴"
