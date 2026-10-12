"""Turso (bulutli SQLite) bilan ishlash. Har tekshiruv shu yerga yoziladi."""
import time
import libsql_client
import config

_client = None


def _normalize_url(url: str) -> str:
    """libsql:// (websocket) o'rniga https:// (HTTP) — barqarorroq va
    xatolarni aniq ko'rsatadi (noto'g'ri token -> 401, 400 emas)."""
    url = url.strip()
    if url.startswith("libsql://"):
        url = "https://" + url[len("libsql://"):]
    elif url.startswith("wss://"):
        url = "https://" + url[len("wss://"):]
    elif url.startswith("ws://"):
        url = "http://" + url[len("ws://"):]
    return url


def _c():
    global _client
    if _client is None:
        _client = libsql_client.create_client(
            url=_normalize_url(config.TURSO_URL),
            auth_token=config.TURSO_TOKEN.strip(),
        )
    return _client


async def init():
    """Jadvallarni yaratadi (bir marta)."""
    await _c().execute("""
        CREATE TABLE IF NOT EXISTS checks (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   INTEGER,
            kind      TEXT,          -- text | link | apk | archive
            verdict   TEXT,          -- green | yellow | red
            score     INTEGER,
            detail    TEXT,          -- qisqa izoh
            created   INTEGER
        )
    """)
    await _c().execute("""
        CREATE TABLE IF NOT EXISTS found_tokens (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            token   TEXT,            -- topilgan firibgar tokeni (qisqartirilgan)
            source  TEXT,            -- qaysi fayldan
            created INTEGER
        )
    """)
    await _c().execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id    INTEGER PRIMARY KEY,
            name       TEXT,
            first_seen INTEGER,
            last_seen  INTEGER,
            checks     INTEGER DEFAULT 0
        )
    """)


async def touch_user(user_id, name, is_check=False):
    """Foydalanuvchini yozadi/yangilaydi. is_check=True bo'lsa tekshiruv sanaydi."""
    now = int(time.time())
    inc = 1 if is_check else 0
    await _c().execute(
        "INSERT INTO users (user_id, name, first_seen, last_seen, checks) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(user_id) DO UPDATE SET name=excluded.name, "
        "last_seen=excluded.last_seen, checks=checks+?",
        [user_id, name, now, now, inc, inc],
    )


async def log_check(user_id, kind, verdict, score, detail):
    await _c().execute(
        "INSERT INTO checks (user_id, kind, verdict, score, detail, created) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [user_id, kind, verdict, score, detail, int(time.time())],
    )


async def save_token(token, source):
    await _c().execute(
        "INSERT INTO found_tokens (token, source, created) VALUES (?, ?, ?)",
        [token, source, int(time.time())],
    )


async def stats():
    """Admin panel uchun umumiy raqamlar."""
    r = await _c().execute(
        "SELECT verdict, COUNT(*) FROM checks GROUP BY verdict"
    )
    by_verdict = {row[0]: row[1] for row in r.rows}
    total = await _c().execute("SELECT COUNT(*), COUNT(DISTINCT user_id) FROM checks")
    day_ago = int(time.time()) - 86400
    today = await _c().execute(
        "SELECT COUNT(*) FROM checks WHERE created > ?", [day_ago])
    by_kind = await _c().execute(
        "SELECT kind, COUNT(*) FROM checks GROUP BY kind")
    ntok = await _c().execute("SELECT COUNT(*) FROM found_tokens")
    return {
        "total": total.rows[0][0],
        "users": total.rows[0][1],
        "today": today.rows[0][0],
        "green": by_verdict.get("green", 0),
        "yellow": by_verdict.get("yellow", 0),
        "red": by_verdict.get("red", 0),
        "by_kind": {row[0]: row[1] for row in by_kind.rows},
        "tokens": ntok.rows[0][0],
    }


async def recent(limit=8):
    """Oxirgi tekshiruvlar."""
    r = await _c().execute(
        "SELECT kind, verdict, score, detail, created FROM checks "
        "ORDER BY id DESC LIMIT ?", [limit])
    return r.rows


async def top_threats(limit=6):
    """Eng ko'p uchragan xavfli tekshiruvlar."""
    r = await _c().execute(
        "SELECT detail, COUNT(*) c FROM checks WHERE verdict='red' "
        "GROUP BY detail ORDER BY c DESC LIMIT ?", [limit])
    return r.rows


async def list_tokens(limit=10):
    """Topilgan firibgar tokenlari."""
    r = await _c().execute(
        "SELECT token, source, created FROM found_tokens "
        "ORDER BY id DESC LIMIT ?", [limit])
    return r.rows


async def users_list(limit=15):
    """Oxirgi faol foydalanuvchilar."""
    r = await _c().execute(
        "SELECT user_id, name, checks, last_seen FROM users "
        "ORDER BY last_seen DESC LIMIT ?", [limit])
    return r.rows


async def users_count():
    r = await _c().execute("SELECT COUNT(*) FROM users")
    return r.rows[0][0]


async def user_checks(user_id, limit=15):
    """Foydalanuvchining o'zi tekshirgan APK/arxivlar tarixi."""
    r = await _c().execute(
        "SELECT verdict, score, detail, created FROM checks "
        "WHERE user_id=? AND kind IN ('apk','archive') "
        "ORDER BY id DESC LIMIT ?", [user_id, limit])
    return r.rows
