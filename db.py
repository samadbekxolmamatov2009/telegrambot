"""Turso (bulutli SQLite) bilan ishlash. Har tekshiruv shu yerga yoziladi."""
import time
import libsql_client
import config

_client = None


def _c():
    global _client
    if _client is None:
        _client = libsql_client.create_client(
            url=config.TURSO_URL, auth_token=config.TURSO_TOKEN
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
    return {
        "total": total.rows[0][0],
        "users": total.rows[0][1],
        "green": by_verdict.get("green", 0),
        "yellow": by_verdict.get("yellow", 0),
        "red": by_verdict.get("red", 0),
    }
