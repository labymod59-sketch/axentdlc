"""
Axent: сайт регистрации + API авторизации для лаунчера.

Запуск:   pip install flask   &&   python app.py
Адрес:    http://127.0.0.1:8080  (порт/хост меняются через переменные AXENT_HOST / AXENT_PORT)

Что делает:
  /                 страница регистрации / входа (форма как на макете)
  POST /api/register  создать аккаунт
  POST /api/login     войти (из лаунчера: выдаёт токен сессии; с сайта: только проверка)
  POST /api/verify    проверить токен сессии (лаунчер зовёт при каждом запуске и перед игрой)
  POST /api/logout    закрыть сессию

Данные лежат в users.db (SQLite) рядом с app.py. Пароли хранятся только в виде хеша (scrypt).
Секрет для подписи формы создаётся автоматически в secret.key.
"""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path

from flask import Flask, g, jsonify, request, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "users.db"
SESSION_DAYS = 30
MIN_FORM_SECONDS = 3          # быстрее человек форму не заполнит: защита от тупых ботов
USERNAME_RE = re.compile(r"[A-Za-z0-9_]{3,16}")   # заодно это ник в игре
EMAIL_RE = re.compile(r"[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}")

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


# ───────────── секрет ─────────────
def _secret() -> bytes:
    p = ROOT / "secret.key"
    if not p.exists():
        p.write_bytes(secrets.token_bytes(32))
    return p.read_bytes()


SECRET = _secret()


def sign_ts(ts: int) -> str:
    return f"{ts}.{hmac.new(SECRET, str(ts).encode(), hashlib.sha256).hexdigest()[:32]}"


def check_ts(value: str) -> bool:
    try:
        ts, _ = value.split(".", 1)
        ts = int(ts)
    except Exception:
        return False
    if not hmac.compare_digest(sign_ts(ts), value):
        return False
    age = time.time() - ts
    return MIN_FORM_SECONDS <= age <= 3600


# ───────────── база ─────────────
def db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    with sqlite3.connect(DB_PATH) as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            pw_hash TEXT NOT NULL,
            created INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions(
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires INTEGER NOT NULL
        );
        """)


# ───────────── лимиты попыток ─────────────
_hits: dict = {}


def limited(key: str, limit: int, window: int = 60) -> bool:
    now = time.time()
    arr = [t for t in _hits.get(key, []) if now - t < window]
    if len(arr) >= limit:
        _hits[key] = arr
        return True
    arr.append(now)
    _hits[key] = arr
    return False


def ip() -> str:
    return request.remote_addr or "?"


def err(code: str, status: int = 400):
    return jsonify(ok=False, error=code), status


# ───────────── API ─────────────
@app.post("/api/register")
def register():
    if limited("reg:" + ip(), 5):
        return err("rate", 429)
    d = request.get_json(silent=True) or {}
    username = str(d.get("username", "")).strip()
    email = str(d.get("email", "")).strip()
    password = str(d.get("password", ""))
    if d.get("website"):                       # honeypot: человек это поле не видит
        return err("bot")
    if d.get("human") is not True or not check_ts(str(d.get("ts", ""))):
        return err("human")
    if not USERNAME_RE.fullmatch(username):
        return err("username")
    if not EMAIL_RE.fullmatch(email) or len(email) > 254:
        return err("email")
    if not (8 <= len(password) <= 128):
        return err("password")
    if password != str(d.get("confirm", "")):
        return err("mismatch")
    if db().execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        return err("username_taken", 409)
    if db().execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
        return err("email_taken", 409)
    try:
        with db() as c:
            c.execute("INSERT INTO users(username,email,pw_hash,created) VALUES(?,?,?,?)",
                      (username, email, generate_password_hash(password), int(time.time())))
    except sqlite3.IntegrityError:           # гонка: два запроса одновременно
        return err("username_taken", 409)
    return jsonify(ok=True, username=username)


@app.post("/api/login")
def login():
    if limited("login:" + ip(), 10):
        return err("rate", 429)
    d = request.get_json(silent=True) or {}
    ident = str(d.get("username", "")).strip()
    row = db().execute("SELECT * FROM users WHERE username=? OR email=?", (ident, ident)).fetchone()
    # проверяем хеш всегда, чтобы время ответа не выдавало, существует ли логин
    ok = check_password_hash(row["pw_hash"] if row else generate_password_hash("x"), str(d.get("password", "")))
    if not row or not ok:
        return err("invalid", 401)
    if d.get("client") != "launcher":          # с сайта только проверяем пароль, сессию не создаём
        return jsonify(ok=True, username=row["username"])
    token = secrets.token_urlsafe(32)
    with db() as c:
        c.execute("DELETE FROM sessions WHERE expires < ?", (int(time.time()),))
        c.execute("INSERT INTO sessions(token_hash,user_id,expires) VALUES(?,?,?)",
                  (hashlib.sha256(token.encode()).hexdigest(), row["id"], int(time.time()) + SESSION_DAYS * 86400))
    return jsonify(ok=True, username=row["username"], token=token)


@app.post("/api/verify")
def verify():
    if limited("verify:" + ip(), 60):
        return err("rate", 429)
    token = str((request.get_json(silent=True) or {}).get("token", ""))
    row = db().execute(
        "SELECT u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>?",
        (hashlib.sha256(token.encode()).hexdigest(), int(time.time()))).fetchone()
    if not row:
        return err("invalid", 401)
    return jsonify(ok=True, username=row["username"])


@app.post("/api/logout")
def logout():
    token = str((request.get_json(silent=True) or {}).get("token", ""))
    with db() as c:
        c.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
    return jsonify(ok=True)


# ───────────── страницы ─────────────
@app.get("/api/ts")
def get_ts():
    return jsonify(ts=sign_ts(int(time.time())))


@app.get("/")
@app.get("/register")
def page_register():
    return send_from_directory(ROOT / "pages", "index.html")


@app.get("/login")
def page_login():
    return send_from_directory(ROOT / "pages", "index.html")


@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Cache-Control"] = "no-store"
    return r


init_db()

if __name__ == "__main__":
    app.run(host=os.environ.get("AXENT_HOST", "127.0.0.1"), port=int(os.environ.get("AXENT_PORT", "8080")))
