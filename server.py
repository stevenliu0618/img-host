import os
import re
import shutil
import mimetypes
import base64
import hashlib
import json
import random
import time
import logging
import threading
from pathlib import Path
from datetime import datetime, timedelta

import requests as http_requests
import jwt as pyjwt
import bcrypt as _bcrypt
import psycopg2
from psycopg2.extras import DictCursor
from psycopg2 import pool
from fastapi import FastAPI, File, UploadFile, HTTPException, Header, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from github import Github, GithubException

# ── 日志配置 ──────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ── 配置 ──────────────────────────────────────────────────────────────────
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO  = os.environ.get("GITHUB_REPO", "stevenliu0618/images")
# jsDelivr CDN URL，动态基于 GITHUB_REPO 生成，无需硬编码
GITHUB_RAW_BASE = f"https://cdn.jsdelivr.net/gh/{GITHUB_REPO}@main/assets"
DATA_DIR    = Path(os.environ.get("DATA_DIR", "/data"))
ASSETS_DIR  = DATA_DIR / "assets"
ALLOWED_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}  # SVG 已移除（XSS 风险）

# ── CORS 配置 ─────────────────────────────────────────────────────────────
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "")  # 例如: https://deepnovis.com

app = FastAPI(title="图床上传服务")

if ALLOWED_ORIGIN:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[ALLOWED_ORIGIN],
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )
else:
    logger.warning("⚠️ 未设置 ALLOWED_ORIGIN，CORS 允许所有来源（生产环境不安全）")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

# ── JWT 配置（强制要求环境变量）───────────────────────────────────────────
JWT_SECRET = os.environ.get("JWT_SECRET", "")
if not JWT_SECRET:
    logger.error("❌ JWT_SECRET 环境变量未设置，拒绝启动。请设置：export JWT_SECRET=<随机字符串>")
    exit(1)
JWT_ALGO = "HS256"
JWT_EXPIRE_HOURS = 72

# ── API Key 加密（Fernet 对称加密）────────────────────────────────────────
_fernet_key = None

def _get_fernet():
    global _fernet_key
    if _fernet_key is None:
        digest = hashlib.sha256(JWT_SECRET.encode()).digest()
        _fernet_key = base64.urlsafe_b64encode(digest)
    from cryptography.fernet import Fernet
    return Fernet(_fernet_key)

def _encrypt_api_key(key: str) -> str:
    if not key:
        return ""
    f = _get_fernet()
    return f.encrypt(key.encode()).decode()

def _decrypt_api_key(encrypted: str) -> str:
    if not encrypted:
        return ""
    f = _get_fernet()
    return f.decrypt(encrypted.encode()).decode()

# ── 暴力破解防护（IP + 邮箱双维度限速）────────────────────────────────────
_ip_rate_limit: dict = {}        # { ip: { count, reset_at } }
_verification_attempts: dict = {}  # { email: [(code_hash, timestamp), ...] }
_max_VERIFICATION_FAILURES = 10   # 验证码连续错误 10 次后封禁该邮箱 30 分钟
_VERIFICATION_FAIL_WINDOW = 1800   # 30 分钟窗口
_CODE_LENGTH = 8                  # 8 位数字字母混合（10^8 穷举难度）

# 定期清理过期记录，防止内存泄漏
def _cleanup_rate_limit():
    now = time.time()
    cutoff = now - 600
    for ip in list(_ip_rate_limit.keys()):
        if _ip_rate_limit[ip]["reset_at"] < cutoff:
            del _ip_rate_limit[ip]
    cutoff2 = now - _VERIFICATION_FAIL_WINDOW * 2
    for email in list(_verification_attempts.keys()):
        _verification_attempts[email] = [
            (h, ts) for h, ts in _verification_attempts[email] if ts > cutoff2
        ]
        if not _verification_attempts[email]:
            del _verification_attempts[email]

_cleanup_thread = threading.Thread(target=lambda: (_cleanup_rate_limit(), time.sleep(60)), daemon=True)
_cleanup_thread.start()

def _check_ip_rate_limit(client_ip: str, max_req: int = 30, window: int = 60) -> bool:
    """检查 IP 频率限制，返回 False 表示被限流。"""
    now = time.time()
    entry = _ip_rate_limit.get(client_ip, {"count": 0, "reset_at": now + window})
    if now > entry["reset_at"]:
        entry = {"count": 0, "reset_at": now + window}
    entry["count"] += 1
    _ip_rate_limit[client_ip] = entry
    return entry["count"] <= max_req

def _check_verification_failures(email: str) -> bool:
    """检查验证码连续失败次数。"""
    now = time.time()
    attempts = _verification_attempts.get(email, [])
    recent = [h for h, ts in attempts if now - ts < _VERIFICATION_FAIL_WINDOW]
    return len(recent) < _max_VERIFICATION_FAILURES


# ── PostgreSQL 配置（强制 SSL）────────────────────────────────────────────
DATABASE_URL = os.environ.get("DATABASE_URL", "")
# 自动追加 sslmode=require 确保生产环境数据库通信加密
if DATABASE_URL and "sslmode" not in DATABASE_URL:
    DATABASE_URL += ("?" if "?" in DATABASE_URL else "&") + "sslmode=require"
_db_pool = None

# ── 超时统一配置 ──────────────────────────────────────────────────────────
HTTP_TIMEOUT_SHORT = 10   # 查询、health check
HTTP_TIMEOUT_MEDIUM = 15  # 邮件、代理
HTTP_TIMEOUT_LONG = 60    # GPT 生成任务

# ── 密码强度验证 ──────────────────────────────────────────────────────────
_PASSWORD_MIN_LEN = 10

def _validate_password_strength(password: str) -> tuple[bool, str]:
    """验证密码复杂度，返回 (是否通过, 错误信息)。"""
    if len(password) < _PASSWORD_MIN_LEN:
        return False, f"密码至少 {_PASSWORD_MIN_LEN} 位字符"
    if not re.search(r"[A-Z]", password):
        return False, "密码需包含至少一个大写字母"
    if not re.search(r"[a-z]", password):
        return False, "密码需包含至少一个小写字母"
    if not re.search(r"[0-9]", password):
        return False, "密码需包含至少一个数字"
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:'\"<>,.?/\\~`]", password):
        return False, "密码需包含至少一个特殊字符"
    return True, ""

def _init_db_pool():
    """初始化 PostgreSQL 连接池（启动时调用一次）。"""
    global _db_pool
    if not DATABASE_URL:
        return False
    try:
        _db_pool = pool.SimpleConnectionPool(
            minconn=1,
            maxconn=10,
            dsn=DATABASE_URL,
        )
        return True
    except Exception:
        return False

def _get_conn():
    """从连接池取一个连接，用完后必须调用 putconn。"""
    if not _db_pool:
        raise HTTPException(500, "数据库未配置")
    return _db_pool.getconn()

def _put_conn(conn):
    if conn and _db_pool:
        _db_pool.putconn(conn)

def init_db():
    """建表（启动时调用）。"""
    if not DATABASE_URL:
        return
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                email       TEXT PRIMARY KEY,
                password    TEXT NOT NULL,
                username    TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                gpt_api_key TEXT NOT NULL DEFAULT ''
            );
        """)
        conn.commit()
        cur.close()
    except Exception as e:
        conn.rollback()
        raise HTTPException(500, f"数据库初始化失败: {e}")
    finally:
        _put_conn(conn)

def _row_to_user(row) -> dict:
    return {
        "password": row["password"],
        "email": row["email"],
        "username": row["username"],
        "created_at": row["created_at"],
        "gpt_api_key": row["gpt_api_key"] or "",
    }

def db_get_user(email: str) -> dict | None:
    """按 email 查用户，不存在返回 None。"""
    conn = _get_conn()
    try:
        cur = conn.cursor(cursor_factory=DictCursor)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        row = cur.fetchone()
        cur.close()
        return _row_to_user(row) if row else None
    finally:
        _put_conn(conn)

def db_user_exists(email: str) -> bool:
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM users WHERE email = %s", (email,))
        exists = cur.fetchone() is not None
        cur.close()
        return exists
    finally:
        _put_conn(conn)

def db_create_user(email: str, password_hash: str, username: str):
    """插入新用户。"""
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (email, password, username, created_at, gpt_api_key) VALUES (%s, %s, %s, %s, %s)",
            (email, password_hash, username, datetime.now().isoformat(), ""),
        )
        conn.commit()
        cur.close()
    except Exception as e:
        conn.rollback()
        raise HTTPException(500, f"创建用户失败: {e}")
    finally:
        _put_conn(conn)

def db_update_user(email: str, **fields):
    """更新用户字段（gpt_api_key、username 等）。"""
    if not fields:
        return
    sets = ", ".join(f"{k} = %s" for k in fields)
    vals = list(fields.values())
    vals.append(email)
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(f"UPDATE users SET {sets} WHERE email = %s", vals)
        conn.commit()
        cur.close()
    except Exception as e:
        conn.rollback()
        raise HTTPException(500, f"更新用户失败: {e}")
    finally:
        _put_conn(conn)

# ── FastAPI 启动事件 ────────────────────────────────────────────────────
@app.on_event("startup")
async def _startup():
    _init_db_pool()
    init_db()

# ── 密码工具函数 ──────────────────────────────────────────────────────────
def _hash_password(password: str) -> str:
    """
    bcrypt 有 72 字节限制，先 SHA-256 再 hash，支持任意长度密码。
    """
    digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return _bcrypt.hashpw(digest.encode("utf-8"), _bcrypt.gensalt()).decode("utf-8")


def _verify_password(password: str, hashed: str) -> bool:
    """
    验证密码：先试 SHA-256 预处理（新注册用户），
    不匹配则试原始密码（兼容旧格式）。
    """
    try:
        digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
        if _bcrypt.checkpw(digest.encode("utf-8"), hashed.encode("utf-8")):
            return True
    except Exception:
        pass
    try:
        return _bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


# ── Resend 邮件配置 ──────────────────────────────────────────────────────
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")

def _send_email(to: str, subject: str, html: str):
    """通过 Resend API 发送邮件。"""
    if not RESEND_API_KEY:
        raise HTTPException(500, "未配置邮件服务")

    resp = http_requests.post(
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "from": "DeepNovis <onboarding@resend.dev>",
            "to": [to],
            "subject": subject,
            "html": html,
        },
        timeout=HTTP_TIMEOUT_MEDIUM,
    )

    if resp.status_code not in (200, 201):
        try:
            detail = resp.json().get("message", resp.text)
        except Exception:
            detail = resp.text[:200]
        raise HTTPException(500, f"邮件发送失败: {detail}")

# 验证码缓存 { email: { code, expire_at } }
verify_codes: dict = {}
CODE_EXPIRE_SECONDS = 300  # 5 分钟

def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS),
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def _decode_token(token: str) -> dict:
    """内部 token 解码逻辑，供 verify_token 和 optional_auth 共用。"""
    return pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])

def verify_token(authorization: str | None = Header(None)) -> dict:
    """验证 JWT token，返回用户信息。未认证时直接 401。"""
    if not authorization:
        raise HTTPException(401, "未登录")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "认证格式错误")
    try:
        payload = _decode_token(token)
        return payload
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(401, "登录已过期，请重新登录")
    except pyjwt.InvalidTokenError:
        raise HTTPException(401, "无效的登录凭证")
    except Exception:
        raise HTTPException(401, "认证失败")

def optional_auth(authorization: str | None = Header(None)) -> dict | None:
    """可选认证，无 token 时返回 None 不报错。"""
    if not authorization:
        return None
    try:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token:
            return _decode_token(token)
    except Exception:
        pass
    return None

# ── 工具函数 ──────────────────────────────────────────────────────────────
def safe_filename(name: str) -> str:
    stem, ext = os.path.splitext(name)
    stem = re.sub(r"[^\w\-]", "_", stem, flags=re.ASCII)
    stem = re.sub(r"_+", "_", stem).strip("_")
    if not stem:
        stem = "image"
    return f"{stem}{ext.lower()}"

def get_github():
    if not GITHUB_TOKEN:
        raise HTTPException(500, "未配置 GITHUB_TOKEN 环境变量")
    return Github(GITHUB_TOKEN)

def push_to_github(filename: str, file_bytes: bytes):
    """通过 GitHub API 把图片推送到仓库。"""
    g = get_github()
    repo = g.get_repo(GITHUB_REPO)
    path = f"assets/{filename}"
    b64 = base64.b64encode(file_bytes).decode()
    # 检查文件是否已存在（获取 sha）
    sha = None
    try:
        existing = repo.get_contents(path)
        # get_contents 返回单个文件或文件列表（目录），取第一个
        if isinstance(existing, list):
            sha = existing[0].sha if existing else None
        else:
            sha = existing.sha
    except GithubException as e:
        if e.status != 404:
            logger.error(f"GitHub API 错误: {e}")
            raise HTTPException(500, f"GitHub API 错误: {e}")

    msg = f"upload: {filename}"
    if sha:
        repo.update_file(path, msg, b64, sha)
    else:
        repo.create_file(path, msg, b64)

def delete_from_github(filename: str):
    """通过 GitHub API 删除图片。"""
    g = get_github()
    repo = g.get_repo(GITHUB_REPO)
    path = f"assets/{filename}"
    try:
        existing = repo.get_contents(path)
        # get_contents 返回单个文件或文件列表，取第一个
        file_obj = existing[0] if isinstance(existing, list) else existing
        repo.delete_file(path, f"delete: {filename}", file_obj.sha)
    except GithubException as e:
        if e.status == 404:
            raise HTTPException(404, "文件不存在")
        logger.error(f"GitHub API 错误: {e}")
        raise HTTPException(500, f"GitHub API 错误: {e}")

# ── 路由 ─────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = Path(__file__).parent / "templates" / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))

@app.get("/prompt-editor", response_class=HTMLResponse)
async def prompt_editor():
    html_path = Path(__file__).parent / "templates" / "prompt-editor.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))

@app.post("/api/upload")
async def upload(file: UploadFile = File(...)):
    mime = file.content_type or mimetypes.guess_type(file.filename or "")[0] or ""
    if mime not in ALLOWED_TYPES:
        raise HTTPException(400, f"不支持的文件类型: {mime}")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = safe_filename(file.filename or "upload")
    filename = f"{ts}_{safe}"

    # 读文件内容
    content = await file.read()

    # 本地持久化存储
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)
    local_path = ASSETS_DIR / filename
    with open(local_path, "wb") as f:
        f.write(content)

    # 推送到 GitHub
    try:
        push_to_github(filename, content)
    except HTTPException:
        local_path.unlink(missing_ok=True)
        raise
    except Exception as e:
        local_path.unlink(missing_ok=True)
        raise HTTPException(500, f"GitHub 推送失败: {e}")

    url = f"{GITHUB_RAW_BASE}/{filename}"
    return JSONResponse({
        "filename": filename,
        "url": url,
        "markdown": f"![]({url})",
    })

@app.get("/api/images")
async def list_images():
    """从 GitHub API 获取图片列表（最可靠）。"""
    try:
        g = get_github()
        repo = g.get_repo(GITHUB_REPO)
        try:
            contents = repo.get_contents("assets")
        except GithubException as e:
            if e.status == 404:
                return JSONResponse({"images": []})
            raise

        images = []
        for item in contents:
            if not item.name.startswith(".") and item.download_url:
                ext = Path(item.name).suffix.lower()
                if ext in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg"}:
                    url = f"{GITHUB_RAW_BASE}/{item.name}"
                    images.append({
                        "filename": item.name,
                        "url": url,
                        "markdown": f"![]({url})",
                        "size": item.size or 0,
                        "mtime": 0,
                    })

        # 按文件名倒序（时间戳前缀）
        images.sort(key=lambda x: x["filename"], reverse=True)
        return JSONResponse({"images": images})
    except HTTPException:
        raise
    except Exception:
        # GitHub API 不可用时 fallback 到本地
        if ASSETS_DIR.exists():
            images = []
            for f in sorted(ASSETS_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
                if f.suffix.lower() in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg"}:
                    url = f"{GITHUB_RAW_BASE}/{f.name}"
                    images.append({
                        "filename": f.name,
                        "url": url,
                        "markdown": f"![]({url})",
                        "size": f.stat().st_size,
                        "mtime": int(f.stat().st_mtime),
                    })
            return JSONResponse({"images": images})
        return JSONResponse({"images": []})

@app.delete("/api/images/{filename}")
async def delete_image(filename: str):
    safe_name = Path(filename).name
    target = ASSETS_DIR / safe_name
    try:
        delete_from_github(safe_name)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"GitHub 删除失败: {e}")

    # 删本地缓存
    target.unlink(missing_ok=True)
    return JSONResponse({"ok": True, "filename": safe_name})
@app.get("/api/proxy/{path:path}")
async def proxy_image(path: str):
    """代理访问 GitHub 图片，通过 jsDelivr CDN 解决国内访问问题。"""
    if not path.startswith("assets/"):
        raise HTTPException(400, "只允许访问 assets 目录")

    cdn_url = f"https://cdn.jsdelivr.net/gh/{GITHUB_REPO}@main/{path}"
    
    try:
        resp = http_requests.get(cdn_url, timeout=HTTP_TIMEOUT_MEDIUM)
        if resp.status_code != 200:
            raise HTTPException(502, "GitHub 返回 " + str(resp.status_code))
        from fastapi.responses import Response
        return Response(content=resp.content, media_type=resp.headers.get("Content-Type", "image/png"))
    except http_requests.Timeout:
        raise HTTPException(502, "GitHub 请求超时")
    except Exception as e:
        raise HTTPException(502, "代理失败: " + str(e))
@app.get("/api/health")
async def health():
    return JSONResponse({"status": "ok", "github_configured": bool(GITHUB_TOKEN)})

# ── 用户认证 API ────────────────────────────────────────────────────────────

@app.post("/api/auth/send-code")
async def send_code(body: dict, request: Request):
    """发送邮箱验证码。"""
    client_ip = request.client.host if request.client else "unknown"
    
    # IP 频率限制：每分钟最多 5 次
    if not _check_ip_rate_limit(client_ip, max_req=5, window=60):
        raise HTTPException(429, "请求过于频繁，请稍后再试")

    email = (body.get("email") or "").strip().lower()
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        raise HTTPException(400, "请输入有效的邮箱地址")

    # 检查验证码失败封禁
    if not _check_verification_failures(email):
        raise HTTPException(429, "验证码尝试次数过多，请 30 分钟后再试")

    # 限制频率：同一邮箱 60 秒内只能发一次
    now = time.time()
    existing = verify_codes.get(email)
    if existing and now - existing.get("sent_at", 0) < 60:
        remaining = int(60 - (now - existing["sent_at"]))
        raise HTTPException(429, f"请 {remaining} 秒后再试")

    # 生成 8 位数字字母混合验证码
    chars = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"  # 去掉易混淆的字符 I, O, L
    code = "".join(random.choices(chars, k=8))
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    # 发送邮件
    try:
        _send_email(
            to=email,
            subject=f"DeepNovis 登录验证码 · {code}",
            html=f"""<div style="font-family:-apple-system,sans-serif;padding:24px;max-width:400px;margin:0 auto;">
<h2 style="font-size:18px;margin-bottom:12px;">DeepNovis 登录验证</h2>
<p style="font-size:14px;color:#555;margin-bottom:20px;">你的验证码为：</p>
<div style="font-size:36px;font-weight:700;letter-spacing:8px;text-align:center;color:#0071e3;padding:16px;background:#f5f5f7;border-radius:12px;">{code}</div>
<p style="font-size:12px;color:#999;margin-top:20px;">验证码 5 分钟内有效，请勿泄露给他人。</p>
</div>"""
        )

        verify_codes[email] = {
            "code_hash": code_hash,
            "sent_at": now,
            "expire_at": now + CODE_EXPIRE_SECONDS,
        }
        return JSONResponse({"msg": "验证码已发送", "email": email})
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"邮件发送失败: {e}")
        raise HTTPException(500, f"邮件发送失败: {e}")

@app.post("/api/auth/register")
async def auth_register(body: dict, request: Request):
    """邮箱 + 验证码 + 密码 → 注册新用户。"""
    client_ip = request.client.host if request.client else "unknown"
    
    # IP 频率限制
    if not _check_ip_rate_limit(client_ip, max_req=10, window=60):
        raise HTTPException(429, "请求过于频繁，请稍后再试")

    email = (body.get("email") or "").strip().lower()
    code = (body.get("code") or "").strip()
    password = (body.get("password") or "").strip()

    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        raise HTTPException(400, "请输入有效的邮箱地址")
    if not code or len(code) != 8:
        raise HTTPException(400, "请输入 8 位验证码")

    # 密码强度验证
    ok, err_msg = _validate_password_strength(password)
    if not ok:
        raise HTTPException(400, err_msg)

    # 校验验证码（hash 比较）
    cached = verify_codes.get(email)
    if not cached:
        raise HTTPException(400, "请先获取验证码")
    if time.time() > cached["expire_at"]:
        verify_codes.pop(email, None)
        raise HTTPException(400, "验证码已过期，请重新获取")

    input_hash = hashlib.sha256(code.encode()).hexdigest()
    if input_hash != cached["code_hash"]:
        # 记录失败次数
        attempts = _verification_attempts.get(email, [])
        attempts.append((input_hash, time.time()))
        _verification_attempts[email] = attempts
        raise HTTPException(400, "验证码错误")

    # 验证码正确后清除
    verify_codes.pop(email, None)

    if db_user_exists(email):
        raise HTTPException(400, "该邮箱已注册，请直接登录")

    username = email.split("@")[0]
    db_create_user(email, _hash_password(password), username)

    token = create_token(email)
    return JSONResponse({
        "token": token,
        "username": username,
        "email": email,
        "msg": "注册成功",
    })

@app.post("/api/auth/login")
async def auth_login(body: dict, request: Request):
    """邮箱 + 密码 → 登录，返回 JWT。"""
    client_ip = request.client.host if request.client else "unknown"

    # IP 频率限制
    if not _check_ip_rate_limit(client_ip, max_req=20, window=60):
        raise HTTPException(429, "请求过于频繁，请稍后再试")

    email = (body.get("email") or "").strip().lower()
    password = (body.get("password") or "").strip()

    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        raise HTTPException(400, "请输入有效的邮箱地址")
    if not password:
        raise HTTPException(400, "请输入密码")

    user = db_get_user(email)
    if not user:
        raise HTTPException(400, "该邮箱未注册，请先注册")

    if not user.get("password"):
        raise HTTPException(400, "该账号无密码，请使用注册流程设置密码")

    if not _verify_password(password, user["password"]):
        # 记录登录失败
        attempts = _verification_attempts.get(email, [])
        attempts.append(("login_fail", time.time()))
        _verification_attempts[email] = attempts
        raise HTTPException(400, "密码错误")

    token = create_token(email)
    username = user.get("username", email.split("@")[0])
    return JSONResponse({
        "token": token,
        "username": username,
        "email": email,
        "msg": "登录成功",
    })

@app.get("/api/auth/me")
async def auth_me(payload: dict = Depends(verify_token)):
    """获取当前登录用户信息。"""
    email = payload["sub"]
    user = db_get_user(email) or {}
    return JSONResponse({
        "username": user.get("username", email.split("@")[0]),
        "email": email,
        "created_at": user.get("created_at", ""),
        "api_key_configured": bool(user.get("gpt_api_key", "")),
    })

@app.post("/api/auth/settings")
async def update_settings(body: dict, payload: dict = Depends(verify_token)):
    """更新用户设置（API Key 等），Key 服务端加密存储，不返回给前端。"""
    email = payload["sub"]
    user = db_get_user(email)
    if not user:
        raise HTTPException(404, "用户不存在")

    updates = {}
    # 严格白名单：只允许更新这两个字段
    if "gpt_api_key" in body:
        raw_key = (body["gpt_api_key"] or "").strip()
        updates["gpt_api_key"] = _encrypt_api_key(raw_key) if raw_key else ""
    if "username" in body:
        name = (body["username"] or "").strip()
        if 2 <= len(name) <= 20:
            updates["username"] = name
    if updates:
        db_update_user(email, **updates)
    return JSONResponse({"msg": "设置已保存"})

# ── GPT-Image-2 代理 API ──────────────────────────────────────────────────

@app.get("/api/gpt/status")
async def gpt_status(payload: dict = Depends(verify_token)):
    """查询当前用户 API Key 配置状态。"""
    user = db_get_user(payload["sub"]) or {}
    encrypted_key = user.get("gpt_api_key", "")
    return JSONResponse({
        "ready": bool(encrypted_key and _decrypt_api_key(encrypted_key)),
    })

@app.post("/api/gpt/generate")
async def gpt_generate(body: dict, payload: dict = Depends(verify_token)):
    """提交生图任务到 API。"""
    user = db_get_user(payload["sub"]) or {}
    encrypted_key = user.get("gpt_api_key", "")
    api_key = _decrypt_api_key(encrypted_key)
    if not api_key:
        raise HTTPException(400, "请先配置 API Key")

    prompt = (body.get("prompt") or "").strip()
    if not prompt:
        raise HTTPException(400, "请输入提示词")
    req_payload = {
        "prompt": prompt,
        "size": body.get("size", "auto"),
    }
    urls = body.get("urls")
    if isinstance(urls, list) and len(urls):
        req_payload["urls"] = urls

    # 通过 Header 传递 API Key（避免 URL 参数暴露）
    url = "https://api.wuyinkeji.com/api/async/image_gpt"
    headers = {
        "Authorization": api_key,
        "Content-Type": "application/json",
        "X-API-Key": api_key,  # 备用字段
    }

    try:
        resp = http_requests.post(url, json=req_payload, headers=headers, timeout=HTTP_TIMEOUT_LONG)
        data = resp.json()

        task_id = data.get("data", {}).get("id") or data.get("id")
        code = data.get("code", resp.status_code)
        msg = data.get("msg") or data.get("message", "")

        return JSONResponse({
            "code": code,
            "msg": msg,
            "data": {"id": task_id} if task_id else None,
        })
    except http_requests.Timeout:
        raise HTTPException(502, "第三方 API 超时")
    except Exception as e:
        logger.error(f"第三方 API 失败: {e}")
        raise HTTPException(502, f"请求第三方 API 失败: {e}")

@app.get("/api/gpt/result/{task_id}")
async def gpt_result(task_id: str, payload: dict = Depends(verify_token)):
    """查询生图任务结果。"""
    user = db_get_user(payload["sub"]) or {}
    encrypted_key = user.get("gpt_api_key", "")
    api_key = _decrypt_api_key(encrypted_key)
    if not api_key:
        raise HTTPException(400, "请先配置 API Key")

    # 通过 Header 传递 API Key（避免 URL 参数暴露）
    url = "https://api.wuyinkeji.com/api/async/detail"
    headers = {
        "Authorization": api_key,
        "X-API-Key": api_key,
    }
    params = {"id": task_id}

    try:
        resp = http_requests.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT_SHORT)
        data = resp.json()

        # 如果成功且有图片 URL，提取并简化返回
        if data.get("code") == 200 and data.get("data", {}).get("status") == 2:
            raw_data = data["data"]
            # 从响应中提取图片 URL
            img_url = _extract_image_url(raw_data)
            if img_url:
                return JSONResponse({
                    "code": 1,
                    "data": img_url,
                    "msg": "生成成功",
                })

        # 失败
        if data.get("data", {}).get("status") == 3:
            return JSONResponse({
                "code": 2,
                "msg": data["data"].get("message", "生成失败"),
            })

        # 处理中
        return JSONResponse({
            "code": 0,
            "msg": "处理中",
        })
    except http_requests.Timeout:
        raise HTTPException(502, "查询超时")
    except Exception as e:
        raise HTTPException(502, f"查询失败: {e}")

def _extract_image_url(data: dict) -> str | None:
    """递归扫描响应数据，提取图片 URL。"""
    if not data or not isinstance(data, dict):
        return None

    candidates = [
        data.get("urls"), data.get("imgUrls"),
        data.get("url"), data.get("imageUrl"), data.get("image_url"),
        data.get("result"), data.get("output"), data.get("images"),
    ]
    for c in candidates:
        if not c:
            continue
        if isinstance(c, str) and (c.startswith("http://") or c.startswith("https://")):
            return c
        if isinstance(c, list) and len(c):
            first = c[0]
            if isinstance(first, str) and first.startswith("http"):
                return first
            if isinstance(first, dict):
                if first.get("url"):
                    return first["url"]
                if first.get("imageUrl"):
                    return first["imageUrl"]
        if isinstance(c, dict):
            if c.get("url"):
                return c["url"]
            if isinstance(c.get("urls"), list) and len(c["urls"]):
                return c["urls"][0]

    # 深层递归
    return _deep_scan_url(data)

def _deep_scan_url(obj, depth=0):
    if depth > 3 or not obj or not isinstance(obj, dict):
        return None
    for val in obj.values():
        if isinstance(val, str) and re.match(r"https?://.*\.(jpg|jpeg|png|gif|webp|svg|bmp|avif)(\?|$)", val, re.I):
            return val
        if isinstance(val, dict):
            found = _deep_scan_url(val, depth + 1)
            if found:
                return found
    return None
