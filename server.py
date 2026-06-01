"""
DeepNovis 图床上传服务 — 安全加固版
"""
import logging
import os
import re
import shutil
import mimetypes
import base64
import hashlib
import json
import secrets
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import defaultdict

import requests as http_requests
import jwt as pyjwt
import bcrypt as _bcrypt
import psycopg2
from psycopg2.extras import DictCursor
from psycopg2 import pool
from fastapi import FastAPI, File, UploadFile, HTTPException, Header, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from github import Github, GithubException

# ── 结构化日志 ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("img-host")

# ── 启动时必需的配置检查 ────────────────────────────────────────────────────
JWT_SECRET = os.environ.get("JWT_SECRET", "")
if not JWT_SECRET:
    logger.warning("JWT_SECRET 环境变量未设置！认证功能不可用，请务必在生产环境设置。"
                   " 生成方法：python -c \"import secrets; print(secrets.token_hex(32))\"")
    JWT_SECRET = "dev-insecure-please-set-env-var-in-production"

ENCRYPTION_KEY_B64 = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY_B64:
    logger.warning(
        "ENCRYPTION_KEY 未设置，API Key 将以明文存储。"
        " 生产环境务必设置！生成方法：python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
    )

# ── 管理员配置 ──────────────────────────────────────────────────────────────
ADMIN_EMAILS = set()
_admin_env = os.environ.get("ADMIN_EMAILS", "")
if _admin_env:
    ADMIN_EMAILS = {e.strip().lower() for e in _admin_env.split(",") if e.strip()}
if ADMIN_EMAILS:
    logger.info("管理员账号: %s", ", ".join(ADMIN_EMAILS))

def is_admin_user(email: str) -> bool:
    """判断邮箱是否为管理员。"""
    return email.lower() in ADMIN_EMAILS


def _seed_admin_users():
    """启动时自动创建管理员账号（如果不存在）。"""
    if not DATABASE_URL or not ADMIN_EMAILS:
        return
    admin_passwords_str = os.environ.get("ADMIN_PASSWORDS", "")
    admin_passwords = [p.strip() for p in admin_passwords_str.split(",") if p.strip()]
    if len(admin_passwords) != len(ADMIN_EMAILS):
        logger.warning("ADMIN_PASSWORDS 数量与 ADMIN_EMAILS 不匹配，跳过自动创建")
        return
    for email, password in zip(ADMIN_EMAILS, admin_passwords):
        if not db_user_exists(email):
            username = email.split("@")[0]
            db_create_user(email, _hash_password(password), username)
            logger.info("管理员账号已自动创建: %s", email)
        else:
            logger.info("管理员账号已存在: %s", email)

# ── API Key 加密工具 ──────────────────────────────────────────────────────
try:
    from cryptography.fernet import Fernet
except ImportError:
    logger.warning("cryptography 未安装，API Key 将以明文存储。pip install cryptography")
    _ferne = None
else:
    try:
        _ferne = Fernet(ENCRYPTION_KEY_B64.encode()) if ENCRYPTION_KEY_B64 else None
    except Exception:
        logger.warning("ENCRYPTION_KEY 格式无效（非法 Fernet 密钥），API Key 将以明文存储。"
                       " 生成方法：python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"")
        _ferne = None


def _encrypt_api_key(plain: str) -> str:
    if not plain or not _ferne:
        return plain
    return _ferne.encrypt(plain.encode()).decode()


def _decrypt_api_key(encrypted: str) -> str:
    if not encrypted or not _ferne:
        return encrypted
    try:
        return _ferne.decrypt(encrypted.encode()).decode()
    except Exception:
        logger.exception("API Key 解密失败")
        return ""


# ── 配置 ──────────────────────────────────────────────────────────────────
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO = os.environ.get("GITHUB_REPO", "stevenliu0618/images")
# 根据 GITHUB_REPO 动态生成 RAW_BASE，避免硬编码不同步
_repo_owner, _repo_name = GITHUB_REPO.split("/", 1)
GITHUB_RAW_BASE = f"https://raw.githubusercontent.com/{_repo_owner}/{_repo_name}/main/assets"
GITHUB_RAW_ROOT = f"https://raw.githubusercontent.com/{_repo_owner}/{_repo_name}/main"

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
ASSETS_DIR = DATA_DIR / "assets"
# 移除 SVG — 存在 XSS 风险
ALLOWED_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
# 常见图片 magic bytes → 对应扩展名
IMAGE_MAGIC: dict[bytes, str] = {
    b"\xff\xd8\xff": ".jpg",
    b"\x89PNG\r\n\x1a\n": ".png",
    b"GIF87a": ".gif",
    b"GIF89a": ".gif",
    b"RIFF": ".webp",  # WEBP 以 RIFF 开头 + 后续签名
}
# CORS — 从环境变量读取白名单，逗号分隔
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "").split(",") if os.environ.get("CORS_ORIGINS") else ["*"]
if CORS_ORIGINS == ["*"]:
    logger.warning("CORS 允许所有来源。生产环境请设置 CORS_ORIGINS 环境变量")

JWT_ALGO = "HS256"
JWT_EXPIRE_HOURS = 72

DATABASE_URL = os.environ.get("DATABASE_URL", "")
# 生产环境推荐启用 SSL
_has_sslmode = "sslmode" in DATABASE_URL.lower() or "ssl" in DATABASE_URL.lower()
if DATABASE_URL and not _has_sslmode:
    sep = "&" if "?" in DATABASE_URL else "?"
    DATABASE_URL = f"{DATABASE_URL}{sep}sslmode=require"
    logger.info("已为 DATABASE_URL 添加 sslmode=require")

_db_pool = None

# ── 密码策略常量 ──────────────────────────────────────────────────────────
MIN_PASSWORD_LENGTH = 8
PASSWORD_PATTERN = re.compile(r"^.{8,}$")

# ── 验证码限流 ────────────────────────────────────────────────────────────
# { email: { code, sent_at, expire_at } } — 使用 secrets 生成更高熵的验证码
CODE_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
CODE_LENGTH = 8
CODE_EXPIRE_SECONDS = 300  # 5 分钟
verify_codes: dict = {}
# IP 级别限流: { ip: [timestamp, ...] }
_ip_rate_map: dict[str, list[float]] = defaultdict(list)
IP_RATE_LIMIT = 5       # 最多
IP_RATE_WINDOW = 300    # 5 分钟窗口


def _check_ip_rate(request: Request):
    """同一 IP 在窗口期内限制请求次数，防暴力破解。"""
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    ts_list = _ip_rate_map[ip]
    # 清除窗口外的记录
    _ip_rate_map[ip] = [t for t in ts_list if now - t < IP_RATE_WINDOW]
    if len(_ip_rate_map[ip]) >= IP_RATE_LIMIT:
        logger.warning("IP 请求超限: %s", ip)
        raise HTTPException(429, "请求过于频繁，请稍后再试")
    _ip_rate_map[ip].append(now)


def _clean_expired_codes():
    """清理过期的验证码条目。"""
    now = time.time()
    expired = [k for k, v in verify_codes.items() if now > v.get("expire_at", 0)]
    for k in expired:
        verify_codes.pop(k, None)
    # 同时清理过期 IP 记录
    for ip in list(_ip_rate_map.keys()):
        _ip_rate_map[ip] = [t for t in _ip_rate_map[ip] if now - t < IP_RATE_WINDOW]
        if not _ip_rate_map[ip]:
            del _ip_rate_map[ip]


# ── 密码工具函数 ──────────────────────────────────────────────────────────
def _validate_password(password: str):
    """校验密码复杂度。"""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(400, f"密码至少 {MIN_PASSWORD_LENGTH} 位字符")
    if not re.search(r"[a-zA-Z]", password):
        raise HTTPException(400, "密码需包含字母")
    if not re.search(r"\d", password):
        raise HTTPException(400, "密码需包含数字")


def _hash_password(password: str) -> str:
    """bcrypt 有 72 字节限制，先 SHA-256 再 hash，支持任意长度密码。"""
    digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return _bcrypt.hashpw(digest.encode("utf-8"), _bcrypt.gensalt()).decode("utf-8")


def _verify_password(password: str, hashed: str) -> bool:
    """验证密码：先试 SHA-256 预处理（新注册用户），不匹配则试原始密码（兼容旧格式）。"""
    for attempt in [hashlib.sha256(password.encode("utf-8")).hexdigest(), password]:
        try:
            if _bcrypt.checkpw(attempt.encode("utf-8"), hashed.encode("utf-8")):
                return True
        except Exception:
            pass
    return False


# ── 文件内容验证 ──────────────────────────────────────────────────────────
def _validate_image_content(data: bytes, expected_ext: str) -> bool:
    """通过 magic bytes 验证文件内容是否为真实图片。"""
    for magic_bytes, ext in IMAGE_MAGIC.items():
        if data.startswith(magic_bytes):
            # WEBP 需要额外验证
            if ext == ".webp":
                return len(data) > 12 and data[8:12] in (b"WEBP",)
            return ext == expected_ext
    return False


# ── 数据库自动降级标记 ──────────────────────────────────────────────────
# 当 DATABASE_URL 未设置或连接池初始化失败时，使用环境变量认证
NO_DB_MODE = not DATABASE_URL

# ── 无数据库模式：管理员信息预加载 ─────────────────────────────────────
ADMIN_USERS_FALLBACK: dict[str, dict] = {}
if NO_DB_MODE and ADMIN_EMAILS:
    _admin_pass_str = os.environ.get("ADMIN_PASSWORDS", "")
    _admin_pws = [p.strip() for p in _admin_pass_str.split(",") if p.strip()]
    for i, email in enumerate(ADMIN_EMAILS):
        pw = _admin_pws[i] if i < len(_admin_pws) else ""
        ADMIN_USERS_FALLBACK[email] = {
            "email": email,
            "username": email.split("@")[0],
            "password": _hash_password(pw) if pw else "",
            "created_at": datetime.now(tz=timezone.utc).isoformat(),
            "gpt_api_key": "",
        }
    logger.info("无数据库模式，已加载 %d 个管理员账号", len(ADMIN_USERS_FALLBACK))

# ── PostgreSQL 连接 ──────────────────────────────────────────────────────
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
        logger.info("数据库连接池初始化成功")
        return True
    except Exception:
        logger.exception("数据库连接池初始化失败")
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
    """建表（启动时调用）。如果数据库不可用，静默跳过。"""
    if not DATABASE_URL:
        return
    if not _db_pool:
        logger.warning("数据库连接池未初始化，跳过建表")
        return
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
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
    except Exception as e:
        conn.rollback()
        logger.exception("数据库初始化失败")
        raise HTTPException(500, f"数据库初始化失败: {e}")
    finally:
        _put_conn(conn)


ALLOWED_UPDATE_FIELDS = frozenset({"gpt_api_key", "username"})


def db_update_user(email: str, **fields):
    """更新用户字段 — 白名单校验字段名，防止 SQL 注入。
    无数据库模式跳过。"""
    if not fields:
        return
    if NO_DB_MODE:
        logger.warning("无数据库模式，跳过更新用户: %s", email)
        return
    # 白名单过滤
    filtered = {k: v for k, v in fields.items() if k in ALLOWED_UPDATE_FIELDS}
    if not filtered:
        raise HTTPException(400, "不允许更新的字段")
    sets = ", ".join(f"{k} = %s" for k in filtered)
    vals = list(filtered.values())
    vals.append(email)
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE users SET {sets} WHERE email = %s", vals)
            conn.commit()
    except Exception as e:
        conn.rollback()
        logger.exception("更新用户失败")
        raise HTTPException(500, f"更新用户失败: {e}")
    finally:
        _put_conn(conn)


def db_get_user(email: str) -> dict | None:
    """按 email 查用户，不存在返回 None。
    无数据库模式时从环境变量 ADMIN_USERS_FALLBACK 查找。"""
    if NO_DB_MODE:
        return ADMIN_USERS_FALLBACK.get(email.lower())

    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            row = cur.fetchone()
            if row:
                user = dict(row)
                # 解密 API Key
                user["gpt_api_key"] = _decrypt_api_key(user.get("gpt_api_key", "") or "")
                return user
            return None
    finally:
        _put_conn(conn)


def db_user_exists(email: str) -> bool:
    if NO_DB_MODE:
        return email.lower() in ADMIN_USERS_FALLBACK
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM users WHERE email = %s", (email,))
            return cur.fetchone() is not None
    finally:
        _put_conn(conn)


def db_create_user(email: str, password_hash: str, username: str):
    """插入新用户。无数据库模式下静默跳过。"""
    if NO_DB_MODE:
        logger.warning("无数据库模式，跳过创建用户: %s", email)
        return
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (email, password, username, created_at, gpt_api_key) VALUES (%s, %s, %s, %s, %s)",
                (email, password_hash, username, datetime.now(tz=timezone.utc).isoformat(), ""),
            )
            conn.commit()
    except Exception as e:
        conn.rollback()
        logger.exception("创建用户失败")
        raise HTTPException(500, f"创建用户失败: {e}")
    finally:
        _put_conn(conn)


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
        timeout=15,
    )

    if resp.status_code not in (200, 201):
        try:
            detail = resp.json().get("message", resp.text)
        except Exception:
            detail = resp.text[:200]
        logger.error("邮件发送失败 [%d]: %s", resp.status_code, detail)
        raise HTTPException(500, f"邮件发送失败: {detail}")

    logger.info("邮件已发送至 %s", to)


# ── JWT 工具函数 ──────────────────────────────────────────────────────────
def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "iat": datetime.now(tz=timezone.utc),
        "exp": datetime.now(tz=timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS),
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def _decode_token(authorization: str) -> dict:
    """提取并验证 JWT token，返回 payload。"""
    if not authorization:
        raise HTTPException(401, "未登录")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "认证格式错误")
    try:
        return pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(401, "登录已过期，请重新登录")
    except pyjwt.InvalidTokenError:
        raise HTTPException(401, "无效的登录凭证")
    except Exception:
        logger.exception("JWT 验证异常")
        raise HTTPException(401, "认证失败")


def verify_token(authorization: str | None = Header(None)) -> dict:
    """验证 JWT token，返回用户信息。未认证时直接 401。"""
    return _decode_token(authorization)


def verify_admin(payload: dict = Depends(verify_token)) -> dict:
    """验证管理员身份。未登录或非管理员直接 403。"""
    email = payload.get("sub", "")
    if not is_admin_user(email):
        logger.warning("非管理员尝试访问管理接口: %s", email)
        raise HTTPException(403, "仅管理员可执行此操作")
    return payload


def optional_auth(authorization: str | None = Header(None)) -> dict | None:
    """可选认证，无 token 时返回 None 不报错。"""
    if not authorization:
        return None
    # authorization is guaranteed non-None here (checked above)
    try:
        return _decode_token(authorization)  # type: ignore[arg-type]
    except HTTPException:
        return None


# ── FastAPI 应用 ──────────────────────────────────────────────────────────
app = FastAPI(title="DeepNovis 图床")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def _startup():
    try:
        _init_db_pool()
    except Exception as e:
        logger.warning("数据库连接池初始化跳过: %s", e)
    try:
        init_db()
    except Exception as e:
        logger.warning("数据库初始化跳过: %s", e)
    try:
        _seed_admin_users()
    except Exception as e:
        logger.warning("管理员账号创建跳过: %s", e)


# ── 文件工具函数 ──────────────────────────────────────────────────────────
def safe_filename(name: str) -> str:
    stem, ext = os.path.splitext(name)
    stem = re.sub(r"[^\w\-]", "_", stem, flags=re.ASCII)
    stem = re.sub(r"_+", "_", stem).strip("_")
    if not stem:
        stem = "image"
    ext = ext.lower()
    # 只保留允许的扩展名
    if ext not in ALLOWED_EXTENSIONS:
        ext = ".jpg"
    return f"{stem}{ext}"


# ── GitHub 工具函数 ──────────────────────────────────────────────────────
def get_github():
    if not GITHUB_TOKEN:
        raise HTTPException(500, "未配置 GITHUB_TOKEN 环境变量")
    return Github(GITHUB_TOKEN)


def push_to_github(filename: str, file_bytes: bytes):
    """通过 GitHub API 把图片推送到仓库。
    PyGithub 的 create_file/update_file 内部会自动 base64 编码，
    所以传入原始 bytes 即可，不要手动编码。"""
    g = get_github()
    repo = g.get_repo(GITHUB_REPO)
    path = f"assets/{filename}"
    sha = None
    try:
        existing = repo.get_contents(path)
        sha = existing.sha
    except GithubException as e:
        if e.status != 404:
            raise HTTPException(500, f"GitHub API 错误: {e}")

    msg = f"upload: {filename}"
    if sha:
        repo.update_file(path, msg, file_bytes, sha)
    else:
        repo.create_file(path, msg, file_bytes)


def delete_from_github(filename: str):
    """通过 GitHub API 删除图片。"""
    g = get_github()
    repo = g.get_repo(GITHUB_REPO)
    path = f"assets/{filename}"
    try:
        existing = repo.get_contents(path)
        repo.delete_file(path, f"delete: {filename}", existing.sha)
    except GithubException as e:
        if e.status == 404:
            raise HTTPException(404, "文件不存在")
        raise HTTPException(500, f"GitHub API 错误: {e}")


# ── 路由：静态页面 ───────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = Path(__file__).parent / "templates" / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@app.get("/prompt-editor", response_class=HTMLResponse)
async def prompt_editor():
    html_path = Path(__file__).parent / "templates" / "prompt-editor.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


# ── 路由：图片上传 ────────────────────────────────────────────────────
@app.post("/api/upload")
async def upload(file: UploadFile = File(...), payload: dict | None = Depends(optional_auth)):
    mime = file.content_type or mimetypes.guess_type(file.filename or "")[0] or ""
    if mime not in ALLOWED_TYPES:
        raise HTTPException(400, f"不支持的文件类型: {mime}")

    content = await file.read()

    # 通过 magic bytes 验证图片内容真实性
    orig_name = file.filename or "upload"
    ext = Path(orig_name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        ext = ".jpg"
    if not _validate_image_content(content, ext):
        logger.warning("文件内容验证失败: %s (声称 %s, 大小 %d)", orig_name, mime, len(content))
        raise HTTPException(400, "文件内容不是有效的图片格式")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = safe_filename(orig_name)
    filename = f"{ts}_{safe}"

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
    logger.info("图片上传成功: %s → %s", filename, url)
    return JSONResponse({
        "filename": filename,
        "url": url,
        "markdown": f"![]({url})",
    })


# ── 路由：图片列表 ────────────────────────────────────────────────────
@app.get("/api/images")
async def list_images(payload: dict = Depends(verify_admin)):
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
                if ext in ALLOWED_EXTENSIONS:
                    url = f"{GITHUB_RAW_BASE}/{item.name}"
                    images.append({
                        "filename": item.name,
                        "url": url,
                        "markdown": f"![]({url})",
                        "size": item.size or 0,
                        "mtime": 0,
                    })

        images.sort(key=lambda x: x["filename"], reverse=True)
        return JSONResponse({"images": images})
    except HTTPException:
        raise
    except Exception:
        # GitHub API 不可用时 fallback 到本地
        if ASSETS_DIR.exists():
            images = []
            for f in sorted(ASSETS_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
                if f.suffix.lower() in ALLOWED_EXTENSIONS:
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


# ── 路由：图片删除 ────────────────────────────────────────────────────
@app.delete("/api/images/{filename}")
async def delete_image(filename: str, payload: dict = Depends(verify_admin)):
    # 防路径穿越：只取文件名最后一段
    safe_name = Path(filename).name
    target = ASSETS_DIR / safe_name
    try:
        delete_from_github(safe_name)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"GitHub 删除失败: {e}")

    target.unlink(missing_ok=True)
    logger.info("图片已删除: %s", safe_name)
    return JSONResponse({"ok": True, "filename": safe_name})


# ── 路由：图片代理（解决部分地区 raw.githubusercontent.com 不可访问）────
@app.get("/api/proxy/{path:path}")
async def proxy_image(path: str):
    # 规范化路径，防止路径遍历
    if not path.startswith("assets/"):
        raise HTTPException(400, "只允许访问 assets 目录")

    github_raw_url = f"{GITHUB_RAW_ROOT}/{path}"

    try:
        resp = http_requests.get(github_raw_url, timeout=15)
        if resp.status_code != 200:
            raise HTTPException(502, f"GitHub 返回 {resp.status_code}")
        return Response(
            content=resp.content,
            media_type=resp.headers.get("Content-Type", "image/png"),
        )
    except http_requests.Timeout:
        raise HTTPException(502, "GitHub 请求超时")
    except Exception as e:
        raise HTTPException(502, f"代理失败: {e}")


# ── 路由：健康检查 ────────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return JSONResponse({
        "status": "ok",
        "github_configured": bool(GITHUB_TOKEN),
        "cors_origins": CORS_ORIGINS,
        "encryption_enabled": bool(_ferne),
    })


# ── 路由：用户认证 ────────────────────────────────────────────────────
@app.post("/api/auth/send-code")
async def send_code(body: dict, request: Request):
    """发送邮箱验证码（含 IP 限流）。"""
    _check_ip_rate(request)

    email = (body.get("email") or "").strip().lower()
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        raise HTTPException(400, "请输入有效的邮箱地址")

    # 定期清理过期验证码
    _clean_expired_codes()

    # 限制频率：同一邮箱 60 秒内只能发一次
    now = time.time()
    existing = verify_codes.get(email)
    if existing and now - existing.get("sent_at", 0) < 60:
        remaining = int(60 - (now - existing["sent_at"]))
        raise HTTPException(429, f"请 {remaining} 秒后再试")

    # 生成 8 位字母数字混合验证码（10^8 倍于 6 位纯数字）
    code = "".join(secrets.choice(CODE_CHARS) for _ in range(CODE_LENGTH))

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
</div>""",
        )

        verify_codes[email] = {
            "code": code,
            "sent_at": now,
            "expire_at": now + CODE_EXPIRE_SECONDS,
        }
        return JSONResponse({"msg": "验证码已发送", "email": email})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"邮件发送失败: {e}")


@app.post("/api/auth/register")
async def auth_register(body: dict, request: Request):
    """邮箱 + 验证码 + 密码 → 注册新用户。"""
    _check_ip_rate(request)

    email = (body.get("email") or "").strip().lower()
    code = (body.get("code") or "").strip()
    password = (body.get("password") or "").strip()

    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        raise HTTPException(400, "请输入有效的邮箱地址")
    if not code or len(code) != CODE_LENGTH:
        raise HTTPException(400, f"请输入 {CODE_LENGTH} 位验证码")
    _validate_password(password)

    # 校验验证码
    cached = verify_codes.get(email)
    if not cached:
        raise HTTPException(400, "请先获取验证码")
    if time.time() > cached["expire_at"]:
        verify_codes.pop(email, None)
        _clean_expired_codes()
        raise HTTPException(400, "验证码已过期，请重新获取")
    if cached["code"] != code:
        raise HTTPException(400, "验证码错误")

    # 验证码正确后清除（防止重复使用）
    verify_codes.pop(email, None)

    if db_user_exists(email):
        raise HTTPException(400, "该邮箱已注册，请直接登录")

    username = email.split("@")[0]
    db_create_user(email, _hash_password(password), username)

    token = create_token(email)
    logger.info("新用户注册: %s", email)
    return JSONResponse({
        "token": token,
        "username": username,
        "email": email,
        "is_admin": is_admin_user(email),
    })


@app.post("/api/auth/login")
async def auth_login(body: dict, request: Request):
    """邮箱 + 密码 → 登录，返回 JWT。"""
    _check_ip_rate(request)

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
        raise HTTPException(400, "密码错误")

    token = create_token(email)
    username = user.get("username", email.split("@")[0])
    return JSONResponse({
        "token": token,
        "username": username,
        "email": email,
        "is_admin": is_admin_user(email),
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
        "is_admin": is_admin_user(email),
    })


@app.post("/api/auth/settings")
async def update_settings(body: dict, payload: dict = Depends(verify_token)):
    """更新用户设置（API Key 等），Key 服务端加密存储，不返回给前端。"""
    email = payload["sub"]
    user = db_get_user(email)
    if not user:
        raise HTTPException(404, "用户不存在")

    updates = {}
    if "gpt_api_key" in body:
        raw_key = (body["gpt_api_key"] or "").strip()
        # 加密后存储
        updates["gpt_api_key"] = _encrypt_api_key(raw_key)
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
    return JSONResponse({
        "ready": bool(user.get("gpt_api_key", "")),
    })


@app.post("/api/gpt/generate")
async def gpt_generate(body: dict, payload: dict = Depends(verify_token)):
    """提交生图任务到 API。"""
    user = db_get_user(payload["sub"]) or {}
    api_key = user.get("gpt_api_key", "")
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

    # API Key 通过 Header 传递，不在 URL 参数中暴露（避免日志泄露）
    url = "https://api.wuyinkeji.com/api/async/image_gpt"
    headers = {
        "Authorization": api_key,
        "Content-Type": "application/json",
    }

    try:
        resp = http_requests.post(url, json=req_payload, headers=headers, timeout=60)
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
        raise HTTPException(502, f"请求第三方 API 失败: {e}")


@app.get("/api/gpt/result/{task_id}")
async def gpt_result(task_id: str, payload: dict = Depends(verify_token)):
    """查询生图任务结果。"""
    user = db_get_user(payload["sub"]) or {}
    api_key = user.get("gpt_api_key", "")
    if not api_key:
        raise HTTPException(400, "请先配置 API Key")

    url = "https://api.wuyinkeji.com/api/async/detail"
    headers = {"Authorization": api_key}
    params = {"id": task_id}

    try:
        resp = http_requests.get(url, params=params, headers=headers, timeout=10)
        data = resp.json()

        if data.get("code") == 200 and data.get("data", {}).get("status") == 2:
            raw_data = data["data"]
            img_url = _extract_image_url(raw_data)
            if img_url:
                return JSONResponse({
                    "code": 1,
                    "data": img_url,
                    "msg": "生成成功",
                })

        if data.get("data", {}).get("status") == 3:
            return JSONResponse({
                "code": 2,
                "msg": data["data"].get("message", "生成失败"),
            })

        return JSONResponse({
            "code": 0,
            "msg": "处理中",
        })
    except http_requests.Timeout:
        raise HTTPException(502, "查询超时")
    except Exception as e:
        raise HTTPException(502, f"查询失败: {e}")


# ── 图片 URL 提取工具 ────────────────────────────────────────────────────
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

    return _deep_scan_url(data)


def _deep_scan_url(obj, depth=0):
    if depth > 3 or not obj or not isinstance(obj, dict):
        return None
    for val in obj.values():
        if isinstance(val, str) and re.match(
            r"https?://.*\.(jpg|jpeg|png|gif|webp|svg|bmp|avif)(\?|$)", val, re.I
        ):
            return val
        if isinstance(val, dict):
            found = _deep_scan_url(val, depth + 1)
            if found:
                return found
    return None
