import os
import re
import shutil
import mimetypes
import base64
import hashlib
import json
import smtplib
import random
import time
from email.mime.text import MIMEText
from pathlib import Path
from datetime import datetime, timedelta

import requests as http_requests
import jwt as pyjwt
from passlib.context import CryptContext
from fastapi import FastAPI, File, UploadFile, HTTPException, Header, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from github import Github, GithubException

# ── 配置 ──────────────────────────────────────────────────────────────────
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO  = os.environ.get("GITHUB_REPO", "stevenliu0618/images")
GITHUB_RAW_BASE = "https://raw.githubusercontent.com/stevenliu0618/images/main/assets"
DATA_DIR    = Path(os.environ.get("DATA_DIR", "/data"))
ASSETS_DIR  = DATA_DIR / "assets"
ALLOWED_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml"}

app = FastAPI(title="图床上传服务")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── 认证配置 ────────────────────────────────────────────────────────────────
JWT_SECRET = os.environ.get("JWT_SECRET", "deepnovis-jwt-secret-change-me")
JWT_ALGO = "HS256"
JWT_EXPIRE_HOURS = 72
BCRYPT = CryptContext(schemes=["bcrypt"], deprecated="auto")
USERS_FILE = DATA_DIR / "users.json"

# ── SMTP 邮件配置 ──────────────────────────────────────────────────────────
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.qq.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER = os.environ.get("SMTP_USER", "liuxixi@deepnovis.com.cn")
SMTP_PASS = os.environ.get("SMTP_PASS", "gfeKYWqDiUZFzvfd")


def _send_email(to: str, subject: str, html: str):
    """发送邮件，支持多端口/协议自动回退。"""
    msg = MIMEText(html, "html", "utf-8")
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = to

    errors = []

    # 优先使用用户配置的端口，不行再试其他
    ports_to_try = [(SMTP_HOST, SMTP_PORT, "ssl")]
    if SMTP_PORT != 465:
        ports_to_try.append(("smtp.qq.com", 465, "ssl"))
    ports_to_try.append(("smtp.qq.com", 587, "starttls"))

    for host, port, mode in ports_to_try:
        try:
            if mode == "ssl":
                with smtplib.SMTP_SSL(host, port, timeout=10) as server:
                    server.login(SMTP_USER, SMTP_PASS)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(host, port, timeout=10) as server:
                    server.starttls()
                    server.login(SMTP_USER, SMTP_PASS)
                    server.send_message(msg)
            return  # 成功
        except smtplib.SMTPAuthenticationError:
            raise HTTPException(500, "邮件服务认证失败，请检查授权码")
        except Exception as e:
            errors.append(f"{host}:{port}({mode}): {e}")
            continue

    raise HTTPException(500, f"邮件发送失败: {'; '.join(errors)}")

# 验证码缓存 { email: { code, expire_at } }
verify_codes: dict = {}
CODE_EXPIRE_SECONDS = 300  # 5 分钟


def _load_users() -> dict:
    if USERS_FILE.exists():
        return json.loads(USERS_FILE.read_text(encoding="utf-8"))
    return {}


def _save_users(users: dict):
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    USERS_FILE.write_text(json.dumps(users, ensure_ascii=False, indent=2), encoding="utf-8")


def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS),
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def verify_token(authorization: str | None = Header(None)) -> dict:
    """验证 JWT token，返回用户信息。未认证时直接 401。"""
    if not authorization:
        raise HTTPException(401, "未登录")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "认证格式错误")
    try:
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
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
        return verify_token.__wrapped__(authorization)
    except HTTPException:
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
        sha = existing.sha
    except GithubException as e:
        if e.status != 404:
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
        repo.delete_file(path, f"delete: {filename}", existing.sha)
    except GithubException as e:
        if e.status == 404:
            raise HTTPException(404, "文件不存在")
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


@app.get("/api/health")
async def health():
    return JSONResponse({"status": "ok", "github_configured": bool(GITHUB_TOKEN)})


# ── 用户认证 API ────────────────────────────────────────────────────────────

@app.post("/api/auth/send-code")
async def send_code(body: dict):
    """发送邮箱验证码。"""
    email = (body.get("email") or "").strip().lower()
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        raise HTTPException(400, "请输入有效的邮箱地址")

    # 限制频率：同一邮箱 60 秒内只能发一次
    now = time.time()
    existing = verify_codes.get(email)
    if existing and now - existing.get("sent_at", 0) < 60:
        remaining = int(60 - (now - existing["sent_at"]))
        raise HTTPException(429, f"请 {remaining} 秒后再试")

    # 生成 6 位验证码
    code = "".join(random.choices("0123456789", k=6))

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
            "code": code,
            "sent_at": now,
            "expire_at": now + CODE_EXPIRE_SECONDS,
        }
        return JSONResponse({"msg": "验证码已发送", "email": email})
    except Exception as e:
        # _send_email 应已处理，兜底
        raise HTTPException(500, f"邮件发送失败: {e}")
    except Exception as e:
        raise HTTPException(500, f"发送失败: {e}")


@app.post("/api/auth/login")
async def auth_login(body: dict):
    """邮箱 + 验证码登录/注册。新用户自动注册。"""
    email = (body.get("email") or "").strip().lower()
    code = (body.get("code") or "").strip()

    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        raise HTTPException(400, "请输入有效的邮箱地址")
    if not code or len(code) != 6 or not code.isdigit():
        raise HTTPException(400, "请输入 6 位验证码")

    # 校验验证码
    cached = verify_codes.get(email)
    if not cached:
        raise HTTPException(400, "请先获取验证码")
    if time.time() > cached["expire_at"]:
        verify_codes.pop(email, None)
        raise HTTPException(400, "验证码已过期，请重新获取")
    if cached["code"] != code:
        raise HTTPException(400, "验证码错误")

    # 验证码正确后清除
    verify_codes.pop(email, None)

    # 用户不存在则自动注册
    users = _load_users()
    if email not in users:
        # 从邮箱前缀取用户名
        username = email.split("@")[0]
        users[email] = {
            "password": "",  # 邮箱验证不需要密码
            "email": email,
            "username": username,
            "created_at": datetime.now().isoformat(),
            "gpt_api_key": "",
        }
        _save_users(users)
        is_new = True
    else:
        is_new = False
        username = users[email].get("username", email.split("@")[0])

    token = create_token(email)
    return JSONResponse({
        "token": token,
        "username": username,
        "email": email,
        "msg": "登录成功" if not is_new else "注册成功",
        "is_new": is_new,
    })


@app.get("/api/auth/me")
async def auth_me(payload: dict = Depends(verify_token)):
    """获取当前登录用户信息。"""
    email = payload["sub"]
    users = _load_users()
    user = users.get(email, {})
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
    users = _load_users()
    if email not in users:
        raise HTTPException(404, "用户不存在")

    if "gpt_api_key" in body:
        key = (body["gpt_api_key"] or "").strip()
        users[email]["gpt_api_key"] = key
    if "username" in body:
        name = (body["username"] or "").strip()
        if 2 <= len(name) <= 20:
            users[email]["username"] = name

    _save_users(users)
    return JSONResponse({"msg": "设置已保存"})


# ── GPT-Image-2 代理 API ──────────────────────────────────────────────────

def _get_user_key(username: str) -> str:
    """获取用户的 API Key。"""
    users = _load_users()
    user = users.get(username, {})
    return user.get("gpt_api_key", "")


@app.get("/api/gpt/status")
async def gpt_status(payload: dict = Depends(verify_token)):
    """查询当前用户 API Key 配置状态。"""
    key = _get_user_key(payload["sub"])
    return JSONResponse({
        "ready": bool(key),
    })


@app.post("/api/gpt/generate")
async def gpt_generate(body: dict, payload: dict = Depends(verify_token)):
    """提交生图任务到速创 API。"""
    username = payload["sub"]
    api_key = _get_user_key(username)
    if not api_key:
        raise HTTPException(400, "请先在个人中心配置 API Key")

    prompt = body.get("prompt", "").strip()
    if not prompt:
        raise HTTPException(400, "请输入提示词")

    payload = {
        "prompt": prompt,
        "size": body.get("size", "auto"),
    }
    urls = body.get("urls")
    if isinstance(urls, list) and len(urls):
        payload["urls"] = urls

    url = f"https://api.wuyinkeji.com/api/async/image_gpt?key={api_key}"
    headers = {
        "Authorization": api_key,
        "Content-Type": "application/json",
    }

    try:
        resp = http_requests.post(url, json=payload, headers=headers, timeout=60)
        data = resp.json()

        # 提取关键字段返回，不透传原始响应
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
    username = payload["sub"]
    api_key = _get_user_key(username)
    if not api_key:
        raise HTTPException(400, "请先在个人中心配置 API Key")

    url = f"https://api.wuyinkeji.com/api/async/detail?key={api_key}&id={task_id}"

    try:
        resp = http_requests.get(url, timeout=10)
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
