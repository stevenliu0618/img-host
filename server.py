import os
import re
import shutil
import mimetypes
import base64
import hashlib
import json
from pathlib import Path
from datetime import datetime

import requests as http_requests
from fastapi import FastAPI, File, UploadFile, HTTPException
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


# ── GPT-Image-2 代理 API ──────────────────────────────────────────────────

# 服务端 API Key（硬编码，前端零接触）
GPTIMAGE_API_KEY = "z257spNXb7V9nbYpIiH5JMh3VM"


@app.get("/api/gpt/status")
async def gpt_status():
    """查询 API Key 配置状态（不暴露完整 Key）。"""
    return JSONResponse({
        "ready": True,
        "keyHint": GPTIMAGE_API_KEY[:8] + "…",
    })


@app.post("/api/gpt/generate")
async def gpt_generate(body: dict):
    """提交生图任务到速创 API。"""
    if not GPTIMAGE_API_KEY:
        raise HTTPException(400, "服务端未配置 API Key")

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

    url = f"https://api.wuyinkeji.com/api/async/image_gpt?key={GPTIMAGE_API_KEY}"
    headers = {
        "Authorization": GPTIMAGE_API_KEY,
        "Content-Type": "application/json",
    }

    try:
        resp = http_requests.post(url, json=payload, headers=headers, timeout=15)
        data = resp.json()
        return JSONResponse(content=data)
    except http_requests.Timeout:
        raise HTTPException(502, "第三方 API 超时")
    except Exception as e:
        raise HTTPException(502, f"请求第三方 API 失败: {e}")


@app.get("/api/gpt/result/{task_id}")
async def gpt_result(task_id: str):
    """查询生图任务结果。"""
    if not GPTIMAGE_API_KEY:
        raise HTTPException(400, "服务端未配置 API Key")

    url = f"https://api.wuyinkeji.com/api/async/detail?key={GPTIMAGE_API_KEY}&id={task_id}"

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
