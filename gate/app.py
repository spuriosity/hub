import asyncio
import json
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

import httpx
import yaml
from fastapi import FastAPI, Request, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

logger = logging.getLogger("gate")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

config_path = Path(os.environ.get("GATE_CONFIG", "/etc/gate/config.yaml"))
with open(config_path) as f:
    config = yaml.safe_load(f)

SECRET_KEY = config["secret_key"]
SESSION_MAX_AGE = config.get("session_max_age", 86400 * 7)  # 7 days
TELEGRAM = config.get("telegram", {})
PROJECTS: dict = config.get("projects", {})

serializer = URLSafeTimedSerializer(SECRET_KEY)
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

# In-memory pending approvals
# {request_id: {email, project, next, status, created}}
pending: dict[str, dict] = {}

# ---------------------------------------------------------------------------
# Lifespan — background tasks
# ---------------------------------------------------------------------------


async def _poll_telegram():
    """Long-poll the Telegram Bot API for callback query updates."""
    bot_token = TELEGRAM.get("bot_token")
    if not bot_token:
        logger.info("No Telegram bot token configured — approval flow disabled")
        return

    offset = 0
    async with httpx.AsyncClient(timeout=60) as client:
        while True:
            try:
                resp = await client.get(
                    f"https://api.telegram.org/bot{bot_token}/getUpdates",
                    params={"offset": offset, "timeout": 30},
                )
                for update in resp.json().get("result", []):
                    offset = update["update_id"] + 1
                    await _handle_update(client, bot_token, update)
            except asyncio.CancelledError:
                return
            except Exception:
                logger.exception("Telegram poll error")
                await asyncio.sleep(5)


async def _handle_update(client: httpx.AsyncClient, bot_token: str, update: dict):
    cb = update.get("callback_query")
    if not cb:
        return

    data: str = cb.get("data", "")
    # Format: "approve:<request_id>" or "deny:<request_id>"
    if ":" not in data:
        return
    action, request_id = data.split(":", 1)
    if request_id not in pending:
        await client.post(
            f"https://api.telegram.org/bot{bot_token}/answerCallbackQuery",
            json={"callback_query_id": cb["id"], "text": "Request expired"},
        )
        return

    entry = pending[request_id]
    if action == "approve":
        entry["status"] = "approved"
        label = "Approved"
    elif action == "deny":
        entry["status"] = "denied"
        label = "Denied"
    else:
        return

    await client.post(
        f"https://api.telegram.org/bot{bot_token}/answerCallbackQuery",
        json={"callback_query_id": cb["id"], "text": label},
    )
    await client.post(
        f"https://api.telegram.org/bot{bot_token}/editMessageText",
        json={
            "chat_id": cb["message"]["chat"]["id"],
            "message_id": cb["message"]["message_id"],
            "text": f"{label}: {entry['email']} for {entry['project']}",
        },
    )


async def _cleanup_pending():
    """Expire stale approval requests every 60 s."""
    while True:
        await asyncio.sleep(60)
        now = time.time()
        expired = [k for k, v in pending.items() if now - v["created"] > 600]
        for k in expired:
            del pending[k]


@asynccontextmanager
async def lifespan(_app: FastAPI):
    t1 = asyncio.create_task(_poll_telegram())
    t2 = asyncio.create_task(_cleanup_pending())
    yield
    t1.cancel()
    t2.cancel()


app = FastAPI(lifespan=lifespan)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cookie_name(project: str) -> str:
    return f"gate_{project}"


def _safe_next(next_url: str, expected_host: str) -> str:
    """Prevent open redirects — only allow relative paths or same-host URLs."""
    if not next_url or next_url == "/":
        return "/"
    parsed = urlparse(next_url)
    if not parsed.scheme:
        # Relative URL
        return next_url
    if parsed.hostname == expected_host:
        return next_url
    return "/"


def _make_session_response(email: str, project: str, next_url: str) -> Response:
    token = serializer.dumps({"email": email, "project": project})
    resp = RedirectResponse(url=next_url, status_code=302)
    resp.set_cookie(
        key=_cookie_name(project),
        value=token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="lax",
    )
    return resp


# ---------------------------------------------------------------------------
# Routes — forward_auth check
# ---------------------------------------------------------------------------


@app.get("/auth/check")
async def auth_check(request: Request, project: str):
    """Called by Caddy forward_auth. Returns 200 to allow, 302 to redirect."""
    if project not in PROJECTS:
        return Response(status_code=403)

    token = request.cookies.get(_cookie_name(project))
    if not token:
        return _redirect_to_login(request, project)

    try:
        data = serializer.loads(token, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return _redirect_to_login(request, project)

    if data.get("project") != project:
        return _redirect_to_login(request, project)

    return Response(status_code=200, headers={"X-Auth-User": data.get("email", "")})


def _redirect_to_login(request: Request, project: str) -> Response:
    proto = request.headers.get("X-Forwarded-Proto", "https")
    host = request.headers.get("X-Forwarded-Host", request.headers.get("host", ""))
    uri = request.headers.get("X-Forwarded-Uri", "/")
    next_url = f"{proto}://{host}{uri}"
    return RedirectResponse(f"/auth/login?project={project}&next={next_url}", status_code=302)


# ---------------------------------------------------------------------------
# Routes — login
# ---------------------------------------------------------------------------


@app.get("/auth/login")
async def login_page(request: Request, project: str, next: str = "/"):
    if project not in PROJECTS:
        return HTMLResponse("Unknown project", status_code=404)
    return templates.TemplateResponse(request, "login.html", {"project": project, "next": next})


@app.post("/auth/login")
async def login_submit(
    request: Request,
    project: str = Form(...),
    email: str = Form(...),
    next: str = Form("/"),
):
    if project not in PROJECTS:
        return HTMLResponse("Unknown project", status_code=404)

    project_config = PROJECTS[project]
    email = email.strip().lower()
    allowlist = [e.lower() for e in project_config.get("allowlist", [])]
    host = request.headers.get("host", "")
    safe_next = _safe_next(next, host)

    # Allowlisted → immediate session
    if email in allowlist:
        return _make_session_response(email, project, safe_next)

    # Telegram approval flow
    if project_config.get("telegram_approval") and TELEGRAM.get("bot_token"):
        request_id = secrets.token_urlsafe(16)
        pending[request_id] = {
            "email": email,
            "project": project,
            "next": safe_next,
            "status": "pending",
            "created": time.time(),
        }
        await _send_telegram_approval(request_id, email, project)
        return templates.TemplateResponse(request, "waiting.html", {"project": project, "request_id": request_id})

    return templates.TemplateResponse(request, "denied.html", {"project": project})


# ---------------------------------------------------------------------------
# Routes — approval polling & claim
# ---------------------------------------------------------------------------


@app.get("/auth/status/{request_id}")
async def approval_status(request_id: str):
    entry = pending.get(request_id)
    if not entry or time.time() - entry["created"] > 600:
        return JSONResponse({"status": "expired"})
    return JSONResponse({"status": entry["status"]})


@app.get("/auth/claim/{request_id}")
async def claim_session(request_id: str, request: Request):
    entry = pending.get(request_id)
    if not entry or entry["status"] != "approved":
        return HTMLResponse("Invalid or expired request", status_code=400)

    host = request.headers.get("host", "")
    next_url = _safe_next(entry["next"], host)
    resp = _make_session_response(entry["email"], entry["project"], next_url)
    del pending[request_id]
    return resp


# ---------------------------------------------------------------------------
# Routes — logout
# ---------------------------------------------------------------------------


@app.get("/auth/logout")
async def logout(project: str, request: Request):
    host = request.headers.get("host", "")
    resp = RedirectResponse(f"/auth/login?project={project}", status_code=302)
    resp.delete_cookie(_cookie_name(project))
    return resp


# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------


async def _send_telegram_approval(request_id: str, email: str, project: str):
    bot_token = TELEGRAM["bot_token"]
    chat_id = TELEGRAM["admin_chat_id"]

    keyboard = {
        "inline_keyboard": [[
            {"text": "Approve", "callback_data": f"approve:{request_id}"},
            {"text": "Deny", "callback_data": f"deny:{request_id}"},
        ]]
    }

    async with httpx.AsyncClient() as client:
        await client.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={
                "chat_id": chat_id,
                "text": f"Access request\n\nEmail: {email}\nProject: {project}",
                "reply_markup": keyboard,
            },
        )
