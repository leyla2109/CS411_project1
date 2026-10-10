"""Server-rendered pages: sign-in, MFA, account, user administration, audit."""
from __future__ import annotations

import base64
import io
import secrets
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import qrcode
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from . import security
from .iam import IAMError, IAMService
from .policy import ROLES, Perm, Principal
from .proxy import SESSION_COOKIE, client_ip

LOGIN_CSRF_COOKIE = "olg_login_csrf"
SIGNUP_COOKIE = "olg_signup"
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

OK_MESSAGES = {
    "mfa_on": "Two-step verification is on. You'll need your app at the next sign-in.",
    "mfa_off": "Two-step verification is off.",
    "pw": "Password changed.",
    "user_added": "User added.",
    "user_saved": "Changes saved.",
    "unlocked": "Account unlocked.",
    "mfa_reset": "Authenticator reset. The user can sign in with a password and set it up again.",
    "welcome": "Your account is ready. Welcome to the gateway.",
    "logged_out": "You're signed out.",
}


def ago(ts: float | None) -> str:
    if not ts:
        return "never"
    delta = time.time() - ts
    if delta < 0:
        days = int(-delta // 86400)
        return f"in {days} day{'s' if days != 1 else ''}" if days else "today"
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if delta >= size:
            n = int(delta // size)
            return f"{n} {unit}{'s' if n != 1 else ''} ago"
    return "just now"


def human_size(n: int | None) -> str:
    if not n:
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} PB"


def build_router(iam: IAMService, settings, gateway, signup) -> APIRouter:
    r = APIRouter(prefix="/ui")
    templates.env.globals["developer_domains"] = settings.developer_domains
    secure = settings.secure_cookies

    def set_session(resp, sid: str, minutes: int) -> None:
        resp.set_cookie(SESSION_COOKIE, sid, max_age=minutes * 60, httponly=True, samesite="lax",
                        secure=secure, path="/")

    def current(request: Request) -> Principal | None:
        return iam.session_principal(request.cookies.get(SESSION_COOKIE))

    def to_login(request: Request) -> RedirectResponse:
        return RedirectResponse(f"/ui/login?next={quote(request.url.path)}", status_code=303)

    def csrf_ok(me: Principal, token: str) -> bool:
        return bool(token) and secrets.compare_digest(token, me.csrf or "")

    def page(request: Request, name: str, me: Principal | None, **ctx) -> HTMLResponse:
        ok = request.query_params.get("ok")
        if ok in OK_MESSAGES and "flash" not in ctx:
            ctx["flash"] = OK_MESSAGES[ok]
        return templates.TemplateResponse(request, name, {"me": me, "roles": ROLES, **ctx})

    def forbidden(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "error.html", {
            "title": "You don't have access to this page",
            "message": "Your role doesn't include this area. Ask an administrator if you need it."}, status_code=403)

    def login_page(request: Request, error: str = "", username: str = "", status: int = 200, info: str = ""):
        token = security.random_token(16)
        resp = templates.TemplateResponse(request, "login.html", {
            "error": error, "info": info, "username": username, "login_csrf": token,
            "next": request.query_params.get("next") or "", "signup_enabled": settings.smtp_configured},
            status_code=status)
        resp.set_cookie(LOGIN_CSRF_COOKIE, token, max_age=1800, httponly=True, samesite="strict", secure=secure)
        return resp

    def safe_next(value: str | None) -> str:
        return value if value and value.startswith("/ui") and not value.startswith("//") else "/ui"

    # ------------------------------------------------------------------ sign in
    @r.get("/login", response_class=HTMLResponse)
    def login_form(request: Request):
        if current(request):
            return RedirectResponse("/ui", status_code=303)
        info = OK_MESSAGES.get(request.query_params.get("ok", ""), "")
        return login_page(request, info=info)

    @r.post("/login")
    def login_submit(request: Request, username: str = Form(""), password: str = Form(""),
                     csrf: str = Form(""), next: str = Form("")):
        cookie = request.cookies.get(LOGIN_CSRF_COOKIE, "")
        if not csrf or not secrets.compare_digest(csrf, cookie):
            return login_page(request, "Your sign-in form expired. Try again.", username, 400)
        if not username.strip() or not password:
            return login_page(request, "Enter both your username and password.", username, 400)
        result = iam.authenticate(username, password, client_ip(request), request.headers.get("user-agent"))
        if not result.ok:
            return login_page(request, result.message, username, 401)
        dest = "/ui/login/mfa" if result.needs_mfa else safe_next(next)
        resp = RedirectResponse(dest, status_code=303)
        set_session(resp, result.session_id, 5 if result.needs_mfa else settings.session_minutes)
        resp.delete_cookie(LOGIN_CSRF_COOKIE)
        return resp

    @r.get("/login/mfa", response_class=HTMLResponse)
    def mfa_form(request: Request):
        row = iam.session_row(request.cookies.get(SESSION_COOKIE, ""))
        if not row or not row["mfa_pending"] or row["revoked"]:
            return RedirectResponse("/ui/login", status_code=303)
        return templates.TemplateResponse(request, "mfa.html", {"csrf": row["csrf"]})

    @r.post("/login/mfa")
    def mfa_submit(request: Request, code: str = Form(""), csrf: str = Form("")):
        sid = request.cookies.get(SESSION_COOKIE, "")
        row = iam.session_row(sid)
        if not row or not row["mfa_pending"] or row["revoked"] or not secrets.compare_digest(csrf, row["csrf"]):
            return RedirectResponse("/ui/login", status_code=303)
        new_sid = iam.complete_mfa(sid, code, client_ip(request))
        if not new_sid:
            return templates.TemplateResponse(request, "mfa.html", {
                "csrf": row["csrf"],
                "error": "That code didn't work. Codes change every 30 seconds — use the one showing now."},
                status_code=401)
        resp = RedirectResponse("/ui", status_code=303)
        set_session(resp, new_sid, settings.session_minutes)
        return resp

    @r.post("/logout")
    def logout(request: Request, csrf: str = Form("")):
        sid = request.cookies.get(SESSION_COOKIE, "")
        row = iam.session_row(sid)
        if row and secrets.compare_digest(csrf, row["csrf"]):
            me = iam.get_user(row["user_id"])
            iam.logout(sid, me["username"] if me else None)
        resp = RedirectResponse("/ui/login?ok=logged_out", status_code=303)
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    # ------------------------------------------------------------------ sign-up
    def signup_page(request: Request, error: str = "", form: dict | None = None, status: int = 200):
        token = security.random_token(16)
        resp = templates.TemplateResponse(request, "signup.html", {
            "error": error, "form": form or {}, "login_csrf": token, "enabled": settings.smtp_configured,
            "developer_domains": settings.developer_domains, "minutes": settings.signup_code_minutes},
            status_code=status)
        resp.set_cookie(LOGIN_CSRF_COOKIE, token, max_age=1800, httponly=True, samesite="strict", secure=secure)
        return resp

    def verify_page(request: Request, pending: dict, error: str = "", info: str = "", status: int = 200):
        token = security.random_token(16)
        resp = templates.TemplateResponse(request, "signup_verify.html", {
            "error": error, "info": info, "email": pending["email"], "login_csrf": token,
            "role": ROLES[pending["role"]]["label"], "minutes": settings.signup_code_minutes}, status_code=status)
        resp.set_cookie(LOGIN_CSRF_COOKIE, token, max_age=1800, httponly=True, samesite="strict", secure=secure)
        return resp

    def form_csrf_ok(request: Request, token: str) -> bool:
        cookie = request.cookies.get(LOGIN_CSRF_COOKIE, "")
        return bool(token) and secrets.compare_digest(token, cookie)

    @r.get("/signup", response_class=HTMLResponse)
    def signup_form(request: Request):
        if current(request):
            return RedirectResponse("/ui", status_code=303)
        return signup_page(request)

    @r.post("/signup")
    def signup_submit(request: Request, email: str = Form(""), display_name: str = Form(""),
                      password: str = Form(""), csrf: str = Form("")):
        form = {"email": email, "display_name": display_name}
        if not settings.smtp_configured:
            return signup_page(request, status=503)
        if not form_csrf_ok(request, csrf):
            return signup_page(request, "Your form expired. Try again.", form, 400)
        try:
            sid = signup.start(email, display_name, password, client_ip(request))
        except IAMError as exc:
            return signup_page(request, str(exc), form, 400)
        resp = RedirectResponse("/ui/signup/verify", status_code=303)
        resp.set_cookie(SIGNUP_COOKIE, sid, max_age=settings.signup_code_minutes * 60 * 3, httponly=True,
                        samesite="lax", secure=secure)
        return resp

    @r.get("/signup/verify", response_class=HTMLResponse)
    def signup_verify_form(request: Request):
        pending = signup.pending(request.cookies.get(SIGNUP_COOKIE))
        if not pending:
            return RedirectResponse("/ui/signup", status_code=303)
        return verify_page(request, pending)

    @r.post("/signup/verify")
    def signup_verify(request: Request, code: str = Form(""), csrf: str = Form("")):
        sid = request.cookies.get(SIGNUP_COOKIE)
        pending = signup.pending(sid)
        if not pending:
            return signup_page(request, "That sign-up expired. Fill in the form again.", status=400)
        if not form_csrf_ok(request, csrf):
            return verify_page(request, pending, "Your form expired. Try again.", status=400)
        try:
            uid = signup.confirm(sid, code, client_ip(request))
        except IAMError as exc:
            if signup.pending(sid) is None:
                return signup_page(request, str(exc), {"email": pending["email"],
                                                       "display_name": pending["display_name"]}, 400)
            return verify_page(request, pending, str(exc), status=400)
        session = iam.login_after_signup(uid, client_ip(request), request.headers.get("user-agent"))
        resp = RedirectResponse("/ui?ok=welcome", status_code=303)
        set_session(resp, session, settings.session_minutes)
        resp.delete_cookie(SIGNUP_COOKIE)
        resp.delete_cookie(LOGIN_CSRF_COOKIE)
        return resp

    @r.post("/signup/resend", response_class=HTMLResponse)
    def signup_resend(request: Request, csrf: str = Form("")):
        sid = request.cookies.get(SIGNUP_COOKIE)
        pending = signup.pending(sid)
        if not pending:
            return RedirectResponse("/ui/signup", status_code=303)
        if not form_csrf_ok(request, csrf):
            return verify_page(request, pending, "Your form expired. Try again.", status=400)
        try:
            signup.resend(sid, client_ip(request))
        except IAMError as exc:
            return verify_page(request, pending, str(exc), status=429)
        return verify_page(request, pending, info=f"We sent a new code to {pending['email']}.")

    # ------------------------------------------------------------------ dashboard
    @r.get("", response_class=HTMLResponse)
    async def dashboard(request: Request):
        me = current(request)
        if not me:
            return to_login(request)
        models, models_error = [], ""
        try:
            res = await gateway.client.get("/api/tags", timeout=5)
            models = [m for m in res.json().get("models", []) if me.may_use_model(m.get("name", ""))]
            for m in models:
                m["size_h"] = human_size(m.get("size"))
        except Exception:
            models_error = "Ollama isn't reachable right now, so the model list is empty."
        return page(request, "dashboard.html", me, active="home", models=models,
                    models_error=models_error, all_perms=list(Perm))

    # ------------------------------------------------------------------ account
    def account_page(request: Request, me: Principal, **extra):
        user = iam.get_user(me.user_id)
        return page(request, "account.html", me, active="account", user=user, **extra)

    @r.get("/account", response_class=HTMLResponse)
    def account(request: Request):
        me = current(request)
        return account_page(request, me) if me else to_login(request)

    @r.post("/account/mfa/start", response_class=HTMLResponse)
    def mfa_start(request: Request, csrf: str = Form("")):
        me = current(request)
        if not me or not csrf_ok(me, csrf):
            return to_login(request)
        secret = iam.begin_mfa_enrolment(me.user_id)
        img = qrcode.make(security.totp_uri(secret, me.username), box_size=6, border=1)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return account_page(request, me, enrol_secret=secret, enrol_qr=base64.b64encode(buf.getvalue()).decode())

    @r.post("/account/mfa/confirm", response_class=HTMLResponse)
    def mfa_confirm(request: Request, code: str = Form(""), csrf: str = Form("")):
        me = current(request)
        if not me or not csrf_ok(me, csrf):
            return to_login(request)
        if iam.confirm_mfa_enrolment(me.user_id, code):
            return RedirectResponse("/ui/account?ok=mfa_on", status_code=303)
        user = iam.get_user(me.user_id)
        img = qrcode.make(security.totp_uri(user["mfa_secret"], me.username), box_size=6, border=1)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return account_page(request, me, enrol_secret=user["mfa_secret"], enrol_qr=base64.b64encode(buf.getvalue()).decode(),
                            flash="That code didn't match. Check the time on your phone and try the current code.",
                            flash_kind="bad")

    @r.post("/account/mfa/disable")
    def mfa_disable(request: Request, csrf: str = Form("")):
        me = current(request)
        if not me or not csrf_ok(me, csrf):
            return to_login(request)
        iam.disable_mfa(me.user_id, me.username)
        return RedirectResponse("/ui/account?ok=mfa_off", status_code=303)

    @r.post("/account/password", response_class=HTMLResponse)
    def change_password(request: Request, current_pw: str = Form("", alias="current"), new: str = Form(""),
                        csrf: str = Form("")):
        me = current(request)
        if not me or not csrf_ok(me, csrf):
            return to_login(request)
        try:
            iam.change_password(me.user_id, current_pw, new)
        except IAMError as exc:
            return account_page(request, me, flash=str(exc), flash_kind="bad")
        return RedirectResponse("/ui/account?ok=pw", status_code=303)

    # ------------------------------------------------------------------ administration
    def users_page(request: Request, me: Principal, **extra):
        users = iam.list_users()
        now = time.time()
        for u in users:
            u["locked"] = u["locked_until"] > now
            u["last_login_h"] = "last seen " + ago(u["last_login_at"])
        return page(request, "admin_users.html", me, active="users", users=users,
                    developer_domains=settings.developer_domains, **extra)

    @r.get("/admin/users", response_class=HTMLResponse)
    def admin_users(request: Request):
        me = current(request)
        if not me:
            return to_login(request)
        return users_page(request, me) if me.can(Perm.IAM_ADMIN) else forbidden(request)

    @r.post("/admin/users", response_class=HTMLResponse)
    async def admin_add_user(request: Request):
        me = current(request)
        form = await request.form()
        if not me or not csrf_ok(me, form.get("csrf", "")):
            return to_login(request)
        if not me.can(Perm.IAM_ADMIN):
            return forbidden(request)
        try:
            iam.create_user(form.get("username", ""), form.get("display_name", ""), form.get("password", ""),
                            form.getlist("roles") or ["viewer"], model_allow=form.get("model_allow", "*"),
                            actor=me.username)
        except IAMError as exc:
            return users_page(request, me, flash=str(exc), flash_kind="bad")
        return RedirectResponse("/ui/admin/users?ok=user_added", status_code=303)

    @r.post("/admin/users/{user_id}", response_class=HTMLResponse)
    async def admin_update_user(request: Request, user_id: int):
        me = current(request)
        form = await request.form()
        if not me or not csrf_ok(me, form.get("csrf", "")):
            return to_login(request)
        if not me.can(Perm.IAM_ADMIN):
            return forbidden(request)
        try:
            iam.update_user(user_id, roles=form.getlist("roles") or ["viewer"],
                            model_allow=form.get("model_allow", "*"), is_active=form.get("is_active") == "1",
                            actor=me.username)
        except IAMError as exc:
            return users_page(request, me, flash=str(exc), flash_kind="bad")
        return RedirectResponse("/ui/admin/users?ok=user_saved", status_code=303)

    @r.post("/admin/users/{user_id}/unlock")
    def admin_unlock(request: Request, user_id: int, csrf: str = Form("")):
        me = current(request)
        if not me or not csrf_ok(me, csrf) or not me.can(Perm.IAM_ADMIN):
            return to_login(request)
        iam.unlock_user(user_id, me.username)
        return RedirectResponse("/ui/admin/users?ok=unlocked", status_code=303)

    @r.post("/admin/users/{user_id}/reset-mfa")
    def admin_reset_mfa(request: Request, user_id: int, csrf: str = Form("")):
        me = current(request)
        if not me or not csrf_ok(me, csrf) or not me.can(Perm.IAM_ADMIN):
            return to_login(request)
        iam.disable_mfa(user_id, me.username)
        return RedirectResponse("/ui/admin/users?ok=mfa_reset", status_code=303)

    @r.get("/admin/audit", response_class=HTMLResponse)
    def admin_audit(request: Request, actor: str = "", decision: str = ""):
        me = current(request)
        if not me:
            return to_login(request)
        if not me.can(Perm.AUDIT_READ):
            return forbidden(request)
        events = iam.audit.recent(300, actor or None, decision or None)
        for e in events:
            e["ts_h"] = datetime.fromtimestamp(e["ts"]).strftime("%d %b %H:%M:%S")
        return page(request, "admin_audit.html", me, active="audit", events=events, actor=actor, decision=decision)

    return r
