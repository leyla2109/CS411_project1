"""Application factory: wires the IAM module, the web UI and the gateway together."""
from __future__ import annotations

import time
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .audit import AuditLog
from .config import Settings
from .db import Database
from .iam import IAMService
from .mailer import Mailer, SMTPMailer
from .proxy import Gateway
from .signup import SignupService
from .web import build_router

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                               "script-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
}


def create_app(settings: Settings | None = None,
               ollama_transport: httpx.AsyncBaseTransport | None = None,
               mailer: Mailer | None = None) -> FastAPI:
    settings = settings or Settings()
    db = Database(settings.db_path)
    audit = AuditLog(db)
    iam = IAMService(db, audit, settings)
    iam.bootstrap()
    gateway = Gateway(iam, audit, settings.ollama_url, transport=ollama_transport)
    signup = SignupService(db, iam, audit, mailer or SMTPMailer(settings), settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        await gateway.close()
        db.close()

    app = FastAPI(title="Ollama Gateway", version="1.0.0", lifespan=lifespan,
                  docs_url="/ui/api-docs", redoc_url=None)
    app.state.iam, app.state.gateway, app.state.signup, app.state.settings = iam, gateway, signup, settings

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/ui"):
            for k, v in SECURITY_HEADERS.items():
                response.headers.setdefault(k, v)
            if request.url.path.startswith("/ui") and "/static/" not in request.url.path:
                response.headers["Cache-Control"] = "no-store"
        return response

    app.mount("/ui/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
    app.include_router(build_router(iam, settings, gateway, signup))

    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        """Public liveness probe. Deliberately reveals no versions or model names."""
        t0 = time.monotonic()
        try:
            res = await gateway.client.get("/", timeout=2)
            reachable = res.status_code == 200
        except httpx.HTTPError:
            reachable = False
        return {"gateway": "ok", "ollama": {"reachable": reachable,
                                            "latency_ms": int((time.monotonic() - t0) * 1000)}}

    @app.api_route("/{path:path}", methods=["GET", "POST", "DELETE", "HEAD", "PUT", "PATCH"],
                   include_in_schema=False)
    async def proxy(request: Request, path: str):
        full = "/" + path
        if full == "/" and request.method == "GET" and "text/html" in request.headers.get("accept", ""):
            return RedirectResponse("/ui", status_code=303)
        return await gateway.handle(request, full)

    @app.exception_handler(404)
    async def not_found(_: Request, __):
        return JSONResponse({"error": "not found"}, status_code=404)

    return app
