"""Policy Enforcement Point: the authenticated reverse proxy in front of Ollama.

Request pipeline (pipes and filters):
  identify caller -> extract model names -> PDP decision
  -> forward (streaming) -> filter listings -> audit
Callers are signed-in users of the gateway's pages: the session cookie
identifies them and an X-CSRF-Token header proves the call comes from our pages.
"""
from __future__ import annotations

import json
import secrets
import time

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from .audit import AuditLog
from .iam import IAMService
from .policy import Principal, decide, match_route, normalize_model

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
              "transfer-encoding", "upgrade", "host", "content-length", "authorization", "cookie"}
SESSION_COOKIE = "olg_session"
MAX_BODY = 64 * 1024 * 1024   # model creation can upload sizeable JSON; blobs are streamed separately


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def models_in_request(path: str, path_params: dict, body: bytes) -> list[str]:
    if "model" in path_params:
        return [path_params["model"]]
    if not body:
        return []
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    found = [data[k] for k in ("model", "name", "source", "destination") if isinstance(data.get(k), str)]
    return found


class Gateway:
    def __init__(self, iam: IAMService, audit: AuditLog, ollama_url: str,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.iam, self.audit = iam, audit
        self.client = httpx.AsyncClient(base_url=ollama_url, transport=transport,
                                        timeout=httpx.Timeout(connect=5, read=None, write=60, pool=5))

    async def close(self) -> None:
        await self.client.aclose()

    # -------------------------------------------------------------- identification
    def identify(self, request: Request) -> tuple[Principal | None, str | None]:
        """Return (principal, error)."""
        principal = self.iam.session_principal(request.cookies.get(SESSION_COOKIE))
        if principal and request.method not in ("GET", "HEAD", "OPTIONS"):
            # Browser calls must prove they come from our own pages (CSRF defence).
            sent = request.headers.get("x-csrf-token", "")
            if not secrets.compare_digest(sent, principal.csrf or ""):
                return None, "Missing or invalid CSRF token."
        return principal, None

    # -------------------------------------------------------------- main entry
    async def handle(self, request: Request, path: str) -> Response:
        rid = request.headers.get("x-request-id") or secrets.token_hex(8)
        started = time.monotonic()
        method = request.method
        principal, ident_error = self.identify(request)
        body = await request.body()
        if len(body) > MAX_BODY:
            return self._error(413, "Request body too large.", rid)

        matched = match_route(method, path)
        models = models_in_request(path, matched[1] if matched else {}, body)
        decision = decide(principal, method, path, models)
        if ident_error and decision.status == 401:
            decision.reason = ident_error

        actor = principal.actor if principal else None
        actor_type = principal.kind if principal else "anonymous"
        model = normalize_model(models[0]) if models else None
        if not decision.allowed:
            self.audit.record(f"api.{method} {path}", "deny", actor=actor, actor_type=actor_type,
                              resource=path, model=model, status=decision.status, ip=client_ip(request),
                              request_id=rid, detail=decision.reason)
            return self._error(decision.status, decision.reason, rid)

        headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP}
        headers["x-request-id"] = rid
        headers["x-forwarded-user"] = principal.username
        try:
            upstream_req = self.client.build_request(method, path, params=request.query_params,
                                                     content=body, headers=headers)
            upstream = await self.client.send(upstream_req, stream=True)
        except httpx.HTTPError:
            self.audit.record(f"api.{method} {path}", "allow", actor=actor, actor_type=actor_type,
                              resource=path, model=model, status=502, ip=client_ip(request),
                              request_id=rid, detail="ollama unreachable")
            return self._error(502, "Ollama isn't reachable from the gateway. Check that it is running.", rid)

        self.audit.record(f"api.{method} {path}", "allow", actor=actor, actor_type=actor_type,
                          resource=path, model=model, status=upstream.status_code, ip=client_ip(request),
                          request_id=rid, detail={"ms_to_first_byte": int((time.monotonic() - started) * 1000)})

        out_headers = {k: v for k, v in upstream.headers.items() if k.lower() not in HOP_BY_HOP | {"content-encoding"}}
        out_headers["x-request-id"] = rid

        # Listing endpoints: hide models the caller isn't allowed to use.
        if path in ("/api/tags", "/v1/models") and upstream.status_code == 200:
            raw = await upstream.aread()
            await upstream.aclose()
            return Response(self._filter_listing(path, raw, principal), status_code=200,
                             media_type="application/json", headers={"x-request-id": rid})

        async def relay():
            try:
                async for chunk in upstream.aiter_raw():
                    yield chunk
            finally:
                await upstream.aclose()

        return StreamingResponse(relay(), status_code=upstream.status_code, headers=out_headers,
                                 media_type=upstream.headers.get("content-type"))

    @staticmethod
    def _filter_listing(path: str, raw: bytes, principal: Principal) -> bytes:
        try:
            data = json.loads(raw)
            if path == "/api/tags":
                data["models"] = [m for m in data.get("models", []) if principal.may_use_model(m.get("name", ""))]
            else:
                data["data"] = [m for m in data.get("data", []) if principal.may_use_model(m.get("id", ""))]
            return json.dumps(data).encode()
        except (ValueError, AttributeError):
            return raw

    @staticmethod
    def _error(status: int, message: str, rid: str) -> JSONResponse:
        # Same {"error": "..."} shape that Ollama itself returns, so existing clients surface it.
        h = {"x-request-id": rid}
        return JSONResponse({"error": message}, status_code=status, headers=h)
