import re
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import mock_ollama  # noqa: E402
from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402
from app.policy import Principal, decide  # noqa: E402

BASE = "http://testserver"


class FakeMailer:
    """Records e-mails instead of sending them."""
    def __init__(self):
        self.sent = []

    def send(self, to, subject, text, html=None):
        self.sent.append({"to": to, "subject": subject, "text": text})

    def last_code(self):
        return re.search(r"\b(\d{6})\b", self.sent[-1]["subject"]).group(1)


@pytest.fixture()
def mailer():
    return FakeMailer()


@pytest.fixture()
def app(tmp_path, mailer):
    settings = Settings(data_dir=tmp_path, public_url=BASE, smtp_host="smtp.test", smtp_from="gw@test",
                        developer_domains=["bilkent.edu.tr"])
    return create_app(settings, ollama_transport=httpx.ASGITransport(app=mock_ollama.app), mailer=mailer)


@pytest.fixture()
def client(app):
    with TestClient(app, base_url=BASE) as c:
        yield c


def login(client, username, password):
    page = client.get("/ui/login")
    token = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    return client.post("/ui/login", data={"username": username, "password": password, "csrf": token},
                       follow_redirects=False)


def csrf_header(client):
    token = re.search(r'name="csrf-token" content="([^"]+)"', client.get("/ui").text).group(1)
    return {"X-CSRF-Token": token}


# ---------------------------------------------------------------- primitives
def test_password_hash_roundtrip():
    h = security.hash_password("Correct-Horse-9")
    assert security.verify_password("Correct-Horse-9", h)
    assert not security.verify_password("correct-horse-9", h)


def test_totp_rfc6238_vector_and_replay():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"   # "12345678901234567890"
    assert security.totp_now(secret, at=59) == "287082"
    step = security.verify_totp(secret, "287082", 0, at=59)
    assert step == 1
    assert security.verify_totp(secret, "287082", last_step=step, at=59) is None   # replay blocked


def test_policy_decisions():
    dev = Principal(1, "d", "D", ["developer"], ["llama3.2*"])
    viewer = Principal(2, "v", "V", ["viewer"], ["*"])
    assert decide(dev, "POST", "/api/chat", ["llama3.2"]).allowed
    assert decide(dev, "POST", "/api/chat", ["qwen3:8b"]).status == 403
    assert decide(dev, "POST", "/api/pull", ["llama3.2"]).status == 403
    assert decide(viewer, "POST", "/api/chat", ["llama3.2"]).status == 403
    assert decide(None, "GET", "/api/tags", []).status == 401
    assert decide(dev, "POST", "/api/unknown", []).status == 404


# ---------------------------------------------------------------- sign-in
def test_login_success_and_generic_failure(client):
    assert login(client, "admin", "wrong").status_code == 401
    r = login(client, "nobody", "whatever")
    assert r.status_code == 401 and "match. Check both" in r.text
    r = login(client, "admin", "ChangeMe!2026")
    assert r.status_code == 303 and r.headers["location"] == "/ui"
    assert client.get("/ui").status_code == 200


def test_login_requires_csrf(client):
    client.get("/ui/login")
    r = client.post("/ui/login", data={"username": "admin", "password": "ChangeMe!2026", "csrf": "forged"})
    assert r.status_code == 400


def test_lockout_after_five_failures(client):
    for _ in range(5):
        login(client, "mert.view", "nope")
    r = login(client, "mert.view", "Viewer!2026x")       # right password, but locked
    assert r.status_code == 401 and "Too many failed attempts" in r.text


def test_mfa_flow(app, client):
    iam = app.state.iam
    uid = iam.find_user("ayse.op")["id"]
    secret = iam.begin_mfa_enrolment(uid)
    assert iam.confirm_mfa_enrolment(uid, security.totp_now(secret, at=__import__("time").time() - 30))
    r = login(client, "ayse.op", "Operator!2026")
    assert r.headers["location"] == "/ui/login/mfa"
    assert client.get("/ui", follow_redirects=False).status_code == 303          # not signed in yet
    page = client.get("/ui/login/mfa")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    assert client.post("/ui/login/mfa", data={"code": "000000", "csrf": csrf}).status_code == 401
    r = client.post("/ui/login/mfa", data={"code": security.totp_now(secret), "csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/ui"
    assert client.get("/ui").status_code == 200


# ---------------------------------------------------------------- gateway
def test_api_requires_auth(client):
    r = client.get("/api/tags")
    assert r.status_code == 401 and r.json()["error"]


def test_developer_allowlist_through_gateway(client):
    login(client, "deniz.dev", "Developer!2026")
    h = csrf_header(client)
    tags = client.get("/api/tags").json()["models"]
    assert {m["name"] for m in tags} == {"llama3.2:latest", "qwen3:8b", "nomic-embed-text:latest"}   # filtered
    r = client.post("/api/chat", headers=h, json={"model": "llama3.2", "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 200 and '"model": "llama3.2:latest"' in r.text
    assert client.post("/api/chat", headers=h, json={"model": "gemma3:12b", "messages": []}).status_code == 403
    assert client.post("/api/pull", headers=h, json={"model": "llama3.2"}).status_code == 403


def test_viewer_cannot_run_models(client):
    login(client, "mert.view", "Viewer!2026x")
    h = csrf_header(client)
    assert client.get("/api/tags").status_code == 200
    r = client.post("/api/chat", headers=h, json={"model": "llama3.2", "messages": []})
    assert r.status_code == 403 and "model:run" in r.json()["error"]


def test_openai_compatible_route_is_enforced(client):
    login(client, "admin", "ChangeMe!2026")
    r = client.post("/v1/chat/completions", headers=csrf_header(client),
                    json={"model": "qwen3:8b", "messages": [{"role": "user", "content": "hello"}]})
    assert r.status_code == 200 and r.json()["choices"][0]["message"]["content"]


def test_disabled_user_loses_access(app, client):
    login(client, "deniz.dev", "Developer!2026")
    assert client.get("/api/tags").status_code == 200
    iam = app.state.iam
    iam.update_user(iam.find_user("deniz.dev")["id"], is_active=False, actor="admin")
    assert client.get("/api/tags").status_code == 401


def test_browser_session_needs_csrf_header(client):
    login(client, "admin", "ChangeMe!2026")
    body = {"model": "llama3.2", "messages": [{"role": "user", "content": "hi"}]}
    assert client.post("/api/chat", json=body).status_code == 401
    csrf = re.search(r'name="csrf-token" content="([^"]+)"', client.get("/ui").text).group(1)
    assert client.post("/api/chat", json=body, headers={"X-CSRF-Token": csrf}).status_code == 200


def test_denials_are_audited(app, client):
    client.get("/api/tags")
    events = app.state.iam.audit.recent(10, decision="deny")
    assert any(e["action"] == "api.GET /api/tags" and e["status"] == 401 for e in events)


# ---------------------------------------------------------------- sign-up
def start_signup(client, email, name="Test User", password="Str0ng-pass!"):
    page = client.get("/ui/signup")
    token = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    return client.post("/ui/signup", data={"email": email, "display_name": name, "password": password,
                                           "csrf": token}, follow_redirects=False)


def confirm_signup(client, code):
    page = client.get("/ui/signup/verify")
    token = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    return client.post("/ui/signup/verify", data={"code": code, "csrf": token}, follow_redirects=False)


def test_signup_bilkent_becomes_developer(app, client, mailer):
    r = start_signup(client, "Ece.Yilmaz@ug.bilkent.edu.tr")
    assert r.status_code == 303 and r.headers["location"] == "/ui/signup/verify"
    assert mailer.sent[-1]["to"] == "ece.yilmaz@ug.bilkent.edu.tr"
    assert app.state.iam.find_user("ece.yilmaz@ug.bilkent.edu.tr") is None      # not before the code
    r = confirm_signup(client, mailer.last_code())
    assert r.status_code == 303 and r.headers["location"].startswith("/ui")
    user = app.state.iam.find_user("ece.yilmaz@ug.bilkent.edu.tr")
    assert user["roles"] == ["developer"] and user["auth_source"] == "signup"
    assert client.get("/ui").status_code == 200                                   # signed in straight away


def test_signup_other_domain_becomes_viewer_and_can_log_in(app, client, mailer):
    start_signup(client, "sam@gmail.com")
    confirm_signup(client, mailer.last_code())
    assert app.state.iam.find_user("sam@gmail.com")["roles"] == ["viewer"]
    client.cookies.clear()
    assert login(client, "sam@gmail.com", "Str0ng-pass!").status_code == 303     # e-mail works as username


def test_signup_wrong_code_limited(app, client, mailer):
    start_signup(client, "x@bilkent.edu.tr")
    right = mailer.last_code()
    wrong = "000000" if right != "000000" else "111111"
    for i in range(4):
        r = confirm_signup(client, wrong)
        assert r.status_code == 400 and "attempt" in r.text
    r = confirm_signup(client, wrong)                       # 5th wrong code discards the sign-up
    assert "Too many wrong codes" in r.text
    assert confirm_signup(client, right).status_code == 400
    assert app.state.iam.find_user("x@bilkent.edu.tr") is None


def test_signup_rejects_duplicates_and_bad_input(client, mailer):
    start_signup(client, "dup@bilkent.edu.tr")
    confirm_signup(client, mailer.last_code())
    client.cookies.clear()
    r = start_signup(client, "DUP@bilkent.edu.tr")
    assert r.status_code == 400 and "already exists" in r.text
    assert start_signup(client, "not-an-email").status_code == 400
    assert start_signup(client, "weak@bilkent.edu.tr", password="short").status_code == 400


def test_signup_resend_cooldown(client, mailer):
    start_signup(client, "r@bilkent.edu.tr")
    page = client.get("/ui/signup/verify")
    token = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    r = client.post("/ui/signup/resend", data={"csrf": token})
    assert r.status_code == 429 and "Wait" in r.text
    assert len(mailer.sent) == 1
