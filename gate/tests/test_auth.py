import os
import time

import pytest
from fastapi.testclient import TestClient
from itsdangerous import URLSafeTimedSerializer

os.environ["GATE_CONFIG"] = os.path.join(os.path.dirname(__file__), "fixtures", "test_config.yaml")

from app import app, pending, serializer, SESSION_MAX_AGE  # noqa: E402


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clear_pending():
    pending.clear()
    yield
    pending.clear()


# ---------------------------------------------------------------------------
# /auth/check
# ---------------------------------------------------------------------------


def test_should_return_302_when_no_session_cookie(client):
    resp = client.get(
        "/auth/check",
        params={"project": "testproj"},
        headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "test.example.com", "X-Forwarded-Uri": "/"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "/auth/login?project=testproj" in resp.headers["location"]


def test_should_return_200_with_valid_session(client):
    token = serializer.dumps({"email": "allowed@example.com", "project": "testproj"})
    resp = client.get(
        "/auth/check",
        params={"project": "testproj"},
        cookies={"gate_testproj": token},
    )
    assert resp.status_code == 200
    assert resp.headers["x-auth-user"] == "allowed@example.com"


def test_should_reject_cookie_for_wrong_project(client):
    token = serializer.dumps({"email": "allowed@example.com", "project": "other"})
    resp = client.get(
        "/auth/check",
        params={"project": "testproj"},
        cookies={"gate_testproj": token},
        headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "test.example.com", "X-Forwarded-Uri": "/"},
        follow_redirects=False,
    )
    assert resp.status_code == 302


def test_should_reject_tampered_cookie(client):
    resp = client.get(
        "/auth/check",
        params={"project": "testproj"},
        cookies={"gate_testproj": "garbage.token.here"},
        headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "test.example.com", "X-Forwarded-Uri": "/"},
        follow_redirects=False,
    )
    assert resp.status_code == 302


def test_should_return_403_for_unknown_project(client):
    resp = client.get("/auth/check", params={"project": "nonexistent"})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# /auth/login GET
# ---------------------------------------------------------------------------


def test_should_show_login_page(client):
    resp = client.get("/auth/login", params={"project": "testproj"})
    assert resp.status_code == 200
    assert "testproj" in resp.text
    assert "<form" in resp.text


def test_should_return_404_for_unknown_project_login(client):
    resp = client.get("/auth/login", params={"project": "nonexistent"})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# /auth/login POST
# ---------------------------------------------------------------------------


def test_should_set_cookie_for_allowlisted_email(client):
    resp = client.post(
        "/auth/login",
        data={"project": "testproj", "email": "allowed@example.com", "next": "/"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "gate_testproj" in resp.cookies


def test_should_be_case_insensitive_on_email(client):
    resp = client.post(
        "/auth/login",
        data={"project": "testproj", "email": "ALLOWED@Example.COM", "next": "/"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "gate_testproj" in resp.cookies


def test_should_deny_non_allowlisted_email_without_telegram(client):
    resp = client.post(
        "/auth/login",
        data={"project": "testproj", "email": "stranger@example.com", "next": "/"},
    )
    assert resp.status_code == 200
    assert "denied" in resp.text.lower() or "don" in resp.text.lower()


# ---------------------------------------------------------------------------
# /auth/status & /auth/claim
# ---------------------------------------------------------------------------


def test_should_return_expired_for_unknown_request(client):
    resp = client.get("/auth/status/nonexistent")
    assert resp.json()["status"] == "expired"


def test_should_return_pending_status(client):
    pending["req123"] = {
        "email": "test@example.com",
        "project": "testproj",
        "next": "/",
        "status": "pending",
        "created": time.time(),
    }
    resp = client.get("/auth/status/req123")
    assert resp.json()["status"] == "pending"


def test_should_return_approved_status(client):
    pending["req456"] = {
        "email": "test@example.com",
        "project": "testproj",
        "next": "/",
        "status": "approved",
        "created": time.time(),
    }
    resp = client.get("/auth/status/req456")
    assert resp.json()["status"] == "approved"


def test_should_issue_cookie_on_claim(client):
    pending["req789"] = {
        "email": "test@example.com",
        "project": "testproj",
        "next": "/",
        "status": "approved",
        "created": time.time(),
    }
    resp = client.get("/auth/claim/req789", follow_redirects=False)
    assert resp.status_code == 302
    assert "gate_testproj" in resp.cookies
    assert "req789" not in pending


def test_should_reject_claim_for_unapproved_request(client):
    pending["reqpending"] = {
        "email": "test@example.com",
        "project": "testproj",
        "next": "/",
        "status": "pending",
        "created": time.time(),
    }
    resp = client.get("/auth/claim/reqpending")
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# /auth/logout
# ---------------------------------------------------------------------------


def test_should_clear_cookie_on_logout(client):
    token = serializer.dumps({"email": "allowed@example.com", "project": "testproj"})
    resp = client.get(
        "/auth/logout",
        params={"project": "testproj"},
        cookies={"gate_testproj": token},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    # Cookie should be deleted (set to empty / max-age=0)
    assert "gate_testproj" in resp.headers.get("set-cookie", "")


# ---------------------------------------------------------------------------
# Open redirect prevention
# ---------------------------------------------------------------------------


def test_should_block_open_redirect_in_next(client):
    resp = client.post(
        "/auth/login",
        data={"project": "testproj", "email": "allowed@example.com", "next": "https://evil.com/steal"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    # Should redirect to / not evil.com
    assert "evil.com" not in resp.headers["location"]
