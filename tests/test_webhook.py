import hmac
import hashlib
import json
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock
from app.main import app

client = TestClient(app)

def _make_signature(payload: bytes, secret: str) -> str:
    """Helper — generate a valid HMAC signature for a payload."""
    return "sha256=" + hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()

WEBHOOK_SECRET = "test-secret"
PR_PAYLOAD = {
    "action": "opened",
    "pull_request": {
        "number": 1,
        "title": "Test PR",
        "user": {"login": "testuser"},
        "base": {"ref": "main"},
        "head": {"ref": "feature"},
        "diff_url": "https://github.com/test/repo/pull/1.diff",
    },
    "repository": {"full_name": "test/repo"},
    "installation": {"id": 12345},
}

@pytest.fixture(autouse=True)
def set_env(monkeypatch):
    """Set required env vars for every test."""
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", WEBHOOK_SECRET)
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token")
    monkeypatch.setenv("GROQ_API_KEY", "fake-key")

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_webhook_valid_signature():
    payload = json.dumps(PR_PAYLOAD).encode()
    sig = _make_signature(payload, WEBHOOK_SECRET)
    with patch("app.api.webhook._run_review", new_callable=AsyncMock), \
         patch("app.api.webhook._lookup_user", return_value={"user_id": None, "email": None}):
        response = client.post(
            "/webhook",
            content=payload,
            headers={
                "x-hub-signature-256": sig,
                "x-github-event": "pull_request",
                "content-type": "application/json",
            },
        )
    assert response.status_code == 200
    assert response.json()["status"] == "queued"

def test_webhook_invalid_signature():
    payload = json.dumps(PR_PAYLOAD).encode()
    response = client.post(
        "/webhook",
        content=payload,
        headers={
            "x-hub-signature-256": "sha256=invalidsignature",
            "x-github-event": "pull_request",
            "content-type": "application/json",
        },
    )
    assert response.status_code == 401

def test_webhook_missing_signature():
    payload = json.dumps(PR_PAYLOAD).encode()
    response = client.post(
        "/webhook",
        content=payload,
        headers={
            "x-github-event": "pull_request",
            "content-type": "application/json",
        },
    )
    assert response.status_code == 401

def test_webhook_ignores_non_pr_events():
    payload = json.dumps({"action": "created"}).encode()
    sig = _make_signature(payload, WEBHOOK_SECRET)
    response = client.post(
        "/webhook",
        content=payload,
        headers={
            "x-hub-signature-256": sig,
            "x-github-event": "push",
            "content-type": "application/json",
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] == "ignored"

def test_webhook_ignores_closed_pr():
    payload = json.dumps({**PR_PAYLOAD, "action": "closed"}).encode()
    sig = _make_signature(payload, WEBHOOK_SECRET)
    response = client.post(
        "/webhook",
        content=payload,
        headers={
            "x-hub-signature-256": sig,
            "x-github-event": "pull_request",
            "content-type": "application/json",
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] == "ignored"