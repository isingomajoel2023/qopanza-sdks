"""QopanzaClient.signup — the one call that works without credentials.

Driven through a real httpx transport rather than a stubbed method, so
these cover what the wire actually carries: that signup goes out with no
API-key header, and that the *next* request goes out with one.
"""

import httpx
import pytest
from qopanza import QopanzaAPIError, QopanzaClient

SIGNUP_BODY = {
    "account": {"id": "acc_1", "plan": "free", "created_at": "2026-08-20T00:00:00Z"},
    "user": {
        "id": "usr_1",
        "email": "you@example.com",
        "role": "admin",
        "created_at": "2026-08-20T00:00:00Z",
    },
    "api_key": "qs_live_the_only_time_you_see_this",
    "session_token": "jwt.session.token",
}


def _client_with(handler) -> QopanzaClient:
    """A client whose transport is a function, so requests are inspectable."""
    client = QopanzaClient(base_url="https://api.example.com")
    client._client = httpx.Client(
        base_url="https://api.example.com/v1",
        transport=httpx.MockTransport(handler),
    )
    return client


def test_signup_returns_the_api_key_to_the_caller():
    """It must be returned, not swallowed — the server issues it once."""
    with _client_with(lambda _: httpx.Response(201, json=SIGNUP_BODY)) as client:
        result = client.signup("you@example.com", "a-real-password")

    assert result["api_key"] == "qs_live_the_only_time_you_see_this"
    assert result["account"]["plan"] == "free"
    assert result["user"]["email"] == "you@example.com"


def test_signup_posts_email_and_password_to_accounts():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["method"] = request.method
        seen["body"] = request.read().decode()
        return httpx.Response(201, json=SIGNUP_BODY)

    with _client_with(handler) as client:
        client.signup("you@example.com", "a-real-password")

    assert seen["method"] == "POST"
    assert seen["url"] == "https://api.example.com/v1/accounts"
    assert '"email":"you@example.com"' in seen["body"].replace(" ", "")
    assert '"password":"a-real-password"' in seen["body"].replace(" ", "")


def test_signup_sends_no_api_key_header():
    """A brand-new user has no key yet; sending an empty one is worse
    than sending none, because the server would try to authenticate it."""
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["has_key"] = "X-API-Key" in request.headers
        return httpx.Response(201, json=SIGNUP_BODY)

    with _client_with(handler) as client:
        client.signup("you@example.com", "a-real-password")

    assert seen["has_key"] is False


def test_signup_adopts_the_key_for_subsequent_requests():
    """The whole point of adopting it: the caller does not have to build
    a second client to make the first real call."""
    headers_seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        headers_seen.append(request.headers.get("X-API-Key"))
        if request.url.path.endswith("/accounts"):
            return httpx.Response(201, json=SIGNUP_BODY)
        return httpx.Response(200, json={"id": "key_1", "purpose": "kem"})

    with _client_with(handler) as client:
        client.signup("you@example.com", "a-real-password")
        client.create_key(purpose="kem")

    assert headers_seen == [None, "qs_live_the_only_time_you_see_this"]


def test_signup_without_api_key_in_response_leaves_headers_alone():
    """Defensive: a malformed response must not install a literal
    "None" as the API key, which would fail confusingly later."""
    body = {k: v for k, v in SIGNUP_BODY.items() if k != "api_key"}

    with _client_with(lambda _: httpx.Response(201, json=body)) as client:
        client.signup("you@example.com", "a-real-password")
        assert "X-API-Key" not in client._client.headers


def test_duplicate_email_raises_with_status_409():
    handler = lambda _: httpx.Response(409, json={"detail": "Email already registered"})

    with _client_with(handler) as client, pytest.raises(QopanzaAPIError) as excinfo:
        client.signup("taken@example.com", "a-real-password")

    assert excinfo.value.status_code == 409
    assert "already registered" in excinfo.value.detail


def test_throttled_signup_raises_with_status_429():
    """Signup throttling is enforced server-side (SIGNUP_LIMIT_PER_WINDOW);
    the SDK must surface it as an error rather than a falsy result."""
    handler = lambda _: httpx.Response(429, json={"detail": "Too many signups"})

    with _client_with(handler) as client, pytest.raises(QopanzaAPIError) as excinfo:
        client.signup("you@example.com", "a-real-password")

    assert excinfo.value.status_code == 429
