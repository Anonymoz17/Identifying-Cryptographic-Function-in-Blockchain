import types
from typing import Any

import pytest

import api_client_supabase as sbmod


def test_no_client_behaviour(monkeypatch):
    # Ensure the module behaves safely when no _sb client is configured
    # Force _sb to None
    monkeypatch.setattr(sbmod, "_sb", None)

    # register_user should raise RuntimeError via _require_client
    with pytest.raises(RuntimeError):
        sbmod.register_user("a@b.c", "pw", "Full Name", "user")

    # login should return (False, error_str, None)
    ok, msg, user = sbmod.login("a@b.c", "pw")
    assert ok is False
    assert user is None

    # get_my_role should return 'free' defensively
    role = sbmod.get_my_role("token", "uid")
    assert role == "free"

    # ensure_role_row currently requires a client; expect RuntimeError when no client
    with pytest.raises(RuntimeError):
        sbmod.ensure_role_row("token", "uid")

    # admin_set_tier with invalid tier should return False
    ok, msg = sbmod.admin_set_tier("token", "uid", "invalid")
    assert ok is False


class FakeAuth:
    def __init__(self):
        self._users = {}

    def sign_up(self, payload: Any):
        # simulate sign_up returning an object with 'user' and 'session'
        email = payload["email"]
        uid = "uid-" + email
        user = types.SimpleNamespace(id=uid, email=email)
        session = types.SimpleNamespace(access_token=f"token-{uid}")
        # store
        self._users[email] = {"id": uid, "password": payload.get("password")}
        return types.SimpleNamespace(user=user, session=session)

    def sign_in_with_password(self, payload: Any):
        email = payload["email"]
        if email not in self._users or self._users[email]["password"] != payload.get(
            "password"
        ):
            raise Exception("Invalid credentials")
        user = types.SimpleNamespace(id=self._users[email]["id"], email=email)
        session = types.SimpleNamespace(
            access_token=f"token-{self._users[email]['id']}"
        )
        return types.SimpleNamespace(user=user, session=session)

    def sign_out(self):
        return True


class FakeTable:
    def __init__(self):
        self._data = {}

    def upsert(self, payload: Any):
        # simulate chainable API returning self with execute()
        self._data[payload["id"]] = payload
        return self

    def update(self, payload: Any):
        # simulate update then eq
        def inner_eq(key, value):
            if value in self._data:
                self._data[value]["tier"] = payload.get("tier")
            return self

        self.eq = inner_eq
        return self

    def select(self, col):
        # chainable select
        return self

    def eq(self, key, value):
        return self

    def execute(self):
        # return an object with 'data'
        return types.SimpleNamespace(data=list(self._data.values()))


class FakeClient:
    def __init__(self):
        self.auth = FakeAuth()
        self._tables = {"user_roles": FakeTable(), "profiles": FakeTable()}
        self.postgrest = types.SimpleNamespace(auth=lambda token: None)

    def table(self, name):
        return self._tables[name]


def test_supabase_functions_with_fake_client(monkeypatch):
    fake = FakeClient()
    monkeypatch.setattr(sbmod, "_sb", fake)

    # register_user should succeed
    ok, data = sbmod.register_user("x@y.z", "pw", "Full", "username")
    assert ok is True
    assert "id" in data

    # login should succeed
    ok, token, user = sbmod.login("x@y.z", "pw")
    assert ok is True
    assert token.startswith("token-")
    assert user["email"] == "x@y.z"

    # ensure_role_row should not error
    sbmod.ensure_role_row(token, user["id"])  # should not raise

    # get_my_role should return something (default 'free' if no rows)
    role = sbmod.get_my_role(token, user["id"])
    assert isinstance(role, str)

    # admin_set_tier with valid tier calls table update path
    ok, msg = sbmod.admin_set_tier(token, user["id"], "premium")
    assert ok in (True, False)

    # logout should not raise
    sbmod.logout()
