# api_client_supabase.py
import os
from typing import Any, Dict, Optional, Tuple

try:
    from dotenv import load_dotenv  # type: ignore
except Exception:

    def load_dotenv():
        return None


load_dotenv()

SB_URL = os.getenv("SUPABASE_URL")
SB_ANON = os.getenv("SUPABASE_ANON_KEY")

_sb = None
if SB_URL and SB_ANON:
    try:
        from supabase import Client, create_client  # imported lazily

        _sb: Client = create_client(SB_URL, SB_ANON)
    except Exception:
        _sb = None


def _require_client():
    if _sb is None:
        raise RuntimeError(
            "Supabase client not configured. Set SUPABASE_URL and SUPABASE_ANON_KEY in a .env file"
        )


def _auth_with_token(token: Optional[str]):
    if _sb is None:
        return
    _sb.postgrest.auth(token)


def register_user(
    email: str, password: str, full_name: str, username: str
) -> Tuple[bool, Any]:
    _require_client()
    res = _sb.auth.sign_up({"email": email, "password": password})
    user = res.user
    session = getattr(res, "session", None)
    if not session:
        try:
            login_res = _sb.auth.sign_in_with_password(
                {"email": email, "password": password}
            )
            session = login_res.session
            user = login_res.user
        except Exception as e:
            return (
                False,
                f"Sign up OK. Please verify your email before logging in. ({e})",
            )

    if not user or not session:
        return False, "Sign up failed (no session). Check Auth settings."

    uid = str(user.id)
    token = session.access_token

    try:
        _auth_with_token(token)
        _sb.table("profiles").upsert(
            {"id": uid, "full_name": full_name, "username": username}
        ).execute()
        _sb.table("user_roles").upsert({"id": uid, "tier": "free"}).execute()
    finally:
        _auth_with_token(None)

    return True, {"id": uid, "email": email, "username": username}


def login(
    identifier_email: str, password: str
) -> Tuple[bool, Any, Optional[Dict[str, Any]]]:
    try:
        _require_client()
        res = _sb.auth.sign_in_with_password(
            {"email": identifier_email, "password": password}
        )
        if not res.session:
            return False, "Invalid credentials", None
        token = res.session.access_token
        user = {"id": str(res.user.id), "email": res.user.email}
        return True, token, user
    except Exception as e:
        return False, str(e), None


def get_my_role(token: str, user_id: str) -> str:
    try:
        _require_client()
        _auth_with_token(token)
        res = _sb.table("user_roles").select("tier").eq("id", user_id).execute()
        data = getattr(res, "data", None)
        if isinstance(data, list) and data:
            return (data[0] or {}).get("tier", "free")
        if isinstance(data, dict) and data:
            return data.get("tier", "free")
        return "free"
    except Exception:
        return "free"
    finally:
        _auth_with_token(None)


def ensure_role_row(token: str, user_id: str):
    try:
        _require_client()
        _auth_with_token(token)
        _sb.table("user_roles").upsert({"id": user_id, "tier": "free"}).execute()
    finally:
        _auth_with_token(None)


def admin_set_tier(token: str, target_user_id: str, new_tier: str) -> Tuple[bool, Any]:
    if new_tier not in ("free", "premium", "admin"):
        return False, "Invalid tier"
    try:
        _require_client()
        _auth_with_token(token)
        _sb.table("user_roles").update({"tier": new_tier}).eq(
            "id", target_user_id
        ).execute()
        return True, "OK"
    except Exception as e:
        return False, str(e)
    finally:
        _auth_with_token(None)


def logout():
    if _sb is None:
        return
    try:
        _sb.auth.sign_out()
    except Exception:
        pass
    finally:
        _auth_with_token(None)
