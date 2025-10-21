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
        from supabase import Client, create_client

        _sb: Client = create_client(SB_URL, SB_ANON)
    except Exception:
        _sb = None


# ---------------------------------------------------------------------
# INTERNAL HELPERS
# ---------------------------------------------------------------------
def _require_client():
    if _sb is None:
        raise RuntimeError(
            "Supabase client not configured. "
            "Set SUPABASE_URL and SUPABASE_ANON_KEY in a .env file."
        )


def _auth_with_token(token: Optional[str]):
    """Temporarily apply bearer token for PostgREST operations."""
    if _sb is None:
        return
    if token:  # only apply if token is non-empty
        _sb.postgrest.auth(token)
    # else: skip clearing auth entirely (prevents ValueError)



# ---------------------------------------------------------------------
# AUTH / USER MANAGEMENT
# ---------------------------------------------------------------------
def register_user(
    email: str, password: str, full_name: str, username: str
) -> Tuple[bool, Any]:
    """Sign up a new user and seed their profile + role rows."""
    _require_client()
    try:
        res = _sb.auth.sign_up({"email": email, "password": password})
    except Exception as e:
        return False, f"Registration failed: {e}"

    user = getattr(res, "user", None)
    session = getattr(res, "session", None)

    # If sign-up requires email verification, session may be None.
    if not session:
        try:
            login_res = _sb.auth.sign_in_with_password(
                {"email": email, "password": password}
            )
            session = getattr(login_res, "session", None)
            user = getattr(login_res, "user", None)
        except Exception:
            return (
                False,
                "Sign up OK. Please verify your email before logging in.",
            )

    if not user or not session:
        return False, "Sign up failed (no session). Check Supabase Auth settings."

    uid = str(user.id)
    token = getattr(session, "access_token", None)
    if not token:
        return False, "Missing Supabase access token."

    try:
        _auth_with_token(token)
        _sb.table("profiles").upsert(
            {"id": uid, "full_name": full_name, "username": username}
        ).execute()
        _sb.table("user_roles").upsert({"id": uid, "tier": "free"}).execute()
    finally:
        _auth_with_token(None)

    return True, {"id": uid, "email": email, "username": username}


def login(identifier_email: str, password: str) -> Tuple[bool, Any, Optional[Dict[str, Any]]]:
    """Email/password login that always returns a valid token if possible."""
    try:
        _require_client()
        res = _sb.auth.sign_in_with_password(
            {"email": identifier_email, "password": password}
        )

        session = getattr(res, "session", None)
        user = getattr(res, "user", None)
        token = getattr(session, "access_token", None)

        if not session or not token or not user:
            return False, "Invalid credentials or missing session/token.", None

        user_dict = {"id": str(user.id), "email": getattr(user, "email", identifier_email)}
        return True, token, user_dict

    except Exception as e:
        return False, f"Login error: {e}", None


def logout():
    """Sign out of the Supabase session."""
    if _sb is None:
        return
    try:
        _sb.auth.sign_out()
    except Exception:
        pass
    finally:
        _auth_with_token(None)


# ---------------------------------------------------------------------
# ROLE MANAGEMENT
# ---------------------------------------------------------------------
def get_my_role(token: str, user_id: str) -> str:
    """Fetch the user's tier (free/premium/admin). Defaults to free."""
    try:
        if not token:
            return "free"
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
    """Guarantee a user_roles row exists."""
    try:
        if not token:
            return
        _require_client()
        _auth_with_token(token)
        _sb.table("user_roles").upsert({"id": user_id, "tier": "free"}).execute()
    finally:
        _auth_with_token(None)


def admin_set_tier(token: str, target_user_id: str, new_tier: str) -> Tuple[bool, Any]:
    """Admin-only tier change."""
    if new_tier not in ("free", "premium", "admin"):
        return False, "Invalid tier"
    try:
        if not token:
            return False, "Missing token"
        _require_client()
        _auth_with_token(token)
        _sb.table("user_roles").update({"tier": new_tier}).eq("id", target_user_id).execute()
        return True, "OK"
    except Exception as e:
        return False, str(e)
    finally:
        _auth_with_token(None)
