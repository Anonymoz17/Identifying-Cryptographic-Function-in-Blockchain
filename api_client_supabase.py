# api_client_supabase.py
import os
from typing import Tuple, Optional, Dict, Any

from dotenv import load_dotenv

# NOTE: Importing the real supabase client at module import time will fail
# if environment variables are not present. To make the project easier to
# run locally for demos, we load environment variables and only create the
# client if SUPABASE_URL and SUPABASE_ANON_KEY are provided. Otherwise we
# set a _sb placeholder to None and functions will raise a clear error when
# Supabase functionality is invoked.
load_dotenv()

SB_URL = os.getenv("SUPABASE_URL")
SB_ANON = os.getenv("SUPABASE_ANON_KEY")

_sb = None
if SB_URL and SB_ANON:
    try:
        from supabase import create_client, Client  # imported lazily
        _sb: Client = create_client(SB_URL, SB_ANON)
    except Exception:
        # Keep _sb as None so callers can detect and show a helpful message
        _sb = None

# ----- helpers -----
def _require_client():
    """Raise a helpful error if the supabase client was not configured.

    This keeps imports safe on machines without .env and makes the
    failure mode explicit when calling Supabase-backed functions.
    """
    if _sb is None:
        raise RuntimeError(
            "Supabase client not configured. Set SUPABASE_URL and SUPABASE_ANON_KEY in a .env file"
        )


def _auth_with_token(token: Optional[str]):
    """Apply a user's access token to PostgREST so RLS sees auth.uid().

    Pass None to clear and go back to 'no user' (unauthenticated) state.
    """
    _require_client()
    _sb.postgrest.auth(token)

# ----- auth & user profile -----
def register_user(email: str, password: str, full_name: str, username: str) -> Tuple[bool, Any]:
    """
    Sign up the user (email/password), then create profile + free role as that user.
    Returns (ok, data_or_error)
    """
    # 1) sign up
    _require_client()
    res = _sb.auth.sign_up({"email": email, "password": password})
    user = res.user
    session = getattr(res, "session", None)

    # If email confirmation is ON, session may be None.
    # For dev, either turn off "Confirm email" or sign in immediately after.
    if not session:
        try:
            login_res = _sb.auth.sign_in_with_password({"email": email, "password": password})
            session = login_res.session
            user = login_res.user
        except Exception as e:
            return False, f"Sign up OK. Please verify your email before logging in. ({e})"

    if not user or not session:
        return False, "Sign up failed (no session). Check Auth settings."

    uid = str(user.id)
    token = session.access_token

    # 2) impersonate user to satisfy RLS (auth.uid() = uid)
    try:
        _auth_with_token(token)
        # upsert profile
        _sb.table("profiles").upsert({
            "id": uid,
            "full_name": full_name,
            "username": username
        }).execute()
        # insert or upsert role as 'free'
        _sb.table("user_roles").upsert({
            "id": uid,
            "tier": "free"
        }).execute()
    finally:
        _auth_with_token(None)

    return True, {"id": uid, "email": email, "username": username}

def login(identifier_email: str, password: str) -> Tuple[bool, Any, Optional[Dict[str, Any]]]:
    """
    Email+password login (Supabase Auth uses email). Returns (ok, token_or_error, user_dict)
    """
    try:
        _require_client()
        res = _sb.auth.sign_in_with_password({"email": identifier_email, "password": password})
        if not res.session:
            return False, "Invalid credentials", None
        token = res.session.access_token
        user = {"id": str(res.user.id), "email": res.user.email}
        return True, token, user
    except Exception as e:
        return False, str(e), None

def get_my_role(token: str, user_id: str) -> str:
    """
    Query current user's tier via RLS using their token.
    If no row exists, default to 'free' without throwing.
    """
    try:
        _require_client()
        _auth_with_token(token)
        res = _sb.table("user_roles").select("tier").eq("id", user_id).execute()
        data = getattr(res, "data", None)
        if isinstance(data, list) and data:
            # normal case: [{'tier': 'free'}]
            return (data[0] or {}).get("tier", "free")
        if isinstance(data, dict) and data:
            # defensive, in case the client returns a dict
            return data.get("tier", "free")
        return "free"
    except Exception:
        # on any fetch error, don't break login flow
        return "free"
    finally:
        _auth_with_token(None)

def ensure_role_row(token: str, user_id: str):
    """Create a 'free' role row if missing (safe to call every login)."""
    try:
        _require_client()
        _auth_with_token(token)
        _sb.table("user_roles").upsert({"id": user_id, "tier": "free"}).execute()
    finally:
        _auth_with_token(None)



# ----- admin -----
def admin_set_tier(token: str, target_user_id: str, new_tier: str) -> Tuple[bool, Any]:
    """
    Update someone else's tier. RLS only allows this if 'token' belongs to an admin.
    """
    if new_tier not in ("free", "premium", "admin"):
        return False, "Invalid tier"
    try:
        _require_client()
        _auth_with_token(token)
        _sb.table("user_roles").update({"tier": new_tier}).eq("id", target_user_id).execute()
        return True, "OK"
    except Exception as e:
        return False, str(e)
    finally:
        _auth_with_token(None)

# -- Log out -- 

def logout():
    """Sign out from Supabase in this client and clear PostgREST auth."""
    try:
        _sb.auth.sign_out()
    except Exception:
        pass
    finally:
        _auth_with_token(None)

