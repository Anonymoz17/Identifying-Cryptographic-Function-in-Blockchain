# api_client_supabase.py
import os
from typing import Tuple, Optional, Dict, Any

from dotenv import load_dotenv
from supabase import create_client, Client

# Load .env once
load_dotenv()

SB_URL  = os.getenv("SUPABASE_URL")
SB_ANON = os.getenv("SUPABASE_ANON_KEY")

if not SB_URL or not SB_ANON:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_ANON_KEY. Set them in a .env file.")

_sb: Client = create_client(SB_URL, SB_ANON)

# ----- helpers -----
def _auth_with_token(token: Optional[str]):
    """
    Apply a user's access token to PostgREST so RLS sees auth.uid().
    Pass None to clear and go back to 'no user' (unauthenticated) state.
    """
    _sb.postgrest.auth(token)

# ----- auth & user profile -----
def register_user(email: str, password: str, full_name: str, username: str) -> Tuple[bool, Any]:
    """
    Sign up the user (email/password), then create profile + free role as that user.
    Returns (ok, data_or_error)
    """
    # 1) sign up
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

