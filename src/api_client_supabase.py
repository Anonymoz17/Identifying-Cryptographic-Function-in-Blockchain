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


def login(
    identifier_email: str, password: str
) -> Tuple[bool, Any, Optional[Dict[str, Any]]]:
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

        user_dict = {
            "id": str(user.id),
            "email": getattr(user, "email", identifier_email),
        }
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
    """
    Guarantee a user_roles row exists WITHOUT overwriting an existing tier.

    - If a row exists: leave it exactly as-is (so premium/admin is preserved).
    - If no row exists: insert a new one and let DB defaults set tier='free'.
    """
    try:
        if not token or not user_id:
            return
        _require_client()
        _auth_with_token(token)

        # 1) Check if the row already exists
        res = (
            _sb.table("user_roles")
            .select("id")
            .eq("id", user_id)
            .execute()
        )
        data = getattr(res, "data", None)

        # If we already have a row, do NOTHING (do not touch tier)
        if isinstance(data, list) and data:
            return
        if isinstance(data, dict) and data:
            return

        # 2) Insert a new row, relying on DB defaults (tier defaults to 'free')
        _sb.table("user_roles").insert({"id": user_id}).execute()

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
        _sb.table("user_roles").update({"tier": new_tier}).eq(
            "id", target_user_id
        ).execute()
        return True, "OK"
    except Exception as e:
        return False, str(e)
    finally:
        _auth_with_token(None)


# ---------------------------------------------------------------------
# QUOTA / USER OVERVIEW
# ---------------------------------------------------------------------
def get_user_overview(token: str, user_id: str) -> Optional[Dict[str, Any]]:
    """
    Fetch a single row from the user_overview view for the given user_id.

    Expects a view like:

        create view public.user_overview as
        select
          u.id,
          u.email,
          p.username,
          p.full_name,
          r.tier,
          r.analysis_count,
          r.analysis_quota_limit,
          p.created_at as profile_created_at,
          r.updated_at as role_updated_at
        from auth.users u
        left join profiles p on p.id = u.id
        left join user_roles r on r.id = u.id;
    """
    try:
        if not token or not user_id:
            return None
        _require_client()
        _auth_with_token(token)

        res = (
            _sb.table("user_overview")
            .select("*")
            .eq("id", user_id)
            .execute()
        )
        data = getattr(res, "data", None)

        if isinstance(data, list) and data:
            return data[0] or {}
        if isinstance(data, dict) and data:
            return data

        return None
    except Exception:
        return None
    finally:
        _auth_with_token(None)


def increment_analysis_count(token: str, user_id: str) -> Optional[Dict[str, Any]]:
    """
    Increment analysis_count for the given user and return the updated user_overview row.

    This solves the 'quota resets on app restart' problem by persisting the count
    to the user_roles table.
    """
    try:
        if not token or not user_id:
            return None
        _require_client()
        _auth_with_token(token)

        # 1) Read current count from user_roles
        res = (
            _sb.table("user_roles")
            .select("analysis_count")
            .eq("id", user_id)
            .execute()
        )
        data = getattr(res, "data", None)

        current = 0
        if isinstance(data, list) and data:
            row = data[0] or {}
            try:
                current = int(row.get("analysis_count") or 0)
            except Exception:
                current = 0

        # 2) Compute new count
        new_count = current + 1

        # 3) Persist back to user_roles (upsert in case row somehow doesn't exist)
        _sb.table("user_roles").upsert(
            {
                "id": user_id,
                "analysis_count": new_count,
            }
        ).execute()

        # 4) Fetch and return updated user_overview row
        res2 = (
            _sb.table("user_overview")
            .select("*")
            .eq("id", user_id)
            .execute()
        )
        data2 = getattr(res2, "data", None)

        if isinstance(data2, list) and data2:
            return data2[0] or {}
        if isinstance(data2, dict) and data2:
            return data2

        # Fallback: at least return the new count
        return {"id": user_id, "analysis_count": new_count}

    except Exception:
        return None
    finally:
        _auth_with_token(None)
