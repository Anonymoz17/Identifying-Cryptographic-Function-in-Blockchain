"""
Access Control Module - Quota Management for CryptoScope

Handles:
- Quota enforcement (free: 5/month, premium: unlimited)
- Quota tracking and incrementing
- Scan history recording
- User tier verification
"""

import logging
from typing import Tuple, Dict, Optional
from datetime import datetime

# Import Supabase client from existing setup
from api_client_supabase import _sb, _auth_with_token, _require_client

logger = logging.getLogger(__name__)


class AccessControl:
    """
    Manages user quota and access permissions.

    Free tier: 5 analyses per month
    Premium tier: Unlimited analyses

    Quota resets on the 1st of each month.
    """

    def __init__(self):
        """Initialize access control module."""
        self.logger = logging.getLogger(f"{__name__}.AccessControl")

    def can_analyze(self, user_id: str, auth_token: str) -> Tuple[bool, str]:
        """
        Check if user can run analysis.

        Returns:
            (bool, str): (can_analyze, message)
            - (True, "OK") if user can analyze
            - (False, reason) if quota exceeded or error
        """
        if not user_id or not auth_token:
            # Fail open: allow if credentials missing
            self.logger.warning("Missing user_id or auth_token, allowing analysis (fail open)")
            return True, "Credentials missing, allowing (fail open)"

        try:
            quota_info = self._get_quota_from_supabase(user_id, auth_token)

            if not quota_info:
                # Fail open: allow if can't get quota
                self.logger.warning(f"Could not fetch quota for {user_id}, allowing (fail open)")
                return True, "Could not fetch quota, allowing (fail open)"

            # Premium users have unlimited access
            if quota_info.get("tier") == "premium":
                return True, "Premium user - unlimited access"

            # Free users have 5 analyses per month
            if quota_info.get("tier") == "free":
                count = quota_info.get("analysis_count", 0)
                limit = quota_info.get("analysis_quota_limit", 5)

                if count >= limit:
                    return False, f"Quota exceeded. Used {count}/{limit} analyses this month."

                remaining = limit - count
                return True, f"OK ({remaining} analyses remaining)"

            # Unknown tier: allow with warning
            self.logger.warning(f"Unknown tier for {user_id}: {quota_info.get('tier')}")
            return True, "Unknown tier, allowing"

        except Exception as e:
            self.logger.error(f"Error checking quota for {user_id}: {e}")
            # Fail open: allow analysis if quota check fails
            return True, f"Quota check failed ({str(e)}), allowing (fail open)"

    def increment_analysis_count(self, user_id: str, auth_token: str) -> bool:
        """
        Increment user's analysis count after successful analysis.

        Calls Supabase Edge Function for secure server-side increment.
        This bypasses RLS and ensures the quota update is secure.

        Returns:
            bool: True if successful, False if error
        """
        if not user_id or not auth_token:
            self.logger.warning("Missing user_id or auth_token, cannot increment")
            return False

        try:
            _require_client()

            # Call Edge Function to safely increment quota server-side
            response = _sb.functions.invoke(
                "increment_quota",
                invoke_options={"body": {"user_id": user_id, "auth_token": auth_token}}
            )

            # Check if function call was successful
            if response and response.get("success"):
                new_count = response.get("new_count", "unknown")
                self.logger.info(f"Incremented analysis count for {user_id} to {new_count}")
                return True
            else:
                error_msg = response.get("error", "Unknown error") if response else "No response"
                self.logger.error(f"Failed to increment quota for {user_id}: {error_msg}")
                return False

        except Exception as e:
            self.logger.error(f"Error incrementing count for {user_id}: {e}")
            return False

    def record_scan_history(
        self,
        user_id: str,
        auth_token: str,
        case_id: Optional[str] = None,
        num_files: int = 0,
        findings_count: int = 0,
        duration_seconds: float = 0.0,
        status: str = "completed",
        error_message: Optional[str] = None
    ) -> bool:
        """
        Record scan history for audit trail and analytics.

        Returns:
            bool: True if successful, False if error
        """
        if not user_id or not auth_token:
            self.logger.warning("Missing user_id or auth_token, cannot record history")
            return False

        try:
            _require_client()
            _auth_with_token(auth_token)

            scan_record = {
                "user_id": user_id,
                "case_id": case_id,
                "analysis_date": datetime.utcnow().isoformat(),
                "num_files_analyzed": num_files,
                "findings_count": findings_count,
                "duration_seconds": duration_seconds,
                "status": status,
                "error_message": error_message
            }

            response = _sb.table("scan_history") \
                .insert(scan_record) \
                .execute()

            _auth_with_token(None)

            if response.data:
                self.logger.info(f"Recorded scan history for {user_id}: {case_id}")
                return True
            else:
                self.logger.error(f"Failed to record scan history for {user_id}")
                return False

        except Exception as e:
            self.logger.error(f"Error recording scan history for {user_id}: {e}")
            _auth_with_token(None)
            return False

    def get_quota_info(self, user_id: str, auth_token: str) -> Optional[Dict]:
        """
        Get current quota information for a user.

        Returns:
            dict with keys: tier, count, limit, reset_date
            None if error
        """
        if not user_id or not auth_token:
            self.logger.warning("Missing user_id or auth_token, cannot get quota")
            return None

        return self._get_quota_from_supabase(user_id, auth_token)

    def _get_quota_from_supabase(self, user_id: str, auth_token: str) -> Optional[Dict]:
        """
        Internal helper to fetch quota from Supabase.

        Returns:
            dict with: tier, analysis_count, analysis_quota_limit, quota_reset_date
            None if error
        """
        try:
            _require_client()
            _auth_with_token(auth_token)

            response = _sb.table("user_roles") \
                .select("tier, analysis_count, analysis_quota_limit, quota_reset_date") \
                .eq("id", user_id) \
                .single() \
                .execute()

            _auth_with_token(None)

            if not response.data:
                self.logger.warning(f"No quota data found for {user_id}")
                return None

            return response.data

        except Exception as e:
            self.logger.error(f"Error fetching quota for {user_id}: {e}")
            _auth_with_token(None)
            return None
