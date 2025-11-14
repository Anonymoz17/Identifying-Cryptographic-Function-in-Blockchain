-- ============================================================================
-- CORRECTED RLS POLICIES: Fix quota update blocking
-- ============================================================================
-- ISSUE: Users couldn't update their own analysis_count
-- SOLUTION: Allow authenticated users to update all columns in their own row
-- ============================================================================

-- Drop OLD policies that might be blocking updates
DROP POLICY IF EXISTS "users_can_view_own_role" ON public.user_roles;
DROP POLICY IF EXISTS "users_can_insert_own_role" ON public.user_roles;
DROP POLICY IF EXISTS "users_can_update_own_role" ON public.user_roles;
DROP POLICY IF EXISTS "service_can_update_role" ON public.user_roles;

-- ============================================================================
-- CREATE NEW POLICIES - Allow users to manage their own rows
-- ============================================================================

-- Users can SELECT their own role (read)
CREATE POLICY "users_can_select_own_role" ON public.user_roles
  FOR SELECT
  USING (auth.uid() = id);

-- Users can INSERT their own role (during signup - backup to trigger)
CREATE POLICY "users_can_insert_own_role" ON public.user_roles
  FOR INSERT
  WITH CHECK (auth.uid() = id);

-- Users can UPDATE their own role (for quota incrementing)
CREATE POLICY "users_can_update_own_role" ON public.user_roles
  FOR UPDATE
  USING (auth.uid() = id)
  WITH CHECK (auth.uid() = id);

-- Service role can UPDATE any role (for webhook/admin operations)
CREATE POLICY "service_can_update_any_role" ON public.user_roles
  FOR UPDATE
  USING (auth.role() = 'service_role')
  WITH CHECK (auth.role() = 'service_role');

-- ============================================================================
-- VERIFY POLICIES
-- ============================================================================
-- Run this to check policies were created:
-- SELECT tablename, policyname, permissive, roles, qual, with_check
-- FROM pg_policies
-- WHERE tablename = 'user_roles'
-- ORDER BY policyname;
--
-- You should see:
-- ✓ service_can_update_any_role
-- ✓ users_can_insert_own_role
-- ✓ users_can_select_own_role
-- ✓ users_can_update_own_role
-- ============================================================================
