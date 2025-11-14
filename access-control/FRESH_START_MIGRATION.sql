-- ============================================================================
-- FRESH START: Complete Supabase Setup - Clean & Aligned with App Code
-- ============================================================================
-- This script creates ALL required tables from scratch with correct RLS policies
-- Tested to work with the app's register_user and login functions
-- ============================================================================

-- ============================================================================
-- 1. CREATE profiles TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  full_name TEXT,
  username TEXT,
  created_at TIMESTAMP DEFAULT now(),
  updated_at TIMESTAMP DEFAULT now(),
  PRIMARY KEY (id)
);

-- Enable RLS
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- RLS Policies - Allow users to read/write their own profile
CREATE POLICY "users_can_read_own_profile" ON public.profiles
  FOR SELECT USING (auth.uid() = id);

CREATE POLICY "users_can_insert_own_profile" ON public.profiles
  FOR INSERT WITH CHECK (auth.uid() = id);

CREATE POLICY "users_can_update_own_profile" ON public.profiles
  FOR UPDATE USING (auth.uid() = id);

-- ============================================================================
-- 2. CREATE user_roles TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.user_roles (
  id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  tier TEXT DEFAULT 'free' CHECK (tier IN ('free', 'premium', 'admin')),

  -- QUOTA TRACKING
  analysis_count INTEGER DEFAULT 0,
  analysis_quota_limit INTEGER DEFAULT 5,
  quota_reset_date TIMESTAMP DEFAULT now(),

  -- STRIPE INTEGRATION
  subscription_id TEXT,
  stripe_customer_id TEXT,
  subscription_status TEXT DEFAULT 'active' CHECK (subscription_status IN ('active', 'canceled', 'past_due', 'unpaid')),
  subscription_end_date TIMESTAMP,

  -- TIMESTAMPS
  created_at TIMESTAMP DEFAULT now(),
  updated_at TIMESTAMP DEFAULT now(),

  PRIMARY KEY (id)
);

-- Enable RLS
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;

-- RLS Policies - Allow users to read their own role, service role can update
CREATE POLICY "users_can_read_own_role" ON public.user_roles
  FOR SELECT USING (auth.uid() = id);

CREATE POLICY "users_can_insert_own_role" ON public.user_roles
  FOR INSERT WITH CHECK (auth.uid() = id);

CREATE POLICY "users_can_update_own_role" ON public.user_roles
  FOR UPDATE USING (auth.uid() = id);

CREATE POLICY "service_can_update_role" ON public.user_roles
  FOR UPDATE USING (auth.role() = 'service_role');

-- ============================================================================
-- 3. CREATE scan_history TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.scan_history (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  case_id TEXT,
  analysis_date TIMESTAMP DEFAULT now(),
  file_hash TEXT,
  num_files_analyzed INTEGER,
  status TEXT CHECK (status IN ('completed', 'failed')),
  findings_count INTEGER DEFAULT 0,
  duration_seconds FLOAT,
  error_message TEXT
);

-- Create index for fast lookups
CREATE INDEX IF NOT EXISTS scan_history_user_id_idx
ON public.scan_history(user_id, analysis_date DESC);

-- Enable RLS
ALTER TABLE public.scan_history ENABLE ROW LEVEL SECURITY;

-- RLS Policies
CREATE POLICY "users_can_read_own_history" ON public.scan_history
  FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "users_can_insert_own_history" ON public.scan_history
  FOR INSERT WITH CHECK (auth.uid() = user_id);

-- ============================================================================
-- 4. CREATE stripe_events TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.stripe_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  stripe_event_id TEXT UNIQUE NOT NULL,
  event_type TEXT,
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  data JSONB,
  processed_at TIMESTAMP DEFAULT now(),
  created_at TIMESTAMP DEFAULT now()
);

-- Create index for fast lookups
CREATE INDEX IF NOT EXISTS stripe_events_user_id_idx
ON public.stripe_events(user_id);

-- Enable RLS
ALTER TABLE public.stripe_events ENABLE ROW LEVEL SECURITY;

-- RLS Policies
CREATE POLICY "service_can_manage_stripe_events" ON public.stripe_events
  FOR ALL USING (auth.role() = 'service_role');

-- ============================================================================
-- 5. CREATE AUTO-SIGNUP TRIGGER & FUNCTION
-- ============================================================================
-- This creates user_roles entry when a new user signs up
-- Profiles are created by app code with actual data from registration form

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  -- Auto-create user_roles with free tier and quota
  INSERT INTO public.user_roles (
    id,
    tier,
    analysis_count,
    analysis_quota_limit,
    quota_reset_date
  )
  VALUES (
    NEW.id,
    'free',
    0,
    5,
    now()
  );

  RETURN NEW;
EXCEPTION WHEN OTHERS THEN
  -- Log error but don't fail signup
  RAISE WARNING 'Failed to create user_roles for %: %', NEW.id, SQLERRM;
  RETURN NEW;
END;
$$;

-- Create trigger
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE PROCEDURE public.handle_new_user();

-- ============================================================================
-- 6. VERIFICATION QUERIES
-- ============================================================================
-- Run these to verify setup:

-- Check profiles table exists
-- SELECT COUNT(*) FROM information_schema.tables WHERE table_name='profiles' AND table_schema='public';

-- Check user_roles table exists
-- SELECT COUNT(*) FROM information_schema.tables WHERE table_name='user_roles' AND table_schema='public';

-- Check scan_history table exists
-- SELECT COUNT(*) FROM information_schema.tables WHERE table_name='scan_history' AND table_schema='public';

-- Check stripe_events table exists
-- SELECT COUNT(*) FROM information_schema.tables WHERE table_name='stripe_events' AND table_schema='public';

-- Check trigger exists
-- SELECT trigger_name FROM information_schema.triggers WHERE trigger_name='on_auth_user_created';

-- Check RLS policies
-- SELECT tablename, policyname FROM pg_policies WHERE schemaname='public' ORDER BY tablename;

-- ============================================================================
-- SETUP COMPLETE
-- ============================================================================
-- Tables created and ready for use:
-- ✅ profiles (user profile information)
-- ✅ user_roles (tier, quota, subscription info)
-- ✅ scan_history (audit trail)
-- ✅ stripe_events (webhook tracking)
-- ✅ Trigger for auto-creating user_roles on signup
-- ✅ RLS policies for security
-- ============================================================================
