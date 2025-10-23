// src/api.js
import { supabase } from "./lib/supabase";

/** PROFILE STORAGE
 * Table: profiles
 *  - id (uuid, PK) -> matches auth.users.id
 *  - email (text)
 *  - name (text)
 *  - plan (text) default 'free'  -- 'free' | 'premium'
 *  - created_at (timestamp) default now()
 *
 * RLS recommended: see SQL snippet at the end.
 */

async function ensureProfile({ user, name }) {
  // Try to read profile
  const { data, error } = await supabase
    .from("profiles")
    .select("id, email, name, plan")
    .eq("id", user.id)
    .maybeSingle();

  if (error && error.code !== "PGRST116") { // allow "no rows found"
    return { error };
  }
  if (data) return { profile: data };

  // Create if missing (e.g., first sign-up or migrated users)
  const { data: inserted, error: insErr } = await supabase
    .from("profiles")
    .insert({
      id: user.id,
      email: user.email,
      name: name || user.user_metadata?.name || null,
      plan: "free",
    })
    .select("id, email, name, plan")
    .single();

  if (insErr) return { error: insErr };
  return { profile: inserted };
}

export async function signUp({ name, email, password }) {
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: { data: { name } }, // stores as user_metadata
  });
  if (error) return { error: error.message };

  // If email confirmation is ON, user may be null until confirmed.
  const user = data.user || data.session?.user;
  if (!user) {
    return {
      user: null,
      plan: "free",
      pendingConfirmation: true,
      message: "Check your email to confirm your account.",
    };
  }

  const { profile, error: pErr } = await ensureProfile({ user, name });
  if (pErr) return { error: pErr.message };
  return { user: { id: profile.id, email: profile.email, name: profile.name }, plan: profile.plan };
}

export async function signIn({ email, password }) {
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) return { error: error.message };

  const user = data.user;
  const { profile, error: pErr } = await ensureProfile({ user });
  if (pErr) return { error: pErr.message };
  return { user: { id: profile.id, email: profile.email, name: profile.name }, plan: profile.plan };
}

export async function signOut() {
  const { error } = await supabase.auth.signOut();
  if (error) return { error: error.message };
  return { ok: true };
}

export async function getCurrentUser() {
  const { data: { session } } = await supabase.auth.getSession();
  const user = session?.user;
  if (!user) return { user: null, plan: "free" };

  const { data, error } = await supabase
    .from("profiles")
    .select("id, email, name, plan")
    .eq("id", user.id)
    .maybeSingle();

  if (error || !data) return { user: { id: user.id, email: user.email }, plan: "free" };
  return { user: { id: data.id, email: data.email, name: data.name }, plan: data.plan };
}

export async function upgradeUserPlan({ userId, plan }) {
  // Call this after your payment succeeds (Stripe/PayNow/etc.)
  const { data, error } = await supabase
    .from("profiles")
    .update({ plan })
    .eq("id", userId)
    .select("plan")
    .single();

  if (error) return { error: error.message };
  return { ok: true, plan: data.plan };
}
