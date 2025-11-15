// src/api.js
import { supabase } from "./lib/supabase";

const ROLES_TABLE = "user_roles";
const PROFILES_TABLE = "profiles";

// Check if Supabase is available
function isSupabaseAvailable() {
  return supabase !== null;
}

// Ensure a roles row exists for this user (defaults to 'free')
async function ensureRoleRow(userId) {
  if (!isSupabaseAvailable()) return { error: "Auth not configured" };

  // 1) Check if it already exists
  const { data, error } = await supabase
    .from(ROLES_TABLE)
    .select("id, tier")
    .eq("id", userId)
    .maybeSingle();

  // If some real error other than "no rows", bubble it up
  if (error && error.code !== "PGRST116") {
    return { error };
  }

  // If row exists, just return it
  if (data) {
    return { role: data };
  }

  // 2) Insert without RETURNING to avoid RLS issues on returning/select
  const { error: upErr } = await supabase
    .from(ROLES_TABLE)
    .insert({ id: userId, tier: "free" });

  // If insert fails with something other than "already exists" (unique violation)
  if (upErr && upErr.code !== "23505") {
    return { error: upErr };
  }

  // We don't need to read it back here
  return { role: { id: userId, tier: "free" } };
}

// Optional: store profile info (username/full_name)
export async function upsertProfile({ id, username, full_name }) {
  if (!isSupabaseAvailable())
    return { ok: false, error: "Auth not configured" };

  const payload = { id };
  if (typeof username === "string") payload.username = username;
  if (typeof full_name === "string") payload.full_name = full_name;

  const { error } = await supabase
    .from(PROFILES_TABLE)
    .upsert(payload, { onConflict: "id" });

  if (error) return { ok: false, error: error.message };
  return { ok: true };
}

// ── AUTH ─────────────────────────────────────────────────────

// SIGN UP: just create auth user + optional profile.
// DO NOT touch user_roles here (RLS + email confirmation can be weird).
export async function signUp({ email, password, name, username }) {
  if (!isSupabaseAvailable())
    return { error: "Authentication is not configured for this deployment" };

  const cleanEmail = String(email ?? "").trim();
  const cleanPassword = String(password ?? "");
  const cleanName = name ? String(name).trim() : null;
  const cleanUsername = username ? String(username).trim() : null;

  if (!cleanEmail || !cleanPassword) {
    return { error: "Email and password are required." };
  }

  const { data, error } = await supabase.auth.signUp({
    email: cleanEmail,
    password: cleanPassword,
    options: {
      data: { name: cleanName, username: cleanUsername },
    },
  });

  if (error) return { error: error.message };

  const user = data.user || data.session?.user;

  // If email confirmation is ON, we won't get a session yet
  if (!user) {
    return {
      user: null,
      plan: "free",
      pendingConfirmation: true,
      message: "Check your email to confirm your account.",
    };
  }

  // Store profile data if provided
  if (cleanName || cleanUsername) {
    await upsertProfile({
      id: user.id,
      full_name: cleanName,
      username: cleanUsername,
    }).catch(() => {});
  }

  // Don't rely on user_roles yet, just default to free
  return {
    user: { id: user.id, email: user.email, name: cleanName },
    plan: "free",
  };
}

export async function signIn({ email, password }) {
  if (!isSupabaseAvailable())
    return { error: "Authentication is not configured for this deployment" };

  const cleanEmail = String(email ?? "").trim();
  const cleanPassword = String(password ?? "");

  if (!cleanEmail || !cleanPassword) {
    return { error: "Email and password are required." };
  }

  const { data, error } = await supabase.auth.signInWithPassword({
    email: cleanEmail,
    password: cleanPassword,
  });

  if (error) return { error: error.message };
  const user = data.user;

  // NOW we definitely have a valid session (authenticated role)
  const res = await ensureRoleRow(user.id);
  if (res.error) {
    return {
      error: res.error.message || String(res.error),
    };
  }

  const { data: roleRow, error: roleReadErr } = await supabase
    .from(ROLES_TABLE)
    .select("tier")
    .eq("id", user.id)
    .maybeSingle();

  const tier = roleReadErr ? "free" : roleRow?.tier || "free";

  return {
    user: {
      id: user.id,
      email: user.email,
      name: user.user_metadata?.name,
    },
    plan: tier,
  };
}

export async function signOut() {
  if (!isSupabaseAvailable()) return { error: "Auth not configured" };
  const { error } = await supabase.auth.signOut();
  if (error) return { error: error.message };
  return { ok: true };
}

export async function getCurrentUser() {
  if (!isSupabaseAvailable()) return { user: null, plan: "free" };

  const {
    data: { session },
  } = await supabase.auth.getSession();

  const user = session?.user;
  if (!user) return { user: null, plan: "free" };

  const { data: roleRow } = await supabase
    .from(ROLES_TABLE)
    .select("tier")
    .eq("id", user.id)
    .maybeSingle();

  const tier = roleRow?.tier || "free";

  return {
    user: {
      id: user.id,
      email: user.email,
      name: user.user_metadata?.name,
    },
    plan: tier,
  };
}

// Call this AFTER your payment succeeds (Stripe/PayNow/etc.)
export async function upgradeUserPlan({ userId, plan }) {
  if (!isSupabaseAvailable()) return { error: "Auth not configured" };

  // Only Free/Premium now
  if (!["free", "premium"].includes(plan)) {
    return { error: "Invalid plan" };
  }

  const { data, error } = await supabase
    .from(ROLES_TABLE)
    .update({ tier: plan })
    .eq("id", userId)
    .select("tier")
    .single();

  if (error) return { error: error.message };
  return { ok: true, plan: data.tier };
}
