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
  const { data, error } = await supabase
    .from(ROLES_TABLE)
    .select("id, tier")
    .eq("id", userId)
    .maybeSingle();

  if (error && error.code !== "PGRST116") return { error }; // allow "no rows"
  if (data) return { role: data };

  const { data: up, error: upErr } = await supabase
    .from(ROLES_TABLE)
    .insert({ id: userId, tier: "free" })
    .select("id, tier")
    .single();

  if (upErr) return { error: upErr };
  return { role: up };
}

// Optional: store profile info (username/full_name)
export async function upsertProfile({ id, username, full_name }) {
  if (!isSupabaseAvailable()) return { ok: false, error: "Auth not configured" };
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
export async function signUp({ email, password, name, username }) {
  if (!isSupabaseAvailable()) return { error: "Authentication is not configured for this deployment" };
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: { data: { name } },
  });
  if (error) return { error: error.message };

  const user = data.user || data.session?.user;
  if (!user) {
    return {
      user: null,
      plan: "free",
      pendingConfirmation: true,
      message: "Check your email to confirm your account.",
    };
  }

  const { error: roleErr } = await ensureRoleRow(user.id);
  if (roleErr) return { error: roleErr.message };

  if (name || username) {
    await upsertProfile({ id: user.id, full_name: name, username }).catch(() => {});
  }

  const { data: roleRow, error: roleReadErr } = await supabase
    .from(ROLES_TABLE)
    .select("tier")
    .eq("id", user.id)
    .single();
  const tier = roleReadErr ? "free" : roleRow?.tier || "free";

  return { user: { id: user.id, email: user.email, name }, plan: tier };
}

export async function signIn({ email, password }) {
  if (!isSupabaseAvailable()) return { error: "Authentication is not configured for this deployment" };
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) return { error: error.message };
  const user = data.user;

  const { error: roleErr } = await ensureRoleRow(user.id);
  if (roleErr) return { error: roleErr.message };

  const { data: roleRow, error: roleReadErr } = await supabase
    .from(ROLES_TABLE)
    .select("tier")
    .eq("id", user.id)
    .single();
  const tier = roleReadErr ? "free" : roleRow?.tier || "free";

  return { user: { id: user.id, email: user.email, name: user.user_metadata?.name }, plan: tier };
}

export async function signOut() {
  if (!isSupabaseAvailable()) return { error: "Auth not configured" };
  const { error } = await supabase.auth.signOut();
  if (error) return { error: error.message };
  return { ok: true };
}

export async function getCurrentUser() {
  if (!isSupabaseAvailable()) return { user: null, plan: "free" };
  const { data: { session } } = await supabase.auth.getSession();
  const user = session?.user;
  if (!user) return { user: null, plan: "free" };

  const { data: roleRow } = await supabase
    .from(ROLES_TABLE)
    .select("tier")
    .eq("id", user.id)
    .maybeSingle();
  const tier = roleRow?.tier || "free";

  return { user: { id: user.id, email: user.email, name: user.user_metadata?.name }, plan: tier };
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
