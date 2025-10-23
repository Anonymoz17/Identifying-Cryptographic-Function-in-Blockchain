// src/api.js
import { createClient } from "@supabase/supabase-js";

/* ---------- Supabase client ---------- */
const SB_URL = import.meta.env.VITE_SUPABASE_URL;
const SB_ANON = import.meta.env.VITE_SUPABASE_ANON_KEY;

// Don’t hard-crash if envs are missing — log and let UI render
if (!SB_URL || !SB_ANON) {
  // eslint-disable-next-line no-console
  console.warn(
    "[CryptoScope] Missing VITE_SUPABASE_URL / VITE_SUPABASE_ANON_KEY. " +
      "Auth calls will fail until you set them in .env.local"
  );
}

export const supabase = createClient(SB_URL || "", SB_ANON || "");

/* ---------- Helpers that match your APP DB ----------

APP DB tables (from your Python app):
- profiles: id, full_name, username   (no 'name', no 'plan', 'email' optional)
- user_roles: id, tier ('free' | 'premium' | 'admin')

We will:
- Authenticate with supabase.auth
- Map "plan" to user_roles.tier
- Never assume profiles.email/name/plan exists
---------------------------------------------------- */

async function ensureRoleRow(userId) {
  // Make sure a user_roles row exists, defaulting to 'free'
  const { data, error } = await supabase
    .from("user_roles")
    .select("tier")
    .eq("id", userId)
    .maybeSingle();

  if (error && error.code !== "PGRST116") {
    // eslint-disable-next-line no-console
    console.warn("[CryptoScope] user_roles select error:", error);
    return "free";
  }

  if (!data) {
    const { error: upErr } = await supabase
      .from("user_roles")
      .upsert({ id: userId, tier: "free" });
    if (upErr) {
      // eslint-disable-next-line no-console
      console.warn("[CryptoScope] user_roles upsert error:", upErr);
    }
    return "free";
  }

  return data.tier || "free";
}

/* ---------- Exports used by App.jsx ---------- */

// Sign in with email/password
export async function signIn({ email, password }) {
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) return { ok: false, error };

  const user = data?.user;
  if (!user) return { ok: false, error: new Error("No user in session") };

  const plan = await ensureRoleRow(user.id);
  return { ok: true, user, plan };
}

// Sign up (store extra fields only in user_metadata; avoid touching profiles directly)
export async function signUp({ name, email, password }) {
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    // Keep consistency with app: write full_name to metadata (optional)
    options: { data: { full_name: name } },
  });
  if (error) return { ok: false, error };

  const user = data?.user || null;
  // If email confirmation is required, session may be null — still ok.
  if (user) {
    await ensureRoleRow(user.id);
  }

  return { ok: true, user, needsEmailVerify: !data?.session };
}

// Sign out
export async function signOut() {
  try {
    // Clear Supabase auth session
    await supabase.auth.signOut();

    // Extra safety: remove cached session key
    for (const key in localStorage) {
      if (key.startsWith("sb-")) localStorage.removeItem(key);
    }

    return { ok: true };
  } catch (error) {
    console.error("[CryptoScope] signOut error:", error);
    return { ok: false, error };
  }
}


// Get current user + current plan (plan = user_roles.tier)
export async function getCurrentUser() {
  const { data, error } = await supabase.auth.getUser();
  if (error || !data?.user) return { ok: false, error: error || new Error("Not signed in") };

  const user = data.user;
  const { data: roleRow, error: rErr } = await supabase
    .from("user_roles")
    .select("tier")
    .eq("id", user.id)
    .maybeSingle();

  // If role row missing, create default 'free' and continue
  let plan = "free";
  if (rErr && rErr.code !== "PGRST116") {
    // eslint-disable-next-line no-console
    console.warn("[CryptoScope] getCurrentUser role error:", rErr);
  } else if (roleRow?.tier) {
    plan = roleRow.tier;
  } else {
    await supabase.from("user_roles").upsert({ id: user.id, tier: "free" });
  }

  return { ok: true, user, plan };
}

// Upgrade plan by writing to user_roles.tier
export async function upgradeUserPlan({ userId, plan }) {
  const valid = new Set(["free", "premium", "admin"]);
  if (!valid.has(plan)) return { ok: false, error: new Error("Invalid plan") };

  const { data, error } = await supabase
    .from("user_roles")
    .update({ tier: plan })
    .eq("id", userId)
    .select("tier")
    .single();

  if (error) return { ok: false, error };
  return { ok: true, plan: data.tier };
}
