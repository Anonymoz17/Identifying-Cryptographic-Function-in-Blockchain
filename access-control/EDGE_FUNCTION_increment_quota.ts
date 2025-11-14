// ============================================================================
// Supabase Edge Function: increment_quota
// ============================================================================
// Purpose: Safely increment user's analysis count server-side
// Security: Runs as service_role, bypasses RLS, verifies user authentication
// ============================================================================

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, x-client-info, content-type",
};

serve(async (req) => {
  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    // Parse request
    const { user_id, auth_token } = await req.json();

    // Validate input
    if (!user_id || !auth_token) {
      return new Response(
        JSON.stringify({ success: false, error: "Missing user_id or auth_token" }),
        {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // Create Supabase client with service role (bypasses RLS)
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

    if (!supabaseUrl || !supabaseKey) {
      return new Response(
        JSON.stringify({ success: false, error: "Missing Supabase credentials" }),
        {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    const supabase = createClient(supabaseUrl, supabaseKey);

    // Verify user is authenticated by checking their token
    const { data: { user }, error: authError } = await supabase.auth.getUser(auth_token);

    if (authError || !user) {
      return new Response(
        JSON.stringify({ success: false, error: "Unauthorized" }),
        {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // Verify user_id matches authenticated user
    if (user.id !== user_id) {
      return new Response(
        JSON.stringify({ success: false, error: "User ID mismatch" }),
        {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // Get current count
    const { data: userData, error: selectError } = await supabase
      .from("user_roles")
      .select("analysis_count, tier")
      .eq("id", user_id)
      .single();

    if (selectError || !userData) {
      return new Response(
        JSON.stringify({ success: false, error: "User not found in user_roles" }),
        {
          status: 404,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // Check if premium (don't increment for premium users)
    if (userData.tier === "premium") {
      return new Response(
        JSON.stringify({ success: true, message: "Premium user, no increment needed" }),
        {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // Increment count
    const newCount = (userData.analysis_count || 0) + 1;

    const { error: updateError } = await supabase
      .from("user_roles")
      .update({ analysis_count: newCount })
      .eq("id", user_id);

    if (updateError) {
      console.error("Update error:", updateError);
      return new Response(
        JSON.stringify({ success: false, error: `Failed to update quota: ${updateError.message}` }),
        {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    return new Response(
      JSON.stringify({
        success: true,
        message: `Quota incremented to ${newCount}`,
        new_count: newCount,
      }),
      {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  } catch (error) {
    console.error("Error:", error);
    return new Response(
      JSON.stringify({ success: false, error: error.message }),
      {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  }
});
