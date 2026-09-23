import { supabase } from "../lib/supabase.client";
export async function GET() {
  const { data } = await supabase.auth.getUser();
  if (!data.user) return new Response("nao autorizado", { status: 401 });
  return Response.json({ id: data.user.id });
}
