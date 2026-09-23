import { supabaseAdmin } from "../lib/supabase.server";
function assert(v: unknown) { if (!v) throw new Error("faltou"); }
export async function GET(req: Request) {
  const caminho = new URL(req.url).searchParams.get("caminho");
  assert(caminho);
  const { data } = await supabaseAdmin.storage.from("docs").createSignedUrl(String(caminho), 60);
  return Response.json(data);
}
