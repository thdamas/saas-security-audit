import { supabaseAdmin } from '../lib/supabase.server'

export async function GET(req: Request) {
  const email = new URL(req.url).searchParams.get('email')
  await supabaseAdmin.from('profiles').update({ newsletter: false }).eq('email', email)
  return new Response('ok')
}
