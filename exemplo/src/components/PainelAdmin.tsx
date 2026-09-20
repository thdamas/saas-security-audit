import { supabaseAdmin } from '../lib/supabase.server'

export function PainelAdmin({ html }: { html: string }) {
  const chave = 'sk_test_51ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  return <div dangerouslySetInnerHTML={{ __html: html }} data-chave={chave} />
}
