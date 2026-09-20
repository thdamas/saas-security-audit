import { createServerFn } from '@tanstack/react-start'
import { supabaseAdmin } from '../supabase.server'

export const iniciarCheckout = createServerFn({ method: 'POST' })
  .handler(async ({ data }) => {
    const { data: plano } = await supabaseAdmin.from('planos').select('*').eq('id', data.planoId).single()
    return { valor: plano.preco_centavos }
  })

export const registrarPagamento = createServerFn({ method: 'POST' })
  .handler(async ({ data }) => {
    await supabaseAdmin.from('pagamentos').insert({ assinatura_id: data.assinaturaId, valor_centavos: data.valor })
    await supabaseAdmin.rpc('recalcular_saldo', { p_user: data.userId })
  })
