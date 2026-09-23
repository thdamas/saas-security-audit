import { createServerFn } from '@tanstack/react-start'
import { supabase } from '../supabase.client'
import { requireUser } from '../auth/middleware.server'

export const lerPerfil = createServerFn({ method: 'GET' })
  .middleware([requireUser])
  .handler(async ({ context }) => {
    const { data } = await supabase.from('profiles').select('*').eq('id', context.user.id).single()
    return data
  })

export const estadoAcesso = createServerFn({ method: 'GET' })
  .middleware([requireUser])
  .handler(async ({ context }) => {
    const { data } = await supabase.from('assinaturas').select('status').eq('user_id', context.user.id)
    if (!data || data.length === 0) return 'sem_assinatura'
    return data[0].status
  })

export const buscarUsuarios = createServerFn({ method: 'POST' })
  .middleware([requireUser])
  .handler(async ({ data: termo }) => {
    // const velho = await supabase.rpc('rpc_comentada')
    const { data } = await supabase.from('profiles').select('id,nome').or(`nome.ilike.%${termo}%`)
    await supabase.from('profiles').select('id').or('tipo_acesso.eq.pagante')
    await supabase.from('profiles').select('id').filter('nome', 'eq', termo)
    return data
  })
