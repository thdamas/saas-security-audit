create or replace function public.eh_staff()
returns boolean
language sql
stable
as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'staff');
$$;

create or replace function public.contar_assinantes()
returns integer
language sql
security definer
set search_path = public
as $$
  select count(*)::integer from public.assinaturas where status = 'ativa';
$$;

create or replace function public.marcar_inadimplente(p_user uuid)
returns void
language plpgsql
security definer
as $fn$
begin
  update public.assinaturas set status = 'inadimplente' where user_id = p_user;
end;
$fn$;

create or replace function public.total_pago(p_user uuid)
returns integer
language sql
stable
as $$
  select coalesce(sum(valor_centavos), 0)::integer
  from public.pagamentos p join public.assinaturas a on a.id = p.assinatura_id
  where a.user_id = p_user;
$$;

create or replace view public.resumo_financeiro
with (security_invoker = false)
as select a.user_id, sum(p.valor_centavos) as total
   from public.pagamentos p join public.assinaturas a on a.id = p.assinatura_id
   group by a.user_id;

create policy "assinaturas_staff_tudo" on public.assinaturas
  for select to authenticated using (public.eh_staff());

create trigger trg_log_assinatura
  after update on public.assinaturas
  for each row execute function public.total_pago(new.user_id);
