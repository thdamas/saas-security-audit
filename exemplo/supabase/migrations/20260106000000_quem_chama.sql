create table public.contas (
  id uuid primary key,
  saldo numeric not null default 0
);
alter table public.contas enable row level security;
create policy "contas_dono" on public.contas
  for select to authenticated using (public.eh_dono());

create or replace function public.extrato_da_conta(p_conta uuid)
returns setof public.contas
language sql
stable
security definer
set search_path = ''
as $$
  select * from public.contas where id = p_conta;
$$;
revoke execute on function public.extrato_da_conta(uuid) from public, anon;
grant execute on function public.extrato_da_conta(uuid) to authenticated;

create or replace function public.saldo_da_conta(p_conta uuid)
returns numeric
language sql
stable
security definer
set search_path = ''
as $$
  select saldo from public.contas where id = p_conta and public.eh_dono();
$$;
revoke execute on function public.saldo_da_conta(uuid) from public, anon;

create or replace function public.contas_do_usuario(p_user uuid)
returns setof public.contas
language plpgsql
stable
security definer
set search_path = ''
as $fn$
begin
  if p_user is distinct from auth.uid() then
    raise exception 'proibido';
  end if;
  return query select * from public.contas where id = p_user;
end;
$fn$;
revoke execute on function public.contas_do_usuario(uuid) from public, anon;

create or replace function public.recalcular_conta(p_conta uuid)
returns void
language sql
security definer
set search_path = ''
as $$
  update public.contas set saldo = 0 where id = p_conta;
$$;
revoke execute on function public.recalcular_conta(uuid) from public, anon, authenticated;

create schema if not exists privado;
create or replace function privado.fechar_conta(p_conta uuid)
returns void
language sql
security definer
set search_path = ''
as $$
  delete from public.contas where id = p_conta;
$$;

create table public.equipe_org (
  user_id uuid primary key,
  org_role text not null default 'membro',
  apelido text
);
alter table public.equipe_org enable row level security;
create policy "equipe_org_edita_propria" on public.equipe_org
  for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create or replace function public.trava_papel_org()
returns trigger
language plpgsql
set search_path = ''
as $fn$
begin
  if new.org_role is distinct from old.org_role then
    raise exception 'papel muda pela função de convite';
  end if;
  return new;
end;
$fn$;
create trigger trg_trava_papel_org before update on public.equipe_org
  for each row execute function public.trava_papel_org();
create or replace function public.eh_gestor_org()
returns boolean
language sql
stable
set search_path = ''
as $$
  select exists (select 1 from public.equipe_org where user_id = auth.uid() and org_role = 'gestor');
$$;

create table public.vitrine (
  user_id uuid primary key,
  tenant_id uuid,
  bio text
);
alter table public.vitrine enable row level security;
create policy "vitrine_edita_propria" on public.vitrine
  for update to authenticated using (user_id = auth.uid());
grant update (bio) on public.vitrine to authenticated;
create or replace function public.vitrine_do_tenant()
returns bigint
language sql
stable
set search_path = ''
as $$
  select count(*) from public.vitrine where tenant_id = (select tenant_id from public.vitrine where user_id = auth.uid());
$$;

create table public.cartao_visita (
  user_id uuid primary key,
  role text
);
alter table public.cartao_visita enable row level security;
create policy "cartao_edita_proprio" on public.cartao_visita
  for update to authenticated using (user_id = auth.uid());

create table public.socios (
  user_id uuid primary key,
  apelido text
);
alter table public.socios
  add column if not exists nivel text,
  add column if not exists org_id uuid;
alter table public.socios enable row level security;
create policy "socios_edita_proprio" on public.socios
  for update to authenticated using (user_id = auth.uid());
create or replace function public.eh_da_org(p_org uuid)
returns boolean
language sql
stable
set search_path = ''
as $$
  select exists (select 1 from public.socios s where s.user_id = auth.uid() and s.org_id = p_org);
$$;

create or replace function public.papel_do_convite_do_cartao()
returns text
language sql
stable
set search_path = ''
as $$
  select c.role from public.cartao_visita v join public.profiles c on c.id = v.user_id where v.user_id = auth.uid();
$$;

create or replace function public.pedidos(p_user uuid)
returns setof public.contas
language sql
stable
security definer
set search_path = ''
as $$
  select * from public.contas where id = p_user;
$$;
create or replace function public.pedidos()
returns setof public.contas
language sql
stable
security definer
set search_path = ''
as $$
  select * from public.contas where id = auth.uid();
$$;
revoke execute on function public.pedidos(uuid) from public, anon;
create or replace function public.resumo_pedidos(p_user uuid)
returns setof public.contas
language sql
stable
security definer
set search_path = ''
as $$
  select * from public.pedidos(p_user);
$$;
revoke execute on function public.resumo_pedidos(uuid) from public, anon;

create or replace function public.apagar_conta_antiga(p_conta uuid)
returns void
language sql
security definer
set search_path = ''
as $$
  delete from public.contas where id = p_conta;
$$;
drop function if exists public.apagar_conta_antiga(uuid);

create or replace function public.historico(p_conta uuid)
returns setof public.contas
language sql
stable
security definer
set search_path = ''
as $$
  select * from public.contas where id = p_conta;
$$;
create or replace function public.historico(p_conta uuid, p_dias integer)
returns setof public.contas
language sql
stable
security definer
set search_path = ''
as $$
  select * from public.contas where id = p_conta and id = auth.uid();
$$;
drop function public.historico(uuid);

create or replace function public.consolidar_conta(p_conta uuid)
returns void
language sql
security definer
set search_path = ''
as $$
  update public.contas set saldo = saldo where id = p_conta;
$$;
do $$
declare
    fn text;
    sig text;
    nomes text[] := array['consolidar_conta'];
begin
    foreach fn in array nomes loop
        for sig in
            select format('public.%I(%s)', p.proname, pg_get_function_identity_arguments(p.oid))
            from pg_proc p join pg_namespace n on n.oid = p.pronamespace
            where n.nspname = 'public' and p.proname = fn and p.prosecdef
        loop
            execute format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC, anon, authenticated', sig);
        end loop;
    end loop;
end $$;

CREATE OR REPLACE FUNCTION public.resumo_mes(p_conta UUID, p_rotulo TEXT DEFAULT 'mensal')
RETURNS SETOF public.contas
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  select * from public.contas where id = p_conta;
$$;
create or replace function public.resumo_mes(p_conta uuid, p_rotulo text default 'mensal'::text)
returns setof public.contas
language sql
stable
security definer
set search_path = ''
as $$
  select * from public.contas where id = p_conta and id = auth.uid();
$$;
revoke execute on function public.resumo_mes(uuid, text) from public, anon;
