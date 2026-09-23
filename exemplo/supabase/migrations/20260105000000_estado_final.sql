create table public.rascunhos_velhos (id bigint);
drop table public.rascunhos_velhos;

create table public.nome_antigo (id bigint primary key);
alter table public.nome_antigo enable row level security;
create policy "nome_antigo_sel" on public.nome_antigo
  for select to authenticated using (id > 0);
alter table public.nome_antigo rename to nome_novo;

create policy "temporaria_aberta" on public.planos for select using (true);
drop policy "temporaria_aberta" on public.planos;

create table public.menus (id bigint primary key, dono uuid);
alter table public.menus enable row level security;
create policy "Enable read for all" on public.menus
  for select to "authenticated" using (dono = auth.uid());
create policy "menus_leitura_2" on public.menus
  for select to authenticated using (dono = auth.uid());

create or replace view public.visao_velha as select 1 as um;
drop view public.visao_velha;

create or replace function public.fn_aspas()
returns void
language sql
security definer
set "search_path" to ''
as $$
  select 1;
$$;

create or replace function public.fn_multi()
returns void
language sql
security definer
set search_path = ''
as $$
  select 1;
$$;
revoke execute on function public.fn_aspas(), public.fn_multi() from public, anon;

create or replace function public.fn_exposta(p_conta uuid)
returns void
language sql
security definer
set search_path = ''
as $$
  select 1;
$$;
grant execute on function public.fn_exposta(uuid) to authenticated;

create view public.visao_segura
  with (security_invoker)
  as select 1 as um;

create table public.cadastro_velho (id bigint primary key);
alter table public.cadastro_velho rename to cadastro_novo;
alter table public.cadastro_novo enable row level security;
create policy "cadastro_novo_sel" on public.cadastro_novo
  for select to authenticated using (id > 0);

create policy "portal_aspas" on storage.objects
  for select to "anon"
  using (exists (select 1 from public.arquivos a where a.caminho = name));

create policy "apontamentos_insert_velha" on public.apontamentos
  for insert to authenticated with check (user_id = auth.uid());
drop policy "apontamentos_insert_velha" on public.apontamentos;
