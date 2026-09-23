create table public.membros (
  id uuid primary key references auth.users(id),
  papel text not null default 'colaborador',
  valor_hora numeric,
  ativo boolean not null default true
);
alter table public.membros enable row level security;
create policy "membros_select_proprio" on public.membros
  for select to authenticated using (id = auth.uid());
grant select (id, papel, valor_hora) on public.membros to authenticated;
grant select (id, papel) on public.membros to anon;

create or replace function public.papel_atual()
returns text
language sql
stable
security definer
set search_path = ''
as $$
  -- nao olha se o membro esta ativo
  select papel from public.membros where id = auth.uid();
$$;

create or replace function public.eh_dono()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.membros where id = auth.uid() and papel = 'dono' and ativo
  );
$$;
revoke execute on function public.eh_dono() from public, anon;

create or replace function public.definir_primeiro_acesso()
returns text
language plpgsql
security definer
set search_path = ''
as $fn$
begin
  if not exists (select 1 from public.membros) then
    return 'dono';
  end if;
  return 'colaborador';
end;
$fn$;
revoke execute on function public.definir_primeiro_acesso() from public, anon;

create table public.convites_equipe (
  email text primary key,
  papel text not null
);
alter table public.convites_equipe enable row level security;
create policy "convites_equipe_dono" on public.convites_equipe
  for all to authenticated using (public.eh_dono()) with check (public.eh_dono());

create or replace function public.aplicar_convite()
returns trigger
language plpgsql
security definer
set search_path = ''
as $fn$
begin
  insert into public.membros (id, papel)
  select new.id, c.papel from public.convites_equipe c where c.email = new.email;
  return new;
end;
$fn$;
revoke execute on function public.aplicar_convite() from public, anon;
create trigger trg_aplicar_convite after insert on auth.users
  for each row execute function public.aplicar_convite();

create or replace function public.aplicar_convite_confirmado()
returns trigger
language plpgsql
security definer
set search_path = ''
as $fn$
begin
  insert into public.membros (id, papel)
  select new.id, c.papel from public.convites_equipe c
  where c.email = new.email and new.email_confirmed_at is not null;
  return new;
end;
$fn$;
revoke execute on function public.aplicar_convite_confirmado() from public, anon;
create trigger trg_aplicar_convite_confirmado after insert or update on auth.users
  for each row execute function public.aplicar_convite_confirmado();

create or replace function public.email_convidado(p_email text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (select 1 from public.convites_equipe where email = p_email);
$$;
grant execute on function public.email_convidado(text) to anon;

create table public.tarefas (
  id bigserial primary key,
  membro_id uuid references public.membros(id) on delete cascade,
  titulo text not null
);
alter table public.tarefas enable row level security;
create policy "tarefas_insert_membro" on public.tarefas
  for insert to authenticated
  with check (membro_id = auth.uid() and public.eh_dono());

create table public.apontamentos (
  id bigserial primary key,
  user_id uuid not null references auth.users(id),
  tarefa_id bigint not null references public.tarefas(id) on delete cascade,
  inicio timestamptz not null,
  fim timestamptz
);
alter table public.apontamentos enable row level security;
create policy "apontamentos_insert_autor" on public.apontamentos
  for insert to authenticated
  with check (user_id = auth.uid());

create table public.pacotes_horas (
  id bigserial primary key,
  cliente text not null,
  data_inicio date not null,
  data_fim date not null,
  check (data_fim >= data_inicio)
);
alter table public.pacotes_horas enable row level security;
create policy "pacotes_horas_dono" on public.pacotes_horas
  for select to authenticated using (public.eh_dono());


create or replace function public.assinaturas_em_aberto()
returns bigint
language sql
stable
set search_path = ''
as $$
  select count(*) from public.assinaturas where status <> 'cancelada';
$$;

create table public.arquivos (
  id bigserial primary key,
  caminho text not null
);
alter table public.arquivos enable row level security;
create policy "arquivos_dono" on public.arquivos
  for select to authenticated using (public.eh_dono());
create policy "portal_baixa_arquivo" on storage.objects
  for select to anon
  using (exists (select 1 from public.arquivos a where a.caminho = name));
create policy "equipe_sobe_arquivo" on storage.objects
  for insert to authenticated
  with check (exists (select 1 from public.arquivos a where a.caminho = name));

grant execute on function public.assinaturas_em_aberto() to anon;

create or replace function public.equipe_vazia()
returns boolean
language sql
stable
set search_path = ''
as $$
  select not exists (select 1 from public.membros where papel <> 'dono');
$$;

create or replace function public.nenhum_cadastro()
returns boolean
language sql
stable
set search_path = ''
as $$
  select not exists (select 1 from public.membros);
$$;

create table public.preferencias (
  user_id uuid primary key references auth.users(id),
  tema text not null default 'claro'
);
alter table public.preferencias enable row level security;
create policy "preferencias_insert_propria" on public.preferencias
  for insert to authenticated
  with check (user_id = auth.uid());

create policy "apontamentos_update_dono_ou_autor" on public.apontamentos
  for update to authenticated
  using ((public.eh_dono()) or (user_id = auth.uid()))
  with check ((public.eh_dono()) or (user_id = auth.uid()));

create table public.creditos_horas (
  id bigserial primary key,
  pacote_id bigint not null,
  horas numeric not null
);
alter table public.creditos_horas add constraint creditos_horas_pacote_fkey
  foreign key (pacote_id) references public.pacotes_horas(id) on delete cascade;
alter table public.creditos_horas enable row level security;
create policy "creditos_horas_dono" on public.creditos_horas
  for select to authenticated using (public.eh_dono());

create or replace function public.assinaturas_ativas_v()
returns bigint
language sql
stable
set search_path = ''
as $$
  select count(*) from public.assinaturas where status <> 'inadimplente';
$$;

create or replace function public.assinaturas_nao_arquivadas()
returns bigint
language sql
stable
set search_path = ''
as $$
  select count(*) from public.assinaturas where status <> 'arquivada';
$$;
