create table "public"."orders" (
    "id" bigint not null
);
alter table "public"."orders" enable row level security;
create policy "Orders visible to owner" on "public"."orders" as permissive for select to authenticated using (public.eh_dono());

create table "public"."payments" (
    "id" bigint not null,
    "user_id" uuid not null,
    "order_id" bigint
);
alter table "public"."payments" enable row level security;
create policy "Users insert own payments" on "public"."payments" as permissive for insert to authenticated with check ((( SELECT auth.uid() AS uid) = user_id));
alter table only "public"."payments" add constraint "payments_order_id_fkey" foreign key (order_id) references orders(id) on delete cascade not valid;

create table public.comentarios (
  id bigserial primary key,
  autor_id uuid not null,
  tarefa_id bigint not null,
  texto text,
  constraint comentarios_tarefa_fk foreign key (tarefa_id) references public.tarefas(id)
);
alter table public.comentarios enable row level security;
create policy "comentarios_update_autor" on public.comentarios
  for update to authenticated using (autor_id = auth.uid());

create table public.lancamentos (
  id bigserial primary key,
  pacote_id bigint not null,
  valor numeric not null,
  constraint lancamentos_pacote_fk foreign key (pacote_id) references public.pacotes_horas(id) on delete cascade
);
alter table public.lancamentos enable row level security;
create policy "lancamentos_dono" on public.lancamentos
  for select to authenticated using (public.eh_dono());

create table public.horarios (
  id bigserial primary key,
  tarefa_id bigint references public.tarefas(id) on delete cascade
);
alter table public.horarios enable row level security;
create policy "horarios_dono" on public.horarios
  for select to authenticated using (public.eh_dono());

create table public.turnos (
  id bigserial primary key,
  started_at timestamptz not null,
  ended_at timestamptz check (ended_at >= started_at)
);
alter table public.turnos enable row level security;
create policy "turnos_dono" on public.turnos
  for select to authenticated using (public.eh_dono());

create table public.sessoes (
  id bigserial primary key,
  inicia_em timestamptz not null,
  termina_em timestamptz
);
alter table only public.sessoes add constraint sessoes_ordem CHECK (TERMINA_EM >= INICIA_EM);
alter table public.sessoes enable row level security;
create policy "sessoes_dono" on public.sessoes
  for select to authenticated using (public.eh_dono());

create table public.documentos_publicos (
  id bigserial primary key,
  caminho text not null,
  publicado boolean not null default false
);
alter table public.documentos_publicos enable row level security;
create policy "documentos_publicos_visitante" on public.documentos_publicos
  for select to anon using (publicado);
create policy "portal_documento_publico" on storage.objects
  for select to anon
  using (exists (select 1 from public.documentos_publicos d where d.caminho = name));
create policy "portal_sem_papel" on storage.objects
  for select
  using (exists (select 1 from public.arquivos a where a.caminho = name));

create or replace function public.recalcular_saldo_interno()
returns void
language plpgsql
security definer
set search_path = ''
as $fn$
begin
  perform 1;
end;
$fn$;
revoke execute on function public.recalcular_saldo_interno() from anon;

create or replace function public.convite_por_token(p_token text)
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select papel from public.convites_equipe where email = p_token;
$$;

create or replace function public.perfil_por_email(p_email text)
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select papel from public.membros where id = auth.uid();
$$;

create or replace function public.email_ja_convidado(p_email text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (select 1 from public.convites_equipe where email = p_email);
$$;
grant execute on function public.email_ja_convidado(text) to anon;
revoke execute on function public.email_ja_convidado(text) from public, anon;

create or replace function public.dono_se_vazio()
returns text
language plpgsql
security definer
set search_path = ''
as $fn$
begin
  if (select count(*) from public.membros) = 0 then
    return 'owner';
  end if;
  return 'colaborador';
end;
$fn$;
revoke execute on function public.dono_se_vazio() from public, anon;

create or replace function public.dono_por_contagem()
returns text
language plpgsql
security definer
set search_path = ''
as $fn$
declare
  n integer;
begin
  select count(*) into n from public.membros;
  if n = 0 then
    return 'dono';
  end if;
  return 'colaborador';
end;
$fn$;
revoke execute on function public.dono_por_contagem() from public, anon;

create or replace trigger trg_convite_de_novo after insert on auth.users
  for each row execute function public.aplicar_convite();

create type "public"."fase" as enum ('aberta', 'fechada');
create table public.chamados (
  id bigserial primary key,
  fase "public"."fase" not null default 'aberta',
  papel text
);
alter table public.chamados enable row level security;
create policy "chamados_dono" on public.chamados
  for select to authenticated using (public.eh_dono());
alter type "public"."fase" add value 'pausada';

create or replace function public.chamados_em_aberto()
returns bigint
language sql
stable
set search_path = ''
as $$
  -- status <> 'ativa' ficou de fora de propósito
  select count(*) from public.chamados where fase <> 'fechada' and papel <> 'cancelada';
$$;

grant select (id, email), update (papel) on public.convites_equipe to authenticated;

create or replace function public.contar_tarefas_do_membro()
returns bigint
language sql
stable
security definer
set search_path = ''
as $$
  select count(*) from public.membros m join public.tarefas t on t.membro_id = m.id;
$$;
revoke execute on function public.contar_tarefas_do_membro() from public, anon;

create table public.etapas (
  id bigserial primary key,
  fase text not null
);
alter table public.etapas enable row level security;
create policy "etapas_dono" on public.etapas
  for select to authenticated using (public.eh_dono());

create or replace function public.etapas_publicadas()
returns bigint
language sql
stable
set search_path = ''
as $$
  select count(*) from public.etapas where fase <> 'rascunho';
$$;

create or replace function public.is_gestor()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (select 1 from public.membros where id = auth.uid() and papel = 'ativo');
$$;
revoke execute on function public.is_gestor() from public, anon;

create or replace function public.tem_tarefa_aberta(p_membro uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (select 1 from public.membros m join public.tarefas t on t.membro_id = m.id where m.id = p_membro);
$$;
revoke execute on function public.tem_tarefa_aberta(uuid) from public, anon;

grant select (id, token_count) on public.membros to authenticated;
grant select (id, telefone) on public.convites_equipe to authenticated with grant option;

create table public.avisos_horas (
  id bigserial primary key,
  pacote_id bigint references public.pacotes_horas(id) on delete cascade
);
alter table public.avisos_horas enable row level security;
create policy "avisos_horas_dono" on public.avisos_horas
  for select to authenticated using (public.eh_dono());

create or replace function public.convite_reaberto(p_email text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (select 1 from public.convites_equipe where email = p_email);
$$;
revoke execute on function public.convite_reaberto(text) from public, anon;
grant execute on function public.convite_reaberto(text) to anon;

create or replace function public.is_org_admin(p_org uuid, p_user uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (select 1 from public.membros where id = p_user and papel = 'dono');
$$;
revoke execute on function public.is_org_admin(uuid, uuid) from public, anon;

create table public.anotacoes (
  id bigserial primary key,
  autor_id uuid not null,
  texto text
);
alter table public.anotacoes enable row level security;
create policy "anotacoes_select_autor" on public.anotacoes
  for select to authenticated using (autor_id = auth.uid());
create policy "anotacoes_insert_livre" on public.anotacoes
  for insert to authenticated;
