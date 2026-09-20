create type public.status_assinatura as enum ('ativa', 'inadimplente', 'cancelada');

create table public.profiles (
  id uuid primary key references auth.users(id),
  nome text,
  role text not null default 'usuario',
  tipo_acesso text not null default 'pagante'
);
alter table public.profiles enable row level security;
create policy "profiles_select_proprio" on public.profiles
  for select to authenticated using (id = auth.uid());
create policy "profiles_update_proprio" on public.profiles
  for update to authenticated using (id = auth.uid());

create table public.assinaturas (
  id bigserial primary key,
  user_id uuid not null references public.profiles(id),
  status public.status_assinatura not null default 'ativa',
  data_inicio timestamptz not null default now()
);
alter table public.assinaturas enable row level security;
create policy "assinaturas_select_proprio" on public.assinaturas
  for select to authenticated using (user_id = auth.uid());

create table public.pagamentos (
  id bigserial primary key,
  assinatura_id bigint not null references public.assinaturas(id),
  valor_centavos integer not null,
  provedor_payment_id text,
  pago_em timestamptz
);
alter table public.pagamentos enable row level security;
create policy "pagamentos_select_proprio" on public.pagamentos
  for select to authenticated
  using (exists (select 1 from public.assinaturas a where a.id = assinatura_id and a.user_id = auth.uid()));

create table public.convites (
  id bigserial primary key,
  email text not null,
  token text not null
);

create table public.logs_admin (
  id bigserial primary key,
  quem uuid,
  acao text,
  quando timestamptz default now()
);
alter table public.logs_admin enable row level security;

create table public.planos (
  id text primary key,
  nome text not null,
  preco_centavos integer not null
);
alter table public.planos enable row level security;
create policy "planos_publicos" on public.planos for select using (true);
grant select on public.planos to anon;
