grant execute on function public.eh_staff() to authenticated;
grant execute on function public.papel_atual() to anon, authenticated;
grant execute on function public.eh_dono() to authenticated;

create table public.log_base (id bigint);
alter table public.log_base enable row level security;
grant select on table public.log_base to anon;

create table public.tabela_crua (id bigint);
grant select on table public.tabela_crua to anon;

create or replace function public.recalcular_tudo()
returns void
language sql
as $$
  select 1;
$$;

revoke execute on function public.papel_atual() from anon;
revoke select on table public.log_base from anon;
revoke select on table public.tabela_crua from anon;
revoke all on function public.eh_staff() from public, anon, authenticated;
grant execute on function public.eh_staff() to authenticated;
