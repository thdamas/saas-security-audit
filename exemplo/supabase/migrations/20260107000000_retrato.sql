SET statement_timeout = 0;
SET check_function_bodies = false;

CREATE OR REPLACE FUNCTION "public"."fechar_mes_da_conta"("p_conta" "uuid") RETURNS "void"
    LANGUAGE "sql" SECURITY DEFINER
    SET "search_path" TO ''
    AS $$
  update public.contas set saldo = 0 where id = p_conta;
$$;

CREATE OR REPLACE FUNCTION "public"."saldo_publico_da_conta"("p_conta" "uuid") RETURNS SETOF "public"."contas"
    LANGUAGE "sql" SECURITY DEFINER
    SET "search_path" TO ''
    AS $$
  select * from public.contas where id = p_conta;
$$;

REVOKE ALL ON FUNCTION "public"."fechar_mes_da_conta"("p_conta" "uuid") FROM PUBLIC;

REVOKE ALL ON FUNCTION "public"."saldo_publico_da_conta"("p_conta" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."saldo_publico_da_conta"("p_conta" "uuid") TO "authenticated";
