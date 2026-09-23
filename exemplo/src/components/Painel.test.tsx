import { supabaseAdmin } from "../lib/supabase.server";
const BANCO_DE_TESTE = "postgres://app:senha123@localhost:5432/app";
export function montar() { return [BANCO_DE_TESTE, supabaseAdmin]; }
