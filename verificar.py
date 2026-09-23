"""
verificar.py — autoteste do saas-security-audit.

Roda o scanner e o painel contra o app de exemplo (`exemplo/`), que tem um defeito plantado
pra cada detector, e confere por asserção que cada um foi achado, que a cobertura fechou e
que o painel saiu íntegro. Se isto passa na sua máquina, a ferramenta funciona na sua
máquina. Se falha, a saída diz exatamente qual detector quebrou.

Uso:
    python verificar.py            # roda tudo, sai 0 se passou, 1 se falhou
    python verificar.py --manter   # não apaga a pasta temporária de saída

Não toca em nada fora de uma pasta temporária.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

AQUI = Path(__file__).resolve().parent
PERFIL = AQUI / "exemplo" / ".claude" / "auditoria" / "perfil.toml"

# Cada linha: (regra, quantidade esperada, o que foi plantado no exemplo)
ESPERADOS = [
    ("rls-ausente", 2, "`convites` e `crm.segredos` (esquema exposto no config.toml); `interno.fila` não é exposto e NÃO entra"),
    ("rls-sem-policy", 1, "tabela `logs_admin` com RLS e zero policy"),
    ("policy-tautologica", 1, "policy `planos_publicos` com using (true); as vizinhas NÃO podem ser acusadas"),
    ("escrita-sem-with-check", 1, "INSERT sem WITH CHECK em `anotacoes`; UPDATE só com USING NÃO entra, porque o Postgres usa o USING como trava"),
    ("definer-sem-search-path", 1, "`marcar_inadimplente`; `contar_assinantes` tem search_path e NÃO entra"),
    ("search-path-mutavel", 2, "`eh_staff` e `total_pago`, não-definer sem search_path"),
    ("view-definer", 1, "view `resumo_financeiro` sem security_invoker = true"),
    ("grant-anon", 1, "grant select em `planos` para anon"),
    ("policy-empilhada", 3, "e `menus`, onde uma se chama \"Enable read for all\" mas é de SELECT; antes: " + "`assinaturas` com 2 de SELECT e `storage.objects` com 3 de SELECT"),
    ("rpc-fantasma", 1, "`recalcular_saldo` chamada e nunca criada"),
    ("privilegio-no-frontend", 1, "supabaseAdmin importado em componente .tsx"),
    ("rota-api-sem-verificacao", 2, "e `api.caminho.ts`, que só faz assert do parâmetro; antes: " + "`api.descadastrar.ts`; o webhook verifica assinatura e NÃO entra"),
    ("headers-ausentes", 1, "vercel.json com 1 de 6 headers"),
    ("segredo-hardcoded", 1, "chave de teste literal no componente"),
    ("render-inseguro", 1, "dangerouslySetInnerHTML no componente"),
    ("filtro-cru-postgrest", 1, "`.or()` com template string em perfil.functions.ts"),
    ("teste-de-seguranca-ausente", 4, "nenhum teste com rls/webhook/autoriz/isolament no nome"),
    ("backup-incerto", 1, "plano free + migration à mão"),
    ("sem-gate-de-ci", 1, "push direto na main sem CI"),
    ("janela-na-reaplicacao", 2, "baseline reaplicado concede `papel_atual` e a `tabela_crua` (sem RLS) a anon e só revoga depois; `log_base` já tem RLS ligada antes e NÃO entra; `eh_dono` nunca é revogado ali e NÃO entra"),
    ("grant-anon-em-massa", 1, "`grant all on all tables in schema public to anon`, o padrão do Supabase, vira regra própria"),
    ("papel-ignora-desativacao", 3, "`papel_atual`, `is_gestor` (só cita 'ativo' como texto) e `is_org_admin` (usuário por parâmetro); `eh_dono` olha e NÃO entra"),
    ("coluna-sensivel-exposta", 3, "`valor_hora`, o de dois privilégios e o `with grant option`; `token_count` NÃO entra; o grant sem coluna sensível NÃO entra"),
    ("escrita-so-confere-autoria", 4, "`apontamentos_insert_autor`, o lado autor do OU, `payments` no formato do db diff e `comentarios` só com USING; `tarefas_insert_membro` confere mais que autoria e NÃO entra"),
    ("storage-anon-inerte", 3, "e `portal_aspas`, com o papel entre aspas; antes: " + "`portal_baixa_arquivo` pra anon e `portal_sem_papel` sem TO; `portal_documento_publico` tem policy de anon na tabela e NÃO entra; a de insert pra authenticated NÃO entra"),
    ("papel-no-cadastro-sem-confirmacao", 2, "`trg_aplicar_convite` e o `create or replace trigger`; a versão que exige email_confirmed_at NÃO entra"),
    ("oraculo-de-convite", 2, "`email_convidado` e `convite_reaberto`, que teve grant DEPOIS do revoke"),
    ("primeiro-usuario-vira-dono", 3, "not exists sem filtro, count em subselect e count into"),
    ("definer-sem-revoke", 9, "e `fn_exposta`, com GRANT explícito; antes: " + "os 4 de antes, o revoke só de anon, `convite_por_token`, `perfil_por_email` e `convite_reaberto`"),
    ("enum-cresceu-comparacao-negativa", 2, "`status <> 'cancelada'` e `fase <> 'fechada'` de enum entre aspas; `papel <> 'cancelada'` e o comentário NÃO entram"),
    ("intervalo-sem-check", 1, "`apontamentos` (inicio, fim); `pacotes_horas` tem check e NÃO entra"),
    ("cascade-apaga-historico", 4, "inline, por alter table, por constraint de tabela e `payments` no formato do db diff; `horarios` NÃO entra; `tarefas.membro_id` não é histórico e NÃO entra"),
    ("doc-cita-policy-inexistente", 1, "INSTALL cita `portal_le_documentos`; `planos_publicos` existe e NÃO entra"),
]

# Casos limpos que NÃO podem aparecer no título de nenhum achado da regra.
NEGATIVOS = [
    ("papel-ignora-desativacao", "eh_dono"),
    ("coluna-sensivel-exposta", "anon"),
    ("escrita-so-confere-autoria", "tarefas_insert_membro"),
    ("storage-anon-inerte", "equipe_sobe_arquivo"),
    ("papel-no-cadastro-sem-confirmacao", "aplicar_convite_confirmado"),
    ("definer-sem-revoke", "eh_dono"),
    ("definer-sem-revoke", "definir_primeiro_acesso"),
    ("intervalo-sem-check", "pacotes_horas"),
    ("cascade-apaga-historico", "tarefas.membro_id"),
    ("doc-cita-policy-inexistente", "planos_publicos"),
    ("doc-cita-policy-inexistente", "vault_master_key"),
    ("doc-cita-policy-inexistente", "trg_aplicar_convite"),
    ("doc-cita-policy-inexistente", "service_role"),
    ("doc-cita-policy-inexistente", "membro_id"),
    ("doc-cita-policy-inexistente", "`select`"),
    ("papel-ignora-desativacao", "contar_tarefas_do_membro"),
    ("storage-anon-inerte", "portal_documento_publico"),
    ("oraculo-de-convite", "convite_por_token"),
    ("oraculo-de-convite", "perfil_por_email"),
    ("oraculo-de-convite", "email_ja_convidado"),
    ("definer-sem-revoke", "email_ja_convidado"),
    ("intervalo-sem-check", "turnos"),
    ("intervalo-sem-check", "sessoes"),
    ("cascade-apaga-historico", "horarios"),
    ("enum-cresceu-comparacao-negativa", "papel <>"),
    ("enum-cresceu-comparacao-negativa", "'ativa'"),
    ("enum-cresceu-comparacao-negativa", "etapas."),
    ("enum-cresceu-comparacao-negativa", "'aberta'"),
    ("enum-cresceu-comparacao-negativa", "'inadimplente'"),
    ("rls-ausente", "interno"),
    ("rls-ausente", "`crm`"),
    ("rls-ausente", "creation"),
    ("rls-ausente", "`if`"),
    ("rls-ausente", "rascunho"),
    ("rls-ausente", "rascunhos_velhos"),
    ("rls-ausente", "nome_"),
    ("rls-sem-policy", "nome_novo"),
    ("policy-tautologica", "temporaria_aberta"),
    ("view-definer", "visao_velha"),
    ("definer-sem-search-path", "fn_aspas"),
    ("definer-sem-revoke", "fn_aspas"),
    ("definer-sem-revoke", "fn_multi"),
    ("rpc-fantasma", "rpc_comentada"),
    ("view-definer", "visao_segura"),
    ("rls-ausente", "cadastro_"),
    ("escrita-so-confere-autoria", "apontamentos_insert_velha"),
    ("render-inseguro", "Aviso"),
    ("segredo-hardcoded", "tarefa.functions"),
    ("privilegio-fora-do-perfil", "tarefa.functions"),
    ("filtro-cru-postgrest", "tarefa.functions"),
    ("janela-na-reaplicacao", "eh_dono"),
    ("janela-na-reaplicacao", "log_base"),
    ("janela-na-reaplicacao", "eh_staff"),
    ("rls-ausente", "cofre"),
    ("rls-ausente", "relatorios"),
    ("enum-cresceu-comparacao-negativa", "'arquivada'"),
    ("doc-cita-policy-inexistente", "middleware"),
    ("rls-ausente", "lote_"),
    ("rls-sem-policy", "lote_"),
    ("segredo-hardcoded", "Painel.test"),
    ("rota-api-sem-verificacao", "api.conta"),
    ("rota-api-sem-verificacao", "api.papel"),
    ("doc-cita-policy-inexistente", "anotacoes_texto_idx"),
    ("cascade-apaga-historico", "faturas_org"),
    ("grant-anon", "tables"),
    ("escrita-sem-with-check", "profiles_update_proprio"),
    ("escrita-sem-with-check", "comentarios_update_autor"),
    ("papel-ignora-desativacao", "tem_tarefa_aberta"),
    ("coluna-sensivel-exposta", "token_count"),
    ("cascade-apaga-historico", "avisos_horas"),
    ("oraculo-de-convite", "assinaturas_em_aberto"),
    ("escrita-so-confere-autoria", "preferencias_insert_propria"),
    ("primeiro-usuario-vira-dono", "equipe_vazia"),
    ("primeiro-usuario-vira-dono", "nenhum_cadastro"),
]

INVENTARIO_ESPERADO = {
    ("banco", "total_tabelas"): 38,
    ("banco", "total_policies"): 40,
    ("banco", "total_funcoes"): 33,
    ("banco", "total_definer"): 22,
    ("codigo", "total_server_functions"): 7,
    ("codigo", "total_rotas_api"): 5,
    ("codigo", "total_testes"): 1,
}


def falha(msg: str, erros: list[str]):
    erros.append(msg)
    print(f"  FALHOU  {msg}")


def ok(msg: str):
    print(f"  ok      {msg}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manter", action="store_true")
    args = ap.parse_args()

    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8")
        except Exception:
            pass

    if sys.version_info < (3, 11):
        print("Python 3.11+ necessário (tomllib).")
        return 1

    saida = Path(tempfile.mkdtemp(prefix="saas-audit-verificar-"))
    erros: list[str] = []
    print(f"saída temporária: {saida}\n")

    # 1. scanner
    print("[1/4] scanner.py contra exemplo/")
    r = subprocess.run([sys.executable, str(AQUI / "scanner.py"), "--perfil", str(PERFIL),
                        "--saida", str(saida)], capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        falha(f"scanner saiu com {r.returncode}:\n{r.stderr}", erros)
        return 1
    if "falhou" in (r.stderr or "").lower():
        falha(f"um detector estourou:\n{r.stderr}", erros)
    rodadas = sorted((saida / "exemplo-assinatura").glob("*-completa"))
    if not rodadas:
        falha("scanner não gravou a pasta da rodada", erros)
        return 1
    pasta = rodadas[-1]
    run = json.loads((pasta / "run.json").read_text(encoding="utf-8"))
    inv = json.loads((pasta / "inventario.json").read_text(encoding="utf-8"))
    mec = json.loads((pasta / "mecanicos.json").read_text(encoding="utf-8"))
    ok(f"artefatos gravados em {pasta.name}")

    # 2. inventário
    print("\n[2/4] inventário medido")
    for (grupo, chave), esperado in INVENTARIO_ESPERADO.items():
        real = inv.get(grupo, {}).get(chave)
        if real == esperado:
            ok(f"{grupo}.{chave} = {real}")
        else:
            falha(f"{grupo}.{chave}: esperado {esperado}, medido {real}", erros)

    # 3. detectores
    print("\n[3/4] detectores mecânicos")
    contagem: dict[str, int] = {}
    for a in mec["achados"]:
        contagem[a["regra"]] = contagem.get(a["regra"], 0) + 1
    for regra, esperado, plantado in ESPERADOS:
        real = contagem.get(regra, 0)
        if real == esperado:
            ok(f"{regra} = {real}  ({plantado})")
        else:
            falha(f"{regra}: esperado {esperado}, achou {real}  ({plantado})", erros)
    inesperadas = sorted(set(contagem) - {r for r, _, _ in ESPERADOS})
    if inesperadas:
        falha(f"regras não previstas no exemplo: {inesperadas}", erros)

    for regra, limpo in NEGATIVOS:
        acusados = [a["titulo"] for a in mec["achados"] if a["regra"] == regra and limpo in a["titulo"] + " " + str(a.get("arquivo", ""))]
        if acusados:
            falha(f"{regra} acusou o caso limpo `{limpo}`: {acusados}", erros)
        else:
            ok(f"{regra} não acusa o caso limpo `{limpo}`")

    sev_exposta = [a["severidade"] for a in mec["achados"] if a["regra"] == "definer-sem-revoke" and "fn_exposta" in a["titulo"]]
    if sev_exposta == ["alto"]:
        ok("definer com GRANT explícito sobe pra alto")
    else:
        falha(f"definer com GRANT explícito deveria ser alto, veio {sev_exposta}", erros)

    # Falso positivo específico do recorte de statement: as policies vizinhas da tautologia.
    titulos_taut = [a["titulo"] for a in mec["achados"] if a["regra"] == "policy-tautologica"]
    if any("assinaturas_select_proprio" in t or "pagamentos_select_proprio" in t for t in titulos_taut):
        falha("recorte de policy invadiu a vizinha: policy sem `true` acusada de tautologia", erros)
    else:
        ok("recorte de policy não invade a vizinha")

    # Prova de cobertura
    provas = run.get("provas_de_cobertura", [])
    if provas and all(p["ok"] for p in provas):
        ok(f"cobertura provada em {len(provas)} universos")
    else:
        falha("prova de cobertura não fechou", erros)
    ids = {l["id"] for l in run["lotes"]}
    if {"dinheiro-01", "matriz-01"} <= ids:
        ok("lotes do orquestrador (dinheiro e matriz) presentes")
    else:
        falha(f"faltou lote do orquestrador: {ids}", erros)
    if run.get("tabelas_dinheiro") == ["assinaturas", "pagamentos"]:
        ok("tabelas de dinheiro registradas no run.json")
    else:
        falha(f"tabelas_dinheiro errado: {run.get('tabelas_dinheiro')}", erros)

    # 4. painel
    print("\n[4/4] painel.py")
    r = subprocess.run([sys.executable, str(AQUI / "painel.py"), "--pasta", str(pasta)],
                       capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        falha(f"painel saiu com {r.returncode}:\n{r.stderr}", erros)
    else:
        html = (pasta / "relatorio.html").read_text(encoding="utf-8")
        n = html.count("</script>")
        if n == 1:
            ok("exatamente um </script>")
        else:
            falha(f"{n} ocorrências de </script>", erros)
        if "sk_test_51ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" in html:
            falha("valor da chave plantada apareceu inteiro no HTML", erros)
        else:
            ok("segredo do exemplo não aparece inteiro no painel")
        externas = [l for l in html.splitlines()
                    if ("https://" in l or "http://" in l) and ("<link" in l or "<script src" in l or "@import" in l)]
        if externas:
            falha(f"painel faz requisição externa: {externas[:2]}", erros)
        else:
            ok("zero requisição externa (fonte, script, css)")
        if (saida / "_achados" / "exemplo-assinatura.json").is_file():
            ok("baseline de status gravado fora da pasta da rodada")
        else:
            falha("baseline não foi gravado", erros)
        if "24 bloqueador" in r.stdout:
            ok("gate contou 24 bloqueadores (5 críticos + 19 altos: 3 definers com GRANT explícito)")
        else:
            falha(f"gate com contagem inesperada: {r.stdout.strip()}", erros)

    print()
    if args.manter:
        print(f"pasta mantida: {saida}")
    else:
        shutil.rmtree(saida, ignore_errors=True)

    if erros:
        print(f"REPROVADO: {len(erros)} falha(s).")
        return 1
    print("APROVADO: scanner, detectores, cobertura e painel funcionam nesta máquina.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
