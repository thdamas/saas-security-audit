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
    ("rls-ausente", 1, "tabela `convites` sem RLS"),
    ("rls-sem-policy", 1, "tabela `logs_admin` com RLS e zero policy"),
    ("policy-tautologica", 1, "policy `planos_publicos` com using (true); as vizinhas NÃO podem ser acusadas"),
    ("escrita-sem-with-check", 1, "policy de UPDATE em `profiles` só com USING"),
    ("definer-sem-search-path", 1, "`marcar_inadimplente`; `contar_assinantes` tem search_path e NÃO entra"),
    ("search-path-mutavel", 2, "`eh_staff` e `total_pago`, não-definer sem search_path"),
    ("view-definer", 1, "view `resumo_financeiro` sem security_invoker = true"),
    ("grant-anon", 1, "grant select em `planos` para anon"),
    ("policy-empilhada", 1, "`assinaturas` com 2 policies de SELECT"),
    ("rpc-fantasma", 1, "`recalcular_saldo` chamada e nunca criada"),
    ("privilegio-no-frontend", 1, "supabaseAdmin importado em componente .tsx"),
    ("rota-api-sem-verificacao", 1, "`api.descadastrar.ts`; o webhook verifica assinatura e NÃO entra"),
    ("headers-ausentes", 1, "vercel.json com 1 de 6 headers"),
    ("segredo-hardcoded", 1, "chave de teste literal no componente"),
    ("render-inseguro", 1, "dangerouslySetInnerHTML no componente"),
    ("filtro-cru-postgrest", 1, "`.or()` com template string em perfil.functions.ts"),
    ("teste-de-seguranca-ausente", 4, "nenhum teste com rls/webhook/autoriz/isolament no nome"),
    ("backup-incerto", 1, "plano free + migration à mão"),
    ("sem-gate-de-ci", 1, "push direto na main sem CI"),
]

INVENTARIO_ESPERADO = {
    ("banco", "total_tabelas"): 6,
    ("banco", "total_policies"): 6,
    ("banco", "total_funcoes"): 4,
    ("banco", "total_definer"): 2,
    ("codigo", "total_server_functions"): 5,
    ("codigo", "total_rotas_api"): 2,
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
        if "11 bloqueador" in r.stdout:
            ok("gate contou 11 bloqueadores (4 críticos + 7 altos)")
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
