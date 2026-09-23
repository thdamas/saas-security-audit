---
name: auditor
description: 'Auditor de segurança e corretude de app ou SaaS. Audita o app inteiro em duas dimensões (A: segurança e abuso, RLS, policies, privilégio, webhook, injeção, IA, LGPD; B: corretude de negócio, que pergunta se o sistema faz a coisa certa com quem age de boa-fé), com cobertura provada por aritmética, verificação adversarial de todo achado grave, e um painel HTML com gate "pronto pra escalar?". Read-only: acha e propõe, nunca corrige sozinho. Use quando a pessoa disser /auditor, "audita o app", "auditoria de segurança", "tem brecha no sistema?", "o app está seguro?", ou antes de escalar campanha, abrir cadastro público ou trazer volume de usuário.'
---

# /auditor — Auditoria de segurança e corretude

**A tese:** a indústria audita **abuso** (o que um atacante alcança). O prejuízo mais provável num SaaS pequeno vem do outro eixo, o de **corretude** (o sistema errando sozinho com quem age de boa-fé). Esta skill cobre os dois.

Instalação, requisitos e visão geral: `README.md` na raiz deste repositório.

## Quando rodar

- Antes de escalar: campanha de tráfego, cadastro aberto, volume novo de usuário, parceiro novo.
- Ao criar **caminho de acesso novo** (tipo de cliente, cortesia, papel de staff). É o gatilho que mais gera bug de corretude.
- Depois de frente grande em banco, autorização ou dinheiro.
- Em marco de negócio. **Não é rotina:** a rodada completa são vários agentes de lote mais os céticos, em modelo forte, e custa de verdade.

**PULAR em:** ajuste de layout, conteúdo, microtarefa, script pontual.

## Garantias

- **Read-only sobre o app.** Nunca altero, movo ou apago arquivo do repositório auditado. Única escrita lá: `.claude/auditoria/perfil.toml`, que é mapa e não achado.
- **Nunca corrijo sozinho, em nenhum modo.** Acho, provo e proponho.
- **Zero pentest ativo.** Sem forjar webhook, sem sondar produção, sem chamar server function direto. Isso é outra fase e exige autorização por ação.
- **Artefato fora do repositório auditado.** Em `~/saas-security-audit/auditorias/` por padrão, ou onde `--saida`/`SAAS_AUDIT_SAIDA` apontar. Relatório de vulnerabilidade dentro do repo fica a um `git add .` do GitHub errado.
- **Segredo mascarado sempre.** Só tipo e localização, valor com primeiros e últimos caracteres.

## Os três modos

| Modo | O que faz |
|---|---|
| `/auditor` | rodada completa: ground truth → mecânico → lotes A e B → dinheiro → matriz → céticos → painel |
| `/auditor leve [dimensao]` | filtro sobre o manifesto: só o mecânico + dinheiro + matriz, ou uma dimensão só |
| `/auditor corrigir <ID>` | pega UM achado aprovado e conduz o conserto com autorização por ação, terminando em teste de regressão |

## As duas dimensões

| | O que pergunta | Onde mora o método |
|---|---|---|
| **A. Segurança e abuso** | o que um atacante alcança que não deveria | `referencias/catalogo-seguranca.md` |
| **B. Corretude de negócio** | o sistema faz a coisa certa com quem age de boa-fé | `referencias/catalogo-corretude.md` |

**As 4 lentes da dimensão B:**

| Lente | A pergunta |
|---|---|
| **B1. Matriz de acesso** | quais portas essa pessoa encontra, e todas sabem que ela existe? |
| **B2. Direção da falha** | quando a leitura protegida falha ou volta vazia, cai em NEGADO ou em LIBERADO? |
| **B3. Consistência entre caminhos** | se N caminhos escrevem o mesmo dado, todos gravam os mesmos campos? |
| **B4. Âncora de regra externa** | a regra de data ou valor sai da fonte que o mundo real honra? |

Severidade da B é por **consequência**: cobra quem não devia > nega quem tem direito > promete o que não cumpre > relata número errado.

## O loop (com portão humano por fase)

**Regra dura: não inicio a fase seguinte sem ok explícito.** Ao retomar, reporto em que fase parei antes de fazer qualquer coisa. As fases aprovadas ficam em `run.json`.

**Fase 0 · Perfil.** Se o app não tem `.claude/auditoria/perfil.toml`, escrevo a partir do `referencias/perfil.template.toml` (o `--descobrir` do scanner dá o rascunho dos caminhos) e **mostro pra aprovar**. Mapa errado audita o lugar errado com confiança.

**Fase 1 · Ground truth.** Puxo o estado REAL, não só as migrations: advisors de segurança, lista de tabelas e extensões, dump de schema, buckets, cron jobs. Grava cru em `ground-truth/`. **Migration diz o que foi pedido; o dump diz o que é.** Com o MCP do Supabase, `get_advisors` já lista de graça as funções `SECURITY DEFINER` executáveis por `anon`.

**Fase 2 · Mecânico.** `python scanner.py --perfil <caminho> --print`. Zero LLM. Produz inventário, achados determinísticos e o **manifesto com a lista explícita de cada lote**, validado por asserção: soma dos lotes igual ao universo, interseção vazia. **Mostro o resumo e a prova de cobertura antes de gastar um agente.** Com o inventário na mão, escrevo o **modelo de ameaça** (seção 0 do `referencias/catalogo-seguranca.md`), que vai no topo do relatório e no briefing de cada lote.

**Fase 3 · Lote 01, o portão de calibragem.** Rodo **um** lote e mostro o formato do achado. Se o prompt estiver torto, o erro morre em 1 em vez de se multiplicar por 14.

**Fase 4 · Fan-out.** Subagentes, um por lote, cada um com briefing autossuficiente (`prompts/lote-seguranca.md` e `prompts/lote-corretude.md`) e gravando **um** arquivo em `lotes/`. Dois lotes o orquestrador faz no próprio contexto: **dinheiro** (`prompts/lote-dinheiro.md`, é onde o erro custa) e **matriz de acesso** (não se particiona, porque o bug mora no cruzamento).

**Fase 5 · Céticos.** Agentes **diferentes**, contexto limpo, tentando **derrubar** cada crítico e alto (`prompts/cetico.md`). Veredito `confirmado` / `refutado` (com bloqueador citado, `arquivo:linha`) / `refutado (não implantado)` / `ajustado`. Sem isso a auditoria é teatro: quem procura o furo concorda consigo mesmo.

**Fase 6 · Painel.** `python painel.py --pasta <...> --abrir`. Antes de entregar, rodar `referencias/gate-auditoria.md`.

## Regras duras

- **Achado sem `arquivo:linha` não vale.** "Melhorar a validação" não; "`perfil.functions.ts:58` descarta o `error` e devolve `sem_assinatura`" sim.
- **Não classificar crítico por ausência de hardening.** Header faltando não é crítico. **Enxurrada de crítico falso mata a confiança no relatório no primeiro minuto, e isso é pior que não ter relatório.**
- **Cético é agente diferente, sempre.** Nunca o mesmo que achou.
- **Refutar é mais difícil que confirmar.** Só com bloqueador citado. Falso negativo aqui custa o incidente; falso positivo custa dez minutos de leitura.
- **Confiança calibrada.** `confirmado` só com evidência lida. A frase "parece plausível" está banida como veredito.
- **Se nada foi achado, dizer o que foi verificado, as limitações e o que exige teste manual.** Nunca só "está seguro".
- **Declarar o não verificado.** Sem HAR, a camada de execução não foi vista. Sem sondagem ativa, o isolamento foi provado por código e não por tentativa. Auditoria que não declara o próprio limite mente por omissão.
- **Nada de teatro.** Sem "hackers vão destruir seu negócio". Consequência concreta neste app, com número quando houver.

## HAR: auditar o app rodando

Opcional e recomendado. Logar na **conta de teste**, percorrer o fluxo, exportar o HAR (DevTools → Network → Save all as HAR) e deixar em `har/` da pasta da execução, depois `--har <arquivo>`. O scanner parseia e responde o que código nenhum responde: **header servido de verdade**, flags reais de cookie, CORS e cache como saíram, e **resposta trazendo campo demais**.

**Regras duras do HAR:** nunca entra no Git; **só da conta de teste, nunca de cliente real** (HAR de sessão real é dado pessoal de gente real em arquivo); sair da conta depois de exportar, pra invalidar o token que ficou dentro. Sem HAR, a dimensão fica marcada como **não verificada**, nunca como aprovada.

## Fora do escopo de código (próximo passo, não achado)

Pentest externo independente · WAF · runbook de incidente · restore de backup testado · **MFA nas contas de infra** (GitHub, Vercel, Supabase, Stripe, Cloudflare). O último é o ponto único de falha real: se a conta cai, nada que a auditoria achou importa. É o mais barato de resolver.

## Saída padrão (o que aparece no chat)

```
AUDITOR · <app> · rodada completa · <data>
Veredito: NÃO ESCALAR · 11 bloqueadores em aberto

Top 3:
  1. [crít] Client privilegiado referenciado em arquivo de tela  ·  src/components/PainelAdmin.tsx
  2. [crít] Tabela `convites` sem RLS habilitado  ·  20260101000000_base.sql
  3. [alto] `marcar_inadimplente` é SECURITY DEFINER sem search_path  ·  20260102000000_funcoes.sql:18

Cobertura provada: 6 tabelas · 5 server functions · 2 rotas  (soma == universo, interseção 0)
Céticos: 12 julgados, 9 confirmados, 2 ajustados, 1 refutado
Não verificado: camada de execução (sem HAR nesta rodada) · isolamento provado por código, não por sondagem

Painel: ~/saas-security-audit/auditorias/<app>/<data>-completa/relatorio.html
```
