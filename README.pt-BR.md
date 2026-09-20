# saas-security-audit

Auditoria de segurança e corretude de um SaaS, feita por agentes de IA com cobertura provada por aritmética e verificação adversarial. Roda no [Claude Code](https://claude.com/claude-code) e entrega um painel HTML autocontido com um gate simples: **pronto pra escalar ou não?**

Read-only: acha, prova e propõe. Nunca corrige sozinho.

> **English:** [README.md](README.md).

---

## O problema que ela ataca

Todo checklist de segurança de aplicação pergunta a mesma coisa: **o que um atacante consegue fazer que não deveria?** É a pergunta certa, e essa ferramenta faz ela inteira (RLS, policies, privilégio, webhook, injeção, storage, LLM, LGPD).

Mas num SaaS pequeno existe um segundo eixo, mais provável, que nenhum checklist cobre: **o sistema faz a coisa certa com quem age de boa-fé?** Ninguém ataca, e o sistema erra sozinho.

- Nega acesso a quem tem direito, porque a guarda foi escrita assumindo que "ter direito" = "ter assinatura paga".
- Oferece um botão de pagamento a quem você convidou de graça.
- Lê uma tabela protegida com o client errado, o RLS devolve **zero linha sem erro**, e zero linha vira "está tudo certo".
- Grava o pagamento por três caminhos diferentes e um deles esquece o id do provedor, então o estorno não acha a venda.
- Promete uma data que o parceiro externo não honra, porque o código derivou o cálculo do campo errado.

Esse eixo não depende de existir alguém interessado em te atacar. Depende só de alguém ter escrito uma condição pensando no caso principal. Aqui ele se chama **dimensão B (corretude)** e tem quatro lentes próprias, em [`referencias/catalogo-corretude.md`](referencias/catalogo-corretude.md).

## O que a torna diferente de "rodar um prompt de auditoria"

| | Como costuma ser | Como é aqui |
|---|---|---|
| **Cobertura** | o agente escolhe o que olhar, e audita por amostragem sem perceber | um scanner determinístico particiona o universo em lotes com lista explícita e **prova por asserção** que a soma dos lotes é igual ao universo e a interseção é vazia |
| **Trabalho barato** | o modelo conta policy e procura `SECURITY DEFINER` | scanner Python, zero LLM, reproduzível. O agente só entra onde precisa de julgamento |
| **Validação** | o agente que achou o problema confirma o próprio problema | **céticos independentes, contexto limpo, tentando derrubar cada achado grave**, e só podem refutar citando o bloqueador com `arquivo:linha` |
| **Severidade** | tudo vira crítico | crítico exige passo de exploração concreto. Ausência de hardening nunca é crítico |
| **Honestidade** | "seu app está seguro" | a auditoria declara o que **não** viu. Sem HAR, a camada de execução fica marcada como não verificada |

## Requisitos

- **Python 3.11+** (usa `tomllib`). Nenhuma dependência externa: só biblioteca padrão.
- **Claude Code** (a skill vira o comando `/auditor`) ou **Codex** (leia `AGENTS.md`, que traz o mesmo método no formato dele). Qualquer runner com subagentes serve. O scanner e o painel rodam sozinhos, sem IA nenhuma.
- Opcional: o **MCP do Supabase** para puxar o estado real do banco (advisors, schema), e um **HAR** exportado do app rodando.

## Calibragem de stack

O motor foi calibrado em **Supabase (Postgres + RLS + PostgREST) + TypeScript + webhook de pagamento + deploy serverless**. O `padrao_servidor` do perfil cobre `tanstack-start`, `next-app`, `supabase-edge` e `api-propria`, e o template traz a receita de globs de cada um.

Em stack diferente (Rails, Django, Laravel, Go), **as duas dimensões e os catálogos continuam valendo**, mas os detectores mecânicos do scanner acham menos: eles leem migrations SQL e código TypeScript. Nesse caso a auditoria roda pelos prompts, e o scanner entra só como inventário parcial. Isso está dito aqui de propósito: é melhor você saber antes de rodar do que concluir que a ferramenta é fraca.

## Começando em 3 minutos

```bash
git clone https://github.com/thdamas/saas-security-audit.git
cd saas-security-audit

# 1. Prova que funciona nesta máquina: roda contra o app de exemplo,
#    que tem um defeito plantado pra cada detector.
python verificar.py

# 2. Roda contra o app de exemplo e abre o painel
python scanner.py --perfil exemplo/.claude/auditoria/perfil.toml --saida ./saida --print
python painel.py --pasta ./saida/exemplo-assinatura/*-completa --abrir
```

O `verificar.py` confere 19 detectores, o inventário medido, a prova de cobertura e 5 propriedades do painel. Se ele imprime `APROVADO`, a ferramenta está funcionando.

### No seu app

```bash
# 1. Rascunho dos caminhos do seu app
python scanner.py --descobrir /caminho/do/seu/app

# 2. Copie o template e preencha (é o passo que mais importa)
cp referencias/perfil.template.toml /caminho/do/seu/app/.claude/auditoria/perfil.toml

# 3. Rode o motor. A saída NUNCA vai dentro do repo auditado.
python scanner.py --perfil /caminho/do/seu/app/.claude/auditoria/perfil.toml --print
```

Depois, dentro do Claude Code, copie `SKILL.md` para `.claude/skills/auditor/SKILL.md` (junto com `prompts/` e `referencias/`) e chame `/auditor`. A skill conduz o loop de 6 fases, com portão humano entre elas.

> **O perfil é o ponto de falha mais barato e mais perigoso.** Se ele lista o papel errado ou esquece uma pasta, a auditoria roda com o mapa torto e reporta com confiança sobre o lugar errado. Leia a definição do enum no schema, não infira de ocorrência de string.

## Como funciona

```
Fase 0  Perfil          o mapa do app, aprovado por um humano
Fase 1  Ground truth    estado REAL do banco (advisors, schema, buckets, cron)
Fase 2  Mecânico        scanner.py: inventário + detecção + partição provada
Fase 3  Lote 01         portão de calibragem: 1 lote, você confere o formato
Fase 4  Fan-out         1 subagente por lote; dinheiro e matriz ficam com o orquestrador
Fase 5  Céticos         agentes diferentes tentando DERRUBAR cada crítico e alto
Fase 6  Painel          painel.py: HTML autocontido, gate "pronto pra escalar?"
```

Dois lotes nunca se delegam:

- **dinheiro**, porque é onde o erro custa direto e um resumo de subagente não serve;
- **matriz de acesso**, porque o bug mora no cruzamento entre uma guarda e um tipo de acesso, e fatiar a matriz esconde exatamente o que ela existe pra achar.

## O painel

Um arquivo HTML, **zero requisição externa** (gráficos em SVG puro, fonte de sistema), abre offline. Traz o gate de escala, distribuição por severidade nas duas dimensões, mapa de calor do schema tabela a tabela, a matriz de acesso, os achados agrupados com status editável que persiste, o plano de correção priorizado por marco de negócio, o que **não** foi verificado, e a prova de cobertura.

O status de cada achado vira baseline em disco (`<saida>/_achados/<app>.json`), então a rodada seguinte não reabre o que você já julgou.

## Segurança do próprio processo

Auditar produz o documento mais sensível que o projeto vai ter. As regras aqui são duras:

- Artefatos **nunca** dentro do repositório auditado. Padrão: `~/saas-security-audit/auditorias/`. O scanner avisa se você apontar a saída pra dentro do repo.
- **Nenhum valor de segredo** é gravado ou impresso: só tipo, arquivo e linha. O painel mascara de novo antes de escrever o HTML, como última linha de defesa.
- **HAR só da conta de teste.** HAR de sessão real carrega token válido e dado pessoal de gente real.
- O único arquivo que a auditoria escreve no app é o `perfil.toml`.

## Limites, ditos na cara

- **É análise estática e passiva.** Não forja webhook, não sonda produção, não chama função direto. Isso é pentest, é outra coisa, e exige autorização explícita.
- **Não substitui pentest externo** nem revisão humana de segurança.
- **O scanner lê migrations**, então ele vê o que foi pedido, não o que está no banco. Por isso a fase 1 existe.
- **Achado de LLM pode errar.** É por isso que existe o cético, o `arquivo:linha` obrigatório e o portão de calibragem.
- Passar no gate **não é certificado de nada**. É um veredito informado sobre o que foi olhado, com a lista do que não foi.

## Estrutura

```
scanner.py          motor determinístico (inventário, detecção, partição, HAR)
painel.py           painel HTML autocontido
verificar.py        autoteste ponta a ponta contra o app de exemplo
SKILL.md            a skill do Claude Code que conduz o loop
prompts/            lote-seguranca · lote-corretude · lote-dinheiro · cetico · leitura
referencias/        catalogo-seguranca · catalogo-corretude · perfil.template · gate
exemplo/            SaaS fictício com um defeito plantado por detector
```

## Licença e crédito

Apache-2.0. Criado por **[ALQUIM_IA.LAB](https://alquimialab.com.br)** (Thiago Menezes).

Se usar em cliente ou adaptar pra outra stack, o crédito é bem-vindo e a contribuição de volta é mais ainda: PR com detector novo, receita de outra stack ou lente de corretude que você descobriu na marra.
