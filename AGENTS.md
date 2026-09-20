# AGENTS.md — como conduzir esta auditoria

> Este arquivo existe para que a auditoria funcione em **qualquer runner com subagentes**, e não
> só no Claude Code. No Claude Code ela é a skill `/auditor` (ver `SKILL.md`); aqui está o mesmo
> método, escrito como instrução de repositório.

## O que é

Auditoria de segurança e corretude de um app ou SaaS, em duas dimensões:

- **A. Segurança e abuso**: o que um atacante alcança que não deveria. Catálogo em
  `referencias/catalogo-seguranca.md`.
- **B. Corretude de negócio**: o sistema faz a coisa certa com quem age de boa-fé? Quatro lentes em
  `referencias/catalogo-corretude.md`. Esta dimensão não existe em checklist de mercado.

## Regras que não se negociam

1. **Read-only sobre o app auditado.** Nunca alterar, criar, mover ou apagar arquivo dele. A única
   escrita permitida lá é `.claude/auditoria/perfil.toml`.
2. **Nunca escrever valor de segredo** em relatório nenhum: só o tipo, o arquivo e a linha.
3. **Achado sem `arquivo:linha` não vale** e não deve ser reportado.
4. **Os artefatos nunca ficam dentro do repositório auditado.** Use `--saida` ou a variável
   `SAAS_AUDIT_SAIDA`. O scanner avisa se a saída apontar para dentro do repo.
5. **Nada de pentest ativo**: sem forjar webhook, sem sondar produção, sem chamar função direto.
6. **Portão humano entre as fases.** Não inicie a fase seguinte sem aprovação explícita.

## O loop, fase a fase

**Fase 0 · Perfil.** Se não existir `.claude/auditoria/perfil.toml` no app, gere o rascunho com
`python scanner.py --descobrir <raiz>`, preencha a partir de `referencias/perfil.template.toml` e
**mostre para um humano aprovar**. Mapa errado audita o lugar errado com confiança.

**Fase 1 · Ground truth.** Puxe o estado REAL do banco, não só as migrations: advisors de
segurança, lista de tabelas, extensões, buckets, cron. Grave cru em `ground-truth/` da pasta da
execução. Migration diz o que foi pedido; o dump diz o que é.

**Fase 2 · Mecânico.** `python scanner.py --perfil <caminho> --print`. Zero LLM. Ele produz o
inventário, os achados determinísticos e o **manifesto com a lista explícita de cada lote**,
validado por asserção (soma dos lotes igual ao universo, interseção vazia). Mostre o resumo e a
prova de cobertura **antes de gastar qualquer agente**.

**Fase 3 · Lote 01, calibragem.** Rode **um** lote e mostre o formato do achado. Se o prompt
estiver torto, o erro morre em 1 em vez de se multiplicar por 14.

**Fase 4 · Fan-out.** Um subagente por lote, em paralelo, cada um com briefing autossuficiente e
gravando **um** arquivo em `lotes/`. Use `prompts/lote-seguranca.md` e `prompts/lote-corretude.md`,
substituindo os `{{...}}`.

> ⚠️ **No Codex o fan-out é de até 6 threads por padrão.** Com mais lotes que isso, rode em ondas
> de 6 e só siga quando a onda anterior tiver gravado os arquivos. Não reduza o número de lotes
> para caber: isso quebra a prova de cobertura, que é a razão de ela existir.

**Dois lotes NÃO se delegam,** e o orquestrador faz no próprio contexto:
- **dinheiro** (`prompts/lote-dinheiro.md`): é onde o erro custa direto, e resumo de subagente não
  serve.
- **matriz de acesso**: o bug mora no cruzamento entre uma guarda e um tipo de acesso, então fatiar
  esconde exatamente o que ela existe para achar.

**Fase 5 · Céticos.** Use `prompts/cetico.md`. Vale a regra estrutural:

> 🔴 **O cético tem que ser um subagente DIFERENTE, com contexto LIMPO.** Nunca o mesmo que achou,
> e nunca com o raciocínio do achador no contexto. Se quem procura o furo é quem julga o furo, ele
> concorda consigo mesmo e a auditoria vira teatro com aparência de rigor.

Vereditos: `confirmado`, `refutado` (exige bloqueador citado com `arquivo:linha`),
`refutado (não implantado)` (o bloqueador existe no código mas não na branch que vai a produção, e
o achado **continua** contando) e `ajustado`.

**Refutar é mais difícil que confirmar**, de propósito: um achado exagerado custa dez minutos de
leitura, um achado descartado por engano custa o incidente.

**Fase 6 · Painel.** `python painel.py --pasta <...> --abrir`. Antes de entregar, rode o checklist
de `referencias/gate-auditoria.md`.

## O que roda sem agente nenhum

`scanner.py` e `painel.py` são Python 3.11+ puro, sem dependência externa. Rodam em qualquer
terminal, em qualquer sistema, sem IA envolvida. O agente entra só onde é preciso julgamento de
contexto.

Para provar que a instalação está sã: `python verificar.py`. Ele roda contra o app de exemplo em
`exemplo/`, que tem um defeito plantado para cada detector, e confere 19 detectores, o inventário
medido, a prova de cobertura e a integridade do painel.

## Ao terminar

- Declare o que **não** foi verificado. Sem HAR, a camada de execução não foi vista; sem sondagem
  ativa, o isolamento foi provado por código e não por tentativa.
- Se nada foi achado, diga o que foi verificado e o que exige teste manual. **Nunca escreva apenas
  "está seguro".**
