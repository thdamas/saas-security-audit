# Prompt — lote do DINHEIRO (as duas dimensões)

> **Este lote NÃO se delega.** O orquestrador faz no próprio contexto, porque é onde o erro
> custa direto e um resumo de subagente não serve: é preciso ter as linhas na cabeça pra
> cruzar com o resto da auditoria. Este arquivo é um roteiro, não um prompt de agente.

---

## Por que este lote existe separado

As tabelas de dinheiro saem da partição normal e viram lote próprio, auditado nas **duas** dimensões. Os bugs mais caros de um SaaS moram aqui, e quase nenhum deles é invasão. Os três padrões que mais se repetem:

- Um dos caminhos que gravam pagamento **não grava o id do pagamento no provedor**. Estorno e chargeback não acham o pagamento, a venda fica órfã, e a empresa **segue pagando comissão sobre dinheiro devolvido**. Costuma existir um caminho de escrita que ninguém lembra.
- A tela oferece **"reativar assinatura"** a um usuário de cortesia, e leva ele a um checkout real.
- O painel mostra **0 assinantes e receita zero** com pagante real na base, porque conta pelo eixo errado de estado.

## O escopo

Tudo em `[tabelas].dinheiro` do perfil, mais os caminhos que escrevem nelas, mais o webhook, mais comissão, repasse, cupom, reajuste e add-on.

## Roteiro

### 1. Autenticidade e unicidade da entrada
- O webhook verifica assinatura antes de processar? Onde, linha?
- Idempotência: o mesmo evento entregue duas vezes credita duas vezes? Qual tabela ou índice único impede?
- Replay: janela de tempo verificada?
- **Quantos segredos de webhook o código aceita?** Segredo temporário de migração que sobreviveu à migração é porta extra. Conferir se ainda deveria existir.

### 2. Consistência entre caminhos (lente B3) — a tabela que revela o furo
Montar de verdade, caminho por caminho. Achar os caminhos por **grep**, não por memória: o caminho esquecido é sempre o furado.

| Campo | webhook | cadastro | reassinatura | reconciliação |
|---|---|---|---|---|
| id do pagamento no provedor | | | | |
| data do pagamento (hora real do provedor?) | | | | |
| `insert` ou `upsert`? | | | | |

**Célula vazia é o achado.** E `upsert` ressuscita registro estornado.

### 3. Preço e plano nunca vêm do cliente
- O valor cobrado é resolvido no servidor, ou aceito do corpo da requisição?
- Cupom e desconto são validados no servidor?
- Reajuste tem trilha de quem aplicou?

### 4. Estado de acesso contra estado de pagamento (lentes B1 e B2)
- Pagamento **pendente** libera acesso? Não deveria.
- **Cancelamento remove acesso?** E na hora certa, ou só no cron?
- Quem não paga (cortesia) encontra caminho de cobrança em algum lugar? **Este é o pior achado possível deste lote.**
- Inadimplência suspende e a reativação devolve? Race condition em upgrade ou downgrade?
- Falha transitória de leitura marca alguém que está em dia como devedor?

### 5. Comissão
- A comissão é calculada sobre valor **líquido confirmado**, ou sobre a intenção de pagamento?
- Estorno e chargeback pós-repasse: existe recuperação?
- A competência usa a data real do pagamento? Divergência de mês põe dinheiro na competência errada.
- Parceiro A alcança comissão de parceiro B? (isolamento horizontal, e aqui é dinheiro além de LGPD)

### 6. Trilha
- Alteração de plano, preço, cupom e status de assinatura deixa registro de **quem** e **quando**?
- A trilha é editável por quem gerou o evento?

### 7. Contas de teste
- A flag de conta de teste é respeitada em **toda** contagem, KPI, export e cálculo de comissão? Uma conta de teste dentro de um KPI é número errado; dentro de uma comissão é dinheiro errado.

## Saída

Mesmo esquema JSON dos lotes de segurança e corretude, gravado em `lotes/dinheiro-01.json`, com `"dimensao": "ambas"` e cada achado etiquetado com sua dimensão. Achado deste lote vai pra **verificação cética igual aos outros**: ser feito pelo orquestrador não isenta de refutação, isenta de delegação.

## Idioma
- **Escreva o texto do achado em português correto, COM ACENTO.** Título e campos de prosa vão direto pro painel que uma pessoa vai ler. Identificador de código (`tipo_acesso`, `titularId`) fica como está no código; a PROSA em volta é acentuada. Texto sem acento lê como rascunho de máquina.
