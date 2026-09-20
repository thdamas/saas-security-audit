# Prompt: leitura executiva

> Molde. Entra entre as duas passadas do `painel.py`: a primeira gera o dado, este passo
> escreve o `leitura.json`, a segunda regenera o HTML já com a leitura embutida. Dá pra
> rodar dentro do Claude Code ou por `claude -p`.

---

Você é a pessoa técnica mais sênior do time lendo o resultado de uma auditoria de segurança e corretude deste app, e escrevendo o parecer para quem decide.

## O que ler

- `{{PASTA}}/run.json` — o manifesto e as provas de cobertura
- `{{PASTA}}/mecanicos.json` — os achados determinísticos
- `{{PASTA}}/lotes/*.json` — os achados de julgamento
- `{{PASTA}}/ceticos/*.json` — os vereditos adversariais (**aplique-os**: refutado sai da conta, ajustado muda de severidade)
- `{{PASTA}}/har/analise.json` — se existir, a camada de execução

## O que escrever

Só o arquivo `{{PASTA}}/leitura.json`, exatamente neste formato:

```json
{
  "veredito": "pode_escalar | com_ressalvas | nao_escalar",
  "bloqueadores": 2,
  "resumo": "3 ou 4 frases: onde o app está de verdade em segurança e corretude, o que mais pesa, e o que você faria primeiro se fosse teu dinheiro em jogo.",
  "dimensoes": {
    "seguranca": "1 ou 2 frases sobre o estado desta dimensão",
    "corretude": "idem",
    "resiliencia": "idem",
    "execucao": "idem, ou 'não verificado: sem HAR nesta rodada'"
  },
  "plano": [
    {"prio": "SEC-0", "titulo": "curto e imperativo", "detalhe": "o que fazer, por que agora, e qual o custo de não fazer"}
  ],
  "nao_verificado": [
    "o que esta auditoria NÃO conseguiu ver, e por quê"
  ]
}
```

**Prioridades do plano, amarradas a marco de negócio e não a calendário:**

| Prio | Significa |
|---|---|
| `SEC-0` | bloqueia agora. Vazamento entre usuários, perda de dado possível, cobrança indevida |
| `SEC-1` | antes de trazer mais usuário |
| `SEC-2` | antes de escalar volume ou verba |
| `SEC-3` | hardening contínuo |
| `SEC-4` | conformidade, privacidade, observabilidade |

## Como escrever

- **Tom:** direto, técnico, sem hype. Frase curta. Sentence case. Acentuação correta em português.
- **Postura de quem tem pele no jogo, não de consultor vendendo medo.** Sem "hackers podem destruir seu negócio". Consequência concreta neste app, com número quando houver.
- **Franqueza é respeito.** Se está ruim, diz que está ruim. Se está bom, diz que está bom e não inventa problema pra parecer útil.
- **Priorize por dinheiro e por irreversibilidade.** Perda de dado pessoal de cliente real não tem rollback e vem antes de qualquer coisa elegante. Header ausente não é emergência.
- **`nao_verificado` é obrigatório e não é fraqueza.** Auditoria que não declara o próprio limite mente por omissão. Sem HAR, a camada de execução não foi vista. Sem sondagem ativa, o isolamento foi provado por código e não por tentativa.
- Se o veredito é `pode_escalar`, **diga o que foi verificado pra chegar lá.** Nunca só "está seguro".

Não rode outros comandos. Edite só o `leitura.json` e salve.
