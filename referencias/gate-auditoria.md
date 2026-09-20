# Gate: checklist antes de entregar a auditoria

Rodar ao fim de uma rodada, antes de mostrar o painel para quem pediu a auditoria. Ele protege contra os dois modos de falha deste tipo de trabalho: **parecer completa sem ser**, e **relatório de vulnerabilidade escapar pro Git**.

Item que não se aplica: marcar N/A e seguir.

- [ ] **Ground truth puxado** — estado real do banco (advisors de segurança, schema, buckets, cron), gravado cru em `ground-truth/`. Migration diz o que foi pedido; o dump diz o que é.
- [ ] **Cobertura provada por aritmética** — as asserções do `scanner.py` passaram (soma dos lotes == universo, interseção vazia) e existe um arquivo em `lotes/` por lote do manifesto. Amostragem esconde.
- [ ] **Todo crítico e alto com veredito de cético** — de agente DIFERENTE, contexto limpo. Sem veredito, não entra no painel como crítico.
- [ ] **Todo `refutado` cita bloqueador com `arquivo:linha`** — refutação sem localização desliga um alarme com base em nada.
- [ ] **Refutação por código recente conferida contra a branch implantada** — correção não commitada não está em produção. O veredito vira `refutado (não implantado)` e o achado **continua** contando como bloqueador.
- [ ] **Achado sem `arquivo:linha` não vale**, e nenhum crítico nasceu de simples ausência de hardening.
- [ ] **Segredo e token mascarados** — só tipo e localização, valor com primeiros e últimos caracteres.
- [ ] **HAR, se usado** — da conta de teste, nunca de cliente real; fora do Git; sessão encerrada depois de exportar, pra invalidar o token que ficou dentro.
- [ ] **Nada vazou** — `git status` no repositório do app. O único arquivo novo permitido lá é `.claude/auditoria/perfil.toml`. Nenhum artefato da auditoria dentro do repo.
- [ ] **Baseline consultado** — `<saida>/_achados/<app>.json` foi lido antes de reabrir achado já julgado como Aceito ou Falso-positivo.
- [ ] **Painel: prova técnica** — exatamente um `</script>` no arquivo, zero requisição externa, status persiste ao recarregar, nenhum token aparece inteiro. O `verificar.py` checa os quatro.
- [ ] **Painel: prova visual** — abrir de verdade e rolar. Nenhuma seção pode depender de animação pra aparecer, e nenhuma pode sair vazia.
- [ ] **Portão humano registrado** — as fases aprovadas estão em `run.json`, e nenhuma fase foi iniciada sem ok.
- [ ] **Limitações declaradas** — o que esta rodada NÃO viu está escrito no painel. Se nada foi achado, dizer o que foi verificado e o que exige teste manual. **Nunca só "está seguro".**
