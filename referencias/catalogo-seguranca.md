# Catálogo de segurança: classe de falha, severidade e o que a REFUTA

Corpo de conhecimento da dimensão A (segurança e abuso). Calibrado pra stack Supabase (Postgres + RLS + PostgREST) com framework de server functions (TanStack Start, Next.js, Edge Functions ou API própria), gateway de pagamento por webhook e deploy serverless. Em outra stack, as classes continuam valendo; muda o "como confirmar".

**A coluna que importa é a última.** Sem ela, o cético improvisa a refutação e ou aceita tudo ou nega tudo. Com ela, ele tem uma lista concreta do que procurar no código antes de confirmar um achado. Achado que não sobrevive ao bloqueador é ruído, e ruído destrói a confiança no relatório inteiro.

**Regra de severidade:** só marca `critico` ou `alto` quem tem **passo de exploração concreto**. Ausência de hardening não é crítico. Na dúvida entre dois níveis, escolhe o menor e explica no campo de confiança.

| Nível | Significa |
|---|---|
| `critico` | vazamento entre usuários, escalada a admin, bypass de pagamento, segredo exposto, perda de dado |
| `alto` | vazamento parcial, bypass de controle importante, XSS armazenado em área logada |
| `medio` | exposição parcial, falta de rate limit, header ausente, log com PII, validação fraca |
| `baixo` | hardening ausente sem exploração clara |
| `info` | observação, melhoria, ponto que exige verificação manual |

---

## 1. RLS e policies

| Classe | Sev. base | Como confirmar | O que REFUTA |
|---|---|---|---|
| Tabela sem RLS | `critico` | `alter table ... enable row level security` ausente pra tabela que existe | A tabela não guarda nada sensível **e** não tem grant pra `anon`/`authenticated` (só service_role toca). Citar o grant. |
| RLS ligado, zero policy | `medio` | tabela em `rls_habilitado` e nenhuma `create policy` | É deny-all deliberado e só service_role escreve. **Não refuta** se alguma leitura do app usa o client do usuário nessa tabela: aí a leitura devolve zero linha **sem erro** e o app pode interpretar como estado válido (ver lente B2). |
| `USING (true)` / `WITH CHECK (true)` | `alto` | tautologia na policy | O dado é público por natureza (tabela de feriado, catálogo de plano, conteúdo de marketing). Citar o que a tabela guarda, coluna por coluna. |
| Escrita sem trava | `alto` | `INSERT` sem `WITH CHECK`, ou `UPDATE`/`ALL` sem `USING` e sem `WITH CHECK`. `UPDATE`/`ALL` só com `USING` **não** é achado: o Postgres usa o `USING` como trava da linha nova (documentação do `CREATE POLICY`) | Existe trigger `BEFORE INSERT/UPDATE` que valida o dono, ou a coluna de dono tem `DEFAULT auth.uid()` e não é atualizável. Citar a migration do trigger. |
| Policy permissiva empilhada | `medio` a `alto` | 2+ policies permissivas na mesma tabela e comando | As policies são mutuamente exclusivas por construção (condições disjuntas comprovadas), ou a policy ampla é `RESTRICTIVE` (aí combina com E, não com OU). **Ler a palavra `restrictive` na migration.** |
| Policy de UPDATE deixa mudar coluna de sistema | `critico` | `WITH CHECK` não impede alterar `role`, `plano`, `owner_id`, `status`, `tipo_acesso` | Trigger `BEFORE UPDATE` barra a mudança da coluna. Citar arquivo e linha. |
| Divergência entre policy de SELECT e de UPDATE | `alto` | condição do UPDATE mais frouxa que a do SELECT | As duas derivam do mesmo helper de vínculo. Citar o helper. |
| Grant direto pra `anon` | `alto` | `grant ... to anon` | RLS na tabela restringe por `auth.uid()` e o grant é só de SELECT em dado público. Precisa das duas coisas. |

**Sobre helpers de isolamento** (as funções que decidem quem você é e de qual escopo). Auditar antes das policies, porque toda policy depende delas:
- `search_path` fixo em `SECURITY DEFINER`? Sem isso é escalada de privilégio.
- Fallback silencioso pra `NULL` ou `true` quando o dado falta?
- Confia em claim do JWT que o próprio usuário controla?
- **Filtra estado ativo?** Helper que só checa "está logado" e não "tem direito hoje" libera quem deveria estar suspenso. E o inverso também é bug: helper que exige estado que a pessoa legitimamente ainda não tem tranca quem tem direito (ver lente B1).
- Gateia por `session_user = 'postgres'`? Nunca vale.

---

## 2. Funções, RPC e views

| Classe | Sev. base | Como confirmar | O que REFUTA |
|---|---|---|---|
| `SECURITY DEFINER` sem `set search_path` | `alto` | função definer e nenhum `set search_path` no statement | Nada refuta a ausência. O que pode baixar a severidade: a função não é executável por `anon`/`authenticated` (conferir no advisor do Supabase ou nos grants). |
| View sem `security_invoker = true` | `alto` | view criada sem a cláusula (em Postgres 15+ o padrão é rodar como o dono) | A view só expõe dado público ou agregado sem granularidade que identifique alguém. |
| RPC aceita id arbitrário sem checar vínculo | `critico` | função recebe id e não confronta com `auth.uid()` nem com o vínculo | A função é definer **e** valida o vínculo internamente (citar a linha do `where`), ou só é chamável por staff (citar o grant/policy). |
| RPC chamada no app e inexistente nas migrations | `medio` | nome em `.rpc()` sem `create function` correspondente | A função foi criada por outro caminho legítimo e está no dump do banco (ground truth). Se não estiver nem no dump, é chamada morta que falha em runtime. |
| Função de escrita de dinheiro chamável fora do fluxo assinado | `critico` | função de billing executável por `authenticated` | Exige staff, ou valida assinatura de webhook internamente. |
| Trilha de auditoria editável por quem gera o evento | `alto` | policy de UPDATE/DELETE em tabela de trilha aberta ao autor | Só service_role escreve e nenhuma policy dá UPDATE/DELETE ao usuário. |

---

## 3. Privilégio e segredo

| Classe | Sev. base | Como confirmar | O que REFUTA |
|---|---|---|---|
| `service_role` alcançável pelo bundle do cliente | `critico` | arquivo que usa o client privilegiado é importado por componente de tela | O arquivo é server-only por contrato do framework (`.server.ts`, `createServerFn`, `'use server'`, route handler) **e** nenhuma cadeia de import chega no cliente. **Traçar a cadeia, não afirmar pelo nome do arquivo.** |
| Segredo literal no código | `critico` | padrão de chave real casado | É valor de exemplo, fixture de teste ou placeholder. Citar o contexto. **Se for real: trocar de lugar não resolve, a chave segue no histórico do Git e tem que ser rotacionada no provedor.** |
| Variável sensível com prefixo público (`VITE_`, `NEXT_PUBLIC_`) | `critico` | prefixo público carregando segredo | É a chave publicável (`anon` key), que pode ir pro cliente por desenho e depende do RLS. Aí o achado real é a qualidade do RLS. |
| Fallback inseguro quando env falta | `alto` | código segue com valor vazio ou pula a verificação se a env não existe | Falha fechada e ruidosa (lança, loga, retorna 500). Caso clássico: segredo de cron ausente no deploy faz a rota inteira virar no-op em silêncio. |
| Segredo em log | `medio` | token, senha, documento pessoal impressos | O log mascara na origem. Log com dado pessoal já é, por si, incidente de privacidade. |

---

## 4. Rotas, webhook e abuso

| Classe | Sev. base | Como confirmar | O que REFUTA |
|---|---|---|---|
| Webhook sem verificação de assinatura | `critico` | nenhum `constructEvent`, HMAC ou `timingSafeEqual` | A verificação existe (citar linha). Sem ela, qualquer um forja "pagamento aprovado" e libera acesso de graça. |
| Webhook sem idempotência | `alto` | nada guarda o id do evento processado | Existe tabela ou índice único de evento. Citar a migration. |
| Sem proteção de replay | `medio` | timestamp/nonce não verificados | A verificação de assinatura do provedor já inclui janela de tempo (o Stripe inclui; citar). |
| Rota pública sem rate limit | `medio`, `alto` se cara | rota alcançável sem login e sem limite | Existe limite na borda (Vercel/Cloudflare) ou lockout/throttle em tabela. Conferir se cobre a rota em questão. |
| **Rota pública que chama serviço pago** | `alto` | endpoint sem login que dispara LLM, imagem, e-mail | Exige autenticação, ou tem cota por usuário. Serverless não cai, serverless **cobra**: exaustão aqui vira fatura, não downtime. |
| Enumeração de identificador | `alto` | resposta diferente pra identificador existente e inexistente | Resposta genérica em todos os caminhos. **Documento com dígito verificador (CPF, CNPJ) é gerável em massa**, então login e checkout por documento são oráculo natural de "essa pessoa é cliente?". |
| Token público sem vínculo, expiração ou uso único | `alto` | link de descadastro, convite ou compartilhamento com token adivinhável | Token com HMAC, expiração curta e invalidação após uso. Citar a geração e a validação. |
| Cron endpoint chamável à mão | `medio` | rota de cron sem `Authorization: Bearer` com comparação segura | Compara com segredo em tempo constante. Comparação por `===` de string é aceitável na prática, mas registrar. |
| Mass assignment | `critico` | corpo da requisição gravado inteiro no banco | Allow-list explícita de campos, ou schema estrito (Zod) que rejeita campo desconhecido, ou trigger que barra coluna de sistema. |

---

## 5. Front-end e injeção nesta stack

| Classe | Sev. base | Como confirmar | O que REFUTA |
|---|---|---|---|
| `dangerouslySetInnerHTML` / `innerHTML` | `alto` | ocorrência do padrão | O conteúdo é **estático e escrito pelo time** (script inline de PWA, CSS de componente). Se vem do usuário, do banco ou da IA, é XSS armazenado e não tem refutação sem sanitizador. Citar a origem do dado. |
| Saída de LLM renderizada como HTML | `alto` | resposta do modelo entra em HTML sem sanitizar | Renderiza como texto (`textContent`) ou passa por sanitizador. |
| **Filtro cru do PostgREST** (`.or()`, `.filter()`) com input do usuário | `alto` | string de filtro montada com dado do usuário | O valor é validado por enum/allow-list antes. Isto é injeção **real** nesta stack: `.eq()` parametriza, `.or()` recebe string. |
| `eval` / `new Function` | `alto` | ocorrência | Nenhuma refutação boa em app de produto. |
| Open redirect | `medio` | destino de redirect vem de query param | Allow-list de destino. |
| Autorização só na UI | `critico` | botão escondido sem guarda no servidor | O handler revalida no servidor. Esconder no front não é proteção: DevTools existe. |
| Segredo ou PII no `localStorage` | `medio` | dado sensível persistido no navegador | É preferência de UI, não dado sensível. Cuidado com **cache de estado por aparelho**: rótulo de uma conta aparecendo em outra é bug clássico dessa família. |
| Headers ausentes (CSP, HSTS, X-Frame-Options) | `medio` | config de deploy sem os headers | Nunca é crítico sozinho. Subir CSP primeiro em `Report-Only` pra mapear violação sem quebrar a página. |

---

## 6. Storage

| Classe | Sev. base | Como confirmar | O que REFUTA |
|---|---|---|---|
| Bucket público com documento sensível | `critico` | `public = true` em bucket com documento pessoal | O bucket só tem asset de marketing. |
| URL pública onde deveria ser assinada | `alto` | `getPublicUrl` em documento privado | Usa `createSignedUrl` com TTL curto. |
| Path não escopado por dono | `critico` | caminho do objeto sem o id do dono, ou policy que não confere | Convenção `(storage.foldername(name))[1] = auth.uid()::text` mais policy que a impõe. |
| Upload sem validação real | `medio` | só valida extensão | Valida MIME de verdade, limita tamanho e restringe a lista. Atenção a SVG e HTML, que executam script. |
| Linha de metadado aponta para caminho de outro dono | `alto` | tabela de arquivo sem UNIQUE em `storage_path` e sem prefixo do dono amarrado na policy; um usuário cria linha própria apontando para o caminho de outro e herda leitura e exclusão | UNIQUE no caminho, caminho gerado pelo servidor com o prefixo do dono, e a policy de storage confere o prefixo. |

---

## 7. IA e LLM

| Classe | Sev. base | Como confirmar | O que REFUTA |
|---|---|---|---|
| Prompt injection extraindo instrução interna | `medio` a `alto` | prompt do usuário concatenado sem delimitação com a base de conhecimento | Instrução do sistema separada da entrada do usuário e o modelo instruído a não revelar. Testar com pedido de "repita suas instruções". |
| Dado de um usuário no prompt de outro | `critico` | contexto montado sem escopo por usuário | O contexto é lido com o id do usuário da sessão. |
| Saída da IA usada em decisão sensível | `alto` | resposta do modelo decide plano, permissão ou estado de cobertura | A IA só informa e a decisão vem do banco. **Nuance: em produto regulado (seguro, saúde, crédito), informar errado tem dano equivalente a permitir errado.** |
| Denial-of-wallet | `medio` a `alto` | endpoint de IA sem cota | Cota por usuário e por período. |
| PII indo pro provedor sem necessidade | `medio` | dado pessoal no prompt sem precisar | Só vai o mínimo. Registrar a retenção do provedor. |

---

## 8. Plataforma, resiliência e supply chain

| Classe | Sev. base | Como confirmar | O que REFUTA |
|---|---|---|---|
| **Sem backup automático com dado real** | `critico` se migration é manual | plano do banco não confirmado ou Free | Plano pago com PITR, ou rotina de dump externo testada. **Backup nunca restaurado não é backup, é esperança.** O par "sem backup + migration aplicada à mão em produção" é perda total sem ponto de retorno. |
| Projeto pausável por inatividade | `alto` | plano Free | Plano pago, ou tráfego/cron diário que impede a pausa. |
| Push direto na main sem gate de CI | `medio` | sem branch protection e sem workflow | Existe gate rodando por PR. **Bundler não faz typecheck: build verde não prova tipo.** Rodar sempre `tsc --noEmit` E `build`. |
| Dependência com CVE alta | `medio` a `alto` | `npm audit` | Não alcançável pelo caminho usado. Colar a saída do comando, nunca simular. |
| Script `postinstall` de pacote desconhecido | `alto` | `postinstall`/`preinstall` em dependência | Pacote conhecido e auditado. |
| Sem MFA na conta de infra | fora do escopo de código | conta de GitHub, Vercel, Supabase, Stripe, Cloudflare | Nada. **Este é o ponto único de falha real: se a conta cai, nada que a auditoria achou importa.** Vai como próximo passo, não como achado. |

---

## 9. LGPD e trilha

| Classe | Sev. base | Como confirmar | O que REFUTA |
|---|---|---|---|
| Ausência de trilha em ação administrativa | `medio` | nenhuma tabela registra quem fez o quê no admin | Existe tabela de trilha e o handler grava. **Conferir que TODA passagem grava**, não só a principal: impersonação sem registro é leitura de dado pessoal sem rastro. |
| Exclusão incompleta | `medio` | pedido de exclusão só marca flag e o dado pessoal fica | Anonimização real das colunas identificáveis. |
| Retenção indefinida | `baixo` | nenhum descarte previsto | Política declarada. |
| Coleta excessiva | `medio` | campo pessoal coletado e nunca usado | Uso demonstrável. |
| Dado pessoal atravessando escopo de tenant ou parceiro | `critico` | agregado ou lista de um tenant incluindo registro de outro | Filtro por `tenant_id` no servidor, provado no `where`. Mesma base, e só o escopo separa. |

---

## Regras duras do catálogo

- **Achado sem `arquivo:linha` não vale.** "Melhorar a validação" não é achado; "`perfil.functions.ts:58` descarta o `error` da leitura e devolve `sem_assinatura`" é.
- **Não classificar crítico por ausência de hardening.** Header faltando não é crítico.
- **Agrupar semelhantes.** 12 ocorrências do mesmo padrão no mesmo arquivo são um achado com 12 localizações.
- **Distinguir vulnerabilidade de melhoria.** As duas entram, com etiquetas diferentes.
- **Confiança obrigatória.** `confirmado` só com evidência lida. Se falta abrir algo, é `plausivel` e diz o que falta verificar. A frase "parece plausível" está banida como veredito.
- **Nada de teatro.** Sem "hackers podem destruir seu negócio". Consequência concreta neste app, ou nada.
