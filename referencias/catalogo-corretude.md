# Catálogo de corretude: as 4 lentes

Dimensão B da auditoria. Ela não existe em checklist de segurança de mercado, e é por isso que este projeto existe.

## Por que existe

A indústria de segurança audita **abuso**: o que um atacante consegue fazer que não deveria. Atacante age, sistema cede.

Existe um segundo eixo, o de **corretude**: o sistema faz a coisa certa com quem age de boa-fé? Ninguém ataca, e o sistema erra sozinho. Nega quem tem direito. Cobra quem foi convidado. Promete uma data que o parceiro externo não honra. Mostra zero tendo pagante na base.

Esse eixo é **mais provável** que o do abuso, porque não depende de existir alguém interessado em te atacar. Depende só de alguém ter escrito uma condição pensando no caso principal.

> **A pergunta que atravessa as 4 lentes:** o código está certo *pra quem escreveu*, ou está certo *pra todo mundo que vai passar por ele*?

## Severidade por consequência, não por explorabilidade

Aqui não existe "passo de exploração", porque não existe atacante. A régua é o dano:

| Nível | Consequência | Exemplo típico |
|---|---|---|
| `critico` | **Cobra quem não devia**, ou perde dinheiro da empresa | tela oferece "reativar assinatura" a um usuário de cortesia e leva ele a um checkout real. Um dos caminhos que gravam pagamento não grava o id do provedor, então estorno não acha a venda e a comissão segue sendo paga |
| `alto` | **Nega quem tem direito**, ou promete o que não se cumpre | cortesia barrada numa tela com "sua assinatura precisa estar ativa"; app promete uma data que o parceiro externo não honraria |
| `medio` | **Relata número errado** pra dentro de casa | painel mostrando 0 assinantes e receita zero com pagante real na base |
| `baixo` | Texto impreciso em canal interno | e-mail interno chamando cortesia de "assinante" |

**Por que "cobra" é pior que "nega":** negar acesso gera atrito e uma reclamação. Cobrar de quem você convidou de graça quebra a relação. Erro de negação se conserta com um pedido de desculpa; erro de cobrança se conserta com estorno, explicação e confiança perdida.

---

## B1. Matriz de acesso

> **A pergunta:** quais portas essa pessoa encontra, e todas elas sabem que ela existe?

**A origem da lente:** um caminho de acesso novo (cortesia, trial, parceiro, staff) é criado, e as guardas que já existiam foram escritas assumindo que "ter direito" = "ter assinatura paga". O tipo novo não tem linha na tabela de assinatura, então cada guarda que consulta aquela tabela o trata como inexistente ou como cancelado. Um caminho novo pode gerar meia dúzia de bugs em dias, todos da mesma raiz.

**Como auditar.** Montar a matriz de verdade, com o `[[tipos_de_acesso]]` do perfil nas linhas e cada guarda e cada tela nas colunas. Célula por célula:

| Símbolo | Significa |
|---|---|
| ✓ | passa, e é isso que se espera |
| ✗ | é barrada, e é isso que se espera |
| ⚠ | **é barrada e não deveria**, ou **passa e não deveria** |
| ? | não deu pra determinar sem executar; declarar como não verificado |

**Regra dura: NÃO PARTICIONAR esta lente.** O bug mora no cruzamento entre uma guarda e um tipo de acesso, então dividir a matriz em lotes esconde exatamente o que ela existe pra achar. Cada guarda, olhada sozinha, costuma estar correta. Ela é o único lote que o orquestrador faz no próprio contexto.

**Onde procurar, em ordem:**
1. Toda guarda que consulta a tabela de pagamento pra decidir direito. É o epicentro.
2. Toda tela que calcula um estado negativo por **ausência** de registro (`cancelado = !temAssinatura`). Ausência não é cancelamento.
3. Todo caminho que oferece pagamento. Oferecer cobrança a quem não paga é o pior erro da família.
4. Toda tela que diz "você não tem X" quando o certo seria "você tem X por outra via".
5. Todo recurso opcional (add-on, upgrade) que aparece disponível e morre no clique. **Oferecer e falhar é pior que não oferecer**, ainda mais pra convidado.
6. Os fluxos de conta: primeiro acesso, recuperação de senha, 2FA. Um perfil nascendo num estado inesperado trava a recuperação de senha inteira.

**Como escrever o achado.** Diz quem, em qual porta, o que vê, e o que deveria ver:
> `perfil.functions.ts:49` exige assinatura `ativa|inadimplente`. Cortesia (`tipo_acesso='cortesia'`) não tem linha em `assinaturas`, então recebe `sem_assinatura` e a tela mostra "sua assinatura precisa estar ativa". Deveria: reconhecer o direito pela via da cortesia, e usar o eixo operacional como equivalente de cancelado.

**Ao criar caminho de acesso novo, a varredura é obrigatória.** É regra de processo, não só de auditoria.

---

## B2. Direção da falha

> **A pergunta:** quando a leitura protegida falha ou volta vazia, ela cai em NEGADO ou em LIBERADO?

**A origem da lente:** uma função lê uma tabela de staff com o client **do usuário**. A tabela só tem policy pra staff, e **o RLS devolve zero linha sem erro**. Zero linha é interpretado como "sem pendência", e o app anuncia estado positivo. Em produto regulado, isso é uma afirmação falsa sobre cobertura.

**O que faz essa classe ser invisível pra auditoria comum:** o controle estava lá. O RLS habilitado, a policy correta, o checklist fecharia verde. O defeito é a **direção** em que a falha cai, e checklist de segurança não pergunta isso.

**Como auditar.** Pra cada leitura que decide direito, cobertura, estado ou valor:

1. **A leitura usa o client certo?** Ler tabela de staff com o client do usuário devolve vazio, calado, sempre.
2. **Vazio é tratado como o quê?** Se `[]` cai no ramo positivo, é falha aberta.
3. **O `error` é lido?** Nesta stack é o defeito mais comum: **`supabase-js` não lança, ele devolve `{ data, error }`**. Ignorar o `error` por convenção transforma falha de infra em dado vazio, e dado vazio em estado válido.
4. **O `catch` cai pra onde?** `catch` que devolve o estado permissivo é falha aberta com aparência de cuidado.
5. **Falha transitória rebaixa alguém?** Erro de rede que marca o cliente como inadimplente é dano em quem está pagando.

**A regra: toda leitura que decide direito é `fail-closed`.** Erro cai em negado, com mensagem honesta de "não conseguimos confirmar agora", nunca em liberado. E o inverso vale pra cobrança: falha na leitura **nunca** habilita caminho de pagamento.

**Como escrever o achado.** Cita a leitura, o client, o que acontece no vazio e onde o erro morre:
> `perfil.functions.ts:58` descarta o `error` da leitura e devolve `sem_assinatura`. Falha de infraestrutura vira "não tem assinatura", indistinguível do caso real. Padrão do arquivo inteiro, não regressão do último diff. Conserto barato: tratar o `error` antes do return.

---

## B3. Consistência entre caminhos

> **A pergunta:** se N caminhos escrevem o mesmo dado, todos gravam os mesmos campos?

**A origem da lente:** três caminhos gravam a tabela de pagamento (webhook, cadastro, reassinatura) e **um deles não grava o id do pagamento no provedor**. Consequência: estorno e chargeback não acham o pagamento, a venda fica órfã, e a empresa segue pagando comissão sobre dinheiro devolvido. Costuma haver ainda um terceiro caminho de escrita que ninguém no time lembra que existe.

**Como auditar.** O perfil declara `[[escritas_concorrentes]]`. Pra cada tabela listada:

1. Achar **todos** os caminhos que escrevem, por grep, não por memória. O caminho esquecido é sempre o furado.
2. Montar a tabela de campos: caminhos nas colunas, campos nas linhas. **A lacuna aparece como célula vazia.**
3. Conferir o campo de tempo. Grava a hora do evento real (do provedor) ou a hora local do processamento? Divergência de mês em competência de comissão é dinheiro na conta errada.
4. Conferir `insert` contra `upsert`. **Upsert ressuscita registro estornado.**
5. Conferir a existência de índice único que impeça duplicata.
6. Vale além de dinheiro: fila de notificação, log de auditoria, evento de CRM. Um caminho que insere sem empurrar a fila faz todo e-mail nascido no admin esperar o cron da madrugada.

**A regra: um caminho, uma função.** Se três lugares escrevem a mesma tabela, os três chamam a mesma função de escrita. Regra que depende de três implementações concordarem diverge com o tempo, sempre.

---

## B4. Âncora de regra externa

> **A pergunta:** a regra de data, valor ou prazo que o código aplica sai da fonte que o mundo real honra?

**A origem da lente:** um app calculava a vigência de 12 meses de um serviço a partir do aniversário da data de início da assinatura. A regra real é que a vigência conta de quando o parceiro externo emite o documento. Pra quem assinou em janeiro e acionou o serviço em julho, o app prometia uma data que o parceiro só honraria seis meses depois. **Promessa escrita na tela que o terceiro não cumpriria.**

E o agravante que vira lição: o schema **já tinha a coluna certa**, e um comentário de migration dizia que ela era a base do cálculo. Ninguém ligou os pontos, e alguém inventou um cálculo próprio porque não procurou antes.

**Como auditar.** O perfil declara `[[ancoras_externas]]`. Pra cada regra:

1. **Quem honra essa regra?** Se é um terceiro (seguradora, banco, adquirente, órgão, contrato), a fonte da verdade é o registro que **ele** reconhece, nunca um cálculo seu conveniente.
2. **O código lê essa fonte?** Ou deriva de um campo próximo que era mais fácil de alcançar?
3. **Existe coluna no schema que já responde isso?** Antes de aceitar qualquer cálculo de data, procurar a coluna. `grep` em migration e comentário.
4. **Sem a fonte, o que acontece?** O certo é recusar com honestidade ("ainda não temos o documento, então não há data a confirmar"), não estimar. **Gravar data que o terceiro não honra é pior que não gravar data.**
5. **Fuso e dia útil.** Servidor roda UTC; prazo comercial conta em dia útil no fuso local. Contar em UTC atrasa um dia útil perto do fim de semana.
6. **Onde a regra mora?** Se o mesmo cálculo aparece na tela e no handler, os dois divergem com o tempo. Uma função, um lugar.

**Sinal de alerta:** cálculo de data que usa aniversário de uma data de início quando existe uma data de fim explícita em outra tabela. Quase sempre é atalho, não regra.

---

## Como reportar um achado de corretude

Mesmo esquema da dimensão A, com dois campos diferentes:

- **`cenario_de_exploracao` vira `cenario_real`:** quem, agindo de boa-fé, encontra isso, e o que acontece com ele. Sem atacante.
- **`impacto` é a consequência de negócio**, na régua acima: cobra, nega, promete, relata errado.

E as regras que valem igual: `arquivo:linha` obrigatório, confiança calibrada, agrupar semelhantes, zero teatro.

---

## Fechar não é achar

Todo achado de corretude `critico` ou `alto` que for corrigido **nasce com teste de regressão**. A razão é medida: numa varredura típica, o único bug que não volta é o que ficou travado por teste, porque era lógica pura. Os que eram condição em guarda e em tela **podem voltar no próximo diff sem nada acusar**.

Achado corrigido sem teste é achado que volta.
