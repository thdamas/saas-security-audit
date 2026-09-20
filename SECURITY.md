# Política de segurança

## Reportar uma vulnerabilidade nesta ferramenta

Se você encontrar uma falha **no saas-security-audit** (por exemplo: um caminho em que um
valor de segredo escapa para o relatório, ou em que a ferramenta escreve dentro do
repositório auditado), reporte de forma privada, por e-mail, para **contato@alquimialab.com.br**,
em vez de abrir uma issue pública.

Inclua o que conseguir: versão, sistema operacional, o comando rodado e o comportamento
observado. Respondo o mais rápido que der.

## O que esta ferramenta NÃO é

- Não é pentest. Ela é estática e passiva: não forja requisição, não sonda produção, não
  chama função direto.
- Não é certificação. Passar no gate é um veredito informado sobre o que foi examinado,
  acompanhado da lista do que não foi.
- Não substitui revisão humana de segurança nem auditoria externa independente.

## Cuidados ao usar

- **Os artefatos de uma rodada são o documento mais sensível do seu projeto.** Eles não
  podem ir para o Git, nem para um canal compartilhado sem controle.
- **HAR só de conta de teste.** Um HAR de sessão real carrega token válido e dado pessoal
  de pessoa real. Saia da conta depois de exportar.
- **Se a ferramenta apontar um segredo real no código**, trocar o arquivo de lugar não
  resolve: a chave segue no histórico do Git e precisa ser rotacionada no provedor.
