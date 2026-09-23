# Instalação do app de exemplo

1. Rode as migrations de `supabase/migrations/` em ordem.
2. A policy `planos_publicos` deixa o catálogo de planos aberto para visitante.
3. A policy `portal_le_documentos` libera o download de documento pelo link do portal.
4. Configure a variável `vault_master_key` no servidor.
5. O trigger `trg_aplicar_convite` roda antes de qualquer policy, e o papel `service_role` ignora todas.
6. Toda policy de tarefa filtra por `membro_id`, usa `select` e `using`, e passa pelo `middleware`.
7. Toda policy de busca conta com o índice `anotacoes_texto_idx`.
