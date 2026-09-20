# Como contribuir

Obrigado por olhar. Três tipos de contribuição são especialmente bem-vindos.

## 1. Detector novo no scanner

Todo detector mecânico precisa de três coisas, nesta ordem:

1. **Um defeito plantado no app de exemplo** (`exemplo/`), pequeno e realista.
2. **A linha correspondente em `ESPERADOS`, no `verificar.py`**, com a contagem exata e a
   descrição do que foi plantado.
3. **O detector em `scanner.py`**, com `arquivo` e `linha` no achado e um `detalhe` que
   diz o que refuta aquilo.

`python verificar.py` tem que passar depois. Se o seu detector acusa algo que já existia
no exemplo e não estava previsto, o autoteste falha de propósito: ele reprova regra não
declarada, porque detector que dispara sem alguém ter pensado no caso é ruído.

**Nenhum detector mecânico pode classificar `critico` por ausência de hardening.** Header
faltando não é crítico. Enxurrada de crítico falso mata a confiança no relatório inteiro.

## 2. Receita para outra stack

O motor foi calibrado em Supabase + TypeScript. Se você fez rodar em Rails, Django,
Laravel, Go ou Prisma, abra um PR com:

- o bloco `[caminhos]` que funcionou, comentado em `referencias/perfil.template.toml`;
- o que o scanner **não** enxergou nessa stack, dito na cara, no README.

Saber o limite vale mais que fingir cobertura.

## 3. Lente de corretude

A dimensão B nasceu de bug real, não de teoria. Se você encontrou uma classe de erro em
que o sistema **erra sozinho com quem age de boa-fé** e que não cabe em B1 a B4, abra uma
issue contando o caso concreto: quem passou por ele, o que o sistema fez, e o que deveria
ter feito. Lente sem bug de origem não entra.

## Regras da casa que valem em qualquer PR

- Achado sem `arquivo:linha` não vale.
- Nenhum valor de segredo é gravado ou impresso, nunca: só tipo, arquivo e linha.
- O painel não pode fazer requisição externa e tem que abrir offline.
- Nada que a ferramenta escreve vai para dentro do repositório auditado, com a única
  exceção do `perfil.toml`.
- Conteúdo não pode depender de animação para aparecer no painel.

## Rodando o autoteste

```bash
python verificar.py            # tem que imprimir APROVADO
python verificar.py --manter   # mantém a pasta temporária pra inspecionar
```
