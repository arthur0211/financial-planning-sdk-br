# ADR 0003 — Primeiro vertical local determinístico

- **Status:** aceito para implementação local; não autoriza publicação ou release
- **Data:** 9 de agosto de 2026
- **Decisor:** owner, por instrução explícita para iniciar a implementação real e mantê-la local

## Contexto

A fundação já contém contratos draft, vetores matemáticos e gates diagnósticos, mas ainda não havia um SDK/CLI executável. Implementar todo o escopo de planejamento financeiro de uma vez misturaria dinheiro, tempo, política brasileira, mortalidade, recomendação e otimização antes de validar o kernel.

O menor corte útil e julgável é um motor determinístico de fluxos e ledger. Ele permite testar dinheiro, datas civis, fatores fornecidos pelo chamador, valor presente, ordem de eventos, transferências internas e a distinção entre `price_return` e `total_return`, sem inventar curva, imposto, benefício ou adequação de produto.

## Decisão

1. A distribuição local chama-se `finplanbr`; o pacote Python é `financial_planning_sdk_br`.
2. O primeiro contrato é `0.1.0-draft.1` e aceita somente BRL, datas civis, dinheiro com duas casas, decimais em strings, fatores explícitos e eventos determinísticos.
3. SDK e CLI chamam a mesma função `compute_deterministic`.
4. `Decimal` é obrigatório. Dinheiro arredonda por `ROUND_HALF_EVEN` apenas em fronteiras monetárias declaradas; PV soma produtos exatos e arredonda uma vez na saída monetária.
5. Eventos chegam em ordem total explícita `(effective_date, sequence)`. A implementação rejeita ordenação implícita e pares duplicados.
6. Transferência gera duas postagens opostas sob um único `economic_source_id` e precisa conservar riqueza consolidada.
7. `total_return` proíbe distribuição/income separado; `price_return` mantém ganho de preço e distribuição separados no resultado.
8. O runtime não importa cliente de rede, não baixa dados e não resolve regra brasileira. Fatores são fornecidos pelo chamador e marcados como não verificados.
9. O resultado usa `computational_status=computed`, mas permanece `artifact_status=draft`, `authority=none`, `deployment_eligibility=not_authorized` e inclui warnings inseparáveis.

## Consequências

- existe uma implementação matemática real e instalável localmente;
- não existe cálculo tributário, inflação, calendário, mortalidade, necessidade, recomendação, ranking, execução ou integração de dados;
- o contrato recusa uso client-specific, recomendação e execução;
- `FPBR-C14N-1` é uma serialização restrita local, não uma alegação de RFC 8785;
- publicação, release e promoção do contrato continuam dependentes de licença, governança humana e gates externos ainda ausentes.

## Referências internas

- [Contrato do vertical](../specification/deterministic-cashflow-ledger.md)
- [Contrato matemático](../specification/mathematical-engine.md)
- [Arquitetura](../architecture.md)
- [Threat model](../security/threat-model.md)
