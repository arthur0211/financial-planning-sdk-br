# ADR 0002 — Valuation, identidade econômica e sobrevivência

- **Status:** aceito como contrato de especificação; requer validação atuarial humana
- **Data:** 8 de agosto de 2026
- **Origem:** correção P0 da revisão adversarial matemática

## 📋 Contexto

A primeira especificação misturava valor presente e futuro na equação de contribuição, combinava componentes sob bases de avaliação não declaradas e permitia ponderar mortalidade duas vezes. Também faltava uma identidade única para impedir que o mesmo recurso entrasse como estoque e fluxo.

## ✅ Decisão

1. Toda avaliação material usa `ValuationContext`: data, moeda, base de preços, finalidade, sobrevivência, conjunto de informação e um `valuation_operator` discriminado. Preço exige dupla medida–numéraire ou kernel de preços de estado; melhor estimativa exige medida de projeção e desconto; equivalente certo usa preferência sobre o resultado consolidado.
2. Publicar separadamente patrimônio de mercado, surplus de funding por melhor estimativa e surplus em equivalente certo.
3. Todo recurso/obrigação deriva de um DAG de `EconomicClaim`; uma fonte econômica entra uma única vez em cada medida agregada.
4. Separar as datas $t_0$ (avaliação), $r$ (aposentadoria) e $\omega$ (terminal). Contribuição, capital necessário e reserva terminal são reconciliados na mesma data $r$.
5. Tratar sobrevivência em exatamente um de dois modos: estados familiares simulados pathwise ou ponderação analítica por estado. Mistura é erro.
6. Decisões estocásticas usam `InformationSet` e são não antecipativas.
7. `ExpectedDeficit`, `ConditionalMeanDeficit` e `TailExpectedShortfall` são métricas distintas; `ES` fica reservado à cauda.
8. Anuidade atuarialmente justa é benchmark separado de reserva de auto-seguro, equivalente certo e cotação comercial.
9. Reserva planejada em $r$ usa $\mathcal I_{t_0}$; reserva replanejada em $r$ usa $\mathcal I_r$. Uma decisão tomada antes de $r$ nunca acessa a segunda.

## 🔍 Consequências

- schemas precisam carregar contexto e proveniência, não apenas números;
- equivalentes certos de componentes não são somados sem prova de aditividade;
- modelos simples ficam mais verbosos, porém dimensionalmente auditáveis;
- household states determinam renda/despesa após óbito;
- ledger e retorno devem declarar `price_return` versus `total_return`;
- comparações antigas sem contexto não são migradas silenciosamente;
- implementação só começa após casos analíticos para datas, claims, sobrevivência e não-antecipatividade.

## 🧪 Vetores bloqueadores

- contribuição com todos os termos avaliados em $r$;
- cupom/dividendo sem dupla contagem sob price e total return;
- transferência interna que conserva riqueza consolidada;
- casal em quatro estados familiares;
- pathwise versus ponderação analítica equivalentes no caso reduzido;
- árvore de dois estágios distinguindo política implementável e informação perfeita.
- contribuição planejada em $t_0$ versus replanejamento em $r$, com resultados diferentes quando chega nova informação.

## 🔗 Referências internas

- [Contrato matemático](../specification/mathematical-engine.md)
- [Risco de modelo](../../MODEL_RISK.md)
- [Parecer adversarial](../reviews/adversarial-review-2026-08-08.md)
