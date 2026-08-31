# Contrato do motor matemático

_Especificação proposta · Financial Planning SDK Brasil · 8 de agosto de 2026_

---

## 📋 Status, finalidade e não objetivos

Este documento define a semântica matemática que uma implementação futura deve obedecer. Ele não contém código executável e não autoriza resultados para uso pessoal, atuarial, tributário ou regulatório.

O motor deve responder três perguntas separadas:

1. **Estado:** quais são recursos, obrigações, riscos e lacunas do domicílio?
2. **Projeção:** como resultados evoluem sob alternativas e incerteza?
3. **Comparação:** quais trade-offs aparecem entre alternativas fornecidas?

O núcleo não responde “o que esta pessoa deve comprar”. Prescrição exige política, habilitação, suitability e governança externas.

### Princípios normativos

- Nenhuma unidade implícita
- Nenhuma regra brasileira sem fonte e vigência
- Nenhum valor desconhecido convertido para zero
- Nenhuma simulação sem `RandomSpec`, identidade do gerador e classe de reprodutibilidade
- Nenhuma solução de solver chamada de ótima sem status e tolerância
- Nenhuma probabilidade apresentada sem população, horizonte e condicionamento
- Nenhuma dupla contagem entre capital humano, benefício, conta e fluxo
- Nenhuma mistura silenciosa entre valores reais e nominais
- Nenhum arredondamento binário usado como regra monetária

### Estados de computação

Todo motor retorna um destes estados:

| Estado | Significado | Ação do consumidor |
| --- | --- | --- |
| `computed` | cálculo terminou e passou pelos gates declarados | pode interpretar somente dentro do escopo aprovado |
| `computed_with_warnings` | cálculo terminou com limitações não fatais | exibir avisos antes das métricas |
| `indeterminate` | informação, autoridade ou identificação necessária não está disponível | coletar dado, obter revisão ou escolher cenário explícito |
| `rejected` | contradição, unidade incompatível, política expirada ou falha numérica | não usar resultado |

`indeterminate`, `null`, zero e `not_applicable` são valores semanticamente distintos. O estado de computação não afirma que o modelo é verdadeiro, que o plano é adequado nem que o uso é juridicamente permitido. O `ResultBundle` registra separadamente `computational_status`, `model_validity`, `policy_authority_status` e `deployment_eligibility`.

## ⚙️ Unidades, tipos e domínios numéricos

### Dinheiro

Uma grandeza monetária é a tupla:

$$
M = (v, c, b, d, i)
$$

onde $v$ é o valor decimal, $c$ a moeda, $b$ a base de preços (`nominal` ou `real`), $d$ a data-base e $i$ o indexador quando necessário.

Operações permitidas:

- soma/subtração somente quando moeda, base de preços e data-base são compatíveis ou convertidas explicitamente;
- multiplicação/divisão por escalar adimensional;
- conversão por uma função registrada que retorna também a fonte;
- quantização apenas na fronteira contratual, não a cada operação intermediária.

O domínio contábil usa `Decimal` ou centavos inteiros. A política de arredondamento deve ser parâmetro nomeado, por exemplo `ROUND_HALF_EVEN` ou a regra contratual aplicável. O motor não usa `round()` binário para imposto, saldo ou pagamento.

### Tempo

Um intervalo financeiro exige:

- `start_date` e `end_date`;
- calendário;
- convenção de contagem;
- regra de ajuste de dia útil;
- inclusão/exclusão das extremidades;
- timezone apenas para eventos intradiários, nunca inferida de uma data civil.

Convenções iniciais:

- `ACT/365F`;
- `ACT/360`;
- `ACT/ACT` com variante identificada;
- `30/360` com variante identificada;
- `BUS/252` com calendário versionado.

`BUS/252` não é simplesmente dias corridos divididos por 252. O número de dias úteis depende do snapshot do calendário.

Convenção temporal normativa: $t_0$, $r$, $\omega$ e $d_k$ são datas civis; $\Delta(t,d)$ é uma duração segundo uma day-count declarada; $\tau_x$ é vida futura em year-fractions desde a data de observação; $\mathcal D_x$ é uma data civil aleatória de óbito. O símbolo isolado $T$ não é usado como horizonte ou tempo de morte no contrato normativo.

### Taxas

Uma taxa é:

```text
Rate(
  value,
  quote_basis,
  compounding,
  frequency,
  day_count,
  price_basis,
  indexer
)
```

O fator de acumulação é a primitiva. Para fração de ano $\tau$:

$$
A(r,\tau)=
\begin{cases}
1+r\tau, & \text{simples} \\
(1+r/m)^{m\tau}, & \text{nominal com frequência }m \\
(1+r)^\tau, & \text{efetiva anual} \\
e^{r\tau}, & \text{contínua}
\end{cases}
$$

Conversão de taxa preserva o fator no mesmo intervalo:

$$
A(r_1,\tau)=A(r_2,\tau)
$$

A relação exata de Fisher, quando as grandezas usam o mesmo horizonte, é:

$$
1+r_n=(1+r_r)(1+\pi)
$$

Usar $r_n\approx r_r+\pi$ só é permitido quando a aproximação é explicitamente solicitada.

`RateQuote`, `DiscountFactor`, `IndexObservation` e `TaxTreatment` são tipos distintos. Tributação pertence ao fluxo, lote, conta ou policy pack; ela não é uma propriedade genérica de toda taxa. O contrato declara o domínio de taxas negativas, rejeita fatores não positivos quando uma potência fracionária não for real e registra o contexto decimal, a precisão intermediária e o expoente monetário aplicável.

### Domínios de cálculo

| Domínio | Tipo preferido | Motivo |
| --- | --- | --- |
| ledger, imposto, pagamentos | decimal/inteiro | reconciliação e regra contratual |
| fatores e curvas | `float64` ou decimal selecionado | desempenho e estabilidade controlada |
| álgebra linear | `float64` | suporte numérico e solvers |
| Monte Carlo | arrays `float64` | vetorização e análise estatística |
| serialização | string decimal e metadados | evitar perda no JSON |

Conversões entram no manifesto e testes verificam erro máximo. A saída monetária estocástica é quantizada depois da agregação, nunca dentro de cada passo sem razão econômica.

## 📊 Fluxos, curvas e balanço econômico

### Fluxos de caixa

Um fluxo contém:

```text
CashFlow(
  amount,
  event_date,
  owner,
  kind,
  certainty,
  priority,
  tax_treatment,
  indexation,
  claim_id
)
```

`claim_id` é chave estrangeira obrigatória para exatamente um `EconomicClaim`; `economic_source_id` existe somente no claim e identifica a fonte econômica comum. `certainty` distingue garantido, contratual, condicional e estocástico. `priority` distingue essencial, desejado e discricionário. O motor rejeita dois fluxos ligados ao mesmo claim e competência quando isso indica dupla importação.

### Curvas de desconto

Uma curva fornece $D(t,d)>0$, o fator de desconto entre a data de avaliação $t$ e uma data civil futura $d$. O valor presente determinístico é:

$$
PV_t=\sum_i C_{d_i}D(t,d_i)
$$

Requisitos:

- interpolar em uma grandeza declarada: desconto, zero, forward ou log-desconto;
- proibir extrapolação silenciosa;
- informar nós, método e domínio;
- preservar positividade de fatores;
- testar consistência entre taxa zero, forward e desconto;
- não assumir desconto monotônico em ambientes de taxa negativa;
- separar curva de marcação, curva de funding e desconto ajustado a risco.

Uma curva real desconta fluxos reais; uma curva nominal desconta fluxos nominais. Indexar fluxo e também usar taxa real sem transformação coerente é dupla correção de inflação.

### Valor presente líquido e TIR

$$
NPV(r)=\sum_i \frac{C_i}{A(r,\tau_i)}
$$

A TIR só é reportada se:

- convenção e calendário forem identificados;
- o algoritmo encontrou raiz no domínio permitido;
- o número de mudanças de sinal for registrado;
- múltiplas raízes ou ausência de raiz forem sinalizadas.

Para decisões de planejamento, NPV e curvas são primários; TIR não deve esconder magnitude, horizonte ou reinvestimento.

### Balanço econômico

Nenhuma identidade econômica pode somar componentes produzidos sob medidas, moedas ou datas incompatíveis. Toda avaliação recebe:

```text
ValuationContext(
  valuation_date,
  base_currency,
  unit_of_account,
  price_basis,
  price_index_id,
  price_base_date,
  valuation_operator,
  purpose,
  survival_treatment,
  information_set_id
)
```

`valuation_operator` é uma união discriminada, nunca uma medida solta combinada informalmente com uma curva:

```text
MarketConsistent(pricing_measure_id, numeraire_id)
StatePrice(reference_measure_id, pricing_kernel_id)
BestEstimate(projection_measure_id, discount_rule_id)
CertaintyEquivalent(projection_measure_id, preference_functional_id, numeraire_or_discount_rule_id)
```

`MarketConsistent` exige a dupla coerente medida–numéraire; `StatePrice` exige um kernel/deflator de preços de estado relativo à medida de referência. `BestEstimate` é uma projeção descontada declarada e não vira preço por receber uma curva. `CertaintyEquivalent` aplica a preferência ao resultado consolidado e não autoriza somar equivalentes certos de componentes, salvo prova de aditividade. Identificadores carregam versão, data-base e domínio de validade.

Para um payoff $X_d$ e exatamente uma representação de preço coerente:

$$
V_t(X_d)=N_t\,\mathbb E^{Q^N}\!\left[\frac{X_d}{N_d}\middle|\mathcal F_t\right]
=\mathbb E^P[M_{t,d}X_d\mid\mathcal F_t]
$$

`unit_of_account`, moeda, índice/base de preços e ativo numéraire são dimensões distintas. O schema rejeita representação incompleta, duas representações simultâneas ou combinação de risco já simulado com um ajuste de desconto que penalize a mesma fonte sem reconciliação explícita.

O projeto publica três objetos diferentes, nunca um único “patrimônio verdadeiro”. Componente sem base de avaliação na medida escolhida é `not_applicable` ou torna a saída `indeterminate`; nunca vira zero:

- `market_net_worth` — ativos e passivos com preço ou valor de liquidação observável na data;
- `best_estimate_funding_surplus` — valor esperado de recursos menos obrigações sob uma medida de projeção declarada;
- `certainty_equivalent_funding_surplus` — equivalente certo sob preferências e modelo de utilidade explicitamente validados.

Dentro de um mesmo `ValuationContext` **linear e aditivo**, a decomposição de funding é:

$$
N_t^{(v)}=F_t^{(v)}+H_t^{(v)}+S_t^{(v)}-L_t^{(v)}
$$

O equivalente certo é calculado sobre a distribuição consolidada de consumo e riqueza. Ele não usa a identidade acima componente a componente, a menos que o funcional de preferência tenha uma propriedade de separabilidade demonstrada e registrada.

onde:

- $F_t^{(v)}$: ativos financeiros líquidos de custos de liquidação e tributos modelados;
- $H_t^{(v)}$: capital humano;
- $S_t^{(v)}$: benefícios, pensões e recursos futuros não incluídos em $H_t^{(v)}$;
- $L_t^{(v)}$: passivos, consumo essencial e metas comprometidas.

O sobrescrito $(v)$ identifica a convenção de avaliação. O sistema mantém reconciliação por componente; a fórmula é uma decomposição, não autorização para misturar valor de mercado de $F$, valor esperado de $H$ e equivalente certo de $L$. Um benefício futuro não pode aparecer simultaneamente em $S_t$ e em uma conta financeira.

### Identidade econômica e prevenção de dupla contagem

Todo estoque ou fluxo material deriva de um `EconomicClaim`:

```text
EconomicClaim(
  economic_source_id,
  claim_id,
  account_id,
  flow_origin,
  stock_or_flow,
  gross_or_net,
  included_in_valuation_component,
  parent_claim_ids
)
```

Os claims formam um grafo acíclico. Cada claim externo gerador de valor pode entrar uma única vez em uma medida agregada. Transferências internas são um débito e um crédito com o mesmo `economic_source_id` e contribuição consolidada zero; cupons e dividendos só são eventos separados quando o retorno usado é `price_return`, nunca quando já estiverem embutidos em `total_return`. Validação rejeita ciclos, inclusão múltipla e identidade estoque-fluxo não reconciliada.

### Família de funded ratios

Para recursos $PV_R$ e obrigações $PV_L$ avaliados no mesmo contexto linear, três famílias não intercambiáveis são:

$$
FR_{ratio\_of\_EPVs}=\frac{\mathbb E[PV_R]}{\mathbb E[PV_L]}
$$

$$
FR_{expected\_pathwise}=\mathbb E\!\left[\frac{PV_R}{PV_L}\middle|PV_L>0\right]
$$

$$
FP=P(PV_R\geq PV_L)
$$

O primeiro é razão de esperanças, o segundo é esperança de uma razão condicional e o terceiro é probabilidade de funding. Nenhuma saída pública usa o nome isolado `funded_ratio`. O identificador completo inclui classe de obrigação, convenção de avaliação $(v)$ e regra de alocação $(a)$. Quando $PV_L=0$, a razão aplicável é `not_applicable`; o contrato também informa a massa $P(PV_L=0)$. O numerador respeita prioridade e impede que o mesmo ativo seja integralmente alocado a duas metas.

## 👤 Pessoas, mortalidade e capital humano

### Linha do tempo individual

Idade é calculada a partir de datas, não como inteiro incrementado por ano. O domínio distingue:

- idade exata;
- idade atuarial;
- competência mensal/anual;
- aposentadoria pretendida;
- elegibilidade legal;
- horizonte máximo do modelo.

O model card declara a convenção subanual: `UDD`, força de mortalidade constante ou interpolação publicada; a regra para 29 de fevereiro; a competência de transição; e se morte no período ocorre antes ou depois de renda, consumo, prêmio e benefício. Datas civis prevalecem sobre arredondamento de idade.

### Tábua de mortalidade

Para idade exata $x$, seja $\tau_x$ a vida futura aleatória, medida como duração a partir da data em que a pessoa está viva em $x$:

- $q_x=P(0<\tau_x\leq1\mid alive\ at\ x)$;
- $p_x=1-q_x$;
- ${}_np_x=\prod_{j=0}^{n-1}p_{x+j}$.

Invariantes:

- $0\leq q_x,p_x\leq1$;
- ${}_0p_x=1$;
- sobrevivência não aumenta com o horizonte;
- probabilidade de morte e sobrevivência reconciliam;
- idade fora da tábua exige regra terminal explícita.

A importação do IBGE preserva ano-base, sexo/categoria publicada, transformação de intervalos, fonte e checksum.[^1]

### Sobrevivência conjunta

Sob independência condicional dado o processo de covariáveis compartilhadas $Z_t$ e a informação inicial:

$$
P(A_t\cap B_t\mid Z_t,\mathcal I_{t_0})
=S_a(t\mid Z_t,\mathcal I_{t_0})S_b(t\mid Z_t,\mathcal I_{t_0})
$$

$$
P(A_t\cup B_t\mid Z_t,\mathcal I_{t_0})
=1-[1-S_a(t\mid Z_t,\mathcal I_{t_0})][1-S_b(t\mid Z_t,\mathcal I_{t_0})]
$$

A probabilidade incondicional integra essas expressões sobre $Z_t$; em geral, $E[S_aS_b]\neq E[S_a]E[S_b]$. Independência é uma hipótese condicional ao conjunto de covariáveis e à informação observada, não um fato. Seleção conjugal, ambiente, epidemias e choques comuns podem invalidá-la; o model card mede ou limita essa transferência. O domicílio usa estados explícitos `both_alive`, `only_a_alive`, `only_b_alive` e `none_alive`. Toda renda, despesa e reversão declara a regra em cada estado e a ordem de eventos após o primeiro e o segundo óbito.

### Melhora de mortalidade

Uma tábua de período não representa automaticamente a mortalidade futura da coorte. O motor suporta:

- `PeriodTable` — taxas observadas/projetadas em um período;
- `CohortTable` — taxas por idade e ano de nascimento;
- `ImprovementScale` — transformação versionada;
- `StochasticMortalityModel` — somente no módulo avançado.

Para idade alcançada $x+t$ no ano-calendário $y+t$, uma projeção de coorte usa a célula correspondente $(x+t,y+t)$, com tratamento subanual documentado; ela não reaproveita a coluna do ano-base como se fosse coorte. Modelos Lee-Carter e Cairns-Blake-Dowd são referências de benchmark, não padrões automáticos.[^2][^3]

### Estados de emprego e renda

O capital humano usa estados conjuntos $z_d$, por exemplo empregado, autônomo, desempregado, incapaz, aposentado e morto. Para métodos de avaliação lineares, uma forma pathwise geral entre a data $t_0$ e a última data elegível de renda $r_Y$ é:

$$
H_{t_0}^{(v)}=\mathbb{E}_{P}\!\left[
\sum_{d\in\mathcal D_Y(t_0,r_Y)}
\mathbf{1}_{alive,d}\,Y_d^{net}(z_d)M_{t_0,d}^{(v)}
\;\middle|\;\mathcal I_{t_0}\right]
$$

$M_{t_0,d}^{(v)}$ é o multiplicador definido pelo `valuation_operator`: fator determinístico no caso de melhor estimativa ou kernel coerente no caso de preço de estado. Sobrevivência, participação, renda e multiplicador permanecem dentro da mesma esperança; fatorar como $p_{t_0,d}\,E[Y_d]v_Y(t_0,d)$ só é válido sob hipóteses condicionais demonstradas e quando nenhum termo já contém sobrevivência. Um desconto ajustado a risco e uma simulação conjunta não podem penalizar a mesma fonte de risco duas vezes. Equivalente certo é aplicado à distribuição consolidada, não obtido por substituição informal de $M$.

Parâmetros mínimos:

- crescimento real/nominal por estado;
- volatilidade e persistência;
- probabilidade/duração de desemprego;
- correlação com mercado, inflação e setor;
- participação laboral e aposentadoria;
- tributos/contribuições de escopo declarado;
- benefício de incapacidade e seguro quando modelados.

O trabalho de Viceira e modelos de ciclo de vida sustentam o tratamento da renda como ativo não negociável arriscado.[^4][^5]

### Reserva de emergência

O motor calcula uma distribuição de necessidade de liquidez sob choques, mas mantém uma regra simples em paralelo. Métricas:

- meses de despesa essencial cobertos;
- probabilidade de iliquidez antes da recuperação;
- valor esperado de venda forçada;
- tempo de acesso ponderado por ativo;
- custo de oportunidade separado do risco de falta.

O resultado é faixa e sensibilidade, não um número sem contexto.

## 🎯 Necessidades, metas, seguros e previdência

### Camadas de consumo

Para período $s$:

$$
C_s=C_s^{essential}+C_s^{target}+C_s^{discretionary}
$$

As camadas têm penalidades e flexibilidade distintas. `essential` não significa imutável: o usuário pode definir contingências, mas o motor nunca reduz piso silenciosamente para tornar um plano “viável”.

### Gap de renda

$$
G_s^{essential}=\max(0,C_s^{essential}-I_s^{secure})
$$

$$
G_s^{target,total}=\max(0,C_s^{essential}+C_s^{target}-I_s^{all})
$$

`secure` e `all` são classificações declaradas. `G_s^{essential}` e `G_s^{target,total}` são visões alternativas e não podem ser somadas. Quando se deseja uma decomposição aditiva, a camada incremental é $G_s^{target,incr}=\max(0,G_s^{target,total}-G_s^{essential})$. Benefício estimado do INSS pode ter haircut ou cenário, mas não ser chamado de garantido sem base.

Sejam $t_0$ a data de avaliação, $r$ a data de aposentadoria e $\omega$ o horizonte terminal, com datas de pagamento $d_k\in(r,\omega]$. Para estados familiares ativos $h$, a reserva **planejada hoje**, expressa monetariamente em $r$ mas usando somente a informação disponível em $t_0$, é:

$$
K_{r\mid t_0}^{plan}=\sum_{d_k\in(r,\omega]}v^{[t_0]}(r,d_k)
\sum_{h\in\mathcal H_{active}}P(H_{d_k}=h\mid\mathcal I_{t_0})G_k^{[t_0]}(h)
$$

Ao chegar a $r$, o motor pode calcular separadamente a reserva replanejada:

$$
K_{r\mid r}^{replan}=\sum_{d_k\in(r,\omega]}v^{[r]}(r,d_k)
\sum_{h\in\mathcal H_{active}}P(H_{d_k}=h\mid\mathcal I_r)G_k^{[r]}(h)
$$

Esses dois objetos não são intercambiáveis: $K_{r\mid t_0}^{plan}$ alimenta uma decisão tomada em $t_0$; $K_{r\mid r}^{replan}$ incorpora apenas informação observada até $r$ e serve à revisão. A diferença recebe atribuição de mudança de premissas, estado e política. Ambos são valores presentes atuariais esperados, não preço de mercado, equivalente certo, custo de auto-seguro em quantil nem prêmio de anuidade. Para casal, $G_k(h)$ aplica a regra de despesa e renda de cada estado familiar.

### Contribuição para funding EPV de melhor estimativa

Para uma agenda de contribuições $a_k$ decidida em $t_0$, em datas $d_k\in(t_0,r]$, e acumulação determinística $A$ parametrizada apenas por $\mathcal I_{t_0}$, todos os termos são trazidos à data $r$:

$$
\widetilde F_r=F_{t_0}A(t_0,r)+\sum_{d_k\in(t_0,r]}a_kA(d_k,r)
$$

$$
Surplus_{r\mid t_0}^{plan}=\widetilde F_r-K_{r\mid t_0}^{plan}-v^{[t_0]}(r,\omega)B_{\omega\mid t_0}^{plan}
$$

O solver encontra uma contribuição constante ou agenda paramétrica que satisfaz $Surplus_{r\mid t_0}^{plan}=0$ dentro da tolerância, com limites de renda e liquidez. Uma contribuição adaptativa é uma política $a_k=\pi_k(\mathcal I_{d_k})$ e exige árvore/cenários com não-antecipatividade; ela nunca pode observar $\mathcal I_r$ antes de $r$. $B_{\omega\mid t_0}^{plan}$ é a reserva terminal planejada na data $\omega$; nunca se subtrai um valor presente em uma equação de valor futuro. Invariantes:

Os nomes normativos são `best_estimate_epv_capital` e `required_contribution_for_best_estimate_epv_funding`. Objetos `self_insurance_reserve_q`, `chance_constrained_capital`, `certainty_equivalent_capital` e `annuity_premium` têm objetivos, premissas e model cards próprios; nenhum é alias desta equação.

- maior contribuição não reduz funding quando todos os demais inputs permanecem iguais;
- adiar aposentadoria não deve piorar capital necessário em caso básico sem efeitos adversos;
- aumentar piso não reduz gap;
- adicionar renda segura não aumenta gap;
- custos e tributos não melhoram resultado líquido.

Quebras legítimas de monotonicidade precisam de explicação, por exemplo perda de benefício ao ultrapassar limiar.

### Metas

Uma meta é:

```text
Goal(
  id,
  amount_distribution,
  date_window,
  priority,
  essentiality,
  indexation,
  currency,
  financing_allowed,
  partial_funding_rule,
  failure_consequence
)
```

Alocação entre metas pode ser:

- lexicográfica por prioridade;
- otimização de penalidade ponderada;
- fronteira de Pareto.

Pesos arbitrários nunca ficam ocultos. O modo padrão recomendado é lexicográfico: piso vital, obrigações legais, metas essenciais, metas desejadas e aspiração.

### Seguro de vida e incapacidade

Para evento $e$:

$$
Gap_e=\max\left(0,PV(L_e)-PV(R_e)-Coverage_e^{existing}\right)
$$

Cada cenário define `event_date`, estado imediatamente anterior, ordem de liquidação, estado familiar posterior e data-base do PV. `L_e` inclui despesas, dívidas, dependentes, educação e transição; `R_e` inclui ativos líquidos, benefícios e renda sobrevivente. `Coverage_e^{existing}` aparece uma única vez e contém prazo de pagamento, carência, tributação e probabilidade de elegibilidade quando modelados. O motor relata necessidade econômica. Prêmio, aceitação, subscrição, exclusão e qualidade do produto ficam fora.

### Anuidades e pooling de longevidade

Uma renda vitalícia atuarialmente justa é benchmark obrigatório de desacumulação, ainda que nenhum produto seja recomendado. Para uma vida com idade exata $x$ em $t_0$ e pagamentos unitários postecipados em $d_k>t_0$:

$$
a_x^{(v)}(t_0)=\sum_{d_k>t_0}v(t_0,d_k)\,
P\!\left(\tau_x>\Delta(t_0,d_k)\mid\mathcal I_{t_0}\right)
$$

$\Delta(t_0,d_k)$ é a duração, na convenção declarada, entre duas datas civis; ela é comparada com a vida futura $\tau_x$, nunca com a própria data. A forma fatorada pressupõe desconto determinístico ou independência condicional suficiente. Com taxa e mortalidade estocásticas dependentes, usa-se a esperança conjunta do kernel de avaliação e do indicador de sobrevivência. Versões temporária, diferida, antecipada, conjunta e reversível usam calendários, estados familiares e ordem de morte explícitos. `actuarial_fair_value`, `self_insurance_reserve`, `certainty_equivalent_value` e `market_quote` são objetos distintos. Uma cotação comercial pode conter despesas, margem, seleção, garantia, crédito e regras SUSEP; não é inferida pela fórmula atuarial. Até esse benchmark e sua revisão atuarial existirem, o escopo não pode alegar cobertura completa de longevidade.

### Moradia, saúde e flexibilidade laboral

Moradia própria pode ser simultaneamente ativo ilíquido, serviço de consumo e fonte de custo; seu valor não pode entrar em $F_t$ e reduzir $L_t$ sem uma reconciliação do mesmo `EconomicClaim`. Saúde e cuidado de longa duração entram como processos de despesa/estado separados de mortalidade. Aposentadoria, horas de trabalho e renda podem ser decisões endógenas em modelos avançados; no núcleo determinístico são cenários fornecidos, não escolhas “ótimas” implícitas. Ausência desses módulos deve aparecer como limite do model card, nunca como risco zero.

### Previdência por lotes

Cada aporte de previdência é um lote:

```text
PensionLot(
  contribution_date,
  principal,
  units,
  tax_regime,
  holding_period_rule,
  fees,
  source_policy
)
```

Resgate consome lotes segundo a regra aplicável. A escolha tributária e sua data são eventos, não propriedades eternas da conta. PGBL e VGBL usam bases tributáveis diferentes no escopo descrito pela autoridade.[^6] Localização e retirada com lotes discretos, mínimos, ordem fiscal ou escolhas irreversíveis podem formar um problema inteiro misto; uma relaxação contínua deve ser identificada como aproximação e reconciliada contra enumeração em casos pequenos.

### RGPS

`br.inss` separa:

- histórico contributivo observado;
- regra legal versionada;
- cenário de salário/contribuição futuro;
- elegibilidade estimada;
- valor estimado;
- incerteza por dados faltantes.

Se faltar histórico necessário, a saída é `indeterminate` com lista de campos. Exemplos e simulador oficiais são referências auxiliares de teste, não substitutos do corpus normativo; o próprio INSS declara que a simulação não garante o direito.[^7] Casos fora do escopo aprovado — inclusive transições, atividade especial, rural, professor, deficiência, contribuições concomitantes ou CNIS insuficiente — falham fechados com reason code.

## 🔄 Acumulação, desacumulação e cenários

### Estado de conta

Para conta $j$ no intervalo $(t,t+1]$, o estado é produzido por uma sequência ordenada de eventos:

$$
W_{j,t+1}=W_{j,t}+\sum_{e\in\mathcal E_{j,(t,t+1]}}\Delta W_e
$$

Cada conta referencia um contrato tipado:

```text
AccountConvention(
  return_basis,
  income_treatment,
  tax_event_timing,
  fee_accrual_basis,
  event_order
)
```

Cada evento declara `effective_at`, `sequence`, `event_type`, valor, moeda, `claim_id`, `account_convention_id` e estado antes/depois. `claim_id` referencia o mesmo registro normativo usado por fluxos e estoques. Contribuir antes ou depois do retorno, cobrar taxa sobre saldo médio ou final e recolher imposto no resgate produzem resultados diferentes; portanto a ordem nunca fica apenas em prosa.

O ledger deve reconciliar:

$$
W_{t+1}-W_t=C_t-X_t+Income_t+Gain_t-Fee_t-Tax_t
$$

dentro da tolerância monetária. Se `return_basis=total_return`, `Income_t` é zero na identidade porque proventos já estão embutidos; se `return_basis=price_return`, proventos entram em `Income_t` e `Gain_t` contém apenas variação de preço. O ledger rejeita a combinação inconsistente.

### Vetor de estado econômico

Um modelo inicial pode usar:

$$
X_t=(\pi_t,r_t^r,y_t^{eq},fx_t,z_t^{labor},h_t)
$$

com inflação, taxa real, retorno de ações, câmbio, estado laboral e choque de despesas/saúde. O gerador deve declarar:

- frequência;
- distribuição marginal e dependência;
- condicionamento à curva atual;
- regime e transições;
- método de estimação;
- período/calibração;
- tratamento de dados faltantes;
- estabilidade fora da amostra.

### Famílias de cenários

| Família | Uso | Limitação |
| --- | --- | --- |
| determinístico | fórmulas e sensibilidade | não mede caudas |
| histórico point-in-time | backtest | história não contém todos os futuros |
| bootstrap em blocos | dependência temporal empírica | amostra finita e regime fixo |
| paramétrico | simulação controlada | risco de especificação |
| regime-switching | mudanças persistentes | identificação e parâmetros frágeis |
| condicionado à curva | coerência com mercado atual | curva não é previsão perfeita |
| stress narrativo | resiliência | probabilidades geralmente desconhecidas |
| ensemble | incerteza de modelo | pesos precisam de governança |

GBM independente é fixture educativa. Um default de produção deve capturar inflação, taxas e dependência ou declarar que não o faz.

### Contrato de RNG

```text
RandomSpec(
  algorithm,
  seed,
  stream_id,
  antithetic,
  quasi_random,
  scramble,
  library_version
)
```

Submódulos usam streams derivados determinísticamente para impedir que adicionar uma variável altere todas as séries existentes sem intenção. O manifesto declara uma classe de reprodução: `exact`, `numeric_tolerance`, `statistical` ou `solver_dependent`. No modo `exact`, ordem de geração e paralelismo são congelados; nos demais, o contrato promete tolerâncias ou distribuição, não igualdade bit a bit entre bibliotecas, CPUs e versões.

### Políticas de retirada

Todas as políticas implementam:

```text
withdraw(state, policy_parameters, period) -> WithdrawalDecision
```

Baselines:

- `fixed_real(amount)`;
- `fixed_percent(rate)`;
- `remaining_value(horizon_rule, floor)`;
- `guardrails(initial_rate, upper, lower, adjustment)`;
- `floor_target(discretionary_rule)`;
- `liability_ladder(matched_cashflows, risk_budget)`.

Cada política especifica comportamento com saldo insuficiente, tributos, ordem de contas, rebalanceamento, valor mínimo e morte. A literatura atuarial sustenta avaliar probabilidade e magnitude de shortfall, não apenas exaustão.[^8]

Uma política é uma função do conjunto de informação disponível, não da trajetória futura completa. Para filtração $\{\mathcal F_t\}$, a decisão $a_t=\pi_t(S_t)$ deve ser $\mathcal F_t$-mensurável. Em uma árvore de cenários, nós com o mesmo histórico observável até $t$ recebem a mesma ação.

### Horizonte móvel

Em datas de revisão $t_k$, o motor resolve um horizonte $[t_k,\omega]$, executa apenas a ação imediata, observa o próximo estado e resolve novamente. Custos e decisões irreversíveis permanecem no estado.

O histórico guarda:

- plano anterior;
- estado observado;
- premissas alteradas;
- diferença de política;
- custo da mudança;
- atribuição estruturada sob o modelo.

## 📈 Portfólio, localização e otimização

### Estimadores

O backend de portfólio recebe estimadores como protocolos:

```text
ExpectedReturnEstimator.fit(data, views) -> Estimate
CovarianceEstimator.fit(data) -> Estimate
ScenarioEstimator.fit(data, state) -> ScenarioSet
```

`Estimate` contém valor, incerteza, janela, método e diagnóstico. Média histórica simples e covariância amostral são baselines, nunca escolhas invisíveis.

Métodos candidatos:

- shrinkage de covariância;
- fatores;
- Black-Litterman com incerteza de views;
- estimadores robustos;
- cenários e CVaR;
- distribuição robusta em `experimental`.

### Baselines obrigatórios

- 100% ativo seguro coerente com a meta;
- 1/N entre classes elegíveis;
- alocação fixa e rebalanceamento periódico;
- glide path declarada;
- liability matching para piso;
- solução anterior sem otimização.

Uma solução complexa só é promovida se superar baselines em avaliação fora da amostra e stress. A literatura mostra que 1/N pode ser competitivo quando erro de estimação domina.[^9]

### Objetivos

Exemplos suportados:

$$
\min_w\;\frac{1}{2}w^\top\Sigma w-\lambda\mu^\top w
$$

$$
\min_w\;CVaR_\alpha(L(w))
$$

$$
\min_w\;\mathbb{E}[(B_\omega-W_\omega)^+]
$$

$$
\min_\pi\;\mathbb{E}\left[\sum_{t=t_0}^{\omega}\beta^{\Delta(t_0,t)}\ell(C_t,B_t)+\phi(W_\omega)\right]
$$

O último é multiperíodo e só entra depois de validar versões reduzidas.

### Informação e não-antecipatividade

Toda formulação estocástica declara `InformationSet` e `Policy`:

```text
InformationSet(time, observed_state_ids, publication_lags, revision_policy)
Policy(action_time, information_set_id, state_to_action_rule)
```

É proibido usar retorno, morte, inflação, revisão de dado ou regra publicados depois da ação. Em programação por cenários, restrições de não-antecipatividade ligam decisões que compartilham o mesmo histórico. Uma solução `wait_and_see` com informação perfeita só pode ser exibida como bound diagnóstico, com direção do bound dependente do objetivo; nunca como política implementável.

### Restrições

- orçamento e não negatividade quando aplicável;
- limites por ativo/classe/emissor/moeda;
- liquidez e prazo da meta;
- lotes mínimos;
- turnover e custos;
- tributação e localização por conta;
- exposição a capital humano/setor;
- margem, alavancagem e short desabilitados por padrão;
- cobertura mínima do piso;
- capacidade de contribuição e retirada.

Restrições regulatórias de produto pertencem à implantação prescritiva, mas o núcleo aceita limites fornecidos e os explica.

### Localização entre contas

O problema decide o par `(asset, account)` considerando retorno pré-imposto, tributação, custos, liquidez, titularidade e regras de retirada. Cada lote preserva base de custo e relógio fiscal. Quando variáveis inteiras forem necessárias, o contrato identifica explicitamente `problem_class=MIP`; uma solução da relaxação não é promovida como solução do problema discreto.

Não se usa uma alíquota marginal constante para todo horizonte quando o evento tributário depende de tempo, renda ou lote. Aproximações precisam ser nomeadas e comparadas a uma avaliação por eventos.

### Solvers

`SolverResult` contém:

```text
status
objective_value
primal_residual
dual_residual
duality_gap
best_bound
mip_gap
iterations
solve_time
active_constraints
solver_name
solver_version
solver_options
fallback_used
global_or_local
```

Campos não aplicáveis são `null` com motivo. Estados de backend são mapeados sem suavização semântica. Se a solução for inexata, a camada de relatório diz “solução numérica aproximada dentro/fora das tolerâncias”, não “ótima”. Solvers não convexos declaram se a garantia é local; MIP declara incumbent, best bound e gap.

### Programação dinâmica e aprendizado

A equação de Bellman conceitual é:

$$
V_t(s)=\max_{a\in A(s)}\left\{u(s,a)+\beta\mathbb{E}[V_{t+1}(S')\mid s,a]\right\}
$$

O model card de utilidade declara domínio, unidade de consumo, aversão a risco, substituição intertemporal, desconto, bequest, piso e tratamento de morte; expected utility, Epstein–Zin e objetivos de shortfall não são intercambiáveis. Maldição da dimensionalidade, erro de aproximação e extrapolação tornam políticas aprendidas perigosas. Todo método aproximado deve:

- comparar com solução exata em caso reduzido;
- publicar erro de Bellman ou diagnóstico equivalente;
- testar estados fora da distribuição de treino;
- respeitar restrições duras por construção;
- possuir fallback simples;
- permanecer em `experimental` até revisão independente.

## 📚 Métricas, explicação e relatório

### Shortfall temporal

Para recursos líquidos $R_i$ e piso $B_i$, ambos expressos como montantes no intervalo civil $[d_i,d_{i+1})$:

$$
D_i=(B_i-R_i)^+
$$

Se a entrada for taxa de consumo/renda, ela é primeiro convertida em montante pela convenção e por $\Delta(d_i,d_{i+1})$; omitir essa unidade é erro dimensional.

O motor seleciona exatamente um tratamento de sobrevivência:

1. `pathwise_household_state`: morte e transições familiares já pertencem a cada trajetória; $B_i$, $R_i$ e $D_i$ são calculados no estado observado e não recebem outro peso de sobrevivência;
2. `analytic_state_weighting`: déficits condicionais $D_i(h)$ são calculados por estado familiar e ponderados uma única vez por $P(H_{d_i}=h\mid\mathcal I_{t_0})$.

Misturar os dois modos é `rejected` por dupla ponderação. As métricas fundamentais são:

$$
P_{any}=P\left(\max_iD_i>0\right)
$$

$$
ExpectedDeficit_i=\mathbb{E}[D_i]
$$

$$
ConditionalMeanDeficit_i=\mathbb{E}[D_i\mid D_i>0]
$$

Se $P(D_i>0)=0$, `ConditionalMeanDeficit_i` é `not_applicable`, não zero.

$$
TailExpectedShortfall_{\alpha,i}=\frac{1}{1-\alpha}\int_{\alpha}^{1}VaR_u(D_i)\,du
$$

Para ponderação analítica de estados:

$$
SurvivalWeightedDeficit=\sum_i v(t_0,d_i)\sum_{h\in\mathcal H_{active}}
P(H_{d_i}=h\mid\mathcal I_{t_0})\,\mathbb E[D_i(h)\mid h,\mathcal I_{t_0}]
$$

No modo pathwise, o análogo é $\sum_i v(t_0,d_i)\mathbb E[D_i]$, sem multiplicador adicional. A duração esperada é $Y_{short}=\mathbb{E}[\sum_i\mathbf{1}(D_i>0)\Delta(d_i,d_{i+1})]$. O relatório inclui quantis, data do primeiro déficit e convenção de perda. A sigla `ES` fica reservada a `TailExpectedShortfall`; déficit esperado incondicional e média condicional recebem nomes completos.

### Renda e consumo

- renda líquida real por período e percentis;
- consumo essencial coberto;
- consumo alvo coberto;
- corte máximo e duração;
- volatilidade de consumo;
- valor presente do consumo;
- consumption-equivalent quando a utilidade for válida.

### Patrimônio e legado

- saldo total e líquido por conta;
- valor terminal condicionado à sobrevivência;
- legado após tributos/custos modelados;
- probabilidade de legado mínimo;
- composição e liquidez;
- máximo drawdown apenas como diagnóstico, não proxy universal de bem-estar.

### Custos, tributos e implementação

- taxa total e por fonte;
- imposto por evento, conta e lote;
- turnover e custo de transação;
- perdas por liquidez/spread quando modeladas;
- tracking error contra política;
- número e magnitude de violações/fallbacks.

### Incerteza da estimativa

Para probabilidade Monte Carlo $\hat p$ com $N$ trajetórias independentes:

$$
SE(\hat p)=\sqrt{\frac{\hat p(1-\hat p)}{N}}
$$

Em trajetórias correlacionadas, quasi-Monte Carlo ou ponderadas, o erro exige método compatível. O motor não aplica a fórmula acima mecanicamente.

Quantis e `TailExpectedShortfall` usam bootstrap ou estimador de variância documentado. Resultados exibem erro amostral separado de incerteza de modelo e parâmetros.

### Atribuição estruturada sob o modelo

Cada métrica pode apontar para contribuições contrafactuais implicadas pelo modelo:

```text
metric: survival_weighted_deficit
baseline: 184000.00 BRL-real-2026
deltas:
  - factor: retirement_date
    value: -42000.00
  - factor: contribution_schedule
    value: -31000.00
  - factor: longevity_assumption
    value: 27000.00
residual: 500.00
method: ordered_recalculation
counterfactual_reference: baseline_plan
order_sensitive: true
interaction_residual: 500.00
```

Quando a decomposição for dependente de ordem, usar Shapley aproximado ou declarar ordem, interações e resíduo. Isso é `AttributionGraph`, não inferência causal sobre o mundo. O termo causal só é permitido com DAG/SCM explícito, intervenção, hipóteses de identificação, dados/estimador adequados, incerteza e revisão independente. Texto narrativo só pode verbalizar o objeto calculado.

### Comparação de planos

Uma comparação válida exige mesmos cenários e estado inicial, salvo quando a diferença é deliberada. _Common random numbers_ reduzem variância da diferença. O relatório mostra:

- diferença estimada;
- erro da diferença;
- casos em que cada alternativa domina;
- trade-offs sem agregação forçada;
- premissas não compartilhadas;
- sensibilidade de ranking.

## 🧪 Invariantes, validação e critérios de aceite

### Invariantes financeiros

- conservação de fluxo e saldo;
- equivalência de taxa preserva fator;
- soma de pesos de portfólio respeita orçamento;
- custos e tributos não criam riqueza;
- desconto e indexação usam a mesma base;
- ativos não são alocados duas vezes;
- probabilidades permanecem no intervalo unitário;
- pesos de cenário somam um dentro da tolerância;
- quantis são não decrescentes;
- CVaR não é menor que VaR para a convenção de perda usada;
- solução reportada respeita restrições dentro da tolerância.

### Propriedades monotônicas esperadas

Em casos controlados:

- aumentar saldo inicial não piora funding;
- aumentar contribuição não piora funding;
- aumentar despesa não melhora funding;
- aumentar taxa/custo não melhora saldo líquido;
- adicionar renda garantida não aumenta necessidade;
- estender horizonte de consumo não reduz capital necessário sem efeito compensador;
- aumentar mortalidade pode reduzir obrigação de renda individual, mas pode aumentar necessidade de seguro — os módulos precisam explicar a diferença.

Quebra de monotonicidade dispara diagnóstico; nem toda quebra é bug, mas nenhuma passa silenciosamente.

### Casos analíticos

O corpus mínimo contém:

1. um fluxo único com desconto conhecido;
2. anuidade certa finita;
3. perpetuidade apenas como teste matemático;
4. anuidade sobrevivência-ponderada pequena;
5. contribuição constante com solução fechada;
6. carteira de dois ativos com solução convexa conhecida;
7. problema de CVaR discreto enumerável;
8. casal com mortalidade determinística para reconciliar estados;
9. conta sem tributo e com tributo simples por lote;
10. sequência de saldo que reconcilia em centavos;
11. cupom/dividendo sob `price_return` versus `total_return`, sem dupla contagem;
12. transferência entre contas que conserva riqueza consolidada;
13. árvore de dois estágios em que não-antecipatividade difere de informação perfeita;
14. déficit pathwise e ponderação analítica que coincidem no caso reduzido, sem peso duplo;
15. contribuição avaliada integralmente na data de aposentadoria, com checagem dimensional.

### Comparadores diferenciais

- convenções e curvas contra `R-fixedincome` e QuantLib;
- calendários contra `python-bizdays` e fonte oficial;
- modelos reduzidos de consumo contra HARK;
- portfólio contra PyPortfolioOpt/skfolio/Riskfolio;
- solver contra enumeração em dimensões pequenas;
- políticas brasileiras contra exemplos da autoridade.

Diferença não é automaticamente erro do novo motor. O teste precisa reconciliar convenção, calendário, arredondamento e domínio antes de julgar.

Bibliotecas externas são comparadores independentes, não oráculos. Verdades de referência são limitadas a derivação fechada, enumeração exaustiva, identidade contábil ou exemplo oficial dentro do escopo exato. Versão, commit, licença SPDX e ambiente de cada comparador entram no manifesto do benchmark.

### Rotas locais de validação e limite do self-check

O corpus executável atual tem 21 vetores: 18 bindings dos 15 casos normativos acima e três casos suplementares com `spec_case_id: null`. Cada vetor declara duas rotas e classifica o alcance da segunda como `independent_algorithm`, `independent_enumeration`, `exact_identity_reconciliation` ou `independent_numeric_representation`. As duas últimas classes não são dois algoritmos independentes; são, respectivamente, uma identidade/reconciliação exata e outra representação numérica da mesma identidade.

`--self-check` verifica o corpus, o adapter Decimal `test_only`, a rota Fraction/enumeração e a sensibilidade das fixtures. Seu status é `self_check_passed` e `sut_conformance_status=not_evaluated`: esse resultado não é conformance de SUT, validação do futuro motor, autoridade de release nem aprovação de domínio. O modo SUT só pode terminar como `sut_conformance_passed` quando recebe juntos o manifesto de mutantes e seu SHA-256, além do SHA-256 fornecido pelo chamador para o manifesto do bundle de validação. Um digest fornecido pelo chamador fixa bytes, mas, sem assinatura/trust externo, não prova autoria, independência nem autorização de release.

O bundle fecha três source sets disjuntos (`reference`, `validation` e `harness`), fixa cada arquivo por SHA-256, recusa bytes idênticos entre as fontes de referência e validação e limita por AST os imports da rota de validação. `reference_adapter`, imports dinâmicos e execução dinâmica são rejeitados nessa rota. Adapter e rota de validação são copiados para roots temporários distintos. A rota de validação precomputa em subprocesso o conjunto fechado de requests, depois de repetir três amostras e exigir respostas byte-canônicas iguais; o cache resultante aceita apenas essas chaves JSON canônicas e devolve cópias defensivas. A sensibilidade das fixtures carrega somente o snapshot privado e test-only da referência no processo do harness, restaura módulos colidentes e protege o contexto Decimal; nunca usa esse atalho para executar o SUT candidato. Isso é evidência de uma fronteira estática de validation route, não prova de independência metodológica: código pode reproduzir o mesmo erro sem importar ou copiar bytes. Por isso o grid também contém sentinelas de identidade que não usam nenhuma das duas rotas; em particular, a anuidade de quatro fatores mata o defeito comum que truncaria a soma em três fatores.

O relatório normativo do harness é o JSON `financial-planning-sdk-br.math-conformance-report.v1`; o texto existe apenas para leitura humana. O JSON fecha status, modo, contagens, evidência da fronteira, contagem do cache fechado e das três repetições, proveniência não autenticada do digest e limites de isolamento. Windows usa Job Object com kill-on-close. Em POSIX, `killpg` é somente `best_effort_same_process_group`: um descendente pode escapar com `setsid`/`setpgid`. Execução estrita de código não confiável exige sandbox/cgroup/namespace externo; filesystem e rede continuam `not_enforced` no runner local.

### Convergência estocástica

Para $N,2N,4N$ trajetórias, registrar estabilidade de:

- média;
- percentis selecionados;
- probabilidade de déficit;
- `TailExpectedShortfall`;
- ranking entre alternativas.

O gate usa tolerância absoluta e relativa definida por métrica. Métricas de cauda exigem amostra maior ou técnica de redução de variância.

### Validação de cenário

- marginais e autocorrelação;
- correlações e dependência de cauda;
- coerência nominal-real;
- curva inicial reproduzida;
- frequência de regimes;
- cobertura de previsão fora da amostra;
- comportamento sob stress;
- estabilidade de parâmetros.

Bom ajuste histórico não é suficiente. O model card explica falhas conhecidas e períodos onde o modelo não é confiável.

### Critérios para promover um módulo

Promoção segue também [MODEL_RISK.md](../../MODEL_RISK.md): model card, owner, reviewer, population, incerteza, usos proibidos, benchmark e prazo de revisão são obrigatórios.

| Nível | Critérios |
| --- | --- |
| `experimental` | API instável, hipótese documentada, exemplos sintéticos |
| `research` | paper/comparador, testes analíticos, benchmark reproduzível |
| `beta` | revisão independente, casos BR, estabilidade e documentação |
| `stable` | política de compatibilidade, validação externa e histórico de release |

Nenhum módulo de recomendação é promovido pelo mesmo processo; isso exigiria uma governança regulatória própria.

### Critérios do primeiro release determinístico

- 100% dos tipos públicos têm unidade e schema;
- zero conversão implícita real/nominal;
- todos os exemplos fechados reconciliam;
- cobertura de propriedades para dinheiro, taxas, datas e fluxos;
- mutação mata alterações de sinal e operador em fórmulas críticas;
- manifesto reproduz execução;
- política vencida resulta em `rejected` ou `indeterminate`, conforme o reason code;
- fonte ou autoridade ausente resulta em `indeterminate`;
- CLI retorna códigos de saída documentados;
- documentação em PT-BR e referência técnica em inglês;
- revisão independente matemática, atuarial e de planejamento;
- revisão jurídico-regulatória, tributária/previdenciária, privacidade e licença de dados para todo módulo correspondente, com aprovação e expiração registradas.

## 🔗 Referências

[^1]: IBGE. “Tábuas Completas de Mortalidade.” <https://www.ibge.gov.br/estatisticas/sociais/populacao/9126-tabuas-completas-de-mortalidade.html>

[^2]: Lee, R. D., and Carter, L. R. (1992). “Modeling and Forecasting U.S. Mortality.” <https://doi.org/10.1080/01621459.1992.10475265>

[^3]: Cairns, A. J. G., Blake, D., and Dowd, K. (2006). “A Two-Factor Model for Stochastic Mortality with Parameter Uncertainty.” <https://doi.org/10.1111/j.1539-6975.2006.00195.x>

[^4]: Viceira, L. M. (2001). “Optimal Portfolio Choice for Long-Horizon Investors with Nontradable Labor Income.” <https://doi.org/10.1111/0022-1082.00333>

[^5]: Cocco, J. F., Gomes, F. J., and Maenhout, P. J. (2005). “Consumption and Portfolio Choice over the Life Cycle.” <https://doi.org/10.1093/rfs/hhi017>

[^6]: Receita Federal. “Como declarar PGBL e VGBL?” <https://www.gov.br/receitafederal/pt-br/acesso-a-informacao/perguntas-frequentes/imposto-de-renda/dirpf/declaracao/pgvl-vgbl>

[^7]: INSS. (2026). “Regras de aposentadoria mudam em 2026; entenda.” <https://www.gov.br/inss/pt-br/noticias/noticias/regras-de-transicao-mudam-os-requisitos-para-aposentadoria-em-2026>

[^8]: Society of Actuaries Research Institute. (2023). “A Primer on Retirement Income Strategy Design and Evaluation.” <https://www.soa.org/globalassets/assets/files/resources/research-report/2023/ret-income-strat-de.pdf>

[^9]: DeMiguel, V., Garlappi, L., and Uppal, R. (2009). “Optimal Versus Naive Diversification.” <https://doi.org/10.1093/rfs/hhm075>

---

_Última atualização: 8 de agosto de 2026_
