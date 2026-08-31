# Contrato `deterministic_cashflow_ledger` 0.1 draft

## Escopo executável

O vertical calcula valor presente de fluxos certos e reproduz um ledger de contas em ordem explícita. É uma biblioteca matemática local: não busca curva, calendário, índice, preço, regra fiscal ou dado pessoal; não compara planos nem produz recomendação.

Superfícies públicas:

```python
from financial_planning_sdk_br import (
    compute_deterministic,
    run_reference_acceptance_pack,
    validate_deterministic_request,
)
```

```powershell
finplanbr validate .\request.json
finplanbr compute deterministic .\request.json
finplanbr compute deterministic .\request.json --output .\result.json
finplanbr reference run
```

SDK e CLI executam o mesmo caso de uso. `compute_deterministic()` e `validate_deterministic_request()` aceitam `JsonObject`, cuja raiz precisa ser `dict` exata e cujos descendentes precisam ser apenas `dict`, `list`, `str`, `int`, `bool` e `None` exatos. Subclasses, custom `Mapping`, custom containers, dataclasses internas, construção manual, `replace()` e objetos com aparência compatível não são inputs públicos. A CLI retorna `0` para sucesso, `2` para contrato inválido e `1` para falha operacional de escrita. Diagnósticos não repetem valores do input.

O namespace provisório `DCL_*` contém 36 códigos fechados em `DETERMINISTIC_REASON_CODES`; `ValidationIssue` recusa código fora do roster. `DCL_NUMERIC_OVERFLOW` identifica resultado monetário exato fora do limite público, enquanto `DCL_NUMERIC_INVARIANT_FAILED` identifica signal, inexatidão ou estado não finito fora da fronteira de arredondamento permitida. Esse namespace pertence ao contrato local 0.1 e ainda não foi promovido ao catálogo F0 de 62 códigos, que permanece draft e bloqueado. Antes de estabilizar a API, a migração precisa ser explícita e versionada, nunca por alias silencioso.

## Entrada fechada

O objeto raiz contém exatamente:

| Campo | Contrato |
| --- | --- |
| `contract_version` | literal `0.1.0-draft.1` |
| `calculation_id` | identificador ASCII lowercase estável |
| `valuation_date` | data civil ISO `YYYY-MM-DD` existente |
| `base_currency` | literal `BRL` nesta versão |
| `use_context` | finalidade research/test/education; três flags operacionais obrigatoriamente falsas |
| `discount_factors` | pares ordenados e únicos de data/fator positivo |
| `cashflows` | fluxos ordenados por data/ID, com `claim_id` e dinheiro BRL |
| `accounts` | contas ordenadas por ID, saldo não negativo e convenção de retorno |
| `events` | ledger em ordem estrita `(effective_date, sequence)` |

Campos desconhecidos falham. Dinheiro é string ASCII com exatamente duas casas; fatores de desconto e taxas de retorno são strings, sem expoente, `+`, `NaN`, infinito ou mais de 38 algarismos significativos/18 casas. Dinheiro, fator e taxa possuem três budgets nominais separados de 38 algarismos; não são chamados de IEEE decimal128 e mudar um não altera os demais. Floats JSON são proibidos. O parser rejeita chaves duplicadas, BOM, profundidade, número de nós e tamanho excessivos.

CLI e SDK compartilham o mesmo contrato lógico de 1 MiB, profundidade 32 e 76.814 nós, teto estrutural do schema. A CLI limita primeiro os bytes adquiridos do arquivo. A API verifica recursivamente apenas os tipos built-in exatos, canonicaliza sob esses budgets e faz strict reparse; o snapshot `FPBR-C14N-1` resultante é a única entrada do parser de negócio. Assim, walker e encoder não invocam protocolo de custom container. Custom `Mapping` e código Python arbitrário estão fora da boundary e não são apresentados como isolados. Os aliases públicos `JsonScalar`, `JsonValue` e `JsonObject` preservam typing sem colapsar em `Any`. O default genérico/Reference Pack permanece 1 MiB/20.000 nós.

Cada cashflow exige um fator explícito na própria data. Não há interpolação ou extrapolação silenciosa. Se houver fator na data de avaliação, ele precisa ser `1`.

## Convenção de sinal e eventos

`posting` aplica um delta monetário a uma conta. `contribution` e `income` são positivos; `withdrawal`, `fee` e `tax` são negativos; `gain` e `adjustment` podem ter qualquer sinal. Esses nomes classificam postagens fornecidas — não calculam imposto ou ganho.

`transfer` contém `from_account_id`, `to_account_id`, valor estritamente positivo e `economic_source_id` único. O motor produz `-amount` e `+amount`; a contribuição consolidada da transferência precisa ser `0.00`.

`return` contém taxa maior ou igual a `-1`, uma convenção igual à da conta e distribuição monetária. O ganho usa o saldo corrente imediatamente anterior ao evento, inclusive depois de transferência, postagem ou retorno anterior; dois retornos sequenciais portanto compõem, em vez de reutilizar o saldo de abertura. Em `price_return`, o motor calcula ganho de preço e soma a distribuição separada. Em `total_return`, a distribuição precisa ser `0.00`; uma postagem `income` separada na mesma conta também é rejeitada.

O saldo de uma conta nunca pode ficar negativo neste primeiro corte. Dívidas e contas com crédito exigirão tipo próprio, não um booleano implícito.

## Aritmética e arredondamento

Para fatores fornecidos pelo chamador:

$$
PV_t=\sum_i C_{d_i}D(t,d_i)
$$

Cada produto e soma de PV usa um `Context` Decimal novo e integralmente explícito: `prec=128`, `ROUND_HALF_EVEN`, `Emin=-127`, `Emax=127`, `capitals=1`, `clamp=0` e flags limpas. O contexto exato faz trap de todos os signals; somente o contexto de quantização monetária permite `Inexact` e `Rounded`. Nenhum contexto mutável é compartilhado ou derivado do chamador. Assim, a matriz de precision/rounding/expoentes/traps/flags do processo não altera bytes e não é alterada pela chamada.

A precisão 128 cobre o bound fechado de dois operandos com 38 algarismos e a acumulação de até 4.096 parcelas em escalas contratuais mistas. O roster extremo combina dois produtos mínimos, 2.047 produtos máximos positivos e 2.047 negativos: o acumulador chega a 98 dígitos; precisão 98/128 preserva `0.00000000000000000002` e 97 falha fechado. `present_value_exact` conserva até 20 casas decimais por produto; `present_value` quantiza o total uma única vez para `0.01`, `ROUND_HALF_EVEN`. Ties isolados obedecem half-even para ambos os sinais: `0.005 → 0.00`, `0.015 → 0.02`, `-0.005 → 0.00` sem zero negativo e `-0.015 → -0.02`; a mesma regra vale para o ganho monetário de retorno. Resultado monetário acima de 38 algarismos significativos falha com `DCL_NUMERIC_OVERFLOW`, em vez de arredondar, truncar ou produzir JSON fora do schema. Signal inesperado falha com `DCL_NUMERIC_INVARIANT_FAILED`, sem `DecimalException` pública.

O replay do ledger converte dinheiro canônico para inteiros de centavos por tuple/expoente, acumula e reconcilia somente inteiros e formata por `divmod`. Eventos de retorno calculam o produto saldo×taxa no contexto exato e quantizam o ganho para centavos na fronteira de cada evento, porque esse valor vira uma postagem do ledger. O resultado precisa satisfazer:

$$
W_{close}=W_{open}+PostingNetChange+ReturnNetChange+TransferNetChange
$$

com `TransferNetChange=0`. `PostingNetChange` agrega somente eventos `posting`; `ReturnNetChange` agrega ganho e distribuição dos eventos `return`. O motor não chama retorno de investimento de fluxo externo.

## Saída e limites de autoridade

A saída canônica é UTF-8, chaves ordenadas, sem whitespace insignificante. O nome desse contrato é `FPBR-C14N-1`; ele não é apresentado como RFC 8785. O teto do resultado determinístico é 5.180.619 bytes/108.065 nós, derivado exatamente das cardinalidades e comprimentos máximos do schema; não altera o budget genérico nem o pack.

Todo resultado inclui:

- `artifact_status=draft`;
- `computational_status=computed` apenas para a aritmética local concluída;
- `authority=none`;
- `deployment_eligibility=not_authorized`;
- warnings sobre advice, autoridade, fatores e motores ausentes;
- PV exato/monetário e contribuições por cashflow;
- saldos antes/depois e postagens por evento;
- reconciliação consolidada.

Hash não anonimiza dados e esta versão não emite fingerprint do input. O exemplo versionado é sintético. Não colocar PII real em fixtures, logs, issues ou documentação.

### ValidationReport v2

Input inválido produz o contrato público `finplanbr.validation-report.v2`, disponível também por `validation_report_schema()`. O wire contém `valid`, `issues` e `truncation`: a forma `complete` não duplica contador, e a forma `truncated` contém somente `omitted_issue_count`. Os accessors derivam `issue_count=len(issues)+omitted_issue_count` e `issues_truncated`. O parser conta todas as violações lógicas, conserva no máximo as primeiras 128 na ordem de descoberta e ordena deterministicamente apenas esse prefixo. Não há materialização nem sort da cauda omitida. Pointer e mensagem são redigidos, ASCII imprimíveis e limitados a 128 caracteres.

Esse relatório tem budget próprio de 128 KiB/1.024 nós, independente dos budgets generic, request, result e Reference Pack. A CLI serializa todo o payload antes da primeira escrita e faz uma única tentativa. Falha de serialização anterior à escrita usa um fallback v2 fixo/redigido; short write retorna RC1 sem retry ou fallback concatenado. Isso não transforma pipe/console em armazenamento transacional.

## Reference Acceptance Pack local

O package inclui um pack corrente `2.0.0-draft.1` de três casos sintéticos fechados. `run_reference_acceptance_pack()` e `finplanbr reference run` executam o mesmo runner e retornam bytes canônicos idênticos. O relatório registra, por caso, operação, `derivation_id`, digest esperado/observado do output completo e assertions com `rule_id`, JSON Pointer, esperado e observado.

O passe exige simultaneamente bytes completos iguais ao expected fixo e todas as assertions iguais com o mesmo tipo JSON. O runtime fecha o SHA-256 da representação canônica do pack, roster, rotas, IDs de derivação e digests dos três outputs. Corromper o pack, trocar derivação ou alterar request sem atualizar a matemática resulta em `local_technical_acceptance_invalid_pack` ou `local_technical_acceptance_failed`.

O arquivo `reference-acceptance-pack.v1.json` permanece empacotado e byte a byte congelado como fixture histórica (SHA-256 raw `b3e5c8078a7258d8df521bb5c8843ef371feeaf681fb6710a6cd57a45918c18c`). Ele não foi sobrescrito. A adoção incondicional de `ValidationReport` v2 exigiu um pack v2 corrente, sem modo condicional: apenas o expected do caso `validate`, a identidade e os digests dependentes mudaram; os dois requests/outputs `compute` são canonicamente idênticos aos do v1. O v2 tem SHA-256 raw `b469fafe7c089e02487d9afe57319b47a96f88b9426b4c75e1c29cf00f831955` e digest canônico `2ffed5c0a763cec1f2b8aae44f457af59b5827407fa353c47ecf01d9029e71cd`.

Esses controles detectam drift local; não criam uma referência independente. O report fixa `provenance=repository_local_untrusted`, `reference_independence=not_claimed`, `authority=none`, `deployment_eligibility=not_authorized` e `release_authorized=false`. Os IDs de derivação nomeiam as regras candidatas documentadas, não uma segunda implementação nem aprovação científica. A decisão original e seus limites estão no [ADR 0005](../decisions/0005-bundled-reference-acceptance-pack.md); a transição preservando v1 está no [ADR 0006](../decisions/0006-explicit-decimal-context-and-mapping-boundary.md).

## Conformance local do corte

O manifesto `tests/vectors/sdk/v1/manifest.json` liga este contrato a sete vetores do corpus: PV unitário, anuidade certa, reconciliação de saldo, transferência interna, price return com distribuição, total return sem distribuição separada e rejeição da combinação de dupla contagem. Os outros 14 IDs são enumerados como fora do escopo; ausência não é convertida em sucesso.

`scripts/validate_sdk_conformance.py` executa o SDK público por worker separado, compara as respostas completas dos sete vetores, roda 71 propriedades em sete famílias e inclui um gate semântico do Reference Acceptance Pack corrente. As propriedades isolam os quatro ties de PV e retorno, limites 38/39 separados para dinheiro/fator/taxa, o bound público de 4.096 termos, recusa de objeto tipado/custom container e retornos sequenciais sobre saldo corrente. As representações auxiliares usam `Fraction` e centavos inteiros; o challenger forte separado não importa Decimal nem o kernel.

O gate de mutação aplica 23 mutantes de código real. Três são compostos e possuem kill cases obrigatórios: half-down somente no ramo negativo, retorno sobre saldo de abertura com ajuste coordenado e falsa reconciliação após omitir posting. O mutante de limite compartilhado 38→39 precisa morrer tanto no caso de fator quanto no de taxa; o mutante de saldo de abertura precisa morrer no retorno sequencial e no pack corrente. Crash, timeout, mutante inviável, survivor ou ausência de qualquer kill obrigatório falham o diagnóstico. São controles limitados, não oráculos do mundo real. O report continua `draft`, sem autenticação de runtime/fonte, sem sandbox e sem autoridade de release; o SUT formal dos 21 vetores permanece `not_evaluated`. A decisão de API e contexto está no [ADR 0006](../decisions/0006-explicit-decimal-context-and-mapping-boundary.md).

## Fora de escopo

- taxa nominal/efetiva, day count, `BUS/252`, curva ou interpolação;
- IPCA, CDI, Selic, marcação a mercado e dados de B3/ANBIMA;
- IRPF, PGBL/VGBL, previdência, RGPS/INSS ou sucessão;
- mortalidade, capital humano, necessidades ou funding;
- comparação, otimização, suitability, recomendação e execução;
- rede, persistência implícita, plugins, YAML e telemetria.
