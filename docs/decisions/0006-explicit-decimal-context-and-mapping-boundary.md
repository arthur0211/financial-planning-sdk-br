# ADR 0006 — contexto decimal explícito, JSON totalizável e relatório bounded

**Estado:** aceito somente para o vertical local `draft` 0.1
**Data:** 2026-08-09

## Contexto

O primeiro kernel copiava o contexto `Decimal` corrente com `localcontext()` e alterava apenas `prec`. Assim, operações herdavam rounding, `Emin`, `Emax`, traps e flags do chamador. Além disso, algumas somas e subtrações do ledger usavam operadores no contexto ambiente. Uma postagem de `0.01` sobre um saldo grande podia perder o centavo e ainda produzir `reconciled=true`, porque fechamento e identidade compartilhavam o mesmo caminho arredondado.

`DeterministicRequest` também era exportado e `compute_deterministic()` confiava em qualquer instância dessa dataclass. Construção manual, `dataclasses.replace()` ou atributos com tipos forjados podiam contornar as invariantes do JSON. `frozen=True`, `slots=True` e annotations descrevem estrutura; não validam valores em runtime.

## Decisão

Fechar as fronteiras como um único contrato:

- `compute_deterministic()` e `validate_deterministic_request()` aceitam somente `JsonObject`: raiz `dict` exata e, recursivamente, apenas `dict`, `list`, `str`, `int`, `bool` e `None` exatos. Subclasses, `Mapping` customizado e qualquer container arbitrário ficam fora da boundary antes de o walker ou encoder invocar protocolo definido pelo objeto;
- a API canonicaliza esse grafo sob o mesmo teto lógico da CLI — 1 MiB, profundidade 32 e 76.814 nós — e faz um parse JSON estrito do snapshot `FPBR-C14N-1`. Esse novo objeto é a única entrada do parser de negócio; a CLI acrescenta apenas a aquisição limitada dos bytes do arquivo antes da mesma etapa;
- toda chamada pública executa novamente o mesmo parser. A representação tipada e o parser que a produz são internos, não fazem parte de `financial_planning_sdk_br.__all__` e nunca funcionam como credencial de validade;
- `JsonScalar`, `JsonValue` e `JsonObject` descrevem a superfície pública sem `Any`; typing não substitui a validação runtime. Código Python arbitrário, custom `Mapping` e custom containers não são isolados pelo processo e são explicitamente recusados, em vez de serem apresentados como input seguro;
- instância tipada interna, `replace()`, objeto incompleto, subclass ou tipo forjado falham na raiz com diagnóstico redigido, sem acessar seus atributos como request válido;
- cada operação Decimal cria um `Context` novo com `prec=128`, `rounding=ROUND_HALF_EVEN`, `Emin=-127`, `Emax=127`, `capitals=1`, `clamp=0` e flags limpas. O contexto exato faz trap de todos os nove signals; somente a quantização monetária nomeada permite `Inexact` e `Rounded`;
- nenhum template de `Context` mutável é compartilhado. `localcontext(explicit_context)` restaura precisão, rounding, limites, traps e flags do chamador;
- dinheiro, fator de desconto e taxa de retorno têm três limites nominais separados de 38 algarismos significativos. Nenhum é IEEE 754 decimal128. Alterar um limite exige decisão explícita por domínio; um relaxamento compartilhado de 38 para 39 não pode promover silenciosamente fator ou taxa;
- o JSON genérico e o Reference Pack mantêm 1 MiB, 20.000 nós e profundidade 32. Somente a rota determinística usa os tetos estruturais derivados de seus schemas: request JSON com 1 MiB e 76.814 nós; resultado com 5.180.619 bytes e 108.065 nós. A API `JsonObject` continua sujeita aos mesmos máximos de arrays e forma do parser;
- saldos, postagens, transferências, agregados e reconciliação do ledger usam inteiros de centavos. A conversão parte de `Decimal.as_tuple()` com expoente `-2`, e a formatação usa `divmod`; não há `value * 100`, `float` ou soma Decimal ambiente;
- somente o ganho de um evento `return` usa produto Decimal exato e a fronteira monetária half-even antes de voltar a centavos inteiros;
- todo tie monetário usa half-even independentemente do sinal: `±0.005` normaliza para `0.00` e `±0.015` para `±0.02`. Cada `return` usa o saldo corrente imediatamente anterior ao evento, de modo que retornos sequenciais compõem sobre o fechamento anterior;
- estouro do domínio público continua `DCL_NUMERIC_OVERFLOW`; signal, inexatidão ou estado não finito fora da fronteira de arredondamento recebe `DCL_NUMERIC_INVARIANT_FAILED`. Nenhuma `DecimalException` integra a interface pública.

`ValidationReport` passa a ser um contrato público versionado, separado do resultado financeiro e do report do Reference Acceptance Pack. O formato `finplanbr.validation-report.v2` evita contagens redundantes no wire: `truncation.status=complete` não contém total e `truncated` contém somente `omitted_issue_count`. Os accessors derivam `issue_count=len(issues)+omitted_issue_count` e `issues_truncated`. O coletor conta todas as violações descobertas, conserva no máximo as primeiras 128 em ordem de descoberta e ordena deterministicamente apenas esse prefixo retido. Pointer e mensagem são ASCII imprimíveis e têm até 128 caracteres; a serialização possui budget próprio de 128 KiB/1.024 nós e schema/acessor públicos.

A CLI prepara integralmente os bytes do report antes da primeira escrita, faz uma única tentativa e não repete short write. Se a serialização falha antes da escrita, usa um fallback v2 fixo, redigido e previamente bounded; depois de escrita parcial não tenta anexar fallback. Isso fecha atomicidade no nível de preparação do payload, não promete transação de pipe/console nem isolamento contra código same-UID.

O bound material tem 4.096 termos: dois produtos `0.01 × 10^-18`, 2.047 produtos máximos positivos e 2.047 negativos. O acumulador pode ocupar 98 dígitos entre adjusted exponent 77 e expoente `-20`; precisão 98 e 128 preservam o resultado `2 × 10^-20`, enquanto 97 falha fechado. O contrato escolhe 128. `Emin/Emax` ±127 cobre os expoentes derivados sem herdar o caller. Esse bound é uma decisão do corte implementado, não uma afirmação de precisão profissional universal.

## Consequências

O mesmo documento produz os mesmos bytes sob contextos ambientes hostis, e o contexto/flags do chamador permanecem inalterados. A identidade consolidada passa a ser exata em centavos e deixa de poder reconciliar uma perda causada por rounding Decimal compartilhado.

A remoção dos dois nomes tipados do inventário público e a recusa de `Mapping` customizado são quebras deliberadas do draft local ainda não publicado. Não há rota de compatibilidade que reintroduza confiança em dataclass ou execute código de container do chamador; consumidores devem conservar um grafo composto somente pelos tipos JSON exatos.

O challenger de teste é separado do package e reconstrói números por parser lexical, `int`, `Fraction` e `divmod` half-even, sem importar `decimal`, `numeric.py` ou o SDK. O diagnóstico local acrescenta ties isolados por sinal/domínio, retornos sequenciais, limites 38/39 separados e mutantes compostos com casos obrigatórios de kill. Um gate executa também o pack corrente; isso continua sem pin externo, sandbox, authority ou autorização de release.

O arquivo histórico `reference-acceptance-pack.v1.json` permanece byte a byte congelado, com SHA-256 raw `b3e5c8078a7258d8df521bb5c8843ef371feeaf681fb6710a6cd57a45918c18c`. Como o expected do caso `validate` precisava adotar `ValidationReport` v2 sem formato condicional, o runner corrente aponta para `reference-acceptance-pack.v2.json`, versão `2.0.0-draft.1`; seus dois requests/outputs de `compute` continuam canonicamente idênticos ao v1. O v1 permanece empacotado como fixture histórica, não é sobrescrito nem apresentado como contrato corrente. O digest raw do v2 é `b469fafe7c089e02487d9afe57319b47a96f88b9426b4c75e1c29cf00f831955` e seu digest canônico `FPBR-C14N-1` é `2ffed5c0a763cec1f2b8aae44f457af59b5827407fa353c47ecf01d9029e71cd`.

O request material de 4.096 termos mede 711.078 bytes/28.695 nós e seu resultado canônico, 1.372.838 bytes/36.897 nós. Os tetos maiores acima não são margem arbitrária: são a soma/serialização exata das cardinalidades e comprimentos máximos publicados nos schemas. `loads_strict` e `canonical_json_bytes` exigem os budgets explicitamente apenas nessas duas rotas; os defaults do pack não foram elevados.

O smoke descartável executa esse mesmo request pela API `JsonObject` sob contexto hostil e pela CLI JSON em source, wheel direto instalado e wheel reconstruído do sdist. Também envia 4.096 eventos inválidos às rotas `validate` e `compute`, exige RC2, schema v2, ausência de traceback, contagem total exata, 128 issues retidas e bytes idênticos entre superfícies. A igualdade observada é de payloads runtime; hashes globais dos builds continuam fora do contrato.

## Alternativas rejeitadas

- alterar somente `prec` em uma cópia do contexto do chamador;
- usar um único `Context` global, cujas flags seriam sticky e compartilhadas entre chamadas;
- tratar signal inesperado como overflow do usuário;
- confiar em `frozen`, `slots`, `Final` ou typing para validação runtime;
- aceitar `Mapping`, `Sequence`, subclasses ou custom containers e alegar que o processo os isola;
- manter uma rota tipada que valide menos que o snapshot JSON estrito;
- truncar a própria contagem de issues, ordenar todas as issues antes do corte ou tentar escrever fallback depois de short write;
- emitir condicionalmente ValidationReport v1/v2 sob o mesmo contrato ou sobrescrever o pack v1 congelado;
- chamar o limite de 38 dígitos de decimal128;
- apresentar o challenger local, mutantes mortos ou pack preservado como validação independente, F0 ou release.
